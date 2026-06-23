'use strict';

const RZ_FRIDA_AGENT_VERSION = 1;

let rangeCache = null;
let moduleCache = null;

const breakpoints = new Map();
let nextBreakpointId = 1;
const parked = [];

function agentInfo() {
  return {
    version: RZ_FRIDA_AGENT_VERSION,
    platform: Process.platform,
    arch: Process.arch,
    pointerSize: Process.pointerSize
  };
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 0x10 ? '0' : '') + bytes[i].toString(16);
  }
  return out;
}

function fromHex(text) {
  if (/^0x/i.test(text)) {
    text = text.slice(2);
  }
  if (text.length % 2 !== 0) {
    throw new Error('hex input must have an even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error('hex input has a non-hex character');
  }
  const out = [];
  for (let i = 0; i < text.length; i += 2) {
    out.push(parseInt(text.slice(i, i + 2), 16));
  }
  return out;
}

function requireAddress(params) {
  if (params.address === undefined || params.address === null || params.address === '') {
    throw new Error('a memory request requires an address');
  }
  return ptr(params.address);
}

function memRead(params) {
  const addr = requireAddress(params);
  const size = params.size;
  if (typeof size !== 'number' || !Number.isInteger(size) || size <= 0) {
    throw new Error('memRead requires a positive integer size');
  }
  requireMapped(addr);
  const buffer = addr.readByteArray(size);
  if (buffer === null) {
    throw new Error('cannot read ' + size + ' bytes at ' + addr);
  }
  const hex = toHex(buffer);
  return { address: addr.toString(), size: hex.length / 2, bytes: hex };
}

function memWrite(params) {
  const addr = requireAddress(params);
  if (typeof params.bytes !== 'string' || params.bytes.length === 0) {
    throw new Error('memWrite requires a hex byte string');
  }
  const bytes = fromHex(params.bytes);
  requireMapped(addr);
  addr.writeByteArray(bytes);
  return { address: addr.toString(), size: bytes.length };
}

function enumerateRanges() {
  return Process.enumerateRanges('---').map(function (range) {
    const out = { base: range.base.toString(), size: range.size, protection: range.protection };
    if (range.file) {
      out.file = { path: range.file.path, offset: range.file.offset, size: range.file.size };
    }
    return out;
  });
}

function rangeContaining(addr) {
  for (let i = 0; i < rangeCache.length; i++) {
    const range = rangeCache[i];
    const base = ptr(range.base);
    if (addr.compare(base) >= 0 && addr.compare(base.add(range.size)) < 0) {
      return range;
    }
  }
  return null;
}

// reject an addr no mapped range backs, refreshing once in case target
// mapped it after cache was filled.
function requireMapped(addr) {
  if (rangeCache === null) {
    rangeCache = enumerateRanges();
  }
  if (rangeContaining(addr) === null) {
    rangeCache = enumerateRanges();
    if (rangeContaining(addr) === null) {
      throw new Error('address ' + addr + ' is not mapped in the target');
    }
  }
}

function ranges(params) {
  const refresh = !!(params && params.refresh);
  const cached = !refresh && rangeCache !== null;
  if (!cached) {
    rangeCache = enumerateRanges();
  }
  return { ranges: rangeCache, cached: cached };
}

// json copy of a frida detail object, every NativePointer becomes a hex str.
function serialize(value) {
  return JSON.parse(JSON.stringify(value));
}

function enumerateThreads() {
  return Process.enumerateThreads().map(function (thread) {
    const out = { id: thread.id, state: thread.state, context: serialize(thread.context) };
    if (thread.entrypoint) {
      out.entrypoint = serialize(thread.entrypoint);
    }
    return out;
  });
}

function threads() {
  return { threads: enumerateThreads() };
}

function enumerateModules() {
  return Process.enumerateModules().map(function (module) {
    return { name: module.name, base: module.base.toString(), size: module.size, path: module.path };
  });
}

function modules(params) {
  const refresh = !!(params && params.refresh);
  const cached = !refresh && moduleCache !== null;
  if (!cached) {
    moduleCache = enumerateModules();
  }
  return { modules: moduleCache, cached: cached };
}

function moduleByName(name) {
  const list = Process.enumerateModules();
  for (let i = 0; i < list.length; i++) {
    if (list[i].name === name) {
      return list[i];
    }
  }
  throw new Error('no module named ' + name);
}

function moduleListing(type, params) {
  if (typeof params.module !== 'string' || params.module.length === 0) {
    throw new Error(type + ' requires a module name');
  }
  const module = moduleByName(params.module);
  const items = (type === 'imports') ? module.enumerateImports()
    : (type === 'symbols') ? module.enumerateSymbols()
      : module.enumerateExports();
  const result = { module: params.module };
  result[type] = serialize(items || []);
  return result;
}

function bpSet(params) {
  const addr = requireAddress(params);
  const key = addr.toString();
  if (breakpoints.has(key)) {
    throw new Error('a breakpoint already exists at ' + key);
  }
  const id = nextBreakpointId++;
  const listener = Interceptor.attach(addr, {
    onEnter() {
      const tid = Process.getCurrentThreadId();
      send({ type: 'frida.bp', bp: id, address: key, threadId: tid, context: serialize(this.context) });
      parked.push(tid);
      let resumed = false;
      do {
        const op = recv('frida.cont.' + tid, function (message) {
          resumed = true;
          if (typeof message.id === 'number') {
            send({ id: message.id, ok: true, result: { resumed: true, threadId: tid } });
          }
        });
        op.wait();
      } while (!resumed);
      const at = parked.indexOf(tid);
      if (at !== -1) {
        parked.splice(at, 1);
      }
    }
  });
  breakpoints.set(key, { id: id, address: key, listener: listener });
  return { address: key, bp: id };
}

function bpList() {
  const list = [];
  breakpoints.forEach(function (bp) {
    list.push({ bp: bp.id, address: bp.address });
  });
  return { breakpoints: list };
}

function bpRemove(params) {
  if (params && params.address === '*') {
    const removed = breakpoints.size;
    breakpoints.forEach(function (bp) {
      bp.listener.detach();
    });
    breakpoints.clear();
    return { removed: removed };
  }
  const addr = requireAddress(params);
  const key = addr.toString();
  const bp = breakpoints.get(key);
  if (!bp) {
    throw new Error('no breakpoint at ' + key);
  }
  bp.listener.detach();
  breakpoints.delete(key);
  return { address: key, removed: 1 };
}

function parkedThreads() {
  return { parked: parked.slice(), recent: parked.length ? parked[parked.length - 1] : null };
}

function invalidateCaches() {
  rangeCache = null;
  moduleCache = null;
}

function handleRequest(request) {
  const type = request.type;
  const params = request.params || {};
  switch (type) {
    case 'ping':
      return agentInfo();
    case 'eval': {
      const source = params.source;
      if (typeof source !== 'string') {
        throw new Error('eval requires a string source');
      }
      // keeps snippet global
      const value = (0, eval)(source);
      invalidateCaches();
      return { value: value === undefined ? null : value, type: typeof value };
    }
    case 'memRead':
      return memRead(params);
    case 'memWrite':
      return memWrite(params);
    case 'ranges':
      return ranges(params);
    case 'threads':
      return threads();
    case 'modules':
      return modules(params);
    case 'exports':
      return moduleListing('exports', params);
    case 'imports':
      return moduleListing('imports', params);
    case 'symbols':
      return moduleListing('symbols', params);
    case 'bpSet':
      return bpSet(params);
    case 'bpList':
      return bpList();
    case 'bpRemove':
      return bpRemove(params);
    case 'bpParked':
      return parkedThreads();
    default:
      throw new Error('unknown request type: ' + String(type));
  }
}

function onRequest(request) {
  recv(onRequest);
  const id = request ? request.id : undefined;
  if (typeof id !== 'number') {
    return;
  }
  try {
    send({ id: id, ok: true, result: handleRequest(request) });
  } catch (e) {
    send({ id: id, ok: false, error: (e && e.message) ? e.message : String(e) });
  }
}

recv(onRequest);

rpc.exports = {
  ping() {
    return agentInfo();
  }
};

send({ type: 'agent.ready', version: RZ_FRIDA_AGENT_VERSION });
