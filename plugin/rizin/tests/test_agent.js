// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// runs injected agent (rzfrida_agent.js) in mocked frida runtime and
// checks host-agent req/response protocol without a live target. meson
// runs this when node is available, else skipped.

'use strict';

const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const agentPath = process.argv[2];
if (!agentPath) {
	console.error('usage: test_agent.js <path to rzfrida_agent.js>');
	process.exit(2);
}
const source = fs.readFileSync(agentPath, 'utf8');

const sent = [];
let pendingRecv = null;

// fake target memory region, backs a known byte pattern at MEM_BASE, addressed through ptr().
const MEM_BASE = 0x1000;
const memory = new Uint8Array(256);
for (let i = 0; i < memory.length; i++) {
	memory[i] = i;
}
function FakePtr(value) {
	this.value = (typeof value === 'string') ? Number(value) : value;
}
FakePtr.prototype.toString = function () {
	return '0x' + this.value.toString(16);
};
FakePtr.prototype.compare = function (other) {
	if (this.value < other.value) { return -1; }
	return this.value > other.value ? 1 : 0;
};
FakePtr.prototype.add = function (n) {
	return new FakePtr(this.value + n);
};
FakePtr.prototype.toJSON = function () {
	return this.toString();
};
FakePtr.prototype.readByteArray = function (size) {
	const off = this.value - MEM_BASE;
	if (off < 0 || off + size > memory.length) {
		return null;
	}
	return memory.slice(off, off + size).buffer;
};
FakePtr.prototype.writeByteArray = function (bytes) {
	const off = this.value - MEM_BASE;
	if (off < 0 || off + bytes.length > memory.length) {
		throw new Error('access violation');
	}
	for (let i = 0; i < bytes.length; i++) {
		memory[off + i] = bytes[i];
	}
};

// fake enumerations, counters so the range & module caches can be checked.
let rangesEnumerated = 0;
let modulesEnumerated = 0;
const fakeRanges = [
	{ base: new FakePtr(0x1000), size: 0x1000, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 0x1000 } },
	{ base: new FakePtr(0x8000), size: 0x2000, protection: 'rw-' }
];
const fakeThreads = [
	{ id: 1, state: 'waiting', context: { pc: new FakePtr(0x401000), sp: new FakePtr(0x7000) } },
	{ id: 2, state: 'running', context: { pc: new FakePtr(0x402000), sp: new FakePtr(0x8000) }, entrypoint: { routine: new FakePtr(0x400000), parameter: new FakePtr(0) } }
];
const fakeExports = [
	{ type: 'function', name: 'main', address: new FakePtr(0x401000) },
	{ type: 'variable', name: 'global', address: new FakePtr(0x402000) }
];
const fakeImports = [
	{ type: 'function', name: 'printf', module: 'libc.so', address: new FakePtr(0x7f0000001000) }
];
const fakeSymbols = [
	{ isGlobal: true, type: 'function', name: 'start', address: new FakePtr(0x401000), size: 32 }
];
const fakeModules = [
	{
		name: 'app', base: new FakePtr(0x400000), size: 0x20000, path: '/data/app/app',
		enumerateExports: function () { return fakeExports; },
		enumerateImports: function () { return fakeImports; },
		enumerateSymbols: function () { return fakeSymbols; }
	},
	{
		name: 'libc.so', base: new FakePtr(0x7f0000000000), size: 0x100000, path: '/system/lib/libc.so',
		enumerateExports: function () { return []; },
		enumerateImports: function () { return []; },
		enumerateSymbols: function () { return []; }
	}
];

const sandbox = {
	Process: {
		platform: 'linux',
		arch: 'x64',
		pointerSize: 8,
		enumerateRanges: function () { rangesEnumerated++; return fakeRanges; },
		enumerateThreads: function () { return fakeThreads; },
		enumerateModules: function () { modulesEnumerated++; return fakeModules; }
	},
	recv: function (cb) { pendingRecv = cb; },
	// frida marshals send() to json over the wire, so capture that form (it also
	// drops vm realm prototype, letting deepStrictEqual compare plain objs).
	send: function (message, data) { sent.push({ message: JSON.parse(JSON.stringify(message)), data: data }); },
	ptr: function (value) { return new FakePtr(value); },
	rpc: {},
	console: console
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'rzfrida_agent.js' });

// send one req, return reply, or null when agent stays silent.
function roundtrip(request) {
	const before = sent.length;
	assert.ok(typeof pendingRecv === 'function', 'agent keeps a recv callback registered');
	pendingRecv(request);
	if (sent.length === before) {
		return null;
	}
	assert.strictEqual(sent.length, before + 1, 'agent sends exactly one reply per request');
	return sent[before].message;
}

assert.deepStrictEqual(sent[0].message, { type: 'agent.ready', version: 1 },
	'agent.ready is emitted on load');

assert.deepStrictEqual(roundtrip({ id: 1, type: 'ping' }),
	{ id: 1, ok: true, result: { version: 1, platform: 'linux', arch: 'x64', pointerSize: 8 } },
	'ping replies with agent info');

assert.deepStrictEqual(roundtrip({ id: 2, type: 'eval', params: { source: '1 + 1' } }),
	{ id: 2, ok: true, result: { value: 2, type: 'number' } },
	'eval of a number');

assert.deepStrictEqual(roundtrip({ id: 3, type: 'eval', params: { source: '"a" + "b"' } }),
	{ id: 3, ok: true, result: { value: 'ab', type: 'string' } },
	'eval of a string');

assert.deepStrictEqual(roundtrip({ id: 4, type: 'eval', params: { source: 'undefined' } }),
	{ id: 4, ok: true, result: { value: null, type: 'undefined' } },
	'eval of undefined keeps its type');

assert.deepStrictEqual(roundtrip({ id: 5, type: 'eval', params: { source: 'Process.arch' } }),
	{ id: 5, ok: true, result: { value: 'x64', type: 'string' } },
	'eval can read the frida globals');

const evalError = roundtrip({ id: 6, type: 'eval', params: { source: 'nope.nope' } });
assert.strictEqual(evalError.id, 6, 'error reply keeps the id');
assert.strictEqual(evalError.ok, false, 'error reply is not ok');
assert.strictEqual(evalError.error, 'nope is not defined', 'error message is forwarded');

const evalBadSource = roundtrip({ id: 7, type: 'eval', params: {} });
assert.strictEqual(evalBadSource.ok, false, 'a missing source is rejected');
assert.strictEqual(evalBadSource.error, 'eval requires a string source', 'the source type is reported');

const unknown = roundtrip({ id: 8, type: 'frobnicate' });
assert.strictEqual(unknown.ok, false, 'an unknown type is rejected');
assert.strictEqual(unknown.error, 'unknown request type: frobnicate', 'the unknown type is named');

assert.strictEqual(roundtrip({ type: 'ping' }), null, 'a request without an id draws no reply');

assert.deepStrictEqual(JSON.parse(JSON.stringify(sandbox.rpc.exports.ping())),
	{ version: 1, platform: 'linux', arch: 'x64', pointerSize: 8 },
	'rpc.exports.ping returns the agent info');

assert.deepStrictEqual(roundtrip({ id: 9, type: 'memRead', params: { address: '0x1000', size: 4 } }),
	{ id: 9, ok: true, result: { address: '0x1000', size: 4, bytes: '00010203' } },
	'memRead returns the requested bytes as hex');

assert.deepStrictEqual(roundtrip({ id: 10, type: 'memRead', params: { address: 0x1004, size: 2 } }),
	{ id: 10, ok: true, result: { address: '0x1004', size: 2, bytes: '0405' } },
	'memRead accepts a numeric address');

const readOob = roundtrip({ id: 11, type: 'memRead', params: { address: '0x1000', size: 4096 } });
assert.strictEqual(readOob.ok, false, 'an unreadable range is rejected');
assert.ok(/cannot read/.test(readOob.error), 'the unreadable range is reported');

const readNoAddr = roundtrip({ id: 12, type: 'memRead', params: { size: 4 } });
assert.strictEqual(readNoAddr.error, 'memRead requires an address', 'a missing address is rejected');

const readBadSize = roundtrip({ id: 13, type: 'memRead', params: { address: '0x1000', size: 0 } });
assert.strictEqual(readBadSize.error, 'memRead requires a positive integer size', 'a non-positive size is rejected');

assert.deepStrictEqual(roundtrip({ id: 15, type: 'memWrite', params: { address: '0x1010', bytes: 'deadbeef' } }),
	{ id: 15, ok: true, result: { address: '0x1010', size: 4 } },
	'memWrite reports the number of bytes written');

assert.deepStrictEqual(roundtrip({ id: 16, type: 'memRead', params: { address: '0x1010', size: 4 } }),
	{ id: 16, ok: true, result: { address: '0x1010', size: 4, bytes: 'deadbeef' } },
	'memRead sees the bytes memWrite stored');

const writeOddHex = roundtrip({ id: 17, type: 'memWrite', params: { address: '0x1010', bytes: 'abc' } });
assert.strictEqual(writeOddHex.error, 'hex input must have an even length', 'odd-length hex is rejected');

const writeBadHex = roundtrip({ id: 18, type: 'memWrite', params: { address: '0x1010', bytes: 'zz' } });
assert.strictEqual(writeBadHex.error, 'hex input has a non-hex character', 'non-hex input is rejected');

const writeOob = roundtrip({ id: 19, type: 'memWrite', params: { address: '0x10f8', bytes: 'deadbeefdeadbeefdeadbeef' } });
assert.strictEqual(writeOob.ok, false, 'a write past the region is rejected');

// memRead/memWrite above filled range cache to validate addrs, clear it
// so cache assertions below start from a known state.
roundtrip({ id: 100, type: 'eval', params: { source: '0' } });
rangesEnumerated = 0;

const firstRanges = roundtrip({ id: 20, type: 'ranges' });
assert.strictEqual(firstRanges.result.cached, false, 'the first ranges call enumerates');
assert.deepStrictEqual(firstRanges.result.ranges, [
	{ base: '0x1000', size: 0x1000, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 0x1000 } },
	{ base: '0x8000', size: 0x2000, protection: 'rw-' }
], 'ranges returns the mapped range details');

assert.strictEqual(roundtrip({ id: 21, type: 'ranges' }).result.cached, true, 'a second call serves the cache');
assert.strictEqual(roundtrip({ id: 22, type: 'ranges', params: { refresh: true } }).result.cached, false, 'refresh re-enumerates');
assert.strictEqual(roundtrip({ id: 23, type: 'ranges' }).result.cached, true, 'the refreshed list is cached again');

roundtrip({ id: 24, type: 'eval', params: { source: '1 + 1' } });
assert.strictEqual(roundtrip({ id: 25, type: 'ranges' }).result.cached, false, 'running code drops the cached ranges');
assert.strictEqual(rangesEnumerated, 3, 'the cache avoided redundant enumeration');

assert.deepStrictEqual(roundtrip({ id: 26, type: 'threads' }),
	{ id: 26, ok: true, result: { threads: [
		{ id: 1, state: 'waiting', context: { pc: '0x401000', sp: '0x7000' } },
		{ id: 2, state: 'running', context: { pc: '0x402000', sp: '0x8000' }, entrypoint: { routine: '0x400000', parameter: '0x0' } }
	] } },
	'threads returns id, state, register context, and entrypoint');

const readUnmapped = roundtrip({ id: 27, type: 'memRead', params: { address: '0x50000', size: 16 } });
assert.strictEqual(readUnmapped.ok, false, 'a read of unmapped memory is rejected');
assert.ok(/not mapped/.test(readUnmapped.error), 'the unmapped read address is reported');

const writeUnmapped = roundtrip({ id: 28, type: 'memWrite', params: { address: '0x50000', bytes: 'deadbeef' } });
assert.strictEqual(writeUnmapped.ok, false, 'a write to unmapped memory is rejected');
assert.ok(/not mapped/.test(writeUnmapped.error), 'the unmapped write address is reported');

const firstModules = roundtrip({ id: 29, type: 'modules' });
assert.strictEqual(firstModules.result.cached, false, 'the first modules call enumerates');
assert.deepStrictEqual(firstModules.result.modules, [
	{ name: 'app', base: '0x400000', size: 0x20000, path: '/data/app/app' },
	{ name: 'libc.so', base: '0x7f0000000000', size: 0x100000, path: '/system/lib/libc.so' }
], 'modules returns the mapped module details');

assert.strictEqual(roundtrip({ id: 30, type: 'modules' }).result.cached, true, 'a second modules call serves the cache');
roundtrip({ id: 31, type: 'eval', params: { source: '0' } });
assert.strictEqual(roundtrip({ id: 32, type: 'modules' }).result.cached, false, 'running code drops the cached modules');
assert.strictEqual(modulesEnumerated, 2, 'the cache avoided redundant module enumeration');

assert.deepStrictEqual(roundtrip({ id: 33, type: 'exports', params: { module: 'app' } }),
	{ id: 33, ok: true, result: { module: 'app', exports: [
		{ type: 'function', name: 'main', address: '0x401000' },
		{ type: 'variable', name: 'global', address: '0x402000' }
	] } },
	'exports lists the module exports');

const exportsMissing = roundtrip({ id: 34, type: 'exports', params: { module: 'nope' } });
assert.strictEqual(exportsMissing.error, 'no module named nope', 'an unknown module is rejected');

const exportsNoName = roundtrip({ id: 35, type: 'exports', params: {} });
assert.strictEqual(exportsNoName.error, 'exports requires a module name', 'a missing module name is rejected');

assert.deepStrictEqual(roundtrip({ id: 36, type: 'imports', params: { module: 'app' } }),
	{ id: 36, ok: true, result: { module: 'app', imports: [
		{ type: 'function', name: 'printf', module: 'libc.so', address: '0x7f0000001000' }
	] } },
	'imports lists the module imports');

const importsNoName = roundtrip({ id: 37, type: 'imports', params: {} });
assert.strictEqual(importsNoName.error, 'imports requires a module name', 'imports needs a module name');

assert.deepStrictEqual(roundtrip({ id: 38, type: 'symbols', params: { module: 'app' } }),
	{ id: 38, ok: true, result: { module: 'app', symbols: [
		{ isGlobal: true, type: 'function', name: 'start', address: '0x401000', size: 32 }
	] } },
	'symbols lists the module symbols');

const symbolsMissing = roundtrip({ id: 39, type: 'symbols', params: { module: 'nope' } });
assert.strictEqual(symbolsMissing.error, 'no module named nope', 'symbols rejects an unknown module');

console.log('ok - agent script protocol');
