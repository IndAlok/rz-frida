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

// fake ranges and threads for enumerations, counter for range cache to be checked.
let rangesEnumerated = 0;
const fakeRanges = [
	{ base: new FakePtr(0x1000), size: 0x1000, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 0x1000 } },
	{ base: new FakePtr(0x8000), size: 0x2000, protection: 'rw-' }
];
const fakeThreads = [
	{ id: 1, state: 'waiting' },
	{ id: 2, state: 'running' }
];

const sandbox = {
	Process: {
		platform: 'linux',
		arch: 'x64',
		pointerSize: 8,
		enumerateRanges: function () { rangesEnumerated++; return fakeRanges; },
		enumerateThreads: function () { return fakeThreads; }
	},
	recv: function (cb) { pendingRecv = cb; },
	// frida marshals send() to json over the wire, so capture that form (it also
	// drops vm realm prototype, letting deepStrictEqual compare plain objs).
	send: function (message, data) { sent.push({ message: JSON.parse(JSON.stringify(message)), data: data }); },
	ptr: function (value) { return new FakePtr(value); },
	Memory: {
		readByteArray: function (p, size) {
			const off = p.value - MEM_BASE;
			if (off < 0 || off + size > memory.length) {
				return null;
			}
			return memory.slice(off, off + size).buffer;
		},
		writeByteArray: function (p, bytes) {
			const off = p.value - MEM_BASE;
			if (off < 0 || off + bytes.length > memory.length) {
				throw new Error('access violation');
			}
			for (let i = 0; i < bytes.length; i++) {
				memory[off + i] = bytes[i];
			}
		}
	},
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

const readOverCap = roundtrip({ id: 14, type: 'memRead', params: { address: '0x1000', size: 0x100001 } });
assert.ok(/byte limit/.test(readOverCap.error), 'a size past the limit is rejected');

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
	{ id: 26, ok: true, result: { threads: [{ id: 1, state: 'waiting' }, { id: 2, state: 'running' }] } },
	'threads returns each thread id and state');

console.log('ok - agent script protocol');
