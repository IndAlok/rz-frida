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

const sandbox = {
	Process: { platform: 'linux', arch: 'x64', pointerSize: 8 },
	recv: function (cb) { pendingRecv = cb; },
	// frida marshals send() to json over the wire, so capture that form (it also
	// drops vm realm prototype, letting deepStrictEqual compare plain objs).
	send: function (message, data) { sent.push({ message: JSON.parse(JSON.stringify(message)), data: data }); },
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

console.log('ok - agent script protocol');
