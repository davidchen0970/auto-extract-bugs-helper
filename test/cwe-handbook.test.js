import { test } from 'node:test';
import assert from 'node:assert/strict';

import inputValidation from '../data/cwe/inputvalidation.js';
import auth from '../data/cwe/auth.js';
import crypto from '../data/cwe/crypto.js';
import memory from '../data/cwe/memory.js';
import webMisc from '../data/cwe/web-misc.js';
import concurrency from '../data/cwe/concurrency.js';
import errors from '../data/cwe/errors.js';
import logging from '../data/cwe/logging.js';
import cryptoExtra from '../data/cwe/crypto-extra.js';
import session from '../data/cwe/session.js';
import permissions from '../data/cwe/permissions.js';
import webInclude from '../data/cwe/web-include.js';
import server from '../data/cwe/server.js';
import brokenAccessControl from '../data/cwe/broken-access-control.js';
import filesPaths from '../data/cwe/files-paths.js';
import resourceDos from '../data/cwe/resource-dos.js';
import cryptoHardening from '../data/cwe/crypto-hardening.js';
import config from '../data/cwe/config.js';
import immutable from '../data/cwe/immutable.js';
import loggingFail from '../data/cwe/logging-fail.js';
import nullC from '../data/cwe/null-c.js';

const CHUNKS = [
	['input-validation', inputValidation],
	['web', webMisc],
	['crypto', crypto],
	['memory', memory],
	['auth', auth],
	['concurrency', concurrency],
	['errors', errors],
	['logging', logging],
	['crypto-extra', cryptoExtra],
	['session', session],
	['permissions', permissions],
	['web-include', webInclude],
	['server', server],
	['broken-access-control', brokenAccessControl],
	['files-paths', filesPaths],
	['resource-dos', resourceDos],
	['crypto-hardening', cryptoHardening],
	['config', config],
	['immutable', immutable],
	['logging-fail', loggingFail],
	['null-c', nullC],
];
const REQUIRED = ['id', 'name', 'status', 'what', 'problem', 'fixed', 'patch', 'refs', 'tags'];

const num = (e) => +e.id.replace(/CWE-/, '');

test('every handbook chunk ships at least one entry', () => {
	for (const [cat, entries] of CHUNKS) {
		assert.ok(entries.length > 0, `${cat} chunk is empty`);
		assert.ok(entries.every((e) => e.id && /^CWE-\d+$/.test(e.id)), `${cat} has a malformed id`);
	}
});

test('every handbook entry has all required fields filled in', () => {
	for (const [cat, entries] of CHUNKS) {
		for (const e of entries) {
			for (const k of REQUIRED) {
				assert.ok(e[k] != null && String(e[k]).length > 0, `${cat}/${e.id} missing or empty '${k}'`);
			}
			assert.ok(e.what.length >= 20, `${cat}/${e.id} 'what' too thin`);
			assert.ok(e.problem.length > 0 && e.fixed.length > 0 && e.patch.length > 0, `${cat}/${e.id} code examples empty`);
		}
	}
});

test('the merged handbook is sorted ascending and has no duplicate CWE ids', () => {
	const merged = CHUNKS.flatMap(([, entries]) => entries).sort((a, b) => num(a) - num(b));
	// synthetic merged catalog (mirrors src/ui/cwe.js CATALOG assembly)
	for (let i = 1; i < merged.length; i++) {
		assert.ok(num(merged[i]) > num(merged[i - 1]), `merged not ascending at index ${i}`);
	}
	const uniq = new Set(merged.map((e) => e.id));
	assert.equal(uniq.size, merged.length, 'duplicate CWE ids across chunks');
});
