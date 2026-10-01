import { test } from 'node:test';
import assert from 'node:assert/strict';

import inputValidation from '../data/cwe/web/inputvalidation.js';
import auth from '../data/cwe/auth/auth.js';
import crypto from '../data/cwe/crypto/crypto.js';
import memory from '../data/cwe/native/memory.js';
import webMisc from '../data/cwe/web/web-misc.js';
import concurrency from '../data/cwe/resilience/concurrency.js';
import errors from '../data/cwe/resilience/errors.js';
import logging from '../data/cwe/resilience/logging.js';
import cryptoExtra from '../data/cwe/crypto/crypto-extra.js';
import session from '../data/cwe/auth/session.js';
import permissions from '../data/cwe/auth/permissions.js';
import webInclude from '../data/cwe/web/web-include.js';
import server from '../data/cwe/resilience/server.js';
import brokenAccessControl from '../data/cwe/auth/broken-access-control.js';
import filesPaths from '../data/cwe/web/files-paths.js';
import resourceDos from '../data/cwe/resilience/resource-dos.js';
import cryptoHardening from '../data/cwe/crypto/crypto-hardening.js';
import config from '../data/cwe/resilience/config.js';
import immutable from '../data/cwe/resilience/immutable.js';
import loggingFail from '../data/cwe/resilience/logging-fail.js';
import nullC from '../data/cwe/native/null-c.js';
import webInjection from '../data/cwe/web/web-injection.js';
import evalReflect from '../data/cwe/web/eval-reflect.js';
import pathVar from '../data/cwe/web/path-var.js';
import authBypass from '../data/cwe/auth/auth-bypass.js';

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
	['web-injection', webInjection],
	['eval-reflect', evalReflect],
	['path-var', pathVar],
	['auth-bypass', authBypass],
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
