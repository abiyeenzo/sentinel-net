import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget, parsePorts } from '../src/target.js';

test('accepts literal IPv4 and IPv6', () => {
  assert.equal(parseTarget('127.0.0.1'), '127.0.0.1');
  assert.equal(parseTarget('::1'), '::1');
});

test('rejects hostnames, CIDRs, whitespace and malformed values', () => {
  for (const value of ['localhost', '10.0.0.0/24', ' 127.0.0.1', '']) assert.throws(() => parseTarget(value));
});

test('validates bounded unique port lists', () => {
  assert.deepEqual(parsePorts('22,443'), [22, 443]);
  for (const value of ['0', '65536', '80,80', '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33', '1;id']) assert.throws(() => parsePorts(value));
});
