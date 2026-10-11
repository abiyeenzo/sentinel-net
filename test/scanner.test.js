import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { scanTcp } from '../src/scanner.js';

test('detects an open loopback TCP listener', async () => {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    const [result] = await scanTcp({ target: '127.0.0.1', ports: [port], timeoutMs: 500 });
    assert.deepEqual(result, { port, state: 'open', reason: 'tcp-connect' });
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('refuses unsafe bounds and supports cancellation', async () => {
  await assert.rejects(scanTcp({ target: '127.0.0.1', ports: [80], concurrency: 9 }));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(scanTcp({ target: '127.0.0.1', ports: [80], signal: controller.signal }), /cancelled/i);
});

test('cancels active probes promptly', async () => {
  const server = net.createServer(socket => socket.pause());
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const controller = new AbortController();
  try {
    const pending = scanTcp({ target: '127.0.0.1', ports: [server.address().port], timeoutMs: 5000, signal: controller.signal });
    setTimeout(() => controller.abort(), 25);
    await assert.rejects(pending, /cancelled/i);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
