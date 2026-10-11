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
