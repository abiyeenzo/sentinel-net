import net from 'node:net';

export async function scanTcp({ target, ports, timeoutMs = 1000, concurrency = 4, signal } = {}) {
  if (!net.isIP(target)) throw new Error('Target must be a literal IP address.');
  if (!Array.isArray(ports) || ports.length < 1 || ports.length > 32 || ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535) || new Set(ports).size !== ports.length) {
    throw new Error('Ports must be 1 to 32 unique valid TCP ports.');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000) throw new Error('Timeout must be 100–5000 ms.');
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 8) throw new Error('Concurrency must be 1–8.');
  if (signal?.aborted) throw new Error('Scan cancelled.');

  const results = new Array(ports.length);
  let next = 0;
  async function worker() {
    while (true) {
      if (signal?.aborted) throw new Error('Scan cancelled.');
      const index = next++;
      if (index >= ports.length) return;
      results[index] = await probe(target, ports[index], timeoutMs, signal);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  return results;
}

function probe(host, port, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (result, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      socket.destroy();
      if (error) reject(error); else resolve(result);
    };
    const abort = () => finish(null, new Error('Scan cancelled.'));
    const timer = setTimeout(() => finish({ port, state: 'unknown', reason: 'timeout' }), timeoutMs);
    timer.unref?.();
    signal?.addEventListener('abort', abort, { once: true });
    socket.once('connect', () => finish({ port, state: 'open', reason: 'tcp-connect' }));
    socket.once('error', error => finish({ port, state: 'unknown', reason: error.code ?? 'network-error' }));
    try { socket.connect({ host, port }); } catch (error) { finish(null, error); }
  });
}
