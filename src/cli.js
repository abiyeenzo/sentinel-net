import { parseTarget, parsePorts } from './target.js';
import { scanTcp } from './scanner.js';

function option(args, name) {
  const i = args.indexOf(name);
  if (i < 0 || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Missing value for ${name}.`);
  return args[i + 1];
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.includes('--authorized')) throw new Error('Explicit authorization required: pass --authorized only for assets you are permitted to scan.');
  const target = parseTarget(option(args, '--target'));
  const ports = parsePorts(option(args, '--ports'));
  const controller = new AbortController();
  process.once('SIGINT', () => controller.abort());
  const observations = await scanTcp({ target, ports, signal: controller.signal });
  process.stdout.write(`${JSON.stringify({ target, startedAt: new Date().toISOString(), observations }, null, 2)}\n`);
}

main().catch(error => {
  process.stderr.write(`Error: ${error.message}\n`);
  process.exitCode = 2;
});
