// Node.js under hellovm (see hellovm/tests/node.rs): one line per check.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const { Worker } = require('worker_threads');

async function main() {
  await new Promise((r) => setTimeout(r, 20));
  console.log('timers: ok');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node-'));
  const file = path.join(dir, 'a.txt');
  await fs.promises.writeFile(file, 'x'.repeat(100000));
  const back = await fs.promises.readFile(file, 'utf8');
  console.log(`fs: ${back.length}`);

  console.log(`sha256: ${crypto.createHash('sha256').update('hellovm').digest('hex').slice(0, 16)}`);

  const out = execFileSync(process.execPath, ['-e', 'process.stdout.write(String(6*7))']).toString();
  console.log(`execFileSync: ${out}`);

  const child = spawn(process.execPath, ['-e', 'process.stdin.pipe(process.stdout)']);
  let echoed = '';
  child.stdout.on('data', (d) => (echoed += d));
  child.stdin.end('piped');
  await new Promise((r) => child.on('close', r));
  console.log(`spawn: ${echoed}`);

  const sum = await new Promise((resolve, reject) => {
    const w = new Worker('const { parentPort } = require("worker_threads"); let s = 0; for (let i = 0; i < 1e6; i++) s += i; parentPort.postMessage(s);', { eval: true });
    w.on('message', resolve);
    w.on('error', reject);
  });
  console.log(`worker: ${sum}`);

  const server = http.createServer((req, res) => res.end(`hi ${req.url}`));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const bodies = await Promise.all([1, 2, 3].map((i) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: `/${i}` }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve(b));
    }).on('error', reject);
  })));
  server.close();
  console.log(`http: ${bodies.join(',')}`);
}

main().then(() => process.exit(3), (err) => { console.error(err); process.exit(1); });
