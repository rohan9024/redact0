import fs from 'node:fs';
import zlib from 'node:zlib';

const file = 'dist/index.mjs';
if (!fs.existsSync(file)) {
  console.error(`File ${file} does not exist. Run npm run build first.`);
  process.exit(1);
}

const content = fs.readFileSync(file);
const gz = zlib.gzipSync(content).length;
console.log(`Core ESM gzip: ${gz} bytes`);

if (gz > 30720) {
  console.error(`Size budget exceeded: ${gz} bytes > 30720 bytes (30 KB)`);
  process.exit(1);
}