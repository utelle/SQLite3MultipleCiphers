import { readFileSync } from 'node:fs';

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error('Usage: node wasm-smoke-test.mjs <path-to-sqlite3.wasm>');
  process.exit(1);
}

console.log(`Compiling ${wasmPath} ...`);
const bytes = readFileSync(wasmPath);

try {
  await WebAssembly.compile(bytes);
  console.log('OK: wasm module compiled successfully.');
} catch (err) {
  console.error('FAIL: wasm module could not be compiled (this is the class of bug from issue #252).');
  console.error(err);
  process.exit(1);
}
