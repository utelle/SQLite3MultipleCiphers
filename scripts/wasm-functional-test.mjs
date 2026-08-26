import { pathToFileURL } from 'node:url';

const mjsPath = process.argv[2];
if (!mjsPath) {
  console.error('Usage: node wasm-functional-test.mjs <path-to-sqlite3.mjs>');
  process.exit(1);
}

const { default: sqlite3InitModule } = await import(pathToFileURL(mjsPath).href);
const sqlite3 = await sqlite3InitModule();

console.log('sqlite3 version:', sqlite3.version?.libVersion);

const db = new sqlite3.oo1.DB(':memory:');
try {
  db.exec('CREATE TABLE t(x); INSERT INTO t VALUES (42);');
  const value = db.selectValue('SELECT x FROM t');
  if (value !== 42) throw new Error(`Unexpected value: ${value}`);
  console.log('OK: functional smoke test passed.');
} finally {
  db.close();
}
