import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findFilePaths, findNetwork, attributeFiles, scanText } from '../lib/index.js';
import { normalizeConfig } from '../lib/index.js';

const REDACT = normalizeConfig(undefined).redact;

test('finds POSIX and Windows file paths', () => {
  const files = findFilePaths('rm -rf /tmp/scratch && copy C:\\Data\\notes.txt D:\\out\\x', 16);
  assert.ok(files.includes('/tmp/scratch'));
  assert.ok(files.some((p) => p.replace(/\\/g, '/').includes('Data/notes.txt')));
});

test('finds dotfiles and relative paths', () => {
  const files = findFilePaths('cat .env; cat ../secrets/id_rsa; code ./src/app.ts', 16);
  assert.ok(files.some((p) => p.includes('.env')));
  assert.ok(files.some((p) => p.includes('id_rsa')));
  assert.ok(files.some((p) => p.includes('src/app.ts')));
});

test('finds outbound URLs and strips query strings', () => {
  const urls = findNetwork('fetch https://example.com/a?secret=1 then https://10.0.0.9:8080/x', 16);
  assert.ok(urls.includes('https://example.com/a'));
  assert.ok(urls.includes('https://10.0.0.9:8080/x'));
});

test('strips URL userinfo so credentials never enter the trail', () => {
  const urls = findNetwork('curl https://admin:supersecret123@accounts.example.com/api', 16);
  assert.deepEqual(urls, ['https://accounts.example.com/api']);
  assert.ok(!urls.join(' ').includes('supersecret123'));
});

test('scan caps lists via config', () => {
  const cfg = normalizeConfig({ redact: { maxFiles: 2, maxNetwork: 1 } }).redact;
  const scan = scanText('a /one /two /three https://a.example https://b.example', cfg);
  assert.equal(scan.files.length, 2);
  assert.equal(scan.network.length, 1);
});

test('attributeFiles buckets write vs read keys', () => {
  const args = { output: '/tmp/out.txt', path: '/etc/hosts', source: 'extra/path' };
  const scanned = ['/tmp/out.txt', '/etc/hosts', 'extra/path'];
  const { filesRead, filesWritten } = attributeFiles('', args, scanned, REDACT);
  assert.deepEqual(filesWritten, ['/tmp/out.txt']);
  assert.ok(filesRead.includes('/etc/hosts'));
  assert.ok(filesRead.includes('extra/path'), 'unknown/mixed keys default to read');
});
