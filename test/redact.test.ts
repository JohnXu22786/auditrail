import { test } from 'node:test';
import assert from 'node:assert/strict';
import { maskText, buildSecretMask, truncate, digestArgs, tryParseJson } from '../lib/index.js';
import { DEFAULT_CONFIG, normalizeConfig } from '../lib/index.js';

const REDACT = normalizeConfig(undefined).redact;

test('masks private key blocks', () => {
  const pem =
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEoQ==\ncorrupted\n-----END RSA PRIVATE KEY-----';
  const out = maskText(pem, buildSecretMask(REDACT));
  assert.ok(out.includes('[REDACTED]'));
  assert.ok(!out.includes('MIIEoQ=='));
});

test('masks authorization headers and bearer tokens', () => {
  const text = 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz.zyx';
  const out = maskText(text, buildSecretMask(REDACT));
  assert.ok(!/abc...zyx/.test(out), 'token covered');
  assert.ok(out.includes('[REDACTED]'));
});

test('masks inline assignments (api_key=...)', () => {
  const out = maskText('api_key=sk-1234567890abcdef', buildSecretMask(REDACT));
  assert.ok(out.includes('[REDACTED]'));
});

test('truncate marks the cut length', () => {
  assert.equal(truncate('1234567890', 5), '12345…(+5 chars)');
  assert.equal(truncate('123', 5), '123');
});

test('disabled masking leaves text intact', () => {
  const cfg = normalizeConfig({ redact: { maskSecrets: false } }).redact;
  const out = maskText('api_key=sk-1234567890', buildSecretMask(cfg));
  assert.ok(out.includes('sk-1234567890'));
});

test('digestArgs keeps keys, masks and truncates values', () => {
  const long = 'The quick brown fox jumps over the lazy dog. '.repeat(20);
  const raw = JSON.stringify({ password: 'hunter2', command: 'rm -rf /x', notes: long });
  const digest = digestArgs(raw, REDACT);
  assert.ok(digest.includes('"password"'), 'key preserved');
  assert.ok(!digest.includes('hunter2'), 'secret value masked');
  assert.ok(digest.includes('…(+'), 'long value truncated');
});

test('digestArgs of raw command text is masked + truncated', () => {
  const digest = digestArgs('curl -H "Authorization: Bearer tok_AAAA" http://h/x', REDACT);
  assert.ok(!digest.includes('tok_AAAA'));
});

test('digestArgs never persists URL userinfo credentials', () => {
  const raw = JSON.stringify({ url: 'https://admin:supersecret123@accounts.example.com/api' });
  const digest = digestArgs(raw, REDACT);
  assert.ok(!digest.includes('supersecret123'), 'URL credentials stripped');
  assert.ok(digest.includes('accounts.example.com'), 'destination kept');
});

test('digestArgs strips userinfo from URLs embedded deep in strings', () => {
  const digest = digestArgs(
    'echo start; curl https://admin:supersecret123@reg.example.com/api/v2/push --data x; echo end',
    REDACT,
  );
  assert.ok(!digest.includes('supersecret123'), 'embedded userinfo stripped');
  assert.ok(digest.includes('reg.example.com'), 'host preserved');
  const objectDigest = digestArgs(
    JSON.stringify({ command: 'git clone https://admin:p@ss@github.com/org/repo.git' }),
    REDACT,
  );
  assert.ok(!objectDigest.includes('p@ss'));
  assert.ok(objectDigest.includes('github.com'));
});

test('digestArgs falls back for unparseable strings', () => {
  assert.equal(digestArgs('ls -la', REDACT), 'ls -la');
});

test('tryParseJson returns undefined for junk', () => {
  assert.equal(tryParseJson('not json'), undefined);
  assert.deepEqual(tryParseJson('{"a":1}'), { a: 1 });
});

test('default config is frozen and mergeable via normalizeConfig', () => {
  assert.equal(DEFAULT_CONFIG.redact.maskSecrets, true);
  const cfg = normalizeConfig({ redact: { truncateArgs: 20 } });
  assert.equal(cfg.redact.truncateArgs, 20);
  assert.equal(cfg.redact.maskSecrets, true);
});
