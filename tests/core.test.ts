import test from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redact, isValidLuhn, isValidIban } from '../src/index';

test('redacts an email and restores it through a vault', () => {
  const vault = createVault();
  const redacted = vault.redact('Contact alice@example.com').value;
  assert.match(redacted, /\[EMAIL_1\]/);
  assert.equal(vault.restore(redacted), 'Contact alice@example.com');
});

test('one-shot redact handles strings', () => {
  const result = redact('Contact alice@example.com');
  assert.doesNotMatch(result, /alice@example\.com/);
});

test('checksum validators accept known valid examples', () => {
  assert.equal(isValidLuhn('4111111111111111'), true);
  assert.equal(isValidIban('DE89370400440532013000'), true);
});
