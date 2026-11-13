import test from 'node:test';
import assert from 'node:assert/strict';
import {
  enforceMaxLength,
  extractUrlsFromText,
  splitTextByHighlights,
} from './urlDetect';

test('extractUrlsFromText extracts http/https and shortener URLs without trailing punctuation', () => {
  const input =
    'اضغط هنا http://paypa1-secure.xyz/login، أو راجع bit.ly/3x9demo!';
  assert.deepEqual(extractUrlsFromText(input), [
    'http://paypa1-secure.xyz/login',
    'bit.ly/3x9demo',
  ]);
});

test('enforceMaxLength truncates over 5000 characters and flags truncated', () => {
  const longText = 'أ'.repeat(5050);
  const res = enforceMaxLength(longText, 5000);
  assert.equal(res.truncated, true);
  assert.equal(res.value.length, 5000);

  const shortRes = enforceMaxLength('رسالة قصيرة', 5000);
  assert.equal(shortRes.truncated, false);
  assert.equal(shortRes.value, 'رسالة قصيرة');
});

test('splitTextByHighlights splits non-overlapping highlights safely', () => {
  const msg = 'مبروك! ربحت 5000$، اضغط http://paypa1-secure.xyz/login وأرسل رمز التحقق';
  const segments = splitTextByHighlights(msg, [
    'مبروك! ربحت',
    'http://paypa1-secure.xyz/login',
    'رمز التحقق',
  ]);

  const highlightedParts = segments.filter((s) => s.highlighted).map((s) => s.text);
  assert.deepEqual(highlightedParts, [
    'مبروك! ربحت',
    'http://paypa1-secure.xyz/login',
    'رمز التحقق',
  ]);
  assert.equal(segments.map((s) => s.text).join(''), msg);
});
