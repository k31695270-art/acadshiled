import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFamilyWarningText, parseBatchMessages } from './batchParse';

test('parseBatchMessages splits blank-line separated blocks and caps at 25', () => {
  const input = 'Message one\n\nMessage two\n\nMessage three';
  assert.deepEqual(parseBatchMessages(input), ['Message one', 'Message two', 'Message three']);

  const many = Array.from({ length: 30 }, (_, i) => `Item ${i + 1}`).join('\n\n');
  assert.equal(parseBatchMessages(many).length, 25);
});

test('parseBatchMessages strips WhatsApp timestamp/sender prefixes on multi-line paste', () => {
  const wa = [
    '[11/12/2026, 9:15 PM] Unknown: مبروك ربحت 5000$ اضغط bit.ly/demo',
    '[11/12/2026, 9:16 PM] Ahmed: لا تفتح هذا الرابط ابداً',
  ].join('\n');
  const parsed = parseBatchMessages(wa);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0], 'مبروك ربحت 5000$ اضغط bit.ly/demo');
});

test('buildFamilyWarningText formats concise bilingual warning', () => {
  const ar = buildFamilyWarningText({
    lang: 'ar',
    score: 85,
    verdictLabel: 'خطيرة',
    categoryLabel: 'سرقة رمز التحقق (OTP)',
    reasons: ['طلب رموز تحقق أو بيانات بنكية حساسة'],
  });
  assert.ok(ar.includes('85/100'));
  assert.ok(ar.includes('OTP'));
});
