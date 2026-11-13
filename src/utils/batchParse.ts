export const MAX_BATCH_MESSAGES = 25;

/**
 * Split pasted multi-message text or WhatsApp chat exports into individual messages.
 * Blocks separated by blank lines or `---` are preferred; if the user pasted
 * single-line messages (e.g. one SMS per line), split by newline when there are
 * multiple lines.
 */
export function parseBatchMessages(raw: string, maxItems: number = MAX_BATCH_MESSAGES): string[] {
  const trimmed = (raw || '').trim();
  if (!trimmed) return [];

  // Prefer explicit separator blocks (blank line or ---)
  const blockSplit = trimmed
    .split(/(?:\r?\n\s*\r?\n|\r?\n-{3,}\r?\n)/)
    .map((s) => s.trim())
    .filter(Boolean);

  if (blockSplit.length > 1) {
    return blockSplit.slice(0, maxItems);
  }

  // Fallback: split by individual non-empty lines if user pasted multiple lines
  const lineSplit = trimmed
    .split(/\r?\n/)
    .map((line) => line.replace(/^\[?\d{1,2}\/\d{1,2}\/\d{2,4},?\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\]?\s*-?\s*[^:]{1,40}:\s*/i, '').trim())
    .filter((line) => line.length >= 4);

  if (lineSplit.length > 1) {
    return lineSplit.slice(0, maxItems);
  }

  return [trimmed].slice(0, maxItems);
}

export function buildFamilyWarningText(params: {
  lang: 'ar' | 'en';
  score: number;
  verdictLabel: string;
  categoryLabel: string;
  reasons: string[];
}): string {
  if (params.lang === 'ar') {
    const bullets = params.reasons
      .slice(0, 3)
      .map((r) => `- ${r}`)
      .join('\n');
    return [
      `⚠️ تنبيه احتيال من أداة كشف (${params.verdictLabel} — ${params.score}/100)`,
      `التصنيف: ${params.categoryLabel}`,
      bullets ? `الأسباب:\n${bullets}` : '',
      'لا تضغط على أي رابط ولا تشارك رمز التحقق (OTP) أو بيانات البطاقة.',
    ]
      .filter(Boolean)
      .join('\n');
  }

  const bullets = params.reasons
    .slice(0, 3)
    .map((r) => `- ${r}`)
    .join('\n');
  return [
    `⚠️ Scam Warning via Kashf (${params.verdictLabel} — ${params.score}/100)`,
    `Category: ${params.categoryLabel}`,
    bullets ? `Detected signals:\n${bullets}` : '',
    'Do not click any link or share OTP codes, passwords, or card details.',
  ]
    .filter(Boolean)
    .join('\n');
}
