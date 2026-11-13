export const MAX_MESSAGE_LENGTH = 5000;

const URL_DETECT_REGEX =
  /(?:https?:\/\/|www\.)[^\s<>"'\u200e\u200f\u202a-\u202e]+|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)\/[^\s<>"'\u200e\u200f]+/gi;

export function extractUrlsFromText(text: string): string[] {
  const seen = new Set<string>();
  const matches = text.match(URL_DETECT_REGEX) ?? [];
  const cleaned: string[] = [];
  for (const raw of matches) {
    const trimmed = raw.replace(/[.,;:!?)،؛]+$/u, '');
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      cleaned.push(trimmed);
    }
  }
  return cleaned;
}

export function enforceMaxLength(
  text: string,
  maxLength: number = MAX_MESSAGE_LENGTH,
): { value: string; truncated: boolean } {
  if (text.length <= maxLength) {
    return { value: text, truncated: false };
  }
  return { value: text.slice(0, maxLength), truncated: true };
}

export interface TextSegment {
  text: string;
  highlighted: boolean;
}

export function splitTextByHighlights(
  text: string,
  highlights: string[],
): TextSegment[] {
  if (!text) return [];
  const validHighlights = Array.from(
    new Set(highlights.filter((h) => h && text.includes(h))),
  ).sort((a, b) => b.length - a.length);

  if (validHighlights.length === 0) {
    return [{ text, highlighted: false }];
  }

  const ranges: Array<{ start: number; end: number }> = [];
  for (const phrase of validHighlights) {
    let searchFrom = 0;
    while (searchFrom < text.length) {
      const idx = text.indexOf(phrase, searchFrom);
      if (idx === -1) break;
      const start = idx;
      const end = idx + phrase.length;
      const overlaps = ranges.some((r) => start < r.end && end > r.start);
      if (!overlaps) {
        ranges.push({ start, end });
      }
      searchFrom = idx + phrase.length;
    }
  }

  if (ranges.length === 0) {
    return [{ text, highlighted: false }];
  }

  ranges.sort((a, b) => a.start - b.start);
  const segments: TextSegment[] = [];
  let cursor = 0;

  for (const range of ranges) {
    if (range.start > cursor) {
      segments.push({ text: text.slice(cursor, range.start), highlighted: false });
    }
    segments.push({ text: text.slice(range.start, range.end), highlighted: true });
    cursor = range.end;
  }

  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), highlighted: false });
  }

  return segments;
}
