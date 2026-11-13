import type { Language, Verdict } from '../types';

export interface ShareCardParams {
  score: number;
  verdict: Verdict;
  verdictLabel: string;
  categoryLabel: string;
  appTitle: string;
  scoreLabel: string;
  categoryHeading: string;
  footerText: string;
  lang: Language;
}

const VERDICT_COLORS: Record<Verdict, string> = {
  safe: '#16a34a',
  suspicious: '#d97706',
  dangerous: '#dc2626',
};

export async function downloadShareCard(params: ShareCardParams): Promise<void> {
  if (typeof document !== 'undefined' && document.fonts?.ready) {
    await document.fonts.ready;
  }

  const size = 1080;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const fontFamily =
    '"HelveticaNowDisplayW01-Rg", "IBM Plex Sans Arabic", system-ui, sans-serif';
  const accent = VERDICT_COLORS[params.verdict];
  const isRtl = params.lang === 'ar';

  // Light editorial background
  ctx.fillStyle = '#f4f4f2';
  ctx.fillRect(0, 0, size, size);

  const pad = 72;
  const cardW = size - pad * 2;
  const cardH = size - pad * 2;
  ctx.fillStyle = '#ffffff';
  ctx.strokeStyle = 'rgba(0, 0, 0, 0.1)';
  ctx.lineWidth = 2;
  drawRoundedRect(ctx, pad, pad, cardW, cardH, 32);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = accent;
  drawRoundedRect(ctx, pad + 48, pad + 48, 120, 6, 3);
  ctx.fill();

  ctx.direction = isRtl ? 'rtl' : 'ltr';
  ctx.textAlign = 'center';
  ctx.fillStyle = 'rgba(0, 0, 0, 0.55)';
  ctx.font = `500 30px ${fontFamily}`;
  ctx.fillText(params.appTitle, size / 2, pad + 120);

  const cx = size / 2;
  const cy = 435;
  const radius = 155;
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
  ctx.lineWidth = 22;
  ctx.stroke();

  const progress = Math.max(0, Math.min(100, params.score)) / 100;
  if (progress > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, radius, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * progress);
    ctx.strokeStyle = accent;
    ctx.lineWidth = 22;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  ctx.direction = 'ltr';
  ctx.textAlign = 'center';
  ctx.fillStyle = '#000000';
  ctx.font = `700 104px ${fontFamily}`;
  ctx.fillText(`${params.score}`, cx, cy + 28);

  ctx.direction = isRtl ? 'rtl' : 'ltr';
  ctx.fillStyle = 'rgba(0, 0, 0, 0.55)';
  ctx.font = `500 26px ${fontFamily}`;
  ctx.fillText(params.scoreLabel, cx, cy + 78);

  ctx.fillStyle = accent;
  ctx.font = `700 62px ${fontFamily}`;
  ctx.fillText(params.verdictLabel, cx, 710);

  ctx.fillStyle = 'rgba(0, 0, 0, 0.78)';
  ctx.font = `500 32px ${fontFamily}`;
  ctx.fillText(`${params.categoryHeading}: ${params.categoryLabel}`, cx, 785);

  ctx.strokeStyle = 'rgba(0, 0, 0, 0.1)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(pad + 64, size - pad - 120);
  ctx.lineTo(size - pad - 64, size - pad - 120);
  ctx.stroke();

  ctx.fillStyle = 'rgba(0, 0, 0, 0.55)';
  ctx.font = `400 24px ${fontFamily}`;
  ctx.fillText(params.footerText, cx, size - pad - 58);

  const blob = await new Promise<Blob | null>((resolve) =>
    canvas.toBlob((b) => resolve(b), 'image/png'),
  );
  if (!blob) return;

  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = `kashf-verdict-${params.score}.png`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
}

function drawRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
): void {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height - radius);
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  ctx.lineTo(x + radius, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
}
