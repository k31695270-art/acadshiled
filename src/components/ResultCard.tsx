import { useState } from 'react';
import type { AnalysisReason, AnalysisResult, Language, Verdict } from '../types';
import { i18n } from '../i18n';
import { splitTextByHighlights } from '../utils/urlDetect';
import { downloadShareCard } from '../utils/shareCard';
import { buildFamilyWarningText } from '../utils/batchParse';
import { RiskGauge } from './RiskGauge';
import { UrlForensicsPanel } from './UrlForensicsPanel';

interface ResultCardProps {
  result: AnalysisResult;
  analyzedText: string;
  lang: Language;
  reporting: boolean;
  reported: boolean;
  reportError: string | null;
  onReport: () => Promise<boolean>;
}

const VERDICT_TEXT_CLASS: Record<Verdict, string> = {
  safe: 'text-[#16a34a]',
  suspicious: 'text-[#d97706]',
  dangerous: 'text-[#dc2626]',
};

const VERDICT_MARK_CLASS: Record<Verdict, string> = {
  safe: 'bg-[#16a34a]/15 text-[#14532d] underline decoration-[#16a34a]/60 underline-offset-4',
  suspicious:
    'bg-[#d97706]/15 text-[#78350f] underline decoration-[#d97706]/60 underline-offset-4',
  dangerous:
    'bg-[#dc2626]/15 text-[#7f1d1d] underline decoration-[#dc2626]/70 underline-offset-4',
};

export function ResultCard({
  result,
  analyzedText,
  lang,
  reporting,
  reported,
  reportError,
  onReport,
}: ResultCardProps) {
  const t = i18n[lang];
  const [sharing, setSharing] = useState(false);
  const [copiedWarning, setCopiedWarning] = useState(false);

  const verdictLabel = t.result.verdicts[result.verdict];
  const categoryLabel = t.categories[result.category] ?? t.categories.other;
  const segments = splitTextByHighlights(analyzedText, result.highlights);
  const steps = t.result.steps[result.verdict];

  const handleShare = async () => {
    if (sharing) return;
    setSharing(true);
    try {
      await downloadShareCard({
        score: result.score,
        verdict: result.verdict,
        verdictLabel,
        categoryLabel,
        appTitle: `${t.brandAr} / ${t.brandEn}`,
        scoreLabel: t.result.riskScoreLabel,
        categoryHeading: t.result.categoryLabel,
        footerText: t.result.shareFooter,
        lang,
      });
    } finally {
      setSharing(false);
    }
  };

  const handleCopyWarning = async () => {
    const text = buildFamilyWarningText({
      lang,
      score: result.score,
      verdictLabel,
      categoryLabel,
      reasons: result.reasons.map((r) => (lang === 'ar' ? r.title_ar : r.title_en)),
    });
    try {
      await navigator.clipboard.writeText(text);
      setCopiedWarning(true);
      setTimeout(() => setCopiedWarning(false), 1800);
    } catch {
      setCopiedWarning(false);
    }
  };

  const handleExportJson = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      engine: 'kashf-python-analyzer',
      result,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `kashf-report-${result.fingerprint}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <section
      aria-live="polite"
      data-testid="analysis-result"
      data-verdict={result.verdict}
      className="kashf-result-enter mt-8 rounded-2xl border border-black/10 bg-white p-6 text-black sm:p-8"
    >
      <div className="flex flex-col items-center gap-6 md:flex-row md:items-start md:gap-8">
        <div className="shrink-0">
          <RiskGauge
            score={result.score}
            verdict={result.verdict}
            scoreLabel={t.result.riskScoreLabel}
            outOfHundred={t.result.outOfHundred}
          />
        </div>

        <div className="flex-1 text-start">
          <div className="flex flex-wrap items-center gap-2.5 text-sm text-black/60">
            <span>
              {t.result.categoryLabel}: {categoryLabel}
            </span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">
              {result.reasons.length}{' '}
              {lang === 'ar' ? 'مؤشرات مرصودة' : 'signals detected'}
            </span>
          </div>

          <h2
            className={`mt-2 text-2xl font-medium sm:text-3xl ${VERDICT_TEXT_CLASS[result.verdict]}`}
            style={{ fontFamily: 'var(--font-heading)' }}
            data-testid="verdict-label"
          >
            {verdictLabel}
          </h2>

          <p className="mt-2.5 max-w-2xl text-base leading-relaxed text-black/75">
            {t.result.verdictSummaries[result.verdict]}
          </p>

          <div className="mt-5 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleShare}
              disabled={sharing}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
            >
              {sharing ? t.result.sharingButton : t.result.shareButton}
            </button>

            <button
              type="button"
              onClick={() => void handleCopyWarning()}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
            >
              {copiedWarning ? t.result.copiedWarningButton : t.result.copyWarningButton}
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-2 text-xs font-medium text-black transition-colors duration-200 hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
            >
              {t.result.exportJsonButton}
            </button>

            <button
              type="button"
              onClick={() => void onReport()}
              disabled={reporting || reported}
              className={`inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border px-4 py-2 text-xs font-medium transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black ${
                reported
                  ? 'border-[#16a34a]/40 bg-[#16a34a]/10 text-[#16a34a]'
                  : 'border-black/15 bg-white text-black hover:bg-black hover:text-white disabled:opacity-60'
              }`}
            >
              {reporting
                ? t.result.reportingButton
                : reported
                  ? t.result.reportedButton
                  : t.result.reportButton}
            </button>
          </div>

          {reportError ? (
            <p className="mt-2 text-xs text-[#dc2626]" role="alert">
              {reportError}
            </p>
          ) : null}
        </div>
      </div>

      {/* Highlighted read-only copy of the message */}
      {analyzedText ? (
        <div className="mt-8 border-t border-black/10 pt-6 text-start">
          <h3 className="text-sm font-medium text-black">
            {t.result.highlightedCopyTitle}
          </h3>
          <div
            data-testid="highlighted-message"
            className="mt-3 rounded-xl border border-black/10 bg-[#f7f7f5] p-4 text-sm leading-7 text-black whitespace-pre-wrap break-words"
          >
            {segments.map((seg, index) =>
              seg.highlighted ? (
                <mark
                  key={`${index}-${seg.text}`}
                  className={`rounded px-1 py-0.5 font-medium ${VERDICT_MARK_CLASS[result.verdict]}`}
                >
                  {seg.text}
                </mark>
              ) : (
                <span key={`${index}-${seg.text.slice(0, 8)}`}>{seg.text}</span>
              ),
            )}
          </div>
        </div>
      ) : null}

      {/* Python URL Forensics X-Ray */}
      {result.url_forensics && result.url_forensics.length > 0 ? (
        <div className="mt-8 border-t border-black/10 pt-6 text-start" data-testid="result-url-forensics">
          <h3 className="text-lg font-medium text-black">{t.result.forensicsTitle}</h3>
          <div className="mt-4 space-y-3">
            {result.url_forensics.map((forensics) => (
              <UrlForensicsPanel
                key={forensics.original_url}
                forensics={forensics}
                lang={lang}
              />
            ))}
          </div>
        </div>
      ) : null}

      {/* Why? list */}
      <div className="mt-8 border-t border-black/10 pt-6 text-start">
        <h3 className="text-lg font-medium text-black">{t.result.whyTitle}</h3>
        {result.reasons.length === 0 ? (
          <p className="mt-3 text-sm text-black/60">{t.result.noReasonsText}</p>
        ) : (
          <ul className="mt-4 divide-y divide-black/10" data-testid="reasons-list">
            {result.reasons.map((reason: AnalysisReason, idx: number) => (
              <li
                key={`${reason.id}-${idx}`}
                className="flex items-start gap-3.5 py-3.5 first:pt-0 last:pb-0"
              >
                <span
                  aria-hidden="true"
                  className="mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full bg-black"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="text-sm font-medium text-black">
                      {lang === 'ar' ? reason.title_ar : reason.title_en}
                    </span>
                    <span className="text-xs tabular-nums text-black/55">
                      +{reason.points} {t.result.pointsSuffix}
                    </span>
                  </div>
                  <p className="mt-1 text-sm leading-relaxed text-black/70">
                    {lang === 'ar' ? reason.detail_ar : reason.detail_en}
                  </p>
                  {reason.match ? (
                    <p className="mt-1.5 text-xs text-black/60">
                      <span>{lang === 'ar' ? 'العبارة المرصودة: ' : 'Matched: '}</span>
                      <span className="font-mono text-black underline decoration-black/30 underline-offset-2 break-all">
                        {reason.match}
                      </span>
                    </p>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* What should I do? */}
      <div className="mt-8 border-t border-black/10 pt-6 text-start">
        <h3 className="text-lg font-medium text-black">{t.result.whatToDoTitle}</h3>
        <ol className="mt-4 space-y-3">
          {steps.map((step, index) => (
            <li
              key={index}
              className="flex items-start gap-3 text-sm leading-relaxed text-black/80"
            >
              <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-black/15 text-xs font-medium tabular-nums text-black">
                {index + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
