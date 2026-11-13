import { useState } from 'react';
import type { Language, LiveUrlProbeResult, UrlForensics } from '../types';
import { i18n } from '../i18n';

interface UrlForensicsPanelProps {
  forensics: UrlForensics;
  lang: Language;
  initialProbe?: LiveUrlProbeResult | null;
}

export function UrlForensicsPanel({
  forensics,
  lang,
  initialProbe = null,
}: UrlForensicsPanelProps) {
  const t = i18n[lang];
  const [copiedDefang, setCopiedDefang] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<LiveUrlProbeResult | null>(initialProbe);
  const [probeError, setProbeError] = useState<string | null>(null);

  const handleCopyDefanged = async () => {
    try {
      await navigator.clipboard.writeText(forensics.defanged_url);
      setCopiedDefang(true);
      setTimeout(() => setCopiedDefang(false), 1800);
    } catch {
      setCopiedDefang(false);
    }
  };

  const handleLiveProbe = async () => {
    if (probing) return;
    setProbing(true);
    setProbeError(null);
    try {
      const res = await fetch('/api/inspect-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: forensics.original_url }),
      });
      if (!res.ok) {
        setProbeError(t.hero.networkError);
        return;
      }
      const data = (await res.json()) as LiveUrlProbeResult;
      setProbeResult(data);
    } catch {
      setProbeError(t.hero.networkError);
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="rounded-xl border border-black/10 bg-[#f7f7f5] p-4 text-start">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-xs font-medium text-black break-all" dir="ltr">
          {forensics.host || forensics.original_url}
        </span>
        <span className="text-xs tabular-nums text-black/60">
          {t.result.entropyLabel}: {forensics.entropy}
          {forensics.tld ? (
            <>
              {' · '}
              <span dir="ltr" className="font-mono">
                {forensics.tld}
              </span>
            </>
          ) : null}
        </span>
      </div>

      {forensics.has_punycode && forensics.punycode_decoded_host !== forensics.host ? (
        <p className="mt-2 text-xs text-[#dc2626]">
          Punycode → <span className="font-mono" dir="ltr">{forensics.punycode_decoded_host}</span>
        </p>
      ) : null}

      {forensics.matched_brand ? (
        <p
          className={`mt-2 text-xs font-medium ${
            forensics.is_official_brand ? 'text-[#16a34a]' : 'text-[#dc2626]'
          }`}
        >
          {forensics.is_official_brand
            ? `${t.result.officialDomainLabel}: ${forensics.matched_brand}`
            : `${t.result.impersonationLabel}: ${forensics.matched_brand}`}
        </p>
      ) : null}

      {/* Defanged safe copy */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-black/10 bg-white px-3 py-2">
        <div className="min-w-0 flex-1">
          <span className="block text-[11px] text-black/55">{t.result.defangedLabel}</span>
          <code className="block truncate font-mono text-xs text-black" dir="ltr">
            {forensics.defanged_url}
          </code>
        </div>
        <button
          type="button"
          onClick={() => void handleCopyDefanged()}
          className="inline-flex min-h-8 shrink-0 items-center whitespace-nowrap rounded-full border border-black/15 bg-white px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black"
        >
          {copiedDefang ? t.result.copiedDefanged : t.result.copyDefanged}
        </button>
      </div>

      {forensics.tracking_params_removed.length > 0 ? (
        <div className="mt-2.5 rounded-lg border border-black/10 bg-white px-3 py-2">
          <span className="block text-[11px] text-black/55">
            {t.result.sanitizedLabel} ({forensics.tracking_params_removed.join(', ')})
          </span>
          <code className="block truncate font-mono text-xs text-black/80" dir="ltr">
            {forensics.sanitized_url}
          </code>
        </div>
      ) : null}

      {forensics.flags.length > 0 ? (
        <ul className="mt-3 space-y-1">
          {forensics.flags.map((flag, i) => (
            <li
              key={i}
              className={`text-xs ${
                flag.severity === 'safe'
                  ? 'text-[#16a34a]'
                  : flag.severity === 'high'
                    ? 'text-[#dc2626]'
                    : 'text-[#d97706]'
              }`}
            >
              · {lang === 'ar' ? flag.title_ar : flag.title_en}
            </li>
          ))}
        </ul>
      ) : null}

      {/* Live DNS / TLS / Redirect Python probe */}
      {!probeResult ? (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => void handleLiveProbe()}
            disabled={probing}
            className="inline-flex min-h-9 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black transition-colors hover:bg-black hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:opacity-60"
          >
            {probing ? t.result.liveProbingButton : t.result.liveProbeButton}
          </button>
          {probeError ? (
            <p className="mt-2 text-xs text-[#dc2626]" role="alert">
              {probeError}
            </p>
          ) : null}
        </div>
      ) : (
        <div className="mt-3 space-y-2 rounded-lg border border-black/10 bg-white p-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-black">{t.result.dnsLabel}</span>
            <span className="font-mono text-black/75" dir="ltr">
              {probeResult.dns.resolved
                ? probeResult.dns.ips.join(', ')
                : probeResult.dns.error || 'Unresolved'}
            </span>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-black/10 pt-2">
            <span className="font-medium text-black">{t.result.tlsLabel}</span>
            <span className={probeResult.tls.valid ? 'text-[#16a34a]' : 'text-[#d97706]'}>
              {probeResult.tls.available && probeResult.tls.valid
                ? `${probeResult.tls.issuer ?? 'TLS'} (${
                    probeResult.tls.days_remaining != null
                      ? `${probeResult.tls.days_remaining}d`
                      : 'valid'
                  })`
                : probeResult.tls.error || 'No HTTPS'}
            </span>
          </div>

          {probeResult.redirects.length > 0 ? (
            <div className="border-t border-black/10 pt-2">
              <span className="font-medium text-black">{t.result.redirectsLabel}</span>
              <ol className="mt-1 space-y-1 font-mono text-[11px] text-black/75" dir="ltr">
                {probeResult.redirects.map((hop, idx) => (
                  <li key={idx} className="truncate">
                    [{hop.status}] {hop.url}
                  </li>
                ))}
              </ol>
              {probeResult.final_url !== forensics.normalized_url ? (
                <p className="mt-1.5 text-xs text-black">
                  <span className="font-medium">{t.result.finalUrlLabel}: </span>
                  <span className="font-mono break-all" dir="ltr">
                    {probeResult.final_url}
                  </span>
                </p>
              ) : null}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
