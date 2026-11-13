import { useCallback, useState } from 'react';
import type { AnalysisResult, Language } from '../types';
import { i18n } from '../i18n';

interface UseAnalyzeReturn {
  loading: boolean;
  error: string | null;
  result: AnalysisResult | null;
  analyzedText: string;
  reporting: boolean;
  reported: boolean;
  reportError: string | null;
  analyze: (text: string, url?: string) => Promise<void>;
  reportResult: () => Promise<boolean>;
  clearError: () => void;
  resetResult: () => void;
}

export function useAnalyze(lang: Language): UseAnalyzeReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analyzedText, setAnalyzedText] = useState('');
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const analyze = useCallback(
    async (text: string, url?: string) => {
      const t = i18n[lang];
      setLoading(true);
      setError(null);
      setReported(false);
      setReportError(null);

      try {
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text,
            url: url?.trim() ? url.trim() : null,
          }),
        });

        if (response.status === 429) {
          setError(t.hero.rateLimitError);
          setResult(null);
          return;
        }

        if (!response.ok) {
          setError(t.hero.networkError);
          setResult(null);
          return;
        }

        const data = (await response.json()) as AnalysisResult;
        setResult(data);
        setAnalyzedText(text);
      } catch {
        setError(t.hero.networkError);
        setResult(null);
      } finally {
        setLoading(false);
      }
    },
    [lang],
  );

  const reportResult = useCallback(async (): Promise<boolean> => {
    if (!result || reported || reporting) return false;
    const t = i18n[lang];
    setReporting(true);
    setReportError(null);

    try {
      const response = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          category: result.category,
          score: result.score,
          fingerprint: result.fingerprint,
        }),
      });
      if (!response.ok) {
        setReportError(t.result.reportError);
        return false;
      }
      setReported(true);
      return true;
    } catch {
      setReportError(t.result.reportError);
      return false;
    } finally {
      setReporting(false);
    }
  }, [lang, reported, reporting, result]);

  const clearError = useCallback(() => setError(null), []);
  const resetResult = useCallback(() => {
    setResult(null);
    setAnalyzedText('');
    setReported(false);
    setReportError(null);
    setError(null);
  }, []);

  return {
    loading,
    error,
    result,
    analyzedText,
    reporting,
    reported,
    reportError,
    analyze,
    reportResult,
    clearError,
    resetResult,
  };
}
