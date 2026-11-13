import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import {
  Activity,
  ArrowUpRight,
  Building2,
  CheckCircle2,
  Download,
  Lock,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import type {
  CertificateVerifyResult,
  DashboardSummary,
  Language,
  SaasPlanTier,
  SaasTenantsResponse,
  SandboxRun,
} from '../types';
import { i18n } from '../i18n';
import { estimateSaasEconomics } from '../utils/saasEconomics';

interface ExecutiveDashboardProps {
  lang: Language;
  refreshKey: number;
  onLaunchAnalyzerTab: (tab: 'academic' | 'dlp') => void;
}

type WorkbenchTab = 'sandbox' | 'saas';

export function ExecutiveDashboard({
  lang,
  refreshKey,
  onLaunchAnalyzerTab,
}: ExecutiveDashboardProps) {
  const t = i18n[lang];
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const [lookupQuery, setLookupQuery] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<CertificateVerifyResult | null>(null);
  const verifierInputRef = useRef<HTMLInputElement | null>(null);
  const workbenchRef = useRef<HTMLDivElement | null>(null);

  const [activeWorkbench, setActiveWorkbench] = useState<WorkbenchTab>('sandbox');

  // Stage 04: University Sandbox PoC State
  const [sandboxDept, setSandboxDept] = useState(t.dashboard.sandbox.presets[0]);
  const [sandboxLoad, setSandboxLoad] = useState(15); // cycles (x3 ops)
  const [sandboxRunning, setSandboxRunning] = useState(false);
  const [latestRun, setLatestRun] = useState<SandboxRun | null>(null);
  const [sandboxHistory, setSandboxHistory] = useState<SandboxRun[]>([]);

  // Stage 05: Iraqi Universities SaaS State
  const [uniName, setUniName] = useState('');
  const [studentsCount, setStudentsCount] = useState(12000);
  const [facultyCount, setFacultyCount] = useState(650);
  const [planTier, setPlanTier] = useState<SaasPlanTier>('campus');
  const [saasSaving, setSaasSaving] = useState(false);
  const [saasError, setSaasError] = useState<string | null>(null);
  const [saasData, setSaasData] = useState<SaasTenantsResponse | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [dashRes, runsRes, saasRes] = await Promise.all([
        fetch('/api/dashboard'),
        fetch('/api/sandbox/runs'),
        fetch('/api/saas/tenants'),
      ]);
      if (dashRes.ok) {
        setSummary((await dashRes.json()) as DashboardSummary);
      }
      if (runsRes.ok) {
        const runsJson = (await runsRes.json()) as { history?: SandboxRun[] };
        const hist = Array.isArray(runsJson.history) ? runsJson.history : [];
        setSandboxHistory(hist);
        if (hist.length > 0) setLatestRun(hist[0]);
      }
      if (saasRes.ok) {
        setSaasData((await saasRes.json()) as SaasTenantsResponse);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchAll();
  }, [fetchAll, refreshKey]);

  const runVerify = async (queryText: string) => {
    const clean = queryText.trim();
    if (!clean) return;
    setVerifying(true);
    try {
      const res = await fetch(
        `/api/certificates/verify?q=${encodeURIComponent(clean)}`
      );
      if (!res.ok) return;
      const data = (await res.json()) as CertificateVerifyResult;
      setVerifyResult(data);
    } finally {
      setVerifying(false);
    }
  };

  const handleVerifySubmit = (e: FormEvent) => {
    e.preventDefault();
    void runVerify(lookupQuery);
  };

  const handleStageAction = (
    stageId: 'academic' | 'dlp' | 'ledger' | 'sandbox' | 'saas'
  ) => {
    if (stageId === 'academic' || stageId === 'dlp') {
      onLaunchAnalyzerTab(stageId);
      return;
    }
    if (stageId === 'ledger') {
      verifierInputRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => verifierInputRef.current?.focus(), 200);
      return;
    }
    setActiveWorkbench(stageId);
    workbenchRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleRunSandbox = async (e: FormEvent) => {
    e.preventDefault();
    setSandboxRunning(true);
    try {
      const res = await fetch('/api/sandbox/benchmark', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          department: sandboxDept.trim() || t.dashboard.sandbox.deptPlaceholder,
          load_size: sandboxLoad,
        }),
      });
      if (!res.ok) return;
      const data = (await res.json()) as { run?: SandboxRun; history?: SandboxRun[] };
      if (data.run) setLatestRun(data.run);
      if (Array.isArray(data.history)) setSandboxHistory(data.history);
    } finally {
      setSandboxRunning(false);
    }
  };

  const handleExportPocJson = () => {
    if (!latestRun) return;
    const payload = {
      platform: 'AcadShield AI × Kashf',
      poc_stage: 'Stage 04 — University Sandbox Pilot',
      benchmark: latestRun,
      ledger_chain_valid: summary?.chain_valid ?? true,
      exported_at: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `acadshield-poc-benchmark-${latestRun.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleRegisterTenant = async (e: FormEvent) => {
    e.preventDefault();
    if (uniName.trim().length < 2) {
      setSaasError(t.dashboard.saas.formError);
      return;
    }
    setSaasSaving(true);
    setSaasError(null);
    try {
      const res = await fetch('/api/saas/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          university_name: uniName.trim(),
          student_count: studentsCount,
          faculty_count: facultyCount,
          plan_tier: planTier,
        }),
      });
      if (!res.ok) {
        setSaasError(t.hero.networkError);
        return;
      }
      const updated = (await res.json()) as SaasTenantsResponse;
      setSaasData(updated);
      setUniName('');
    } finally {
      setSaasSaving(false);
    }
  };

  const handleDeleteTenant = async (tenantCode: string) => {
    try {
      const res = await fetch(
        `/api/saas/tenants/${encodeURIComponent(tenantCode)}`,
        { method: 'DELETE' }
      );
      if (!res.ok) return;
      setSaasData((await res.json()) as SaasTenantsResponse);
    } catch {
      // Ignore network error
    }
  };

  const roiEstimate = estimateSaasEconomics(studentsCount, facultyCount, planTier);

  return (
    <section
      id="dashboard"
      aria-labelledby="dashboard-heading"
      className="mt-16 scroll-mt-24 border-t border-black/10 pt-12 text-start"
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2
            id="dashboard-heading"
            className="text-2xl font-medium text-black"
            style={{ fontFamily: 'var(--font-heading)' }}
          >
            {t.dashboard.title}
          </h2>
          <p className="mt-1.5 max-w-3xl text-sm text-black/65">{t.dashboard.subtitle}</p>
        </div>

        <button
          type="button"
          onClick={() => void fetchAll()}
          disabled={loading}
          className="inline-flex min-h-10 items-center justify-center whitespace-nowrap rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs text-black transition-colors hover:bg-black hover:text-white disabled:opacity-50"
        >
          {t.dashboard.refreshButton}
        </button>
      </div>

      {/* 4 Live KPI Cards */}
      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-black/10 bg-white px-4 py-4">
          <span className="block text-xs text-black/55">{t.dashboard.kpiCertificates}</span>
          <span
            className="mt-1.5 block text-2xl font-medium tabular-nums text-black"
            data-testid="kpi-certificates"
          >
            {summary ? summary.certificates_issued : '—'}
          </span>
        </div>

        <div className="rounded-xl border border-black/10 bg-white px-4 py-4">
          <span className="block text-xs text-black/55">{t.dashboard.kpiOriginality}</span>
          <span className="mt-1.5 block text-2xl font-medium tabular-nums text-black">
            {summary && summary.certificates_issued > 0 ? `${summary.avg_originality}%` : '—'}
          </span>
        </div>

        <div className="rounded-xl border border-black/10 bg-white px-4 py-4">
          <span className="block text-xs text-black/55">{t.dashboard.kpiReports}</span>
          <span className="mt-1.5 block text-2xl font-medium tabular-nums text-black">
            {summary ? summary.cyber_reports : '—'}
          </span>
        </div>

        <div className="rounded-xl border border-black/10 bg-white px-4 py-4">
          <span className="block text-xs text-black/55">{t.dashboard.kpiChainStatus}</span>
          <span
            className={`mt-1.5 flex items-center gap-1.5 text-sm font-medium ${
              summary?.chain_valid ? 'text-[#16a34a]' : 'text-[#dc2626]'
            }`}
          >
            <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>
              {summary
                ? summary.chain_valid
                  ? t.dashboard.chainValid
                  : t.dashboard.chainInvalid
                : '—'}
            </span>
          </span>
        </div>
      </div>

      {/* Certificate Verification Lookup & Recent Ledger */}
      <div className="mt-6 rounded-2xl border border-black/10 bg-white p-5 sm:p-6">
        <h3 className="text-base font-medium text-black">{t.dashboard.verifierTitle}</h3>

        <form onSubmit={handleVerifySubmit} className="mt-3 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute top-1/2 h-4 w-4 -translate-y-1/2 text-black/40 start-3.5"
              aria-hidden="true"
            />
            <input
              ref={verifierInputRef}
              id="cert-verifier-input"
              type="text"
              dir="ltr"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder={t.dashboard.verifierPlaceholder}
              className="h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] ps-10 pe-4 font-mono text-sm text-black placeholder:text-black/40 focus:border-black focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={verifying || !lookupQuery.trim()}
            className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-50"
          >
            {verifying ? t.dashboard.verifyingButton : t.dashboard.verifyButton}
          </button>
        </form>

        {verifyResult ? (
          <div
            className="kashf-result-enter mt-4 rounded-xl border border-black/10 bg-[#f7f7f5] p-4"
            data-testid="verify-result"
          >
            {verifyResult.found && verifyResult.certificate ? (
              <div className="space-y-2">
                <div
                  className={`flex items-center gap-2 text-sm font-medium ${
                    verifyResult.hash_valid && verifyResult.chain_valid
                      ? 'text-[#16a34a]'
                      : 'text-[#dc2626]'
                  }`}
                >
                  {verifyResult.hash_valid && verifyResult.chain_valid ? (
                    <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                  )}
                  <span>
                    {verifyResult.hash_valid && verifyResult.chain_valid
                      ? t.dashboard.verifyFoundValid
                      : t.dashboard.verifyFoundTampered}
                  </span>
                </div>
                <div className="grid grid-cols-1 gap-2 text-xs text-black/75 sm:grid-cols-3">
                  <div>
                    <strong className="text-black">{verifyResult.certificate.title}</strong>
                  </div>
                  <div>
                    {verifyResult.certificate.author} — {verifyResult.certificate.institution}
                  </div>
                  <div className="font-mono tabular-nums" dir="ltr">
                    {verifyResult.certificate.cert_id} · {verifyResult.certificate.originality_score}%
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-sm text-[#dc2626]">{t.dashboard.verifyNotFound}</p>
            )}
          </div>
        ) : null}

        <div className="mt-6 border-t border-black/10 pt-5">
          <h3 className="text-sm font-medium text-black">{t.dashboard.ledgerTitle}</h3>

          {!summary || summary.recent_certificates.length === 0 ? (
            <p className="mt-2 text-sm text-black/60">{t.dashboard.ledgerEmpty}</p>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[600px] text-start text-sm">
                <thead>
                  <tr className="border-b border-black/10 text-xs text-black/55">
                    <th className="py-2 font-medium text-start">{t.dashboard.colCertId}</th>
                    <th className="py-2 font-medium text-start">{t.dashboard.colResearch}</th>
                    <th className="py-2 font-medium text-start">{t.dashboard.colAuthor}</th>
                    <th className="py-2 font-medium text-start">{t.dashboard.colOriginality}</th>
                    <th className="py-2 font-medium text-start">{t.dashboard.colHash}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-black/10">
                  {summary.recent_certificates.map((cert) => (
                    <tr key={cert.cert_id} className="hover:bg-[#f7f7f5]">
                      <td className="py-2.5 pe-3">
                        <button
                          type="button"
                          onClick={() => {
                            setLookupQuery(cert.cert_id);
                            void runVerify(cert.cert_id);
                          }}
                          className="font-mono text-xs font-medium text-black underline underline-offset-2 hover:opacity-70"
                          dir="ltr"
                        >
                          {cert.cert_id}
                        </button>
                      </td>
                      <td className="py-2.5 pe-3 font-medium text-black">{cert.title}</td>
                      <td className="py-2.5 pe-3 text-xs text-black/70">
                        {cert.author}
                        <span className="block text-[11px] text-black/50">{cert.institution}</span>
                      </td>
                      <td className="py-2.5 pe-3 font-medium tabular-nums text-[#16a34a]">
                        {cert.originality_score}%
                      </td>
                      <td className="py-2.5 font-mono text-xs text-black/55">
                        <span dir="ltr">{cert.block_hash.slice(0, 14)}…</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Interactive 5-Stage Actionable Module Cards */}
      <div className="mt-8">
        <h3 className="text-lg font-medium text-black">{t.dashboard.roadmapTitle}</h3>
        <p className="mt-1 text-sm text-black/65">{t.dashboard.roadmapSubtitle}</p>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {t.dashboard.roadmapStages.map((item) => {
            const isSelected =
              (item.id === 'sandbox' && activeWorkbench === 'sandbox') ||
              (item.id === 'saas' && activeWorkbench === 'saas');
            return (
              <article
                key={item.stage}
                className={`flex flex-col justify-between rounded-2xl border p-4 transition-colors ${
                  isSelected
                    ? 'border-black bg-white shadow-sm'
                    : 'border-black/10 bg-white hover:border-black/30'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 text-[11px] text-black/55">
                    <span className="font-mono tabular-nums">{item.stage}</span>
                    <span className="font-medium text-[#16a34a]">{item.status}</span>
                  </div>
                  <h4 className="mt-2 text-sm font-medium leading-snug text-black">
                    {item.title}
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-black/65">{item.summary}</p>
                </div>

                <button
                  type="button"
                  onClick={() => handleStageAction(item.id)}
                  data-testid={`stage-btn-${item.id}`}
                  className={`mt-4 inline-flex min-h-9 w-full items-center justify-between gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition-colors ${
                    isSelected
                      ? 'border-black bg-black text-white'
                      : 'border-black/15 bg-[#f7f7f5] text-black hover:bg-black hover:text-white'
                  }`}
                >
                  <span>{item.actionLabel}</span>
                  <ArrowUpRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                </button>
              </article>
            );
          })}
        </div>
      </div>

      {/* Stage 04 & Stage 05 Interactive Execution Workbench */}
      <div
        ref={workbenchRef}
        className="mt-6 scroll-mt-24 rounded-2xl border border-black/10 bg-white p-5 sm:p-6"
        data-testid="acadshield-workbench"
      >
        <div
          role="tablist"
          aria-label={t.dashboard.roadmapTitle}
          className="inline-flex max-w-full flex-wrap items-center gap-1 rounded-xl border border-black/10 bg-[#f4f4f2] p-1"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeWorkbench === 'sandbox'}
            onClick={() => setActiveWorkbench('sandbox')}
            data-testid="workbench-tab-sandbox"
            className={`inline-flex min-h-9 items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-medium transition-colors sm:text-sm ${
              activeWorkbench === 'sandbox'
                ? 'bg-white text-black shadow-sm'
                : 'text-black/65 hover:text-black'
            }`}
          >
            <Activity className="h-4 w-4" aria-hidden="true" />
            <span>{t.dashboard.roadmapStages[3].stage}: {t.dashboard.roadmapStages[3].title}</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeWorkbench === 'saas'}
            onClick={() => setActiveWorkbench('saas')}
            data-testid="workbench-tab-saas"
            className={`inline-flex min-h-9 items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-medium transition-colors sm:text-sm ${
              activeWorkbench === 'saas'
                ? 'bg-white text-black shadow-sm'
                : 'text-black/65 hover:text-black'
            }`}
          >
            <Building2 className="h-4 w-4" aria-hidden="true" />
            <span>{t.dashboard.roadmapStages[4].stage}: {t.dashboard.roadmapStages[4].title}</span>
          </button>
        </div>

        {activeWorkbench === 'sandbox' ? (
          <div className="mt-5" data-testid="sandbox-panel">
            <h3 className="text-base font-medium text-black">{t.dashboard.sandbox.title}</h3>
            <p className="mt-1 text-sm text-black/65">{t.dashboard.sandbox.subtitle}</p>

            <form onSubmit={handleRunSandbox} className="mt-4 space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {t.dashboard.sandbox.presets.map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => setSandboxDept(preset)}
                    className="min-h-8 rounded-full border border-black/15 bg-[#f7f7f5] px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white"
                  >
                    {preset}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <label htmlFor="sandbox-dept" className="block text-xs font-medium text-black">
                    {t.dashboard.sandbox.deptLabel}
                  </label>
                  <input
                    id="sandbox-dept"
                    type="text"
                    value={sandboxDept}
                    onChange={(e) => setSandboxDept(e.target.value)}
                    placeholder={t.dashboard.sandbox.deptPlaceholder}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3.5 text-sm text-black focus:border-black focus:outline-none"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-load" className="block text-xs font-medium text-black">
                    {t.dashboard.sandbox.loadLabel}
                  </label>
                  <select
                    id="sandbox-load"
                    value={sandboxLoad}
                    onChange={(e) => setSandboxLoad(Number(e.target.value))}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3 text-sm tabular-nums text-black focus:border-black focus:outline-none"
                  >
                    <option value={6}>18 ops (6×3)</option>
                    <option value={15}>45 ops (15×3)</option>
                    <option value={30}>90 ops (30×3)</option>
                    <option value={60}>180 ops (60×3)</option>
                  </select>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="submit"
                  disabled={sandboxRunning}
                  data-testid="run-sandbox-btn"
                  className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-60"
                >
                  {sandboxRunning
                    ? t.dashboard.sandbox.runningButton
                    : t.dashboard.sandbox.runButton}
                </button>

                {latestRun ? (
                  <button
                    type="button"
                    onClick={handleExportPocJson}
                    className="inline-flex min-h-10 items-center gap-2 rounded-full border border-black/15 bg-white px-4 py-1.5 text-xs font-medium text-black hover:bg-black hover:text-white"
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{t.dashboard.sandbox.exportJsonButton}</span>
                  </button>
                ) : null}
              </div>
            </form>

            {latestRun ? (
              <div
                className="kashf-result-enter mt-5 rounded-xl border border-black/10 bg-[#f7f7f5] p-4"
                data-testid="sandbox-result"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-black/10">
                  <strong className="text-sm text-black">{latestRun.department}</strong>
                  <span className="text-xs font-medium text-[#16a34a]">
                    {latestRun.sla_status === 'optimal'
                      ? t.dashboard.sandbox.slaOptimal
                      : t.dashboard.sandbox.slaAcceptable}
                  </span>
                </div>

                <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.sandbox.totalOpsLabel}
                    </span>
                    <span className="mt-1 block text-xl font-medium tabular-nums text-black">
                      {latestRun.load_size}
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.sandbox.avgLatencyLabel}
                    </span>
                    <span className="mt-1 block text-xl font-medium tabular-nums text-black" dir="ltr">
                      {latestRun.avg_latency_ms} ms
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.sandbox.throughputLabel}
                    </span>
                    <span className="mt-1 block text-xl font-medium tabular-nums text-[#16a34a]" dir="ltr">
                      {latestRun.throughput_per_sec} /s
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.sandbox.detectionsLabel}
                    </span>
                    <span className="mt-1 block text-xl font-medium tabular-nums text-black">
                      {latestRun.ai_flagged +
                        latestRun.cyber_threats_caught +
                        latestRun.dlp_leaks_caught}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="mt-4 text-sm text-black/60">{t.dashboard.sandbox.historyEmpty}</p>
            )}

            {sandboxHistory.length > 0 ? (
              <div className="mt-5">
                <h4 className="text-xs font-medium text-black/65">
                  {t.dashboard.sandbox.historyTitle}
                </h4>
                <div className="mt-2 overflow-x-auto">
                  <table className="w-full min-w-[560px] text-start text-xs">
                    <thead>
                      <tr className="border-b border-black/10 text-black/55">
                        <th className="py-2 text-start font-medium">#</th>
                        <th className="py-2 text-start font-medium">
                          {t.dashboard.sandbox.deptLabel}
                        </th>
                        <th className="py-2 text-start font-medium">
                          {t.dashboard.sandbox.totalOpsLabel}
                        </th>
                        <th className="py-2 text-start font-medium">
                          {t.dashboard.sandbox.avgLatencyLabel}
                        </th>
                        <th className="py-2 text-start font-medium">
                          {t.dashboard.sandbox.throughputLabel}
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-black/10">
                      {sandboxHistory.map((item) => (
                        <tr key={item.id}>
                          <td className="py-2 pe-3 font-mono tabular-nums text-black/60">#{item.id}</td>
                          <td className="py-2 pe-3 font-medium text-black">{item.department}</td>
                          <td className="py-2 pe-3 tabular-nums">{item.load_size}</td>
                          <td className="py-2 pe-3 tabular-nums">
                            <span dir="ltr">{item.avg_latency_ms} ms ({item.elapsed_ms} ms)</span>
                          </td>
                          <td className="py-2 font-medium tabular-nums text-[#16a34a]">
                            <span dir="ltr">{item.throughput_per_sec} ops/s</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="mt-5" data-testid="saas-panel">
            <h3 className="text-base font-medium text-black">{t.dashboard.saas.title}</h3>
            <p className="mt-1 text-sm text-black/65">{t.dashboard.saas.subtitle}</p>

            <form onSubmit={handleRegisterTenant} noValidate className="mt-4 space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {t.dashboard.saas.presets.map((preset) => (
                  <button
                    key={preset.name}
                    type="button"
                    onClick={() => {
                      setUniName(preset.name);
                      setStudentsCount(preset.students);
                      setFacultyCount(preset.faculty);
                      setSaasError(null);
                    }}
                    className="min-h-8 rounded-full border border-black/15 bg-[#f7f7f5] px-3 py-1 text-xs text-black transition-colors hover:bg-black hover:text-white"
                  >
                    {preset.name}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <label htmlFor="saas-uni-name" className="block text-xs font-medium text-black">
                    {t.dashboard.saas.uniLabel}
                  </label>
                  <input
                    id="saas-uni-name"
                    type="text"
                    value={uniName}
                    onChange={(e) => {
                      setUniName(e.target.value);
                      setSaasError(null);
                    }}
                    placeholder={t.dashboard.saas.uniPlaceholder}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3.5 text-sm text-black focus:border-black focus:outline-none"
                  />
                </div>

                <div>
                  <label htmlFor="saas-students" className="block text-xs font-medium text-black">
                    {t.dashboard.saas.studentsLabel}
                  </label>
                  <input
                    id="saas-students"
                    type="number"
                    min={50}
                    max={500000}
                    value={studentsCount}
                    onChange={(e) => setStudentsCount(Number(e.target.value))}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3.5 text-sm tabular-nums text-black focus:border-black focus:outline-none"
                  />
                </div>

                <div>
                  <label htmlFor="saas-faculty" className="block text-xs font-medium text-black">
                    {t.dashboard.saas.facultyLabel}
                  </label>
                  <input
                    id="saas-faculty"
                    type="number"
                    min={5}
                    max={50000}
                    value={facultyCount}
                    onChange={(e) => setFacultyCount(Number(e.target.value))}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3.5 text-sm tabular-nums text-black focus:border-black focus:outline-none"
                  />
                </div>

                <div>
                  <label htmlFor="saas-tier" className="block text-xs font-medium text-black">
                    {t.dashboard.saas.planLabel}
                  </label>
                  <select
                    id="saas-tier"
                    value={planTier}
                    onChange={(e) => setPlanTier(e.target.value as SaasPlanTier)}
                    className="mt-1.5 h-11 w-full rounded-xl border border-black/15 bg-[#f7f7f5] px-3 text-sm text-black focus:border-black focus:outline-none"
                  >
                    <option value="starter">{t.dashboard.saas.plans.starter}</option>
                    <option value="campus">{t.dashboard.saas.plans.campus}</option>
                    <option value="national">{t.dashboard.saas.plans.national}</option>
                  </select>
                </div>
              </div>

              {/* Live Economic ROI Preview */}
              <div className="rounded-xl border border-black/10 bg-[#f7f7f5] p-4">
                <h4 className="text-xs font-medium text-black/65">
                  {t.dashboard.saas.previewTitle}
                </h4>
                <div className="mt-2.5 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.saas.localCostLabel}
                    </span>
                    <span className="mt-1 block text-lg font-medium tabular-nums text-black" dir="ltr">
                      ${roiEstimate.annualLocalUsd.toLocaleString()}
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.saas.foreignCostLabel}
                    </span>
                    <span
                      className="mt-1 block text-lg font-medium tabular-nums text-black/55 line-through"
                      dir="ltr"
                    >
                      ${roiEstimate.foreignBenchmarkUsd.toLocaleString()}
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.saas.savingsLabel}
                    </span>
                    <span className="mt-1 block text-lg font-medium tabular-nums text-[#16a34a]" dir="ltr">
                      ${roiEstimate.annualSavingsUsd.toLocaleString()} ({roiEstimate.savingsPct}%)
                    </span>
                  </div>
                  <div className="rounded-lg bg-white p-3">
                    <span className="block text-[11px] text-black/55">
                      {t.dashboard.saas.savingsIqdLabel}
                    </span>
                    <span className="mt-1 block text-sm font-medium tabular-nums text-black" dir="ltr">
                      {(roiEstimate.annualSavingsIqd / 1_000_000).toFixed(1)}M IQD
                    </span>
                  </div>
                </div>
              </div>

              {saasError ? (
                <p className="text-xs font-medium text-[#dc2626]" role="alert">
                  {saasError}
                </p>
              ) : null}

              <button
                type="submit"
                disabled={saasSaving}
                data-testid="register-saas-btn"
                className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-full bg-black px-6 py-2 text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:opacity-60"
              >
                {saasSaving
                  ? t.dashboard.saas.registeringButton
                  : t.dashboard.saas.registerButton}
              </button>
            </form>

            {/* Registered Iraqi Universities SQLite Table */}
            <div className="mt-6 border-t border-black/10 pt-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-sm font-medium text-black">
                  {t.dashboard.saas.tenantsTitle}
                </h4>
                {saasData && saasData.summary.tenant_count > 0 ? (
                  <span className="text-xs tabular-nums text-black/65">
                    {saasData.summary.tenant_count} ·{' '}
                    {saasData.summary.total_students.toLocaleString()} ·{' '}
                    <strong className="text-[#16a34a]" dir="ltr">
                      ${saasData.summary.total_savings_usd.toLocaleString()}/yr saved
                    </strong>
                  </span>
                ) : null}
              </div>

              {!saasData || saasData.tenants.length === 0 ? (
                <p className="mt-2 text-sm text-black/60">{t.dashboard.saas.tenantsEmpty}</p>
              ) : (
                <div className="mt-3 overflow-x-auto" data-testid="saas-tenants-table">
                  <table className="w-full min-w-[680px] text-start text-xs sm:text-sm">
                    <thead>
                      <tr className="border-b border-black/10 text-xs text-black/55">
                        <th className="py-2 text-start font-medium">{t.dashboard.saas.colCode}</th>
                        <th className="py-2 text-start font-medium">
                          {t.dashboard.saas.colUniversity}
                        </th>
                        <th className="py-2 text-start font-medium">{t.dashboard.saas.colUsers}</th>
                        <th className="py-2 text-start font-medium">{t.dashboard.saas.colKey}</th>
                        <th className="py-2 text-start font-medium">{t.dashboard.saas.colSavings}</th>
                        <th className="py-2 text-end font-medium"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-black/10">
                      {saasData.tenants.map((tenant) => (
                        <tr key={tenant.tenant_code}>
                          <td className="py-2.5 pe-4 font-mono text-xs font-medium text-black">
                            <span dir="ltr">{tenant.tenant_code}</span>
                          </td>
                          <td className="py-2.5 pe-4 font-medium text-black">
                            {tenant.university_name}
                            <span className="block text-[11px] text-black/50">
                              {t.dashboard.saas.plans[tenant.plan_tier]}
                            </span>
                          </td>
                          <td className="py-2.5 pe-4 tabular-nums text-black/75">
                            {tenant.student_count.toLocaleString()} /{' '}
                            {tenant.faculty_count.toLocaleString()}
                          </td>
                          <td className="py-2.5 pe-4 font-mono text-[11px] text-black/65">
                            <span dir="ltr">{tenant.api_key_prefix}…</span>
                          </td>
                          <td className="py-2.5 pe-4 font-medium tabular-nums text-[#16a34a]">
                            <span dir="ltr">
                              ${tenant.annual_savings_usd.toLocaleString()} ({tenant.savings_pct}%)
                            </span>
                          </td>
                          <td className="py-2.5 text-end">
                            <button
                              type="button"
                              onClick={() => void handleDeleteTenant(tenant.tenant_code)}
                              aria-label={`${t.dashboard.saas.removeButton} ${tenant.university_name}`}
                              className="inline-flex h-8 items-center gap-1 rounded-lg border border-black/10 px-2.5 text-xs text-black/60 hover:border-[#dc2626]/40 hover:text-[#dc2626]"
                            >
                              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                              <span>{t.dashboard.saas.removeButton}</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
