export type Language = 'ar' | 'en';

export type Verdict = 'safe' | 'suspicious' | 'dangerous';

export type ScamCategory =
  | 'phishing_bank'
  | 'fake_prize'
  | 'fake_delivery'
  | 'investment_fraud'
  | 'otp_theft'
  | 'fake_job'
  | 'other';

export interface AnalysisReason {
  id: string;
  points: number;
  title_ar: string;
  title_en: string;
  detail_ar: string;
  detail_en: string;
  match: string;
}

export interface UrlForensicFlag {
  severity: 'high' | 'medium' | 'low' | 'safe';
  title_ar: string;
  title_en: string;
}

export interface UrlForensics {
  original_url: string;
  normalized_url: string;
  defanged_url: string;
  sanitized_url: string;
  scheme: string;
  host: string;
  punycode_decoded_host: string;
  tld: string;
  port: number | null;
  path: string;
  entropy: number;
  is_ip: boolean;
  is_shortener: boolean;
  is_https: boolean;
  has_punycode: boolean;
  has_non_ascii: boolean;
  has_at_symbol: boolean;
  subdomain_depth: number;
  tracking_params_removed: string[];
  suspicious_params: string[];
  matched_brand: string | null;
  is_official_brand: boolean;
  forensic_score: number;
  verdict: Verdict;
  flags: UrlForensicFlag[];
}

export interface LiveUrlProbeResult {
  forensics: UrlForensics;
  dns: {
    resolved: boolean;
    ips: string[];
    error: string | null;
  };
  tls: {
    available: boolean;
    valid: boolean;
    issuer?: string;
    not_after?: string;
    days_remaining?: number | null;
    protocol?: string;
    cipher?: string;
    error?: string;
  };
  redirects: Array<{
    url: string;
    status: number;
  }>;
  final_url: string;
  final_forensics?: UrlForensics | null;
}

export interface AnalysisResult {
  score: number;
  verdict: Verdict;
  category: ScamCategory;
  reasons: AnalysisReason[];
  highlights: string[];
  fingerprint: string;
  urls: string[];
  url_forensics?: UrlForensics[];
}

export interface BatchAnalysisItem {
  index: number;
  preview: string;
  text: string;
  result: AnalysisResult;
}

export interface BatchAnalysisResult {
  total: number;
  dangerous_count: number;
  suspicious_count: number;
  safe_count: number;
  max_score: number;
  items: BatchAnalysisItem[];
}

export interface QuizScenario {
  id: string;
  channel: string;
  sender: string;
  text_ar: string;
  text_en: string;
}

export interface QuizVerifyResult {
  id: string;
  correct: boolean;
  is_scam: boolean;
  explanation_ar: string;
  explanation_en: string;
  analysis: AnalysisResult;
}

export interface TrendingItem {
  category: ScamCategory;
  count: number;
  avg_score: number;
  daily: number[];
}

export interface CommunityStats {
  total_reports: number;
  active_categories: number;
  avg_score: number;
  top_category: ScamCategory | null;
}

export interface LocalHistoryItem {
  id: string;
  timestamp: number;
  preview: string;
  text: string;
  score: number;
  verdict: Verdict;
  category: ScamCategory;
}

export type AcademicVerdict = 'authentic' | 'review_needed' | 'flagged';

export type BehaviorStatus =
  | 'not_captured'
  | 'human_verified'
  | 'robotic_cadence'
  | 'bulk_pasted'
  | 'mixed_input';

export interface BehaviorTelemetry {
  keystrokes: number;
  pasted_chars: number;
  total_chars: number;
  avg_interval_ms: number;
  interval_std_ms: number;
}

export interface AcademicSignal {
  severity: 'high' | 'medium' | 'low' | 'safe';
  title_ar: string;
  title_en: string;
  detail: string;
}

export interface PlagiarismMatch {
  source: string;
  overlap_pct: number;
  sample: string;
}

export interface AcademicAnalysisResult {
  word_count: number;
  sentence_count: number;
  lexical_richness: number;
  burstiness: number;
  ai_probability: number;
  plagiarism_pct: number;
  originality_score: number;
  verdict: AcademicVerdict;
  matched_ai_phrases: string[];
  plagiarism_matches: PlagiarismMatch[];
  behavior: {
    status: BehaviorStatus;
    score: number;
    paste_ratio: number;
  };
  signals: AcademicSignal[];
  eligible_for_certificate: boolean;
}

export interface DlpFinding {
  id: string;
  title_ar: string;
  title_en: string;
  masked_value: string;
  severity: 'high' | 'medium';
}

export interface DlpScanResult {
  risk_score: number;
  verdict: Verdict;
  dlp_findings: DlpFinding[];
  urls_found: string[];
  url_forensics: UrlForensics[];
  cyber_reasons: AnalysisReason[];
}

export interface CertificateRecord {
  block_index: number;
  cert_id: string;
  title: string;
  author: string;
  institution: string;
  originality_score: number;
  doc_hash: string;
  prev_hash: string;
  block_hash: string;
  ts: number;
}

export interface CertificateVerifyResult {
  found: boolean;
  hash_valid?: boolean;
  chain_valid: boolean;
  certificate?: CertificateRecord;
}

export interface DashboardSummary {
  cyber_reports: number;
  cyber_avg_risk: number;
  top_threat_category: ScamCategory | null;
  certificates_issued: number;
  avg_originality: number;
  chain_valid: boolean;
  recent_certificates: CertificateRecord[];
}

export interface SandboxRun {
  id: number;
  department: string;
  load_size: number;
  elapsed_ms: number;
  avg_latency_ms: number;
  throughput_per_sec: number;
  ai_flagged: number;
  cyber_threats_caught: number;
  dlp_leaks_caught: number;
  sla_status: 'optimal' | 'acceptable';
  ts: number;
}

export type SaasPlanTier = 'starter' | 'campus' | 'national';

export interface SaasTenant {
  tenant_code: string;
  university_name: string;
  student_count: number;
  faculty_count: number;
  plan_tier: SaasPlanTier;
  api_key_prefix: string;
  annual_local_usd: number;
  foreign_benchmark_usd: number;
  annual_savings_usd: number;
  savings_pct: number;
  status: 'active' | 'sandbox';
  ts: number;
}

export interface SaasTenantsResponse {
  tenants: SaasTenant[];
  summary: {
    tenant_count: number;
    total_students: number;
    total_savings_usd: number;
  };
}


