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

export type UrlClassification = 'malicious' | 'suspicious' | 'no_known_threat' | 'unknown';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';
export type EvidenceStrength = 'strong' | 'moderate' | 'weak' | 'insufficient';
export type ThreatSourceStatus = 'hit' | 'clean' | 'not_configured' | 'unavailable' | 'error';

export interface EvidenceItem {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';
  title_ar: string;
  title_en: string;
  detail_ar: string;
  detail_en: string;
  source: string;
  timestamp: string;
  observed_value: string;
}

export interface SourceConflict {
  topic_ar: string;
  topic_en: string;
  source_a: string;
  result_a: string;
  source_b: string;
  result_b: string;
}

export interface LimitationItem {
  code: string;
  ar: string;
  en: string;
}

export interface ConfidenceAssessment {
  calibrated: boolean;
  evidence_strength: EvidenceStrength;
  calibrated_probability: number | null;
  detection_ratio: string | null;
  explanation_ar: string;
  explanation_en: string;
}

export interface EvidenceBundle {
  scan_timestamp: string;
  risk_level: RiskLevel;
  evidence: EvidenceItem[];
  conflicts: SourceConflict[];
  limitations: LimitationItem[];
  confidence: ConfidenceAssessment;
}

export interface ThreatSourceResult {
  source_id: string;
  source_name: string;
  status: ThreatSourceStatus;
  verdict_detail_ar: string;
  verdict_detail_en: string;
  checked_at: string;
  requires_api_key: boolean;
  env_var: string | null;
  detection_ratio: string | null;
  categories: string[];
}

export interface RdapInfo {
  available: boolean;
  domain: string;
  registered_at?: string | null;
  age_days: number | null;
  registrar?: string | null;
  error?: string | null;
}

export interface DnsRecordsInfo {
  available: boolean;
  a: string[];
  mx: string[];
  txt: string[];
  has_spf: boolean;
  error: string | null;
}

export interface RecommendedAction {
  ar: string;
  en: string;
}

export interface SuspiciousSegment {
  text: string;
  threat_type: string;
  severity: string;
  reason_ar: string;
  reason_en: string;
}

export interface LinkVerificationItem {
  url: string;
  defanged_url: string;
  static_classification: UrlClassification;
  needs_separate_intel_check: boolean;
  reason_ar: string;
  reason_en: string;
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
  is_mixed_script_homograph?: boolean;
  scripts_detected?: string[];
  homograph_skeleton?: string;
  has_at_symbol: boolean;
  subdomain_depth: number;
  tracking_params_removed: string[];
  suspicious_params: string[];
  matched_brand: string | null;
  is_official_brand: boolean;
  forensic_score: number;
  classification?: UrlClassification;
  verdict: Verdict;
  flags: UrlForensicFlag[];
  evidence_bundle?: EvidenceBundle;
}

export interface LiveUrlProbeResult {
  forensics: UrlForensics;
  dns: {
    resolved: boolean;
    ips: string[];
    error: string | null;
  };
  dns_records?: DnsRecordsInfo;
  rdap?: RdapInfo;
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
  threat_intel?: ThreatSourceResult[];
  classification?: UrlClassification;
  evidence_bundle?: EvidenceBundle;
  recommended_actions?: RecommendedAction[];
  scan_timestamp?: string;
}

export interface AnalysisResult {
  score: number;
  verdict: Verdict;
  risk_level?: RiskLevel;
  category: ScamCategory;
  threat_types?: string[];
  reasons: AnalysisReason[];
  highlights: string[];
  suspicious_segments?: SuspiciousSegment[];
  links_requiring_verification?: LinkVerificationItem[];
  recommended_actions?: RecommendedAction[];
  auxiliary_llm?: {
    used: boolean;
    status: string;
    cue_detected?: boolean;
    summary_ar: string;
    summary_en: string;
  };
  fingerprint: string;
  urls: string[];
  url_forensics?: UrlForensics[];
  evidence_bundle?: EvidenceBundle;
  scan_timestamp?: string;
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

export type AiTextClassification = 'human_leaning' | 'ai_leaning' | 'inconclusive';

export interface AiDetectionResult {
  language: 'ar' | 'en';
  word_count: number;
  sentence_count: number;
  classification: AiTextClassification;
  headline_ar: string;
  headline_en: string;
  is_probabilistic_only: boolean;
  calibrated_ai_probability: number | null;
  model_oof_brier: number;
  metrics: {
    perplexity_proxy: number;
    cross_entropy_human_bits: number;
    cross_entropy_ai_bits: number;
    lm_log_ratio: number;
    burstiness_cv: number;
    adjacent_sentence_shift: number;
    root_ttr: number;
    hapax_ratio: number;
    bigram_repetition: number;
    starter_uniformity: number;
    discourse_marker_rate: number;
    punctuation_entropy: number;
  };
  evidence_bundle: EvidenceBundle;
  scan_timestamp: string;
}

export interface AcademicAnalysisResult {
  word_count: number;
  sentence_count: number;
  lexical_richness: number;
  burstiness: number;
  ai_probability: number | null;
  plagiarism_pct: number;
  originality_score: number;
  verdict: AcademicVerdict;
  matched_ai_phrases?: string[];
  plagiarism_matches: PlagiarismMatch[];
  behavior: {
    status: BehaviorStatus;
    score: number;
    paste_ratio: number;
  };
  signals: AcademicSignal[];
  ai_detection?: AiDetectionResult;
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

export interface UrlSandboxAction {
  id: string;
  severity: 'high' | 'medium' | 'low' | 'safe';
  observed: boolean;
  title_ar: string;
  title_en: string;
  detail_ar: string;
  detail_en: string;
}

export interface UrlSandboxNetworkTrace {
  dns_resolved: boolean;
  dns_ips: string[];
  dns_error: string | null;
  tls: {
    available: boolean;
    valid: boolean;
    issuer?: string;
    days_remaining?: number | null;
    error?: string;
  };
  redirects: Array<{
    url: string;
    status: number;
  }>;
  final_url: string;
  http_status: number | null;
  content_type: string | null;
  server: string | null;
  cookies_attempted: number;
  download_filename: string | null;
}

export interface UrlSandboxDomTelemetry {
  page_title: string;
  visible_text_preview: string;
  forms_count: number;
  password_inputs: number;
  sensitive_inputs: string[];
  form_actions_defanged: string[];
  cross_domain_form: boolean;
  scripts_count: number;
  external_script_hosts: string[];
  obfuscated_js_hits: number;
  js_redirect_detected: boolean;
  exfil_webhook_detected: boolean;
  keylogger_or_clipboard: boolean;
  iframes_count: number;
  hidden_iframes_count: number;
  meta_refresh_target: string | null;
}

export interface UrlSandboxResult {
  input_url: string;
  defanged_url: string;
  execution_mode: 'live_captured' | 'simulated_offline' | 'blocked_ssrf' | 'blocked_unsafe_scheme';
  sandbox_score: number;
  verdict: Verdict;
  forensics: UrlForensics;
  network_trace: UrlSandboxNetworkTrace;
  dom_telemetry: UrlSandboxDomTelemetry;
  what_it_tries_to_do: UrlSandboxAction[];
  safety_guarantees: {
    js_executed: boolean;
    cookies_stored: boolean;
    files_written: boolean;
    ssrf_protected: boolean;
  };
}



