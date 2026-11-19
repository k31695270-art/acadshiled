"""Context-aware, evidence-based scam and phishing message analyzer (Arabic/Iraqi/MSA/English)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from typing import Any, TypedDict
from urllib.parse import urlparse

from brands import BRANDS
from evidence_engine import (
    EvidenceBundle,
    EvidenceItem,
    RiskLevel,
    build_evidence_bundle,
    make_evidence,
    make_limitation,
    utc_now_iso,
)
from url_inspector import (
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    UrlForensics,
    defang_url,
    inspect_url_forensics,
)

URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\u200e\u200f\u202a-\u202e]+|"
    r"\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|ow\.ly|shorturl\.at|rebrand\.ly|t\.ly)/[^\s<>\"'\u200e\u200f]+",
    re.IGNORECASE,
)

IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
TASHKEEL_OR_ZW_REGEX = re.compile(r"[\u064B-\u065F\u0670\u0640\u200B-\u200D\uFEFF]")

EMOJI_REGEX = re.compile(
    "["
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F900-\U0001F9FF"
    "\u2600-\u26FF"
    "\u2700-\u27BF"
    "]",
    flags=re.UNICODE,
)


class Reason(TypedDict):
    id: str
    points: int
    title_ar: str
    title_en: str
    detail_ar: str
    detail_en: str
    match: str


class SuspiciousSegment(TypedDict):
    text: str
    threat_type: str
    severity: str
    reason_ar: str
    reason_en: str


class AnalysisResult(TypedDict):
    score: int
    verdict: str
    risk_level: RiskLevel
    category: str
    threat_types: list[str]
    reasons: list[Reason]
    highlights: list[str]
    suspicious_segments: list[SuspiciousSegment]
    links_requiring_verification: list[dict[str, Any]]
    recommended_actions: list[dict[str, str]]
    auxiliary_llm: dict[str, Any]
    fingerprint: str
    urls: list[str]
    url_forensics: list[UrlForensics]
    evidence_bundle: EvidenceBundle
    scan_timestamp: str


def normalize_arabic_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize Arabic text while keeping an index map back to the original string."""
    out_chars: list[str] = []
    index_map: list[int] = []
    char_replacements = {
        "أ": "ا",
        "إ": "ا",
        "آ": "ا",
        "ى": "ي",
        "ة": "ه",
    }

    for idx, ch in enumerate(text):
        if TASHKEEL_OR_ZW_REGEX.match(ch):
            continue
        mapped = char_replacements.get(ch, ch).lower()
        out_chars.append(mapped)
        index_map.append(idx)

    return "".join(out_chars), index_map


def normalize_arabic(text: str) -> str:
    """Normalize Arabic text for hashing and rule matching."""
    normalized, _ = normalize_arabic_with_map(text)
    return re.sub(r"\s+", " ", normalized).strip()


def compute_fingerprint(text: str) -> str:
    """Compute privacy-preserving 16-hex SHA-256 fingerprint of normalized message."""
    normalized = normalize_arabic(text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr_row = [i]
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            curr_row.append(min(curr_row[j - 1] + 1, prev_row[j] + 1, prev_row[j - 1] + cost))
        prev_row = curr_row
    return prev_row[-1]


def normalize_brand_token(token: str) -> str:
    cleaned = token.lower().replace("-", "")
    return cleaned.replace("0", "o").replace("1", "l").replace("rn", "m")


def extract_urls(text: str, extra_url: str | None = None) -> list[str]:
    """Extract URLs from text and merge optional explicit URL."""
    found: list[str] = []
    seen: set[str] = set()

    for match in URL_REGEX.finditer(text):
        raw = match.group(0).rstrip(".,;:!?)،؛")
        if raw and raw not in seen:
            seen.add(raw)
            found.append(raw)

    if extra_url and extra_url.strip():
        candidate = extra_url.strip().rstrip(".,;:!?)،؛")
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)

    return found


def _match_phrases(
    raw_text: str,
    norm_text: str,
    index_map: list[int],
    phrases: list[str],
) -> str | None:
    """Find first boundary-aware phrase match and return original substring."""
    for phrase in phrases:
        norm_phrase, _ = normalize_arabic_with_map(phrase)
        parts = [re.escape(p) for p in norm_phrase.split()]
        if not parts:
            continue
        pattern_str = r"(?<!\w)" + r"[\s!؟?,،.:؛\-]+".join(parts) + r"(?!\w)"
        m = re.search(pattern_str, norm_text)
        if m:
            start_norm, end_norm = m.start(), m.end()
            if start_norm < len(index_map) and end_norm - 1 < len(index_map):
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                return raw_text[orig_start:orig_end]
    return None


def _split_sentences(raw_text: str) -> list[str]:
    parts = re.split(r"(?<=[.!؟?\n])\s+|\n+", raw_text.strip())
    return [p.strip() for p in parts if p.strip()]


def _find_containing_sentence(sentences: list[str], snippet: str) -> str:
    if not snippet:
        return sentences[0] if sentences else ""
    for sent in sentences:
        if snippet in sent:
            return sent
    return snippet


def _run_optional_gemini_auxiliary(text: str, timeout: float = 3.5) -> dict[str, Any]:
    """Optional auxiliary semantic review using GEMINI_API_KEY (never sole verdict source)."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or api_key.startswith("MY_"):
        return {
            "used": False,
            "status": "not_configured",
            "summary_ar": "المحلل الدلالي المساعد (Gemini) غير مفعّل — يعتمد التحليل على المحرك الحتمي.",
            "summary_en": "Auxiliary LLM review (Gemini) not configured; deterministic rule & context engine used.",
        }

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    prompt = (
        "Analyze if this message shows social engineering or BEC/phishing cues. "
        "Respond strictly in JSON with keys: cue_detected (boolean), reason_ar (string), reason_en (string). "
        f"Message:\n{text[:1200]}"
    )
    body = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read(65536).decode("utf-8", errors="replace"))
        cand_text = (
            raw.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        parsed = json.loads(cand_text) if cand_text else {}
        return {
            "used": True,
            "status": "ok",
            "cue_detected": bool(parsed.get("cue_detected", False)),
            "summary_ar": str(parsed.get("reason_ar") or "تمت المراجعة الدلالية المساعدة."),
            "summary_en": str(parsed.get("reason_en") or "Auxiliary semantic check completed."),
        }
    except Exception:
        return {
            "used": False,
            "status": "unavailable",
            "summary_ar": "تعذر الوصول للمحلل الدلالي المساعد (مهلة/شبكة).",
            "summary_en": "Auxiliary Gemini check unavailable or timed out.",
        }


def analyze_message(
    text: str,
    url: str | None = None,
    *,
    use_auxiliary_llm: bool = False,
) -> AnalysisResult:
    """Context-aware analysis of SMS/WhatsApp/email text and embedded URLs."""
    scan_ts = utc_now_iso()
    raw_text = (text or "")[:5000]
    urls = extract_urls(raw_text, url)
    norm_text, index_map = normalize_arabic_with_map(raw_text)
    sentences = _split_sentences(raw_text)

    reasons: list[Reason] = []
    highlights: list[str] = []
    evidence: list[EvidenceItem] = []
    suspicious_segments: list[SuspiciousSegment] = []
    threat_types: list[str] = []

    category_points: dict[str, int] = {
        "phishing_bank": 0,
        "fake_prize": 0,
        "fake_delivery": 0,
        "investment_fraud": 0,
        "otp_theft": 0,
        "fake_job": 0,
        "other": 0,
    }

    def add_reason(
        rule_id: str,
        points: int,
        title_ar: str,
        title_en: str,
        detail_ar: str,
        detail_en: str,
        match: str,
        category_key: str,
        threat_type: str,
        severity: str = "medium",
        source: str = "phishing_context_engine",
    ) -> None:
        reasons.append(
            {
                "id": rule_id,
                "points": points,
                "title_ar": title_ar,
                "title_en": title_en,
                "detail_ar": detail_ar,
                "detail_en": detail_en,
                "match": match,
            }
        )
        category_points[category_key] = category_points.get(category_key, 0) + points
        if threat_type not in threat_types:
            threat_types.append(threat_type)
        if match and match in raw_text and match not in highlights:
            highlights.append(match)
        evidence.append(
            make_evidence(
                evidence_id=rule_id,
                category=threat_type,
                severity=severity,  # type: ignore[arg-type]
                title_ar=title_ar,
                title_en=title_en,
                detail_ar=detail_ar,
                detail_en=detail_en,
                source=source,
                observed_value=match[:120],
                timestamp=scan_ts,
            )
        )
        seg_text = _find_containing_sentence(sentences, match)
        if seg_text and not any(s["text"] == seg_text and s["threat_type"] == threat_type for s in suspicious_segments):
            suspicious_segments.append(
                {
                    "text": seg_text,
                    "threat_type": threat_type,
                    "severity": severity,
                    "reason_ar": detail_ar,
                    "reason_en": detail_en,
                }
            )

    # --- 1. Inspect URLs with upgraded url_inspector ---
    url_forensics = [inspect_url_forensics(u) for u in urls]
    url_rule_flags: set[str] = set()
    has_risky_url = False

    for uf in url_forensics:
        raw_url = uf["original_url"]
        if uf["matched_brand"] and not uf["is_official_brand"] and "brand_impersonation" not in url_rule_flags:
            url_rule_flags.add("brand_impersonation")
            has_risky_url = True
            add_reason(
                "brand_impersonation",
                35,
                f"انتحال علامة معروفة في الرابط ({uf['matched_brand']})",
                f"Brand impersonation in URL ({uf['matched_brand']})",
                f"الرابط يقلّد أو يضمّن اسم {uf['matched_brand']} على نطاق غير رسمي.",
                f"URL mimics or embeds {uf['matched_brand']} on an unofficial domain.",
                raw_url,
                "phishing_bank",
                "fake_authority_impersonation",
                severity="high",
                source="url_static_forensics",
            )
        if uf["is_ip"] and "raw_ip_url" not in url_rule_flags:
            url_rule_flags.add("raw_ip_url")
            has_risky_url = True
            add_reason(
                "raw_ip_url",
                25,
                "الرابط يستخدم عنوان IP مباشر بدل اسم نطاق",
                "Raw IP address used instead of domain",
                "الخدمات الشرعية تستخدم نطاقات رسمية بدلاً من أرقام IP.",
                "Legitimate services do not route login flows through raw IP addresses.",
                raw_url,
                "phishing_bank",
                "suspicious_link",
                severity="high",
                source="url_static_forensics",
            )
        if (uf["is_mixed_script_homograph"] or uf["has_punycode"]) and "punycode_or_homograph" not in url_rule_flags:
            url_rule_flags.add("punycode_or_homograph")
            has_risky_url = True
            add_reason(
                "punycode_or_homograph",
                25,
                "حروف متشابهة مخادعة (Homograph) أو ترميز Punycode",
                "Homograph spoofing or Punycode domain",
                "النطاق يستخدم أحرفاً غير قياسية لخداع القارئ.",
                "Domain uses Punycode or mixed-script characters to spoof legitimate text.",
                raw_url,
                "phishing_bank",
                "suspicious_link",
                severity="high",
                source="url_static_forensics",
            )
        if uf["is_shortener"] and "shortened_url" not in url_rule_flags:
            url_rule_flags.add("shortened_url")
            has_risky_url = True
            add_reason(
                "shortened_url",
                15,
                "رابط مختصر يخفي الوجهة الحقيقية",
                "Shortened URL hides final destination",
                "تمنع الروابط المختصرة رؤية النطاق الحقيقي قبل فتحها.",
                "Shortened links obscure destination host until resolved.",
                raw_url,
                "other",
                "suspicious_link",
                severity="medium",
                source="url_static_forensics",
            )
        if uf["tld"] in SUSPICIOUS_TLDS and "suspicious_tld" not in url_rule_flags:
            url_rule_flags.add("suspicious_tld")
            has_risky_url = True
            add_reason(
                "suspicious_tld",
                15,
                f"امتداد نطاق مرتفع المخاطر ({uf['tld']})",
                f"High-abuse top-level domain ({uf['tld']})",
                "الرابط ينتهي بامتداد شائع في حملات التصيّد.",
                "Domain uses a TLD heavily abused in phishing campaigns.",
                raw_url,
                "other",
                "suspicious_link",
                severity="medium",
                source="url_static_forensics",
            )
        if (uf["subdomain_depth"] >= 3 or uf["has_at_symbol"]) and "excessive_subdomains_or_at" not in url_rule_flags:
            url_rule_flags.add("excessive_subdomains_or_at")
            has_risky_url = True
            add_reason(
                "excessive_subdomains_or_at",
                15,
                "بنية رابط مضللة بكثرة النطاقات الفرعية أو الرمز @",
                "Deceptive subdomain depth or '@' syntax",
                "ترتيب النطاق الفرعي مصمم لإخفاء اسم المضيف الفعلي.",
                "Excessive subdomains or '@' syntax obscures the true host.",
                raw_url,
                "other",
                "suspicious_link",
                severity="medium",
                source="url_static_forensics",
            )
        if not uf["is_https"] and uf["scheme"] == "http" and "no_https" not in url_rule_flags:
            url_rule_flags.add("no_https")
            add_reason(
                "no_https",
                5,
                "الرابط غير مشفر (HTTP بدون HTTPS)",
                "Unencrypted HTTP link",
                "البيانات عبر HTTP غير محمية بالتشفير.",
                "HTTP links lack transport encryption.",
                raw_url,
                "other",
                "suspicious_link",
                severity="low",
                source="url_static_forensics",
            )

    all_official_urls = bool(url_forensics) and all(uf["is_official_brand"] for uf in url_forensics)

    # --- 2. Context Signals (avoid triggering on benign words in isolation) ---
    action_lure_phrases = [
        "اضغط الرابط",
        "افتح الرابط",
        "انقر هنا",
        "ادخل الرابط",
        "سجل عبر",
        "سجل بالرابط",
        "حدث بياناتك",
        "اكد معلوماتك",
        "تحديث بيانات",
        "تحديث الحساب",
        "دزلي",
        "ارسل الرمز",
        "click the link",
        "click here",
        "open the link",
        "verify via",
        "update your account",
        "confirm your details",
        "fill out the form",
        "submit below",
    ]
    action_match = _match_phrases(raw_text, norm_text, index_map, action_lure_phrases)
    has_action_or_link = bool(urls or action_match)

    # Benign institutional / public notice markers (e.g. university seminar, official award news)
    benign_context_phrases = [
        "الدخول مجاني",
        "الحضور مجاني",
        "مجاناً للطلبة",
        "مجانا للطلبة",
        "ندوة علمية",
        "ورشة عمل",
        "قاعة المؤتمرات",
        "اجتماع القسم",
        "التفوق العلمي",
        "جائزة التفوق",
        "حصلت الطالبة",
        "حصل الطالب",
        "بريد الجامعة الرسمي",
        "البريد الرسمي للشركة",
        "free admission",
        "free entry",
        "academic award",
        "meeting reminder",
        "conference room",
        "monthly report",
    ]
    has_benign_context = bool(_match_phrases(raw_text, norm_text, index_map, benign_context_phrases))

    # --- 3. Text Threat Rules (Context-Sensitive) ---
    # A. Sensitive Credential / OTP Theft (+35) — always strong risk (MSA + Iraqi dialect + English)
    sensitive_phrases = [
        "otp",
        "cvv",
        "pin",
        "رمز التحقق",
        "كود التحقق",
        "رمز التاكيد",
        "كود التفعيل",
        "دزلي الرمز",
        "دز الرمز",
        "دز الكود",
        "ارسل الرمز",
        "وصلتك رسالة بيها رقم",
        "كلمه المرور",
        "كلمه السر",
        "الرقم السري",
        "رقم البطاقه",
        "بيانات البطاقه",
        "معلومات البطاقه",
        "تاريخ الانتهاء",
        "بيانات الدخول",
        "verification code",
        "password",
        "passcode",
        "card number",
        "security code",
        "one time password",
        "login credentials",
    ]
    sensitive_match = _match_phrases(raw_text, norm_text, index_map, sensitive_phrases)
    has_sensitive = bool(sensitive_match)
    if sensitive_match:
        add_reason(
            "sensitive_data",
            35,
            "طلب رموز تحقق أو كلمات مرور أو بيانات بطاقة حساسة",
            "Request for OTP, password, or payment credentials",
            "المصارف والجهات الرسمية لا تطلب أبداً إرسال رمز OTP أو كلمة المرور أو بيانات البطاقة.",
            "Banks and legitimate services never ask users to share OTPs, passwords, or CVV codes.",
            sensitive_match,
            "otp_theft",
            "otp_credential_theft",
            severity="critical",
        )

    # B. Money Transfer / Gift Card / Fee Demand (+25)
    transfer_phrases = [
        "تحويل مبلغ",
        "حول مبلغ",
        "حول لي",
        "ارسال مبلغ",
        "دفع رسوم",
        "بطاقه هدايا",
        "بطاقات هدايا",
        "كرت شحن",
        "كارت رصيد",
        "ارسل رصيد",
        "حواله ماليه",
        "غيرنا حساب التحويل",
        "تغيير رقم الحساب البنكي",
        "transfer money",
        "wire transfer",
        "send money",
        "gift card",
        "gift cards",
        "itunes card",
        "steam card",
        "routing changed",
        "updated bank account",
    ]
    transfer_match = _match_phrases(raw_text, norm_text, index_map, transfer_phrases)
    if transfer_match:
        add_reason(
            "money_transfer_giftcard",
            25,
            "طلب تحويل أموال أو دفع رسوم أو تغيير حساب الدفع",
            "Request for money transfer, upfront fee, or changed payment routing",
            "طلبات التحويل العاجلة أو بطاقات الهدايا أو تغيير الحساب المصرفي من سمات الاحتيال المالي.",
            "Urgent wire transfers, gift cards, or sudden payment routing changes indicate financial fraud.",
            transfer_match,
            "phishing_bank",
            "financial_fraud",
            severity="high",
        )

    # C. Urgency & Coercive Threat Tactics (+15 ONLY when threatening suspension OR paired with link/action/sensitive ask)
    coercive_urgency_phrases = [
        "سيتم ايقاف حسابك",
        "سيتم تعليق حسابك",
        "سيتم حظر حسابك",
        "حسابك راح ينسد",
        "حسابك سينغلق",
        "اخر تحذير",
        "تنبيه اخير",
        "قبل انتهاء المهله",
        "account suspended",
        "will be suspended",
        "final warning",
        "last warning",
        "your account will be locked",
    ]
    soft_urgency_phrases = [
        "خلال 24 ساعه",
        "خلال ٢٤ ساعه",
        "خلال ساعات",
        "فورا",
        "عاجل جدا",
        "عاجل",
        "act now",
        "within 24 hours",
        "immediately",
        "urgent action",
        "before end of day",
    ]
    coercive_match = _match_phrases(raw_text, norm_text, index_map, coercive_urgency_phrases)
    soft_urg_match = _match_phrases(raw_text, norm_text, index_map, soft_urgency_phrases)
    has_urgency = False
    if coercive_match:
        has_urgency = True
        add_reason(
            "urgency",
            20,
            "تهديد بإيقاف الحساب وضغط زمني للتحايل على التحقق",
            "Account suspension threat and pressure tactic",
            "التهديد بإغلاق الحساب يهدف لخلق ذعر يمنعك من التحقق عبر القنوات الرسمية.",
            "Threatening imminent account suspension pressures victims into skipping verification.",
            coercive_match,
            "other",
            "urgency_pressure",
            severity="high",
        )
    elif soft_urg_match and (has_risky_url or has_sensitive or bool(transfer_match) or (bool(action_match) and not all_official_urls and not has_benign_context)):
        has_urgency = True
        add_reason(
            "urgency",
            15,
            "استعجال مقترن بدعوة لإجراء أو رابط غير موثوق",
            "Urgency paired with call-to-action or untrusted link",
            "الاستعجال بحد ذاته ليس دليلاً، لكنه مقترن هنا بدعوة فورية أو رابط يستوجب الحذر.",
            "Urgency alone is benign, but here it is paired with an immediate link or action demand.",
            soft_urg_match,
            "other",
            "urgency_pressure",
            severity="medium",
        )

    # D. Fake Prize / Free Offer Lure — context-aware! ("مبروك ربحت 5000$" + link/claim vs "جائزة التفوق العلمي")
    direct_prize_scam_phrases = [
        "مبروك ربحت",
        "مبروك فزت",
        "لقد ربحت",
        "دخلت السحب",
        "فائز في السحب",
        "سحب عشوائي",
        "لاستلام الجائزه",
        "استلم جائزتك",
        "منحه ماليه فوريه",
        "عرض مجاني محدود",
        "you won",
        "you have won",
        "congratulations you won",
        "claim your prize",
        "lucky winner",
        "selected as a winner",
    ]
    weak_prize_words = ["ربحت", "جائزه", "جائزه نقديه", "جائزه ماليه", "مجاني", "مجانا", "cash prize", "free gift"]
    direct_prize_match = _match_phrases(raw_text, norm_text, index_map, direct_prize_scam_phrases)
    weak_prize_match = _match_phrases(raw_text, norm_text, index_map, weak_prize_words)
    if direct_prize_match and not has_benign_context:
        add_reason(
            "prize_reward",
            25,
            "إغراء بجائزة مالية أو سحب غير مبرر",
            "Unsolicited prize or lottery lure",
            "الادعاء بالفوز بجائزة أو سحب عشوائي وطلب التفاعل عبر رابط هو نمط احتيالي شائع.",
            "Unsolicited cash prize or raffle win claims are classic social engineering lures.",
            direct_prize_match,
            "fake_prize",
            "fake_offer_prize",
            severity="high",
        )
    elif weak_prize_match and not has_benign_context and (has_risky_url or has_sensitive or bool(transfer_match) or bool(action_match)):
        add_reason(
            "prize_reward",
            20,
            "إغراء بمكافأة أو عرض مجاني مقترن برابط أو طلب إجراء",
            "Prize/free offer lure paired with link or action demand",
            "تم اقتران ذكر الجائزة أو العرض المجاني بدعوة ضغط رابط أو تقديم بيانات.",
            "Prize or free-offer language is paired with a suspicious action or link.",
            weak_prize_match,
            "fake_prize",
            "fake_offer_prize",
            severity="medium",
        )

    # E. Fake Delivery / Customs Fee (+20)
    delivery_phrases = [
        "طردك",
        "شحنتك",
        "رسوم جمركيه",
        "تعذر التسليم",
        "تعذر توصيل",
        "اعاده جدوله التوصيل",
        "توصيل الطرد",
        "البريد العراقي",
        "customs fee",
        "delivery failed",
        "your package",
        "your parcel",
        "shipping fee",
        "unable to deliver",
    ]
    delivery_match = _match_phrases(raw_text, norm_text, index_map, delivery_phrases)
    if delivery_match and (has_action_or_link or bool(transfer_match)):
        add_reason(
            "fake_delivery",
            20,
            "ادعاء طرد معلق أو رسوم شحن/جمارك مع رابط أو طلب دفع",
            "Delivery or customs fee claim paired with link/payment",
            "رسائل تعذّر التسليم ورسوم الجمارك الصغيرة تُستخدم لسرقة بيانات الدفع.",
            "Fake delivery holds and micro customs fees are commonly used for card harvesting.",
            delivery_match,
            "fake_delivery",
            "social_engineering",
            severity="medium",
        )

    # F. Fake Job / Guaranteed Investment / Fake Gov Grant (+25)
    job_phrases = [
        "رسوم تسجيل للوظيفه",
        "رسوم توظيف",
        "تعيين فوري",
        "العمل من المنزل براتب",
        "توظيف فوري",
        "job fee",
        "registration fee",
        "hiring fee",
        "work from home earn",
    ]
    investment_phrases = [
        "ربح يومي مضمون",
        "دخل يومي مضمون",
        "ارباح مضمونه",
        "استثمار مضمون",
        "تداول مضمون",
        "مضاعفه راس المال",
        "اربح يوميا",
        "guaranteed daily profit",
        "guaranteed return",
        "guaranteed profit",
        "double your money",
    ]
    invest_match = _match_phrases(raw_text, norm_text, index_map, investment_phrases)
    job_match = _match_phrases(raw_text, norm_text, index_map, job_phrases)
    if invest_match:
        add_reason(
            "fake_job_investment",
            25,
            "وعد بأرباح مضمونة أو مضاعفة رأس المال",
            "Guaranteed profit or investment fraud lure",
            "لا يوجد استثمار حقيقي يضمن أرباحاً يومية ثابتة أو خالية من المخاطر.",
            "No legitimate investment guarantees daily fixed returns.",
            invest_match,
            "investment_fraud",
            "financial_fraud",
            severity="high",
        )
    elif job_match:
        add_reason(
            "fake_job_investment",
            25,
            "عرض توظيف مشبوه يطلب رسوماً أو يعد بربح غير واقعي",
            "Suspicious employment lure or upfront job fee",
            "جهات التوظيف الموثوقة لا تطلب رسوم تسجيل مسبقة.",
            "Legitimate employers do not charge upfront hiring or registration fees.",
            job_match,
            "fake_job",
            "financial_fraud",
            severity="high",
        )

    # G. Subtle Social Engineering / Authority Impersonation / Quiet Credential Sync (+25)
    subtle_se_phrases = [
        "الدعم التقني",
        "فريق تقنيه المعلومات",
        "عدم مزامنه بريدك",
        "مزامنه الحساب",
        "تفعيل البوابه البديله",
        "استمرار خدمتك",
        "اعاده التحقق من هويتك",
        "تحديث البوابه",
        "تحديث بيانات البطاقه الوطنيه",
        "منحه الرعايه الاجتماعيه",
        "it support team",
        "helpdesk",
        "mailbox sync",
        "alternate portal",
        "confirm your access",
        "re-validate your profile",
        "vendor payment details",
        "audit review",
    ]
    authority_phrases = [
        "المصرف",
        "مصرف الرافدين",
        "مصرف الرشيد",
        "البنك المركزي",
        "البنك",
        "زين كاش",
        "كي كارد",
        "اسياسيل",
        "شركه زين",
        "كورك",
        "الشرطه",
        "مديريه المرور",
        "وزاره الداخليه",
        "وزاره الماليه",
        "الوزاره",
        "الضرائب",
        "الحكومه",
        "خدمه العملاء",
        "bank",
        "central bank",
        "telecom",
        "police",
        "ministry",
        "tax authority",
        "government",
        "customer support",
    ]
    subtle_match = _match_phrases(raw_text, norm_text, index_map, subtle_se_phrases)
    authority_match = _match_phrases(raw_text, norm_text, index_map, authority_phrases)

    if subtle_match and (urls or has_action_or_link or bool(transfer_match)) and not all_official_urls:
        add_reason(
            "subtle_social_engineering",
            30,
            "هندسة اجتماعية هادئة تطلب تأكيد الوصول أو تحديث بيانات عبر قناة بديلة",
            "Subtle social engineering / alternate-portal credential lure",
            "تنتحل هذه الصيغة صفة دعم تقني أو مالي دون كلمات صاخبة لإقناع الضحية بتأكيد الدخول أو التحويل.",
            "Uses calm administrative/IT-support framing instead of noisy buzzwords to elicit credentials or transfers.",
            subtle_match,
            "phishing_bank",
            "social_engineering",
            severity="high",
        )
    elif urls and authority_match and not all_official_urls:
        add_reason(
            "authority_impersonation_link",
            20,
            "انتحال أو إشارة لجهة مصرفية/رسمية مع رابط غير موثّق",
            "Bank/authority reference combined with unverified link",
            "المصارف والمؤسسات الرسمية لا ترسل روابط خارج نطاقاتها الموثقة لتحديث البيانات.",
            "Banks and authorities do not request updates via unofficial external domains.",
            authority_match,
            "phishing_bank",
            "fake_authority_impersonation",
            severity="high",
        )

    # H. Excessive formatting (+5 only if combined with another signal)
    punct_bursts = re.findall(r"[!؟?]{3,}", raw_text)
    emojis = EMOJI_REGEX.findall(raw_text)
    if (punct_bursts or len(emojis) >= 4) and len(reasons) > 0:
        fmt = punct_bursts[0] if punct_bursts else "".join(emojis[:4])
        add_reason(
            "excessive_formatting",
            5,
            "تهويل بصري بالعلامات أو الرموز التعبيرية",
            "Visual pressure via excessive punctuation or emojis",
            "تستخدم مع مؤشرات أخرى لرفع التوتر البصري.",
            "Combined with scam cues to amplify visual urgency.",
            fmt,
            "other",
            "social_engineering",
            severity="low",
        )

    # I. Text Obfuscation (+15)
    zw_matches = re.findall(r"[\u200B-\u200D\uFEFF]+", raw_text)
    tatweel_burst = re.search(r"[^\s]*\u0640{3,}[^\s]*", raw_text)
    if len(zw_matches) >= 2 or tatweel_burst:
        obf_match = tatweel_burst.group(0) if tatweel_burst else ""
        add_reason(
            "text_obfuscation",
            15,
            "تمويه النص برموز غير مرئية أو تطويل مفرط لتجاوز الفلاتر",
            "Zero-width characters or tatweel filter evasion",
            "تمويه الكلمات الحساسة تقنية معروفة لتخطي فلاتر الرسائل.",
            "Obfuscating words with zero-width characters or elongation evades naive keyword filters.",
            obf_match,
            "other",
            "filter_evasion",
            severity="medium",
        )

    raw_score = sum(r["points"] for r in reasons)

    # Benign institutional context dampener if no sensitive credential request & no malicious URL
    if has_benign_context and not has_sensitive and not has_risky_url and not transfer_match:
        raw_score = max(0, raw_score - 20)
    elif not urls and not has_sensitive and not has_urgency and not transfer_match and not subtle_match:
        raw_score = max(0, raw_score - 10)

    final_score = max(0, min(100, raw_score))

    if final_score <= 29:
        verdict = "safe"
    elif final_score <= 64:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    risk_level: RiskLevel = (
        "critical"
        if final_score >= 80
        else "high"
        if final_score >= 60
        else "medium"
        if final_score >= 30
        else "low"
        if final_score >= 10
        else "minimal"
    )

    specific_priority = [
        "otp_theft",
        "fake_prize",
        "fake_delivery",
        "investment_fraud",
        "fake_job",
        "phishing_bank",
    ]
    best_category = "other"
    best_pts = 0
    for cat in specific_priority:
        pts = category_points.get(cat, 0)
        if pts > best_pts:
            best_pts = pts
            best_category = cat

    # Flag links needing separate live Threat Intel verification
    links_requiring_verification: list[dict[str, Any]] = []
    for uf in url_forensics:
        needs_intel = not uf["is_official_brand"]
        links_requiring_verification.append(
            {
                "url": uf["original_url"],
                "defanged_url": uf["defanged_url"],
                "static_classification": uf["classification"],
                "needs_separate_intel_check": needs_intel,
                "reason_ar": (
                    "هذا الرابط ليس نطاقاً رسمياً موثقاً ويحتاج فحصاً منفصلاً عبر قواعد Threat Intelligence و Sandbox الآمن."
                    if needs_intel
                    else "النطاق يطابق مرجعاً رسمياً، ومع ذلك يُنصح بفحصه إذا كان مختصراً أو متغيراً."
                ),
                "reason_en": (
                    "URL is not on the verified official domain registry and requires separate Threat Intel / Sandbox inspection."
                    if needs_intel
                    else "Domain matches a known official entry; verify context independently."
                ),
            }
        )

    # Recommended user actions tailored to findings
    recommended_actions: list[dict[str, str]] = []
    if verdict == "dangerous":
        recommended_actions.extend(
            [
                {
                    "ar": "تجنب التفاعل مع الرسالة تماماً ولا تفتح الروابط ولا ترسل أي رمز تحقق أو بيانات بطاقة.",
                    "en": "Do not reply, click embedded links, or share any OTP, password, or card details.",
                },
                {
                    "ar": "تواصل مع الجهة المذكورة عبر رقمها أو تطبيقها الرسمي فقط للتحقق المستقل.",
                    "en": "Verify directly through the institution's official website or known customer service line.",
                },
            ]
        )
    elif verdict == "suspicious":
        recommended_actions.extend(
            [
                {
                    "ar": "لا تقم بأي إجراء عاجل؛ افحص أي رابط مرفق في تبويب «تشريح رابط» أو «Sandbox الآمن» أولاً.",
                    "en": "Do not rush; inspect any attached URL in URL X-Ray or Safe Sandbox first.",
                },
                {
                    "ar": "تحقق من هوية المرسل عبر قناة اتصال أخرى معروفة مسبقاً.",
                    "en": "Confirm sender identity out-of-band via a known trusted channel.",
                },
            ]
        )
    else:
        recommended_actions.append(
            {
                "ar": "لم تُرصد مؤشرات احتيال قوية في النص، لكن غياب المؤشرات لا يضمن سلامة الروابط غير المفحوصة خارجياً.",
                "en": "No strong phishing cues detected in text, though embedded unfamiliar links still merit caution.",
            }
        )

    if urls:
        recommended_actions.append(
            {
                "ar": "يوجد رابط مرفق — استخدم زر «اختبار الرابط في Sandbox الآمن» أو «فحص حي» قبل الوثوق به.",
                "en": "Embedded URL found — run live Threat Intel probe or Safe Sandbox before opening.",
            }
        )

    auxiliary_llm = (
        _run_optional_gemini_auxiliary(raw_text)
        if use_auxiliary_llm
        else {
            "used": False,
            "status": "skipped",
            "summary_ar": "اعتمد الفحص على المحرك الحتمي السياقي دون استدعاء نموذج لغوي خارجي.",
            "summary_en": "Analyzed purely by the deterministic context engine without external LLM calls.",
        }
    )

    limitations = [
        make_limitation(
            "message_text_scope",
            "تحليل الرسالة يقيّم الأنماط اللغوية وبنية الروابط ساكنًا؛ المرفقات أو الروابط تحتاج فحص Threat Intelligence منفصل للتحقق من سمعتها الحية.",
            "Message analysis evaluates linguistic cues and URL structure statically; URLs require separate Threat Intel lookup for live reputation.",
        )
    ]
    if urls:
        limitations.append(
            make_limitation(
                "urls_need_live_intel",
                f"تحتوي الرسالة على {len(urls)} رابط/روابط تحتاج فحصاً منفصلاً عبر Threat Intelligence.",
                f"Message contains {len(urls)} link(s) requiring separate Threat Intelligence verification.",
            )
        )

    bundle = build_evidence_bundle(
        evidence=evidence,
        risk_level=risk_level,
        limitations=limitations,
        has_authoritative_hit=False,
        data_sufficient=len(raw_text.strip()) >= 8,
        scan_timestamp=scan_ts,
    )

    return {
        "score": final_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "category": best_category,
        "threat_types": threat_types,
        "reasons": reasons,
        "highlights": highlights,
        "suspicious_segments": suspicious_segments,
        "links_requiring_verification": links_requiring_verification,
        "recommended_actions": recommended_actions,
        "auxiliary_llm": auxiliary_llm,
        "fingerprint": compute_fingerprint(raw_text),
        "urls": urls,
        "url_forensics": url_forensics,
        "evidence_bundle": bundle,
        "scan_timestamp": scan_ts,
    }


def analyze_batch(messages: list[str]) -> dict[str, object]:
    """Analyze up to 25 messages in a single Python pass and return aggregate statistics."""
    cleaned = [m.strip()[:5000] for m in messages if m and m.strip()][:25]
    items: list[dict[str, object]] = []
    dangerous_count = 0
    suspicious_count = 0
    safe_count = 0
    max_score = 0

    for idx, msg in enumerate(cleaned):
        res = analyze_message(msg)
        if res["verdict"] == "dangerous":
            dangerous_count += 1
        elif res["verdict"] == "suspicious":
            suspicious_count += 1
        else:
            safe_count += 1
        if res["score"] > max_score:
            max_score = res["score"]
        items.append(
            {
                "index": idx,
                "preview": msg[:140] + ("..." if len(msg) > 140 else ""),
                "text": msg,
                "result": res,
            }
        )

    items.sort(key=lambda entry: int(entry["result"]["score"]), reverse=True)  # type: ignore[index]

    return {
        "total": len(items),
        "dangerous_count": dangerous_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "max_score": max_score,
        "items": items,
    }
