"""Pure-Python offline scam and phishing message analyzer."""

from __future__ import annotations

import hashlib
import re
from typing import TypedDict
from urllib.parse import urlparse

from brands import BRANDS
from url_inspector import (
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    UrlForensics,
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


class AnalysisResult(TypedDict):
    score: int
    verdict: str
    category: str
    reasons: list[Reason]
    highlights: list[str]
    fingerprint: str
    urls: list[str]
    url_forensics: list[UrlForensics]


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
    """Compute Levenshtein edit distance between two strings."""
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
            curr_row.append(
                min(
                    curr_row[j - 1] + 1,      # insertion
                    prev_row[j] + 1,          # deletion
                    prev_row[j - 1] + cost,   # substitution
                )
            )
        prev_row = curr_row
    return prev_row[-1]


def normalize_brand_token(token: str) -> str:
    """Normalize domain label for lookalike brand checks."""
    cleaned = token.lower().replace("-", "")
    cleaned = cleaned.replace("0", "o").replace("1", "l").replace("rn", "m")
    return cleaned


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


def _parse_url_parts(raw_url: str) -> tuple[str, str, str]:
    """Return (scheme, hostname, path) for a URL string."""
    candidate = raw_url if re.match(r"^https?://", raw_url, re.IGNORECASE) else f"http://{raw_url}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    return parsed.scheme.lower(), host, (parsed.path or "").lower()


def _is_official_brand_domain(host: str, domains: list[str]) -> bool:
    for d in domains:
        d_low = d.lower()
        if host == d_low or host.endswith(f".{d_low}"):
            return True
    return False


def _has_mixed_script_or_non_ascii(host: str) -> bool:
    has_ascii_alpha = any("a" <= ch <= "z" for ch in host)
    has_non_ascii = any(ord(ch) > 127 for ch in host)
    if has_non_ascii and has_ascii_alpha:
        return True
    if has_non_ascii:
        return True
    return False


def _match_phrases(
    raw_text: str,
    norm_text: str,
    index_map: list[int],
    phrases: list[str],
) -> str | None:
    """Find first matching phrase using boundary-aware matching and return original substring."""
    for phrase in phrases:
        norm_phrase, _ = normalize_arabic_with_map(phrase)
        # Allow optional punctuation/whitespace between words in multi-word phrases
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


def analyze_message(text: str, url: str | None = None) -> AnalysisResult:
    """Analyze a suspicious message and optional URL without any network calls."""
    raw_text = (text or "")[:5000]
    urls = extract_urls(raw_text, url)
    norm_text, index_map = normalize_arabic_with_map(raw_text)

    reasons: list[Reason] = []
    highlights: list[str] = []
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
        if match and match in raw_text and match not in highlights:
            highlights.append(match)

    # Track triggered rule flags so each URL rule triggers at most once (highest severity match)
    url_rule_flags: set[str] = set()

    for raw_url in urls:
        scheme, host, path = _parse_url_parts(raw_url)
        if not host:
            continue

        # 1. Shortened URL (+15)
        if "shortened_url" not in url_rule_flags:
            if any(host == s or host.endswith(f".{s}") for s in SHORTENER_DOMAINS):
                url_rule_flags.add("shortened_url")
                add_reason(
                    "shortened_url",
                    15,
                    "رابط مختصر يخفي الوجهة الحقيقية",
                    "Shortened URL hides final destination",
                    "تُستخدم الروابط المختصرة لإخفاء اسم الموقع الحقيقي ومنعك من التحقق منه قبل النقر.",
                    "Shortened links conceal the actual destination domain before you click.",
                    raw_url,
                    "other",
                )

        # 2. Suspicious TLD (+15)
        if "suspicious_tld" not in url_rule_flags:
            matched_tld = next((tld for tld in SUSPICIOUS_TLDS if host.endswith(tld)), None)
            if matched_tld:
                url_rule_flags.add("suspicious_tld")
                add_reason(
                    "suspicious_tld",
                    15,
                    f"نطاق إنترنت منخفض الموثوقية ({matched_tld})",
                    f"High-risk top-level domain ({matched_tld})",
                    "النطاق ينتهي بامتداد رخيص وشائع بكثرة في مواقع التصيّد والاحتيال.",
                    "The domain uses a top-level extension frequently abused in phishing campaigns.",
                    raw_url,
                    "other",
                )

        # 3. Raw IP address (+25)
        if "raw_ip_url" not in url_rule_flags:
            if IPV4_REGEX.match(host) or ":" in host:
                url_rule_flags.add("raw_ip_url")
                add_reason(
                    "raw_ip_url",
                    25,
                    "الرابط يستخدم عنوان IP بدلاً من اسم موقع",
                    "Raw IP address used instead of domain",
                    "المواقع الرسمية والبنوك لا تطلب منك تسجيل الدخول عبر أرقام IP مباشرة.",
                    "Legitimate services use official domain names rather than raw IP addresses.",
                    raw_url,
                    "phishing_bank",
                )

        # 4. Too many subdomains (>3 dots) or '@' inside URL (+15)
        if "excessive_subdomains_or_at" not in url_rule_flags:
            if host.count(".") > 3 or "@" in raw_url:
                url_rule_flags.add("excessive_subdomains_or_at")
                add_reason(
                    "excessive_subdomains_or_at",
                    15,
                    "بنية رابط مضلّلة أو متعددة النطاقات الفرعية",
                    "Deceptive URL structure or excessive subdomains",
                    "الرابط يحتوي على عدد مريب من النطاقات الفرعية أو الرمز @ لخداع القارئ.",
                    "The URL contains too many subdomains or an '@' symbol designed to mislead.",
                    raw_url,
                    "other",
                )

        # 5. Punycode or mixed-script homograph (+25)
        if "punycode_or_homograph" not in url_rule_flags:
            if "xn--" in host or _has_mixed_script_or_non_ascii(host):
                url_rule_flags.add("punycode_or_homograph")
                add_reason(
                    "punycode_or_homograph",
                    25,
                    "حروف متشابهة أو ترميز Punycode لخداع البصر",
                    "Homograph characters or Punycode spoofing",
                    "النطاق يستخدم حروفاً غير قياسية أو ترميزاً مخادعاً يشبه أسماء مواقع معروفة.",
                    "The domain uses Punycode or lookalike characters to mimic a legitimate address.",
                    raw_url,
                    "phishing_bank",
                )

        # 6. Brand impersonation (+35 lookalike, +30 brand in subdomain/path)
        if "brand_impersonation" not in url_rule_flags:
            labels = [lbl for lbl in host.split(".") if lbl]
            # Strip TLD (last label) and common ccTLD suffixes for comparison
            domain_labels = labels[:-1] if len(labels) > 1 else labels
            main_label = domain_labels[-1] if domain_labels else host
            subdomain_labels = domain_labels[:-1]

            impersonated_brand: str | None = None
            impersonation_points = 0
            impersonation_kind = "lookalike"

            is_shortener_host = any(host == s or host.endswith(f".{s}") for s in SHORTENER_DOMAINS)

            for brand in BRANDS:
                if _is_official_brand_domain(host, brand["domains"]):
                    continue

                # Check lookalike distance on main domain label and hyphenated parts (skip known shorteners)
                main_parts = (
                    []
                    if is_shortener_host
                    else [main_label] + [p for p in main_label.split("-") if len(p) >= 3]
                )
                matched_lookalike = False
                for part in main_parts:
                    norm_part = normalize_brand_token(part)
                    for alias in brand["aliases"]:
                        norm_alias = normalize_brand_token(alias)
                        if len(norm_alias) < 3:
                            continue
                        max_dist = 1 if len(norm_alias) <= 4 else 2
                        dist = levenshtein_distance(norm_part, norm_alias)
                        # Distance 0 after 0->o / 1->l / rn->m / hyphen removal means exact lookalike
                        # Distance 1-2 on raw or normalized label means typosquatting
                        if dist <= max_dist and part.lower() != alias.lower():
                            matched_lookalike = True
                            break
                        if part.lower() == alias.lower():
                            # Exact brand word used on a non-official domain (e.g. paypal-login.xyz or paypal.evil.com)
                            matched_lookalike = True
                            break
                    if matched_lookalike:
                        break

                if matched_lookalike:
                    impersonated_brand = brand["name"]
                    impersonation_points = 35
                    impersonation_kind = "lookalike"
                    break

                # Check brand name appearing in subdomain or path of unrelated domain
                sub_joined = " ".join(normalize_brand_token(s) for s in subdomain_labels)
                path_norm = normalize_brand_token(path)
                for alias in brand["aliases"]:
                    norm_alias = normalize_brand_token(alias)
                    if len(norm_alias) < 3:
                        continue
                    if norm_alias in sub_joined or norm_alias in path_norm:
                        impersonated_brand = brand["name"]
                        impersonation_points = 30
                        impersonation_kind = "embedded"
                        break
                if impersonated_brand:
                    break

            if impersonated_brand:
                url_rule_flags.add("brand_impersonation")
                if impersonation_kind == "lookalike":
                    add_reason(
                        "brand_impersonation",
                        impersonation_points,
                        f"انتحال اسم علامة تجارية معروفة ({impersonated_brand})",
                        f"Impersonating a known brand ({impersonated_brand})",
                        f"الرابط يقلّد اسم {impersonated_brand} بتغيير حروف متشابهة أو إضافات مضلّلة وليس النطاق الرسمي.",
                        f"The URL mimics {impersonated_brand} using lookalike characters or deceptive additions.",
                        raw_url,
                        "phishing_bank",
                    )
                else:
                    add_reason(
                        "brand_impersonation",
                        impersonation_points,
                        f"استغلال اسم {impersonated_brand} داخل رابط غير رسمي",
                        f"Brand name ({impersonated_brand}) embedded in unrelated link",
                        f"اسم {impersonated_brand} مذكور في مسار أو نطاق فرعي لموقع غريب وغير رسمي.",
                        f"The name {impersonated_brand} appears inside the subdomain or path of an unrelated domain.",
                        raw_url,
                        "phishing_bank",
                    )

        # 7. No HTTPS (+5)
        if "no_https" not in url_rule_flags:
            if scheme == "http":
                url_rule_flags.add("no_https")
                add_reason(
                    "no_https",
                    5,
                    "الرابط غير مشفّر (HTTP بدلاً من HTTPS)",
                    "Unencrypted link (HTTP without HTTPS)",
                    "المواقع الحساسة والبنوك تستخدم دائماً اتصال HTTPS المشفّر لحماية بياناتك.",
                    "Legitimate login and banking pages always enforce encrypted HTTPS connections.",
                    raw_url,
                    "other",
                )

    # --- Text Rules ---
    has_urgency = False
    has_sensitive = False

    # 1. Urgency (+15)
    urgency_phrases = [
        "خلال 24 ساعه",
        "خلال ٢٤ ساعه",
        "خلال ساعات",
        "سيتم ايقاف حسابك",
        "سيتم تعليق حسابك",
        "سيتم حظر حسابك",
        "فورا",
        "عاجل جدا",
        "اخر تحذير",
        "تنبيه اخير",
        "قبل انتهاء المهله",
        "last warning",
        "final warning",
        "act now",
        "within 24 hours",
        "immediately",
        "account suspended",
        "will be suspended",
        "urgent action",
    ]
    urgency_match = _match_phrases(raw_text, norm_text, index_map, urgency_phrases)
    if urgency_match:
        has_urgency = True
        add_reason(
            "urgency",
            15,
            "أسلوب استعجال وضغط لاتخاذ قرار سريع",
            "Artificial urgency and pressure tactics",
            "المحتالون يهددون بإغلاق الحساب أو انتهاء المهلة لمنعك من التفكير والتحقق.",
            "Scammers create artificial urgency or threaten suspension so you act before verifying.",
            urgency_match,
            "other",
        )

    # 2. Prize or reward (+25)
    prize_phrases = [
        "مبروك ربحت",
        "مبروك فزت",
        "لقد ربحت",
        "ربحت جائزه",
        "ربحت",
        "جائزه نقديه",
        "جائزه ماليه",
        "جائزه",
        "دخلت السحب",
        "فائز في السحب",
        "سحب عشوائي",
        "سحب على",
        "you won",
        "you have won",
        "congratulations you won",
        "claim your prize",
        "cash prize",
        "lucky winner",
    ]
    prize_match = _match_phrases(raw_text, norm_text, index_map, prize_phrases)
    if prize_match:
        add_reason(
            "prize_reward",
            25,
            "إغراء بجائزة مالية أو سحب وهمي",
            "Fake prize or lottery lure",
            "الرسائل التي تخبرك بفوزك بجائزة أو سحب لم تشارك به هي وسيلة شائعة لسرقة البيانات.",
            "Unsolicited messages claiming you won a cash prize or draw are classic phishing lures.",
            prize_match,
            "fake_prize",
        )

    # 3. Requests for sensitive data (+35)
    sensitive_phrases = [
        "otp",
        "cvv",
        "pin",
        "رمز التحقق",
        "كود التحقق",
        "رمز التاكيد",
        "كود التفعيل",
        "كلمه المرور",
        "كلمه السر",
        "الرقم السري",
        "رقم البطاقه",
        "بيانات البطاقه",
        "معلومات البطاقه",
        "تاريخ الانتهاء",
        "verification code",
        "password",
        "passcode",
        "card number",
        "security code",
        "one time password",
    ]
    sensitive_match = _match_phrases(raw_text, norm_text, index_map, sensitive_phrases)
    if sensitive_match:
        has_sensitive = True
        add_reason(
            "sensitive_data",
            35,
            "طلب رموز تحقق أو بيانات بنكية حساسة",
            "Request for OTP or sensitive credentials",
            "أي جهة رسمية أو مصرفية لن تطلب منك أبداً إرسال رمز التحقق OTP أو كلمة المرور أو رقم البطاقة.",
            "No legitimate bank or service will ever ask for your OTP code, password, or CVV.",
            sensitive_match,
            "otp_theft",
        )

    # 4. Asks to transfer money or buy gift cards (+25)
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
        "transfer money",
        "wire transfer",
        "send money",
        "gift card",
        "gift cards",
        "itunes card",
        "steam card",
    ]
    transfer_match = _match_phrases(raw_text, norm_text, index_map, transfer_phrases)
    if transfer_match:
        add_reason(
            "money_transfer_giftcard",
            25,
            "طلب تحويل أموال أو شراء بطاقات شحن وهدايا",
            "Request for money transfer or gift cards",
            "طلب إرسال مبالغ مالية أو بطاقات رصيد وهدايا غير قابلة للاسترداد علامة واضحة على الاحتيال.",
            "Asking for wire transfers, mobile credit, or non-refundable gift cards is a common scam sign.",
            transfer_match,
            "phishing_bank",
        )

    # 5. Fake delivery or customs fee (+20)
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
    if delivery_match:
        add_reason(
            "fake_delivery",
            20,
            "ادعاء وجود طرد معلق أو رسوم جمركية للتوصيل",
            "Fake delivery notification or customs fee",
            "رسائل تعذّر التسليم والرسوم الجمركية البسيطة تُستخدم لسرقة بيانات بطاقتك المصرفية.",
            "Fake parcel delivery notices and small customs fee requests are used to steal card details.",
            delivery_match,
            "fake_delivery",
        )

    # 6. Fake job offer with fee or guaranteed daily profit investment (+25)
    job_phrases = [
        "رسوم تسجيل للوظيفه",
        "رسوم توظيف",
        "وظيفه براتب",
        "فرصه عمل من المنزل",
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
    job_match = _match_phrases(raw_text, norm_text, index_map, job_phrases)
    invest_match = _match_phrases(raw_text, norm_text, index_map, investment_phrases)
    if invest_match:
        add_reason(
            "fake_job_investment",
            25,
            "وعد بأرباح يومية مضمونة أو استثمار وهمي",
            "Guaranteed profit or investment fraud lure",
            "لا يوجد استثمار شرعي يضمن أرباحاً يومية ثابتة أو مضاعفة سريعة للأموال.",
            "No legitimate investment guarantees fixed daily returns or risk-free profits.",
            invest_match,
            "investment_fraud",
        )
    elif job_match:
        add_reason(
            "fake_job_investment",
            25,
            "عرض عمل وهمي يطلب رسوماً أو يَعِد براتب غير منطقي",
            "Fake job offer or upfront employment fee",
            "جهات التوظيف الحقيقية لا تطلب رسوم تسجيل أو عمولات مسبقة من المتقدمين.",
            "Legitimate employers never ask candidates to pay upfront registration or hiring fees.",
            job_match,
            "fake_job",
        )

    # 7. Impersonating authority (bank, telecom, police, ministry) combined with a link (+20)
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
    if urls:
        authority_match = _match_phrases(raw_text, norm_text, index_map, authority_phrases)
        if authority_match:
            add_reason(
                "authority_impersonation_link",
                20,
                "انتحال صفة جهة رسمية أو مصرفية مع إرفاق رابط",
                "Authority or bank impersonation combined with a link",
                "المؤسسات الرسمية والبنوك والمصارف لا ترسل روابط عشوائية لتحديث الحسابات عبر الرسائل.",
                "Banks, telecoms, and government bodies do not ask for account updates via unsolicited links.",
                authority_match,
                "phishing_bank",
            )

    # 8. Excessive punctuation, ALL CAPS, or many emojis (+5)
    punct_bursts = re.findall(r"[!؟?]{3,}", raw_text)
    caps_words = re.findall(r"\b[A-Z]{4,}\b", raw_text)
    # Exclude normal acronyms like OTP, CVV, PIN, URL, HTTP from triggering ALL CAPS alone unless >= 2 words
    non_code_caps = [w for w in caps_words if w not in {"HTTP", "HTTPS"}]
    emojis = EMOJI_REGEX.findall(raw_text)
    formatting_match = ""
    if punct_bursts:
        formatting_match = punct_bursts[0]
    elif len(non_code_caps) >= 2:
        formatting_match = " ".join(non_code_caps[:2])
    elif len(emojis) >= 4:
        formatting_match = "".join(emojis[:4])

    if formatting_match:
        add_reason(
            "excessive_formatting",
            5,
            "أسلوب مبالغ فيه بالعلامات أو الأحرف الكبيرة أو الرموز",
            "Excessive punctuation, ALL CAPS, or emoji density",
            "الرسائل الاحتيالية تعتمد على التهويل البصري وكثرة علامات التعجب والرموز لجذب الانتباه.",
            "Scam texts frequently rely on excessive exclamation marks, all-caps urgency, or emoji clutter.",
            formatting_match,
            "other",
        )

    # 9. Zero-width character or heavy tatweel obfuscation (+15)
    zw_matches = re.findall(r"[\u200B-\u200D\uFEFF]+", raw_text)
    tatweel_burst = re.search(r"[^\s]*\u0640{3,}[^\s]*", raw_text)
    if len(zw_matches) >= 2 or tatweel_burst:
        obf_match = tatweel_burst.group(0) if tatweel_burst else ""
        add_reason(
            "text_obfuscation",
            15,
            "تمويه النص برموز مخفية أو تطويل مفرط لتجاوز الفلاتر",
            "Hidden zero-width characters or tatweel filter-evasion",
            "الرسالة تستخدم رموزاً غير مرئية أو تطويل حروف غير طبيعي للتحايل على أنظمة الحماية.",
            "The text uses invisible zero-width characters or excessive elongation to bypass spam filters.",
            obf_match,
            "other",
        )

    raw_score = sum(r["points"] for r in reasons)

    # Safe-signal rule: no links, no sensitive-data request, no urgency -> subtract 10 (min 0)
    if not urls and not has_sensitive and not has_urgency:
        raw_score = max(0, raw_score - 10)

    final_score = max(0, min(100, raw_score))

    if final_score <= 29:
        verdict = "safe"
    elif final_score <= 64:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    # Choose category from highest-scoring specific group; fall back to 'other' only if none scored
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

    url_forensics = [inspect_url_forensics(u) for u in urls]

    return {
        "score": final_score,
        "verdict": verdict,
        "category": best_category,
        "reasons": reasons,
        "highlights": highlights,
        "fingerprint": compute_fingerprint(raw_text),
        "urls": urls,
        "url_forensics": url_forensics,
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

