"""Pure-Python URL forensic analyzer, homograph detector, Threat Intel aggregator & SSRF-safe live inspector."""

from __future__ import annotations

import http.client
import ipaddress
import math
import re
import socket
import ssl
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from brands import BRANDS
from evidence_engine import (
    EvidenceBundle,
    EvidenceItem,
    SourceConflict,
    build_evidence_bundle,
    make_evidence,
    make_limitation,
    utc_now_iso,
)
from threat_intel import (
    ThreatSourceResult,
    lookup_dns_records,
    lookup_rdap_domain_age,
    query_all_threat_intel,
)

UrlClassification = Literal["malicious", "suspicious", "no_known_threat", "unknown"]

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "igshid",
    "si",
    "spm",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "redirect_uri",
    "next",
    "return",
    "return_url",
    "url",
    "target",
    "dest",
    "token",
    "otp",
    "pin",
    "cvv",
    "password",
    "session",
    "auth",
    "verify",
    "login",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".icu",
    ".tk",
    ".gq",
    ".work",
    ".live",
    ".cf",
    ".ml",
    ".ga",
    ".buzz",
    ".cam",
    ".monster",
    ".cfd",
    ".sbs",
    ".zip",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "ow.ly",
    "shorturl.at",
    "rebrand.ly",
    "t.ly",
    "goo.gl",
    "buff.ly",
}

# Confusable non-Latin characters commonly abused in homograph attacks
CONFUSABLE_MAP = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u03bf": "o",  # Greek omicron
    "\u03b1": "a",  # Greek alpha
    "\u03b5": "e",  # Greek epsilon
    "\u03c1": "p",  # Greek rho
    "\u03ba": "k",  # Greek kappa
}


class RedirectHop(TypedDict):
    url: str
    status: int


class UrlForensics(TypedDict):
    original_url: str
    normalized_url: str
    defanged_url: str
    sanitized_url: str
    scheme: str
    host: str
    punycode_decoded_host: str
    tld: str
    port: int | None
    path: str
    entropy: float
    is_ip: bool
    is_shortener: bool
    is_https: bool
    has_punycode: bool
    has_non_ascii: bool
    is_mixed_script_homograph: bool
    scripts_detected: list[str]
    homograph_skeleton: str
    has_at_symbol: bool
    subdomain_depth: int
    tracking_params_removed: list[str]
    suspicious_params: list[str]
    matched_brand: str | None
    is_official_brand: bool
    is_official_institution: bool
    custom_blocklisted: bool
    custom_allowlisted: bool
    forensic_score: int
    classification: UrlClassification
    verdict: str
    flags: list[dict[str, str]]
    evidence_bundle: EvidenceBundle


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def defang_url(raw_url: str) -> str:
    """Convert a clickable URL into a safe non-clickable defanged representation."""
    text = raw_url.strip()
    text = re.sub(r"^https://", "hxxps://", text, flags=re.IGNORECASE)
    text = re.sub(r"^http://", "hxxp://", text, flags=re.IGNORECASE)
    if "://" in text:
        scheme_part, rest = text.split("://", 1)
        if "/" in rest:
            host_part, path_part = rest.split("/", 1)
            return f"{scheme_part}://{host_part.replace('.', '[.]')}/{path_part}"
        return f"{scheme_part}://{rest.replace('.', '[.]')}"
    return text.replace(".", "[.]")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            curr.append(
                min(
                    curr[j - 1] + 1,
                    prev[j] + 1,
                    prev[j - 1] + (0 if ch_a == ch_b else 1),
                )
            )
        prev = curr
    return prev[-1]


def _normalize_token(token: str) -> str:
    replaced = "".join(CONFUSABLE_MAP.get(ch, ch) for ch in token.lower())
    return (
        replaced.replace("-", "")
        .replace("0", "o")
        .replace("1", "l")
        .replace("5", "s")
        .replace("3", "e")
        .replace("rn", "m")
    )


def _decode_punycode(host: str) -> str:
    if not host:
        return ""
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def analyze_homograph_scripts(host: str, decoded_host: str) -> dict[str, Any]:
    """Analyze Unicode scripts in domain labels to detect mixed-script homographs."""
    target = decoded_host or host
    scripts: set[str] = set()
    confusable_chars: list[str] = []

    for ch in target:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if "LATIN" in name:
            scripts.add("Latin")
        elif "CYRILLIC" in name:
            scripts.add("Cyrillic")
        elif "GREEK" in name:
            scripts.add("Greek")
        elif "ARABIC" in name:
            scripts.add("Arabic")
        else:
            scripts.add("Other")
        if ch in CONFUSABLE_MAP:
            confusable_chars.append(ch)

    has_latin = "Latin" in scripts
    has_spoof_script = "Cyrillic" in scripts or "Greek" in scripts
    is_mixed = (len(scripts) > 1 and has_spoof_script) or (bool(confusable_chars) and has_latin)
    # Pure Cyrillic/Greek with confusables mimicking ASCII (e.g. every char in CONFUSABLE_MAP)
    if not is_mixed and has_spoof_script and confusable_chars:
        is_mixed = True

    skeleton = "".join(CONFUSABLE_MAP.get(ch, ch) for ch in target.lower())
    return {
        "scripts": sorted(scripts),
        "is_mixed_script_homograph": is_mixed,
        "confusable_count": len(confusable_chars),
        "homograph_skeleton": skeleton,
    }


def _check_explicit_non_http_scheme(raw_url: str) -> str | None:
    """Detect explicit non-HTTP(S) URI schemes without misclassifying host:port strings."""
    trimmed = (raw_url or "").strip()
    lower = trimmed.lower()
    for exec_scheme in ("javascript:", "data:", "vbscript:", "file:"):
        if lower.startswith(exec_scheme):
            return exec_scheme
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(?://|[^0-9])", trimmed)
    if match:
        scheme = match.group(1).lower()
        if scheme not in {"http", "https"}:
            return f"{scheme}:"
    return None


def inspect_url_forensics(raw_url: str) -> UrlForensics:
    """Run deep offline URL forensic inspection with honest 4-state classification."""
    ts = utc_now_iso()
    trimmed = (raw_url or "").strip()

    # Handle dangerous or unsupported non-HTTP(S) schemes safely before urlparse/normalization
    bad_scheme = _check_explicit_non_http_scheme(trimmed)
    if bad_scheme:
        is_exec = bad_scheme in {"javascript:", "data:", "vbscript:", "file:"}
        ev = [
            make_evidence(
                evidence_id="unsafe_uri_scheme",
                category="technical",
                severity="critical" if is_exec else "high",
                title_ar=f"مخطط رابط غير آمن أو غير مدعوم ({bad_scheme})",
                title_en=f"Unsafe or unsupported URI scheme ({bad_scheme})",
                detail_ar="الرابط يستخدم مخططاً غير HTTP/HTTPS وقد يستهدف تنفيذ كود أو بروتوكولاً محلياً.",
                detail_en="URL uses a non-HTTP(S) scheme instead of standard web transport.",
                source="url_static_forensics",
                observed_value=bad_scheme,
                timestamp=ts,
            )
        ]
        bundle = build_evidence_bundle(
            evidence=ev,
            risk_level="critical" if is_exec else "high",
            has_authoritative_hit=is_exec,
            data_sufficient=True,
            scan_timestamp=ts,
        )
        return {
            "original_url": trimmed,
            "normalized_url": trimmed,
            "defanged_url": defang_url(trimmed),
            "sanitized_url": trimmed,
            "scheme": bad_scheme.rstrip(":"),
            "host": "",
            "punycode_decoded_host": "",
            "tld": "",
            "port": None,
            "path": "",
            "entropy": 0.0,
            "is_ip": False,
            "is_shortener": False,
            "is_https": False,
            "has_punycode": False,
            "has_non_ascii": False,
            "is_mixed_script_homograph": False,
            "scripts_detected": [],
            "homograph_skeleton": "",
            "has_at_symbol": False,
            "subdomain_depth": 0,
            "tracking_params_removed": [],
            "suspicious_params": [],
            "matched_brand": None,
            "is_official_brand": False,
            "is_official_institution": False,
            "custom_blocklisted": False,
            "custom_allowlisted": False,
            "forensic_score": 98 if is_exec else 88,
            "classification": "malicious",
            "verdict": "dangerous",
            "flags": [
                {
                    "severity": "high",
                    "title_ar": f"مخطط رابط غير آمن ({bad_scheme})",
                    "title_en": f"Unsafe URI scheme ({bad_scheme})",
                }
            ],
            "evidence_bundle": bundle,
        }

    has_explicit_scheme = bool(re.match(r"^https?://", trimmed, re.IGNORECASE))
    normalized = trimmed if has_explicit_scheme else f"https://{trimmed}"
    parsed = urllib.parse.urlparse(normalized)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "http").lower() if has_explicit_scheme else "http"
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or "/"

    punycode_decoded = _decode_punycode(host)
    has_punycode = "xn--" in host
    has_non_ascii = any(ord(ch) > 127 for ch in host)
    script_info = analyze_homograph_scripts(host, punycode_decoded)
    is_mixed_script = bool(script_info["is_mixed_script_homograph"])
    homograph_skeleton = str(script_info["homograph_skeleton"])
    has_at_symbol = "@" in trimmed

    is_ip = False
    try:
        if host:
            ipaddress.ip_address(host)
            is_ip = True
    except ValueError:
        is_ip = False

    labels = [lbl for lbl in host.split(".") if lbl]
    tld = f".{labels[-1]}" if len(labels) >= 2 and not is_ip else ""
    main_label = labels[-2] if len(labels) >= 2 and not is_ip else host
    subdomain_depth = max(0, len(labels) - 2) if not is_ip else 0
    entropy = shannon_entropy(main_label)
    is_shortener = any(host == s or host.endswith(f".{s}") for s in SHORTENER_DOMAINS)
    is_https = scheme == "https"

    # Parse query parameters & strip tracking
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    kept_pairs: list[tuple[str, str]] = []
    removed_tracking: list[str] = []
    suspicious_params: list[str] = []

    for k, v in query_pairs:
        k_low = k.lower()
        if k_low in TRACKING_PARAMS:
            removed_tracking.append(k)
        else:
            kept_pairs.append((k, v))
            if k_low in SUSPICIOUS_QUERY_KEYS or re.search(r"https?://", v, re.IGNORECASE):
                suspicious_params.append(k)

    sanitized_query = urllib.parse.urlencode(kept_pairs)
    sanitized_url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, sanitized_query, parsed.fragment)
    )

    # Check Developer Console custom blocklist/allowlist rules (safe fallback if DB unavailable)
    custom_blocklisted = False
    custom_allowlisted = False
    try:
        from dev_console import get_domain_rules_map  # local import avoids circular startup

        rules_map = get_domain_rules_map()
        blocklist = rules_map.get("blocklist", set())
        allowlist = rules_map.get("allowlist", set())
        if host:
            custom_blocklisted = any(host == d or host.endswith(f".{d}") for d in blocklist)
            custom_allowlisted = any(host == d or host.endswith(f".{d}") for d in allowlist)
    except Exception:
        custom_blocklisted = False
        custom_allowlisted = False

    # Official Iraqi institutional domains (.gov.iq / .edu.iq) when free of deception markers
    is_official_institution = bool(
        host
        and not is_ip
        and not has_punycode
        and not is_mixed_script
        and not has_at_symbol
        and not suspicious_params
        and (
            host == "gov.iq"
            or host.endswith(".gov.iq")
            or host == "edu.iq"
            or host.endswith(".edu.iq")
        )
    )

    # Brand matching (check both raw host and homograph skeleton)
    matched_brand: str | None = None
    is_official_brand = False
    for brand in BRANDS:
        for official in brand["domains"]:
            off_low = official.lower()
            if host == off_low or host.endswith(f".{off_low}"):
                matched_brand = brand["name"]
                is_official_brand = True
                break
        if is_official_brand:
            break

    if custom_allowlisted and not is_official_brand and not custom_blocklisted:
        is_official_brand = True

    if not is_official_brand and not is_ip and labels:
        skel_host = homograph_skeleton or host
        skel_labels = [lbl for lbl in skel_host.split(".") if lbl]
        domain_labels = skel_labels[:-1] if len(skel_labels) > 1 else skel_labels
        candidate_main = domain_labels[-1] if domain_labels else skel_host
        main_parts = (
            []
            if is_shortener
            else [candidate_main] + [p for p in candidate_main.split("-") if len(p) >= 3]
        )
        sub_and_path = " ".join(
            [_normalize_token(s) for s in domain_labels[:-1]] + [_normalize_token(path)]
        )
        for brand in BRANDS:
            hit = False
            for part in main_parts:
                norm_part = _normalize_token(part)
                for alias in brand["aliases"]:
                    norm_alias = _normalize_token(alias)
                    if len(norm_alias) < 3:
                        continue
                    max_dist = 1 if len(norm_alias) <= 4 else 2
                    dist = _levenshtein(norm_part, norm_alias)
                    if dist <= max_dist or part.lower() == alias.lower():
                        matched_brand = brand["name"]
                        hit = True
                        break
                if hit:
                    break
            if hit:
                break
            for alias in brand["aliases"]:
                norm_alias = _normalize_token(alias)
                if len(norm_alias) >= 3 and norm_alias in sub_and_path:
                    matched_brand = brand["name"]
                    hit = True
                    break
            if hit:
                break

    flags: list[dict[str, str]] = []
    evidence: list[EvidenceItem] = []
    score = 0

    if custom_blocklisted:
        score += 55
        flags.append(
            {
                "severity": "high",
                "title_ar": f"نطاق محظور في قائمة المطورين ({host})",
                "title_en": f"Domain explicitly blocklisted by administrators ({host})",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="custom_domain_blocklist",
                category="domain_pattern",
                severity="critical",
                title_ar=f"النطاق مدرج في قائمة الحظر المخصصة ({host})",
                title_en=f"Domain is in custom administrator blocklist ({host})",
                detail_ar="تم تصنيف هذا النطاق كمحظور يدوياً عبر لوحة تحكم المطورين في منصة كشف.",
                detail_en="This domain was explicitly blocklisted via the Kashf Developer Console.",
                source="dev_domain_rules",
                observed_value=host,
                timestamp=ts,
            )
        )
    elif custom_allowlisted:
        flags.append(
            {
                "severity": "safe",
                "title_ar": f"نطاق موثوق في قائمة السماح ({host})",
                "title_en": f"Domain verified on custom allowlist ({host})",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="custom_domain_allowlist",
                category="domain_pattern",
                severity="safe",
                title_ar=f"النطاق مدرج في قائمة السماح المخصصة ({host})",
                title_en=f"Domain verified on custom allowlist ({host})",
                detail_ar="تم اعتماد هذا النطاق ضمن قائمة النطاقات الموثوقة عبر لوحة تحكم المطورين.",
                detail_en="This domain is trusted in the Kashf Developer Console allowlist.",
                source="dev_domain_rules",
                observed_value=host,
                timestamp=ts,
            )
        )
    elif is_official_institution:
        flags.append(
            {
                "severity": "safe",
                "title_ar": f"نطاق رسمي أكاديمي/حكومي عراقي ({host})",
                "title_en": f"Verified Iraqi institutional domain ({host})",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="official_institution_iq",
                category="domain_pattern",
                severity="safe",
                title_ar=f"يطابق امتداداً مؤسسياً عراقياً موثقاً ({tld or host})",
                title_en=f"Matches official Iraqi .gov.iq / .edu.iq namespace",
                detail_ar="النطاق ينتمي إلى البنية الرسمية الحكومية أو الجامعية العراقية ولا يحتوي على معاملات إعادة توجيه مشبوهة.",
                detail_en="Domain belongs to the official Iraqi government or university namespace with clean parameters.",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )

    if matched_brand and not is_official_brand:
        score += 35
        flags.append(
            {
                "severity": "high",
                "title_ar": f"انتحال محتمل لعلامة {matched_brand}",
                "title_en": f"Possible {matched_brand} impersonation",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="brand_impersonation",
                category="domain_pattern",
                severity="high",
                title_ar=f"اشتباه انتحال اسم علامة ({matched_brand})",
                title_en=f"Lookalike / embedded impersonation of {matched_brand}",
                detail_ar=f"النطاق ({host}) يشابه أو يضمّن اسم {matched_brand} خارج نطاقاتها الرسمية.",
                detail_en=f"Domain ({host}) resembles or embeds {matched_brand} outside its official domains.",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )
    elif is_official_brand and matched_brand:
        flags.append(
            {
                "severity": "safe",
                "title_ar": f"نطاق رسمي مطابق لعلامة {matched_brand}",
                "title_en": f"Matches known official {matched_brand} domain",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="official_brand_match",
                category="domain_pattern",
                severity="safe",
                title_ar=f"يطابق النطاق الرسمي المسجل لعلامة {matched_brand}",
                title_en=f"Matches registered official domain for {matched_brand}",
                detail_ar="تطابق اسم المضيف مع قائمة النطاقات الرسمية المرجعية؛ مع بقاء التحقق من المسار ضرورياً.",
                detail_en="Hostname matches known official brand domain list.",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )

    if is_ip:
        score += 25
        flags.append(
            {
                "severity": "high",
                "title_ar": "استخدام عنوان IP مباشر بدل اسم نطاق",
                "title_en": "Raw IP address used instead of domain name",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="raw_ip_url",
                category="url_structure",
                severity="high",
                title_ar="استخدام عنوان IP مباشر بدل اسم نطاق",
                title_en="Raw IP-based URL instead of domain name",
                detail_ar="المؤسسات والخدمات الموثوقة لا توجّه المستخدمين لتسجيل الدخول عبر عنوان IP خام.",
                detail_en="Legitimate public services rarely ask users to authenticate via raw IP addresses.",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )

    if is_mixed_script or has_punycode:
        pts = 30 if is_mixed_script else 20
        score += pts
        flags.append(
            {
                "severity": "high" if is_mixed_script else "medium",
                "title_ar": (
                    "هجوم حروف متشابهة مختلطة الأبجدية (Homograph)"
                    if is_mixed_script
                    else "استخدام ترميز نطاق دولي Punycode (xn--)"
                ),
                "title_en": (
                    "Mixed-script Unicode homograph detected"
                    if is_mixed_script
                    else "Punycode internationalized domain (xn--) detected"
                ),
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="homograph_or_punycode",
                category="homograph",
                severity="high" if is_mixed_script else "medium",
                title_ar="تم رصد ترميز Punycode أو خلط أبجديات مخادع" if is_mixed_script else "تم رصد نطاق بترميز Punycode",
                title_en="Mixed-script homograph spoofing" if is_mixed_script else "Punycode domain encoding",
                detail_ar=f"النطاق المفكوك: {punycode_decoded} | الأبجديات: {', '.join(script_info['scripts']) or 'ASCII'}",
                detail_en=f"Decoded host: {punycode_decoded} | Scripts: {', '.join(script_info['scripts']) or 'ASCII'}",
                source="url_static_forensics",
                observed_value=punycode_decoded,
                timestamp=ts,
            )
        )

    if is_shortener:
        score += 15
        flags.append(
            {
                "severity": "medium",
                "title_ar": "رابط مختصر يخفي الوجهة النهائية",
                "title_en": "Shortened URL hides final destination",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="url_shortener",
                category="url_structure",
                severity="medium",
                title_ar="رابط مختصر يخفي اسم الموقع الحقيقي",
                title_en="URL shortener masks true destination",
                detail_ar="تمنع الروابط المختصرة المستخدم من معرفة النطاق النهائي قبل تتبع التحويل.",
                detail_en="Shortened links obscure destination host until redirect chain is resolved.",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )

    if tld in SUSPICIOUS_TLDS:
        score += 15
        flags.append(
            {
                "severity": "medium",
                "title_ar": f"امتداد نطاق مرتفع الشيوع في حملات التصيّد ({tld})",
                "title_en": f"High-abuse top-level domain ({tld})",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="suspicious_tld",
                category="domain_pattern",
                severity="medium",
                title_ar=f"امتداد نطاق منخفض الموثوقية ({tld})",
                title_en=f"Frequently abused TLD ({tld})",
                detail_ar="هذا الامتداد شائع في النطاقات المؤقتة وحملات التصيد، وإن كان قد يُستخدم أحياناً بشكل مشروع.",
                detail_en="Extension has elevated phishing abuse prevalence (not conclusive on its own).",
                source="url_static_forensics",
                observed_value=tld,
                timestamp=ts,
            )
        )

    if subdomain_depth >= 3 or has_at_symbol:
        score += 15
        flags.append(
            {
                "severity": "medium",
                "title_ar": "تعمّد تضليل البنية بكثرة النطاقات الفرعية أو @",
                "title_en": "Deceptive subdomain depth or '@' credential syntax",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="deceptive_structure",
                category="url_structure",
                severity="medium",
                title_ar="بنية نطاق مضللة (نطاقات فرعية مفرطة أو الرمز @)",
                title_en="Excessive subdomains or '@' authority separator",
                detail_ar=f"عمق النطاقات الفرعية: {subdomain_depth}",
                detail_en=f"Subdomain depth: {subdomain_depth}",
                source="url_static_forensics",
                observed_value=host,
                timestamp=ts,
            )
        )

    if entropy >= 3.7 and len(main_label) >= 8 and not is_official_brand:
        score += 10
        flags.append(
            {
                "severity": "medium",
                "title_ar": f"عشوائية عالية في اسم النطاق (Entropy {entropy})",
                "title_en": f"High domain randomness (Entropy {entropy})",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="high_domain_entropy",
                category="domain_pattern",
                severity="low",
                title_ar=f"عشوائية مرتفعة في اسم النطاق ({entropy} bits/char)",
                title_en=f"Elevated lexical entropy in domain label ({entropy} bits/char)",
                detail_ar="قد يشير إلى نطاق مولّد خوارزمياً (DGA) أو عنوان عشوائي.",
                detail_en="Elevated Shannon entropy can indicate algorithmically generated domains.",
                source="url_static_forensics",
                observed_value=main_label,
                timestamp=ts,
            )
        )

    if suspicious_params:
        has_embedded_url_param = bool(re.search(r"https?://", parsed.query, re.IGNORECASE))
        pts = 20 if has_embedded_url_param else 10
        sev = "high" if has_embedded_url_param else "medium"
        score += pts
        flags.append(
            {
                "severity": sev,
                "title_ar": (
                    f"إعادة توجيه مفتوحة أو رابط مضمّن داخل المعاملات ({', '.join(suspicious_params[:3])})"
                    if has_embedded_url_param
                    else f"معاملات رابط حساسة: {', '.join(suspicious_params[:3])}"
                ),
                "title_en": (
                    f"Open-redirect target embedded in parameters ({', '.join(suspicious_params[:3])})"
                    if has_embedded_url_param
                    else f"Sensitive URL parameters: {', '.join(suspicious_params[:3])}"
                ),
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="suspicious_query_params",
                category="url_structure",
                severity=sev,
                title_ar="معاملات استعلام حساسة أو إعادة توجيه مفتوحة" if has_embedded_url_param else "معاملات استعلام حساسة أو إعادة توجيه",
                title_en="Open-redirect URL in query parameters" if has_embedded_url_param else "Sensitive or open-redirect query parameters",
                detail_ar=", ".join(suspicious_params[:5]),
                detail_en=", ".join(suspicious_params[:5]),
                source="url_static_forensics",
                observed_value=", ".join(suspicious_params[:3]),
                timestamp=ts,
            )
        )

    if not is_https and has_explicit_scheme:
        score += 10
        flags.append(
            {
                "severity": "low",
                "title_ar": "اتصال غير مشفّر (HTTP)",
                "title_en": "Unencrypted HTTP connection",
            }
        )
        evidence.append(
            make_evidence(
                evidence_id="no_https",
                category="transport",
                severity="low",
                title_ar="غياب التشفير (HTTP بدون TLS)",
                title_en="Unencrypted HTTP transport",
                detail_ar="أي بيانات مرسلة عبر HTTP مكشوفة على الشبكة.",
                detail_en="Data sent over HTTP lacks TLS transport encryption.",
                source="url_static_forensics",
                observed_value="http",
                timestamp=ts,
            )
        )

    final_score = max(0, min(100, score))

    # Honest 4-state static classification (offline mode before external Threat Intel)
    high_flags = sum(1 for f in flags if f["severity"] == "high")
    if (
        custom_blocklisted
        or final_score >= 60
        or (matched_brand and not is_official_brand and final_score >= 45)
        or (is_mixed_script and high_flags >= 1 and final_score >= 45)
    ):
        classification: UrlClassification = "malicious"
        verdict = "dangerous"
    elif final_score >= 15:
        classification = "suspicious"
        verdict = "suspicious"
    elif is_official_brand or custom_allowlisted or is_official_institution:
        classification = "no_known_threat"
        verdict = "safe"
    else:
        classification = "unknown"
        verdict = "safe"

    risk_level = (
        "critical"
        if final_score >= 75
        else "high"
        if final_score >= 55
        else "medium"
        if final_score >= 30
        else "low"
        if final_score >= 10
        else "minimal"
    )
    limitations = [
        make_limitation(
            "static_only",
            "هذا التقييم الأولي يعتمد على تحليل البنية الساكن للرابط فقط دون استعلام مصادر Threat Intelligence الخارجية.",
            "Static analysis only; external Threat Intelligence feeds and live DNS/TLS checks were not yet executed.",
        )
    ]

    bundle = build_evidence_bundle(
        evidence=evidence,
        risk_level=risk_level,
        limitations=limitations,
        has_authoritative_hit=custom_blocklisted,
        data_sufficient=bool(host) and (final_score > 0 or is_official_brand or is_official_institution or custom_blocklisted or custom_allowlisted),
        scan_timestamp=ts,
    )

    return {
        "original_url": trimmed,
        "normalized_url": normalized,
        "defanged_url": defang_url(trimmed),
        "sanitized_url": sanitized_url,
        "scheme": scheme,
        "host": host,
        "punycode_decoded_host": punycode_decoded,
        "tld": tld,
        "port": port,
        "path": path,
        "entropy": entropy,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "is_https": is_https,
        "has_punycode": has_punycode,
        "has_non_ascii": has_non_ascii,
        "is_mixed_script_homograph": is_mixed_script,
        "scripts_detected": script_info["scripts"],
        "homograph_skeleton": homograph_skeleton,
        "has_at_symbol": has_at_symbol,
        "subdomain_depth": subdomain_depth,
        "tracking_params_removed": removed_tracking,
        "suspicious_params": suspicious_params,
        "matched_brand": matched_brand,
        "is_official_brand": is_official_brand,
        "is_official_institution": is_official_institution,
        "custom_blocklisted": custom_blocklisted,
        "custom_allowlisted": custom_allowlisted,
        "forensic_score": final_score,
        "classification": classification,
        "verdict": verdict,
        "flags": flags,
        "evidence_bundle": bundle,
    }


_EXTRA_BLOCKED_NETS = (
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata & link-local IPv4
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),   # Benchmarking
    ipaddress.ip_network("fc00::/7"),        # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
)


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.split("%", 1)[0])
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or not ip_obj.is_global
        ):
            return False
        for net in _EXTRA_BLOCKED_NETS:
            if ip_obj.version == net.version and ip_obj in net:
                return False
        return True
    except ValueError:
        return False


def _resolve_public_host(host: str) -> tuple[bool, list[str], str | None]:
    """Resolve host via DNS and enforce SSRF protection against private/local/metadata IPs."""
    clean_host = (host or "").strip().lower().rstrip(".")
    if not clean_host:
        return False, [], "Invalid hostname"
    if (
        clean_host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"}
        or clean_host.endswith(".local")
        or clean_host.endswith(".internal")
        or clean_host.endswith(".localhost")
    ):
        return False, [], "Blocked local/internal host"

    try:
        infos = socket.getaddrinfo(clean_host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, [], f"DNS resolution failed: {exc}"

    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
        if not _is_public_ip(ip):
            return False, ips, "Blocked private or reserved IP target"

    if not ips:
        return False, [], "No DNS records returned"
    return True, ips, None


def _inspect_tls(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
    pinned_ip: str | None = None,
) -> dict[str, Any]:
    """Fetch TLS certificate metadata using pinned public IP to prevent DNS rebinding."""
    ctx = ssl.create_default_context()
    connect_target = pinned_ip or host
    if pinned_ip and not _is_public_ip(pinned_ip):
        return {"available": False, "valid": False, "error": "Blocked non-public TLS target"}
    try:
        with socket.create_connection((connect_target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                if not cert:
                    return {"available": False, "valid": False, "error": "No certificate presented"}

                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for k, v in rdn:
                        if k in {"organizationName", "commonName"}:
                            issuer_parts.append(str(v))

                not_after_raw = str(cert.get("notAfter", ""))
                days_remaining: int | None = None
                if not_after_raw:
                    try:
                        exp = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        days_remaining = (exp - datetime.now(timezone.utc)).days
                    except Exception:
                        days_remaining = None

                return {
                    "available": True,
                    "valid": True,
                    "issuer": " · ".join(dict.fromkeys(issuer_parts)) or "Unknown CA",
                    "not_after": not_after_raw,
                    "days_remaining": days_remaining,
                    "protocol": ssock.version() or "TLS",
                    "cipher": cipher[0] if cipher else "",
                }
    except ssl.SSLCertVerificationError as exc:
        return {"available": True, "valid": False, "error": f"Untrusted SSL: {exc.reason}"}
    except Exception as exc:
        return {"available": False, "valid": False, "error": type(exc).__name__}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection pinned directly to a pre-validated public IP (anti-DNS-rebinding)."""

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a public IP with SNI/cert validation on the real hostname."""

    def __init__(
        self,
        host: str,
        port: int,
        pinned_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._sni_host = host

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=self._sni_host)


def _pinned_http_request(
    url: str,
    *,
    pinned_ip: str,
    method: str = "HEAD",
    timeout: float = 3.5,
    max_bytes: int = 0,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, bytes]:
    """Perform a single SSRF-pinned HTTP(S) request without auto-following redirects."""
    if not _is_public_ip(pinned_ip):
        raise ValueError("Blocked non-public IP target")

    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported scheme: {scheme}")

    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    req_headers = {
        "Host": parsed.netloc,
        "Connection": "close",
        **(headers or {}),
    }

    conn: http.client.HTTPConnection
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = _PinnedHTTPSConnection(host, port, pinned_ip, timeout, ctx)
    else:
        conn = _PinnedHTTPConnection(host, port, pinned_ip, timeout)

    try:
        conn.request(method.upper(), target, headers=req_headers)
        resp = conn.getresponse()
        status = int(resp.status)
        body = resp.read(max_bytes) if max_bytes > 0 else b""
        return status, resp.headers, body
    finally:
        conn.close()


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_recommended_actions(classification: UrlClassification, has_shortener: bool) -> list[dict[str, str]]:
    if classification == "malicious":
        return [
            {
                "ar": "لا تفتح هذا الرابط إطلاقاً ولا تدخل أي بيانات دخول أو رموز تحقق فيه.",
                "en": "Do not open this link or enter any credentials, OTPs, or payment information.",
            },
            {
                "ar": "إذا كنت قد فتحته مسبقاً، غيّر كلمات المرور فوراً وافحص جهازك.",
                "en": "If already visited, rotate affected passwords immediately and run a device check.",
            },
        ]
    if classification == "suspicious":
        actions = [
            {
                "ar": "تريث ولا تسجّل الدخول عبر الرابط؛ افتح الموقع الرسمي بنفسك من المتصفح.",
                "en": "Pause and avoid entering credentials; navigate directly to the official site instead.",
            },
            {
                "ar": "جرّب الرابط في Sandbox الآمن لرؤية سلوكه دون المخاطرة بجهازك.",
                "en": "Inspect the link inside the isolated Safe Sandbox before trusting it.",
            },
        ]
        if has_shortener:
            actions.append(
                {
                    "ar": "تحقق من الوجهة النهائية بعد فك الاختصار قبل التفاعل مع الصفحة.",
                    "en": "Verify the final expanded destination domain after redirects.",
                }
            )
        return actions
    if classification == "no_known_threat":
        return [
            {
                "ar": "عدم وجود تهديد معروف لا يضمن الأمان التام؛ تأكد من سياق الرسالة وهوية المرسل.",
                "en": "No Known Threat does not mean guaranteed Safe; always verify sender context.",
            },
            {
                "ar": "تحقق من وجود HTTPS وشهادة صالحة قبل إدخال أي معلومات.",
                "en": "Confirm HTTPS and valid domain spelling before submitting any personal details.",
            },
        ]
    return [
        {
            "ar": "تعذر التحقق الكامل من الرابط عبر المصادر الخارجية أو DNS؛ تعامل معه بحذر شديد.",
            "en": "Full verification was unavailable across external sources/DNS; treat with caution.",
        },
        {
            "ar": "قم بتكوين مفاتيح VirusTotal أو Google Safe Browsing أو اختبر الرابط في Sandbox الآمن.",
            "en": "Configure VirusTotal / Safe Browsing API keys or detonate in the Safe Sandbox.",
        },
    ]


def probe_url_live(
    raw_url: str,
    timeout: float = 3.5,
    *,
    include_intel: bool = True,
) -> dict[str, Any]:
    """Run SSRF-safe live DNS + TLS + redirect + Threat Intel + RDAP inspection."""
    scan_ts = utc_now_iso()
    forensics = inspect_url_forensics(raw_url)
    host = forensics["host"]
    allowed, ips, dns_error = _resolve_public_host(host)

    dns_info = {
        "resolved": allowed,
        "ips": ips[:4],
        "error": dns_error,
    }
    dns_records = lookup_dns_records(host, timeout=min(timeout, 3.0)) if allowed else {
        "available": False,
        "a": [],
        "mx": [],
        "txt": [],
        "has_spf": False,
        "error": dns_error or "DNS unresolved or blocked",
    }
    rdap_info = lookup_rdap_domain_age(host, timeout=min(timeout, 3.5)) if allowed else {
        "available": False,
        "domain": host,
        "age_days": None,
        "error": dns_error or "Skipped for non-resolvable/blocked host",
    }

    threat_intel: list[ThreatSourceResult] = (
        query_all_threat_intel(forensics["normalized_url"], host, timeout=min(timeout, 4.0))
        if include_intel
        else []
    )

    if not allowed:
        evidence = list(forensics["evidence_bundle"]["evidence"])
        if dns_error and "Blocked" in dns_error:
            evidence.append(
                make_evidence(
                    evidence_id="ssrf_blocked",
                    category="security_guard",
                    severity="high",
                    title_ar="تم حظر الوصول لأن الرابط يستهدف عنواناً داخلياً أو محجوزاً (SSRF)",
                    title_en="Blocked private, loopback, or reserved network target (SSRF guard)",
                    detail_ar=dns_error,
                    detail_en=dns_error,
                    source="ssrf_guard",
                    observed_value=host,
                    timestamp=scan_ts,
                )
            )
            classification: UrlClassification = "malicious"
        else:
            classification = forensics["classification"]

        limitations = [
            make_limitation(
                "dns_unresolved",
                f"تعذر تحليل DNS أو تم حظر الهدف ({dns_error or 'غير معروف'})، ما يحدّ من التحقق الحي.",
                f"DNS resolution failed or was blocked ({dns_error or 'unknown'}), limiting live checks.",
            )
        ]
        for ti in threat_intel:
            if ti["status"] in {"not_configured", "unavailable", "error"}:
                limitations.append(
                    make_limitation(
                        f"ti_{ti['source_id']}_{ti['status']}",
                        f"{ti['source_name']}: {ti['verdict_detail_ar']}",
                        f"{ti['source_name']}: {ti['verdict_detail_en']}",
                    )
                )

        hits = [ti for ti in threat_intel if ti["status"] == "hit"]
        if hits:
            classification = "malicious"
            for hit in hits:
                evidence.append(
                    make_evidence(
                        evidence_id=f"ti_hit_{hit['source_id']}",
                        category="threat_intel",
                        severity="critical",
                        title_ar=f"تطابق مؤكد في {hit['source_name']}",
                        title_en=f"Threat matched in {hit['source_name']}",
                        detail_ar=hit["verdict_detail_ar"],
                        detail_en=hit["verdict_detail_en"],
                        source=hit["source_name"],
                        observed_value=hit["detection_ratio"] or ", ".join(hit["categories"]),
                        timestamp=hit["checked_at"],
                    )
                )

        bundle = build_evidence_bundle(
            evidence=evidence,
            risk_level="critical" if classification == "malicious" else forensics["evidence_bundle"]["risk_level"],
            limitations=limitations,
            has_authoritative_hit=bool(hits) or ("Blocked" in (dns_error or "")),
            data_sufficient=bool(hits) or bool(forensics["flags"]) or ("Blocked" in (dns_error or "")),
            scan_timestamp=scan_ts,
        )
        return {
            "forensics": forensics,
            "dns": dns_info,
            "dns_records": dns_records,
            "rdap": rdap_info,
            "tls": {"available": False, "valid": False, "error": dns_error or "DNS unresolved"},
            "redirects": [],
            "final_url": forensics["normalized_url"],
            "final_forensics": None,
            "threat_intel": threat_intel,
            "classification": classification,
            "evidence_bundle": bundle,
            "recommended_actions": _build_recommended_actions(classification, forensics["is_shortener"]),
            "scan_timestamp": scan_ts,
        }

    port = forensics["port"] or 443
    tls_info = _inspect_tls(host, port=port, timeout=min(timeout, 3.0), pinned_ip=ips[0] if ips else None)

    # Trace up to 5 HTTP redirect hops using pinned-IP connections with per-hop SSRF check
    current_url = forensics["normalized_url"]
    redirects: list[RedirectHop] = []
    redirect_ssrf_reason: str | None = None
    deadline = time.monotonic() + max(timeout * 2.5, 6.0)

    for _ in range(5):
        remaining = deadline - time.monotonic()
        if remaining <= 0.2:
            break
        bad_hop_scheme = _check_explicit_non_http_scheme(current_url)
        if bad_hop_scheme:
            redirect_ssrf_reason = f"Blocked unsafe redirect scheme ({bad_hop_scheme})"
            break
        parsed_curr = urllib.parse.urlparse(current_url)
        curr_host = (parsed_curr.hostname or "").lower()
        ok_hop, hop_ips, hop_err = _resolve_public_host(curr_host)
        if not ok_hop or not hop_ips:
            if hop_err and "Blocked" in hop_err:
                redirect_ssrf_reason = hop_err
            break

        try:
            status, resp_headers, _ = _pinned_http_request(
                current_url,
                pinned_ip=hop_ips[0],
                method="HEAD",
                timeout=min(timeout, remaining),
                max_bytes=0,
                headers={"User-Agent": "Kashf-Security-Inspector/2.0"},
            )
            redirects.append({"url": current_url, "status": status})
            location = resp_headers.get("Location") if resp_headers else None
            if status in {301, 302, 303, 307, 308} and location:
                next_url = urllib.parse.urljoin(current_url, location)
                bad_next = _check_explicit_non_http_scheme(next_url)
                if bad_next:
                    redirect_ssrf_reason = f"Blocked unsafe redirect target scheme ({bad_next})"
                    break
                next_host = (urllib.parse.urlparse(next_url).hostname or "").lower()
                ok_next, _, next_err = _resolve_public_host(next_host)
                if not ok_next:
                    if next_err and "Blocked" in next_err:
                        redirect_ssrf_reason = next_err
                    break
                current_url = next_url
                continue
            break
        except Exception:
            break

    final_url = redirects[-1]["url"] if redirects else forensics["normalized_url"]
    final_forensics = inspect_url_forensics(final_url) if final_url != forensics["normalized_url"] else None

    # Merge technical + Threat Intel + RDAP + TLS evidence
    evidence: list[EvidenceItem] = list(forensics["evidence_bundle"]["evidence"])
    if final_forensics:
        for item in final_forensics["evidence_bundle"]["evidence"]:
            if item["id"] not in {e["id"] for e in evidence}:
                evidence.append(item)

    if tls_info.get("available"):
        if tls_info.get("valid"):
            evidence.append(
                make_evidence(
                    evidence_id="tls_valid",
                    category="tls",
                    severity="safe",
                    title_ar="شهادة TLS/SSL صالحة ومشفرة",
                    title_en="Valid TLS/SSL certificate presented",
                    detail_ar=f"المُصدِر: {tls_info.get('issuer')} | الصلاحية: {tls_info.get('days_remaining')} يوم",
                    detail_en=f"Issuer: {tls_info.get('issuer')} | Remaining: {tls_info.get('days_remaining')} days",
                    source="tls_handshake",
                    observed_value=str(tls_info.get("issuer") or ""),
                    timestamp=scan_ts,
                )
            )
        else:
            evidence.append(
                make_evidence(
                    evidence_id="tls_invalid",
                    category="tls",
                    severity="high",
                    title_ar="شهادة SSL/TLS غير موثوقة أو منتهية",
                    title_en="Untrusted or invalid TLS/SSL certificate",
                    detail_ar=str(tls_info.get("error") or "Untrusted TLS"),
                    detail_en=str(tls_info.get("error") or "Untrusted TLS"),
                    source="tls_handshake",
                    observed_value="invalid_tls",
                    timestamp=scan_ts,
                )
            )

    age_days = rdap_info.get("age_days")
    if rdap_info.get("available") and isinstance(age_days, int):
        if age_days < 30:
            evidence.append(
                make_evidence(
                    evidence_id="young_domain_age",
                    category="domain_age",
                    severity="high",
                    title_ar=f"نطاق حديث الإنشاء جداً (العمر: {age_days} يوماً فقط)",
                    title_en=f"Newly registered domain ({age_days} days old)",
                    detail_ar=f"تاريخ التسجيل عبر RDAP: {rdap_info.get('registered_at')}",
                    detail_en=f"RDAP registration date: {rdap_info.get('registered_at')}",
                    source="RDAP (rdap.org)",
                    observed_value=f"{age_days}d",
                    timestamp=scan_ts,
                )
            )
        else:
            evidence.append(
                make_evidence(
                    evidence_id="domain_age_info",
                    category="domain_age",
                    severity="info",
                    title_ar=f"عمر النطاق المسجل: {age_days} يوماً",
                    title_en=f"Registered domain age: {age_days} days",
                    detail_ar=f"تاريخ التسجيل عبر RDAP: {rdap_info.get('registered_at')}",
                    detail_en=f"RDAP registration date: {rdap_info.get('registered_at')}",
                    source="RDAP (rdap.org)",
                    observed_value=f"{age_days}d",
                    timestamp=scan_ts,
                )
            )

    hits = [ti for ti in threat_intel if ti["status"] == "hit"]
    cleans = [ti for ti in threat_intel if ti["status"] == "clean"]
    vt_ratio = next((ti["detection_ratio"] for ti in threat_intel if ti["source_id"] == "virustotal" and ti["detection_ratio"]), None)

    for hit in hits:
        evidence.append(
            make_evidence(
                evidence_id=f"ti_hit_{hit['source_id']}",
                category="threat_intel",
                severity="critical",
                title_ar=f"رصد تهديد في {hit['source_name']}",
                title_en=f"Threat flagged by {hit['source_name']}",
                detail_ar=hit["verdict_detail_ar"],
                detail_en=hit["verdict_detail_en"],
                source=hit["source_name"],
                observed_value=hit["detection_ratio"] or ", ".join(hit["categories"]),
                timestamp=hit["checked_at"],
            )
        )

    # Limitations & Source Conflict Detection
    limitations: list[dict[str, str]] = []
    if not rdap_info.get("available"):
        limitations.append(
            make_limitation(
                "rdap_unavailable",
                f"تعذر الحصول على عمر النطاق عبر RDAP ({rdap_info.get('error', 'غير متوفر')}).",
                f"RDAP domain age unavailable ({rdap_info.get('error', 'unavailable')}).",
            )
        )
    for ti in threat_intel:
        if ti["status"] in {"not_configured", "unavailable", "error"}:
            limitations.append(
                make_limitation(
                    f"ti_{ti['source_id']}_{ti['status']}",
                    f"{ti['source_name']}: {ti['verdict_detail_ar']}",
                    f"{ti['source_name']}: {ti['verdict_detail_en']}",
                )
            )

    conflicts: list[SourceConflict] = []
    tech_score = max(forensics["forensic_score"], final_forensics["forensic_score"] if final_forensics else 0)
    if hits and cleans:
        conflicts.append(
            {
                "topic_ar": "تباين نتائج قواعد استخبارات التهديدات",
                "topic_en": "Threat-intelligence feed disagreement",
                "source_a": hits[0]["source_name"],
                "result_a": "threat_detected",
                "source_b": cleans[0]["source_name"],
                "result_b": "no_match",
            }
        )
    if cleans and not hits and tech_score >= 45:
        conflicts.append(
            {
                "topic_ar": "لم يُرصد في القوائم الخارجية رغم وجود مؤشرات انتحال/تلاعب تقنية",
                "topic_en": "Not listed in checked feeds despite strong technical impersonation indicators",
                "source_a": ", ".join(c["source_name"] for c in cleans[:2]),
                "result_a": "no_match",
                "source_b": "url_static_forensics",
                "result_b": f"forensic_score={tech_score}",
            }
        )
    if hits and forensics["is_official_brand"]:
        conflicts.append(
            {
                "topic_ar": "تعارض بين قائمة النطاقات الرسمية وتنبيه مصدر خارجي",
                "topic_en": "Conflict between official brand allowlist and external threat-intel hit",
                "source_a": hits[0]["source_name"],
                "result_a": "flagged",
                "source_b": "official_brand_registry",
                "result_b": str(forensics["matched_brand"]),
            }
        )

    if redirect_ssrf_reason:
        evidence.append(
            make_evidence(
                evidence_id="ssrf_redirect_blocked",
                category="security_guard",
                severity="critical",
                title_ar="تم حظر إعادة توجيه تستهدف عنواناً داخلياً أو مخططاً غير آمن (SSRF)",
                title_en="Blocked redirect attempting SSRF or unsafe URI scheme",
                detail_ar=redirect_ssrf_reason,
                detail_en=redirect_ssrf_reason,
                source="ssrf_guard",
                observed_value=defang_url(final_url),
                timestamp=scan_ts,
            )
        )

    # Strict 4-state live classification (TLS alone on an unseen domain does NOT imply no_known_threat)
    has_invalid_tls = tls_info.get("available") and not tls_info.get("valid")
    is_very_young = isinstance(age_days, int) and age_days < 30

    if (
        redirect_ssrf_reason
        or hits
        or tech_score >= 60
        or (forensics["matched_brand"] and not forensics["is_official_brand"] and (is_very_young or has_invalid_tls or tech_score >= 45))
    ):
        classification = "malicious"
        risk_level = "critical" if (redirect_ssrf_reason or hits or tech_score >= 70) else "high"
    elif tech_score >= 15 or is_very_young or has_invalid_tls or (final_forensics and final_forensics["forensic_score"] >= 15):
        classification = "suspicious"
        risk_level = "high" if (tech_score >= 45 or has_invalid_tls) else "medium"
    elif cleans or forensics["is_official_brand"] or forensics["is_official_institution"] or forensics["custom_allowlisted"]:
        classification = "no_known_threat"
        risk_level = "minimal"
    else:
        classification = "unknown"
        risk_level = "low"

    data_sufficient = bool(redirect_ssrf_reason or hits or cleans or forensics["is_official_brand"] or forensics["is_official_institution"] or forensics["flags"])
    bundle = build_evidence_bundle(
        evidence=evidence,
        risk_level=risk_level,
        conflicts=conflicts,
        limitations=limitations,
        has_authoritative_hit=bool(hits or redirect_ssrf_reason),
        data_sufficient=data_sufficient,
        detection_ratio=vt_ratio,
        scan_timestamp=scan_ts,
    )

    return {
        "forensics": forensics,
        "dns": dns_info,
        "dns_records": dns_records,
        "rdap": rdap_info,
        "tls": tls_info,
        "redirects": redirects,
        "final_url": final_url,
        "final_forensics": final_forensics,
        "threat_intel": threat_intel,
        "classification": classification,
        "evidence_bundle": bundle,
        "recommended_actions": _build_recommended_actions(classification, forensics["is_shortener"]),
        "scan_timestamp": scan_ts,
    }
