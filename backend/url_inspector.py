"""Pure-Python URL forensic analyzer & SSRF-safe live DNS/TLS/Redirect inspector."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, TypedDict

from brands import BRANDS

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
    has_at_symbol: bool
    subdomain_depth: int
    tracking_params_removed: list[str]
    suspicious_params: list[str]
    matched_brand: str | None
    is_official_brand: bool
    forensic_score: int
    verdict: str
    flags: list[dict[str, str]]


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
    return (
        token.lower()
        .replace("-", "")
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


def inspect_url_forensics(raw_url: str) -> UrlForensics:
    """Run deep offline URL forensic inspection."""
    trimmed = (raw_url or "").strip()
    has_explicit_scheme = bool(re.match(r"^https?://", trimmed, re.IGNORECASE))
    normalized = trimmed if has_explicit_scheme else f"https://{trimmed}"
    parsed = urllib.parse.urlparse(normalized)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "http").lower() if has_explicit_scheme else "http"
    port = parsed.port
    path = parsed.path or "/"

    punycode_decoded = _decode_punycode(host)
    has_punycode = "xn--" in host
    has_non_ascii = any(ord(ch) > 127 for ch in host)
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

    # Parse query parameters & build sanitized URL
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

    # Brand matching
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

    if not is_official_brand and not is_ip and labels:
        domain_labels = labels[:-1] if len(labels) > 1 else labels
        candidate_main = domain_labels[-1] if domain_labels else host
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

    # Build forensic flags and score
    flags: list[dict[str, str]] = []
    score = 0

    if matched_brand and not is_official_brand:
        score += 35
        flags.append(
            {
                "severity": "high",
                "title_ar": f"انتحال محتمل لعلامة {matched_brand}",
                "title_en": f"Possible {matched_brand} impersonation",
            }
        )
    elif is_official_brand and matched_brand:
        flags.append(
            {
                "severity": "safe",
                "title_ar": f"نطاق رسمي مطابق لعلامة {matched_brand}",
                "title_en": f"Verified official {matched_brand} domain",
            }
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

    if has_punycode or has_non_ascii:
        score += 25
        flags.append(
            {
                "severity": "high",
                "title_ar": "ترميز Punycode أو أحرف متشابهة مخادعة",
                "title_en": "Punycode or mixed-script homograph detected",
            }
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

    if tld in SUSPICIOUS_TLDS:
        score += 15
        flags.append(
            {
                "severity": "medium",
                "title_ar": f"امتداد نطاق عالي الخطورة ({tld})",
                "title_en": f"High-risk top-level domain ({tld})",
            }
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

    if entropy >= 3.7 and len(main_label) >= 8 and not is_official_brand:
        score += 10
        flags.append(
            {
                "severity": "medium",
                "title_ar": f"عشوائية عالية في اسم النطاق (Entropy {entropy})",
                "title_en": f"High domain randomness (Entropy {entropy})",
            }
        )

    if suspicious_params:
        score += 10
        flags.append(
            {
                "severity": "medium",
                "title_ar": f"معاملات رابط حساسة: {', '.join(suspicious_params[:3])}",
                "title_en": f"Sensitive URL parameters: {', '.join(suspicious_params[:3])}",
            }
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

    final_score = max(0, min(100, score))
    verdict = "safe" if final_score <= 29 else ("suspicious" if final_score <= 64 else "dangerous")

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
        "has_at_symbol": has_at_symbol,
        "subdomain_depth": subdomain_depth,
        "tracking_params_removed": removed_tracking,
        "suspicious_params": suspicious_params,
        "matched_brand": matched_brand,
        "is_official_brand": is_official_brand,
        "forensic_score": final_score,
        "verdict": verdict,
        "flags": flags,
    }


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def _resolve_public_host(host: str) -> tuple[bool, list[str], str | None]:
    """Resolve host via DNS and enforce SSRF protection against private/local IPs."""
    if not host:
        return False, [], "Invalid hostname"
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return False, [], "Blocked local/internal host"

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
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


def _inspect_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, Any]:
    """Fetch TLS certificate metadata without trusting or downloading page content."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                if not cert:
                    return {"available": False, "error": "No certificate presented"}

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
        return {"available": False, "valid": False, "error": str(exc)}


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_url_live(raw_url: str, timeout: float = 3.5) -> dict[str, Any]:
    """Run an SSRF-safe live DNS + TLS + redirect chain probe using Python stdlib."""
    forensics = inspect_url_forensics(raw_url)
    host = forensics["host"]
    allowed, ips, dns_error = _resolve_public_host(host)

    dns_info = {
        "resolved": allowed,
        "ips": ips[:4],
        "error": dns_error,
    }

    if not allowed:
        return {
            "forensics": forensics,
            "dns": dns_info,
            "tls": {"available": False, "valid": False, "error": dns_error or "DNS unresolved"},
            "redirects": [],
            "final_url": forensics["normalized_url"],
        }

    port = forensics["port"] or 443
    tls_info = _inspect_tls(host, port=port, timeout=min(timeout, 3.0))

    # Trace up to 5 HTTP redirect hops via HEAD without executing content
    opener = urllib.request.build_opener(_NoAutoRedirect())
    current_url = forensics["normalized_url"]
    redirects: list[RedirectHop] = []

    for _ in range(5):
        parsed_curr = urllib.parse.urlparse(current_url)
        curr_host = (parsed_curr.hostname or "").lower()
        ok_hop, _, hop_err = _resolve_public_host(curr_host)
        if not ok_hop:
            break

        req = urllib.request.Request(
            current_url,
            method="HEAD",
            headers={"User-Agent": "Kashf-Security-Inspector/1.0"},
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = getattr(resp, "status", 200)
                redirects.append({"url": current_url, "status": int(status)})
                break
        except urllib.error.HTTPError as err:
            status = int(err.code)
            redirects.append({"url": current_url, "status": status})
            location = err.headers.get("Location") if err.headers else None
            if status in {301, 302, 303, 307, 308} and location:
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            break
        except Exception:
            break

    final_url = redirects[-1]["url"] if redirects else forensics["normalized_url"]
    final_forensics = inspect_url_forensics(final_url) if final_url != forensics["normalized_url"] else None

    return {
        "forensics": forensics,
        "dns": dns_info,
        "tls": tls_info,
        "redirects": redirects,
        "final_url": final_url,
        "final_forensics": final_forensics,
    }
