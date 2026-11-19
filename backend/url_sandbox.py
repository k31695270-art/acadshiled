"""Pure-Python Isolated Safe URL Sandbox.

Detonates suspicious URLs inside a strict server-side Python environment without executing
JavaScript, storing cookies, writing files to disk, or reaching internal/private networks.
Inspects live HTTP headers, redirect chains, and static HTML/script payloads (forms, OTP/card
harvesters, hidden iframes, meta-refresh, JS redirects, obfuscation, Telegram webhooks) and
falls back to predictive behavioral simulation when a domain is offline or unreachable.
"""

from __future__ import annotations

import os
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

from url_inspector import (
    _NoAutoRedirect,
    _inspect_tls,
    _resolve_public_host,
    defang_url,
    inspect_url_forensics,
)

MAX_SANDBOX_BYTES = 131_072  # 128 KB hard read cap
DANGEROUS_DOWNLOAD_EXTS = {
    ".apk",
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".iso",
    ".dmg",
    ".pkg",
    ".zip",
    ".rar",
    ".7z",
    ".jar",
}

SENSITIVE_FIELD_HINTS = {
    "pass",
    "pwd",
    "otp",
    "pin",
    "cvv",
    "cvc",
    "card",
    "iban",
    "token",
    "code",
    "ssn",
    "secret",
    "كلمة",
    "السر",
    "رمز",
    "بطاقة",
    "التحقق",
}


class _SafeSandboxHTMLParser(HTMLParser):
    """Passive HTML tokenizer that extracts DOM indicators without executing anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.skip_depth = 0
        self.in_script = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.external_script_hosts: list[str] = []
        self.scripts_count = 0
        self.script_bodies: list[str] = []
        self.iframes: list[dict[str, str]] = []
        self.meta_refresh_url: str | None = None
        self.sensitive_inputs: list[str] = []
        self.password_inputs = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if t == "title":
            self.in_title = True
            return

        if t == "script":
            self.scripts_count += 1
            self.in_script = True
            self.skip_depth += 1
            src = attr_map.get("src", "").strip()
            if src:
                parsed_src = urllib.parse.urlparse(src)
                if parsed_src.hostname:
                    self.external_script_hosts.append(parsed_src.hostname.lower())
            return

        if t in {"style", "noscript", "svg"}:
            self.skip_depth += 1
            return

        if t == "meta":
            http_equiv = attr_map.get("http-equiv", "").strip().lower()
            content = attr_map.get("content", "")
            if http_equiv == "refresh" and content:
                match = re.search(r"url\s*=\s*['\"]?([^'\"\s;>]+)", content, re.IGNORECASE)
                if match:
                    self.meta_refresh_url = match.group(1).strip()
            return

        if t == "form":
            self._current_form = {
                "method": (attr_map.get("method") or "GET").upper(),
                "action": attr_map.get("action", "").strip(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
            return

        if t == "input":
            itype = (attr_map.get("type") or "text").lower().strip()
            iname = (attr_map.get("name") or attr_map.get("id") or "").strip()
            placeholder = attr_map.get("placeholder", "").strip()
            combined = f"{itype} {iname} {placeholder}".lower()

            if itype == "password":
                self.password_inputs += 1
            if itype == "password" or any(h in combined for h in SENSITIVE_FIELD_HINTS):
                label = iname or placeholder or itype
                if label not in self.sensitive_inputs:
                    self.sensitive_inputs.append(label[:40])

            if self._current_form is not None and itype != "hidden":
                self._current_form["inputs"].append(f"{itype}:{iname or placeholder or 'field'}")
            return

        if t == "iframe":
            src = attr_map.get("src", "").strip()
            style = attr_map.get("style", "").lower()
            hidden = (
                "display:none" in style.replace(" ", "")
                or "visibility:hidden" in style.replace(" ", "")
                or attr_map.get("width") in {"0", "1"}
                or attr_map.get("height") in {"0", "1"}
            )
            self.iframes.append({"src": src, "hidden": "true" if hidden else "false"})

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t == "script":
            self.in_script = False
            self.skip_depth = max(0, self.skip_depth - 1)
        elif t in {"style", "noscript", "svg"}:
            self.skip_depth = max(0, self.skip_depth - 1)
        elif t == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_script:
            self.script_bodies.append(data)
        elif self.skip_depth == 0:
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)


def inspect_html_payload(html_text: str, base_url: str) -> dict[str, Any]:
    """Statically parse captured HTML/JS inside Python without executing scripts."""
    parser = _SafeSandboxHTMLParser()
    try:
        parser.feed(html_text[:MAX_SANDBOX_BYTES])
        parser.close()
    except Exception:
        pass

    base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    form_actions_defanged: list[str] = []
    cross_domain_form = False
    for form in parser.forms:
        action = form.get("action") or base_url
        abs_action = urllib.parse.urljoin(base_url, action)
        form_actions_defanged.append(defang_url(abs_action))
        action_host = (urllib.parse.urlparse(abs_action).hostname or "").lower()
        if action_host and base_host and action_host != base_host:
            cross_domain_form = True

    combined_scripts = "\n".join(parser.script_bodies) + "\n" + html_text
    obfuscated_hits = len(
        re.findall(
            r"\b(?:eval|atob|unescape|fromCharCode|document\.write)\s*\(",
            combined_scripts,
            re.IGNORECASE,
        )
    )
    js_redirect_detected = bool(
        re.search(
            r"(?:window\.location|document\.location|location\.href\s*=|location\.replace\s*\()",
            combined_scripts,
            re.IGNORECASE,
        )
    )
    exfil_webhook_detected = bool(
        re.search(
            r"(?:api\.telegram\.org/bot|discord\.com/api/webhooks)",
            combined_scripts,
            re.IGNORECASE,
        )
    )
    keylogger_or_clipboard = bool(
        re.search(
            r"(?:navigator\.clipboard|addEventListener\s*\(\s*['\"](?:keydown|keypress|paste)['\"])",
            combined_scripts,
            re.IGNORECASE,
        )
    )

    visible_text = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()[:450]
    page_title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:120]

    return {
        "page_title": page_title,
        "visible_text_preview": visible_text,
        "forms_count": len(parser.forms),
        "password_inputs": parser.password_inputs,
        "sensitive_inputs": parser.sensitive_inputs[:8],
        "form_actions_defanged": form_actions_defanged[:5],
        "cross_domain_form": cross_domain_form,
        "scripts_count": parser.scripts_count,
        "external_script_hosts": list(dict.fromkeys(parser.external_script_hosts))[:8],
        "obfuscated_js_hits": obfuscated_hits,
        "js_redirect_detected": js_redirect_detected,
        "exfil_webhook_detected": exfil_webhook_detected,
        "keylogger_or_clipboard": keylogger_or_clipboard,
        "iframes_count": len(parser.iframes),
        "hidden_iframes_count": sum(1 for f in parser.iframes if f["hidden"] == "true"),
        "meta_refresh_target": defang_url(urllib.parse.urljoin(base_url, parser.meta_refresh_url))
        if parser.meta_refresh_url
        else None,
    }


def _extract_download_extension(url: str, content_disposition: str = "") -> str | None:
    if content_disposition:
        m = re.search(r"filename\*?=['\"]?([^'\";\n]+)", content_disposition, re.IGNORECASE)
        if m:
            ext = posixpath.splitext(m.group(1).strip().lower())[1]
            if ext:
                return ext
    parsed_path = urllib.parse.urlparse(url).path.lower()
    ext = posixpath.splitext(parsed_path)[1]
    return ext if ext in DANGEROUS_DOWNLOAD_EXTS else None


def detonate_url_in_sandbox(raw_url: str, timeout: float = 4.0) -> dict[str, Any]:
    """Safely detonate a URL in an isolated Python sandbox and explain what it does."""
    trimmed = (raw_url or "").strip()[:2000]
    lower_trimmed = trimmed.lower()

    safety_guarantees = {
        "js_executed": False,
        "cookies_stored": False,
        "files_written": False,
        "ssrf_protected": True,
    }

    # 1. Block dangerous non-network URI schemes immediately
    for bad_scheme in ("javascript:", "data:", "vbscript:", "file:"):
        if lower_trimmed.startswith(bad_scheme):
            return {
                "input_url": trimmed,
                "defanged_url": defang_url(trimmed),
                "execution_mode": "blocked_unsafe_scheme",
                "sandbox_score": 98,
                "verdict": "dangerous",
                "forensics": {
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
                    "has_at_symbol": False,
                    "subdomain_depth": 0,
                    "tracking_params_removed": [],
                    "suspicious_params": [],
                    "matched_brand": None,
                    "is_official_brand": False,
                    "forensic_score": 98,
                    "verdict": "dangerous",
                    "flags": [],
                },
                "network_trace": {
                    "dns_resolved": False,
                    "dns_ips": [],
                    "dns_error": f"Blocked executable scheme ({bad_scheme})",
                    "tls": {"available": False, "valid": False},
                    "redirects": [],
                    "final_url": defang_url(trimmed),
                    "http_status": None,
                    "content_type": None,
                    "server": None,
                    "cookies_attempted": 0,
                    "download_filename": None,
                },
                "dom_telemetry": {
                    "page_title": "",
                    "visible_text_preview": "",
                    "forms_count": 0,
                    "password_inputs": 0,
                    "sensitive_inputs": [],
                    "form_actions_defanged": [],
                    "cross_domain_form": False,
                    "scripts_count": 0,
                    "external_script_hosts": [],
                    "obfuscated_js_hits": 0,
                    "js_redirect_detected": False,
                    "exfil_webhook_detected": False,
                    "keylogger_or_clipboard": False,
                    "iframes_count": 0,
                    "hidden_iframes_count": 0,
                    "meta_refresh_target": None,
                },
                "what_it_tries_to_do": [
                    {
                        "id": "unsafe_scheme",
                        "severity": "high",
                        "observed": True,
                        "title_ar": f"محاولة تنفيذ كود محلي مباشر عبر مخطط ({bad_scheme})",
                        "title_en": f"Direct client-side code execution attempt via {bad_scheme}",
                        "detail_ar": "لو فُتح هذا الرابط في المتصفح لحاول حقن أو تشغيل أوامر داخل الجلسة مباشرة. قام صندوق الرمل بحظره فوراً.",
                        "detail_en": "Opening this link would attempt immediate script or local URI execution; blocked inside the sandbox.",
                    }
                ],
                "safety_guarantees": safety_guarantees,
            }

    forensics = inspect_url_forensics(trimmed)
    host = forensics["host"]
    allowed, ips, dns_error = _resolve_public_host(host)

    # 2. SSRF Block check
    if not allowed and dns_error and "Blocked" in dns_error:
        return {
            "input_url": trimmed,
            "defanged_url": forensics["defanged_url"],
            "execution_mode": "blocked_ssrf",
            "sandbox_score": 90,
            "verdict": "dangerous",
            "forensics": forensics,
            "network_trace": {
                "dns_resolved": False,
                "dns_ips": ips[:4],
                "dns_error": dns_error,
                "tls": {"available": False, "valid": False},
                "redirects": [],
                "final_url": forensics["defanged_url"],
                "http_status": None,
                "content_type": None,
                "server": None,
                "cookies_attempted": 0,
                "download_filename": None,
            },
            "dom_telemetry": inspect_html_payload("", forensics["normalized_url"]),
            "what_it_tries_to_do": [
                {
                    "id": "ssrf_local_target",
                    "severity": "high",
                    "observed": True,
                    "title_ar": "يستهدف عنوان شبكة محلي أو داخلي (SSRF / LAN Probe)",
                    "title_en": "Targets internal or private network address",
                    "detail_ar": "يحاول الرابط الوصول إلى جهاز داخلي أو راوتر أو خدمة محلية. منعه الدرع الأمني لصندوق الرمل تماماً.",
                    "detail_en": "This URL points to a private/loopback IP range and was isolated by the SSRF guard.",
                }
            ],
            "safety_guarantees": safety_guarantees,
        }

    # 3. Live isolated fetch when DNS resolves publicly
    tls_info: dict[str, Any] = {"available": False, "valid": False}
    redirects: list[dict[str, Any]] = []
    http_status: int | None = None
    content_type: str | None = None
    server_hdr: str | None = None
    content_disp: str = ""
    cookies_attempted = 0
    captured_body = ""
    live_captured = False

    current_url = forensics["normalized_url"]

    if allowed:
        port = forensics["port"] or 443
        tls_info = _inspect_tls(host, port=port, timeout=min(timeout, 2.5))
        opener = urllib.request.build_opener(_NoAutoRedirect())

        for _ in range(6):
            parsed_curr = urllib.parse.urlparse(current_url)
            curr_host = (parsed_curr.hostname or "").lower()
            ok_hop, _, _ = _resolve_public_host(curr_host)
            if not ok_hop:
                break

            req = urllib.request.Request(
                current_url,
                method="GET",
                headers={
                    "User-Agent": "Kashf-Isolated-Sandbox/1.0 (+no-js; +no-cookies)",
                    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
                },
            )
            try:
                with opener.open(req, timeout=timeout) as resp:
                    http_status = int(getattr(resp, "status", 200))
                    redirects.append({"url": defang_url(current_url), "status": http_status})
                    headers = resp.headers
                    if headers:
                        content_type = headers.get("Content-Type")
                        server_hdr = headers.get("Server")
                        content_disp = headers.get("Content-Disposition") or ""
                        set_cookies = headers.get_all("Set-Cookie") or []
                        cookies_attempted += len(set_cookies)
                    raw_bytes = resp.read(MAX_SANDBOX_BYTES)
                    if raw_bytes and (
                        not content_type
                        or "text" in content_type.lower()
                        or "html" in content_type.lower()
                        or "json" in content_type.lower()
                        or "javascript" in content_type.lower()
                    ):
                        captured_body = raw_bytes.decode("utf-8", errors="replace")
                    live_captured = True
                    break
            except urllib.error.HTTPError as err:
                http_status = int(err.code)
                redirects.append({"url": defang_url(current_url), "status": http_status})
                if err.headers:
                    set_cookies = err.headers.get_all("Set-Cookie") or []
                    cookies_attempted += len(set_cookies)
                    content_type = err.headers.get("Content-Type")
                    server_hdr = err.headers.get("Server")
                    content_disp = err.headers.get("Content-Disposition") or ""
                location = err.headers.get("Location") if err.headers else None
                if http_status in {301, 302, 303, 307, 308} and location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    continue
                try:
                    err_bytes = err.read(MAX_SANDBOX_BYTES)
                    if err_bytes:
                        captured_body = err_bytes.decode("utf-8", errors="replace")
                except Exception:
                    pass
                live_captured = True
                break
            except Exception:
                break

    final_forensics = inspect_url_forensics(current_url)
    dom_telemetry = inspect_html_payload(captured_body, current_url)
    download_ext = _extract_download_extension(current_url, content_disp)
    is_binary_download = bool(
        download_ext
        or (
            content_type
            and any(
                b in content_type.lower()
                for b in (
                    "application/octet-stream",
                    "application/vnd.android.package-archive",
                    "application/x-msdownload",
                    "application/zip",
                )
            )
        )
    )

    actions: list[dict[str, Any]] = []
    score = max(forensics["forensic_score"], final_forensics["forensic_score"])

    # Observed live behaviors from captured HTML/headers
    if dom_telemetry["exfil_webhook_detected"]:
        score += 35
        actions.append(
            {
                "id": "telegram_exfil",
                "severity": "high",
                "observed": True,
                "title_ar": "يرسل البيانات المسروقة خفية إلى بوت تيليغرام أو Webhook خارجي",
                "title_en": "Exfiltrates captured input to external Telegram/Discord webhook",
                "detail_ar": "كشف صندوق الرمل عنوان إرسال آلي داخل الشيفرة المصدريّة للصفحة (تكنيك شائع في صفحات سرقة الحسابات).",
                "detail_en": "Static script inspection detected an automated Telegram/Discord exfiltration endpoint.",
            }
        )

    if dom_telemetry["password_inputs"] > 0 or dom_telemetry["sensitive_inputs"]:
        score += 25
        fields_str = ", ".join(dom_telemetry["sensitive_inputs"][:4]) or "password"
        actions.append(
            {
                "id": "credential_form",
                "severity": "high" if not final_forensics["is_official_brand"] else "low",
                "observed": True,
                "title_ar": f"يعرض نموذجاً لجمع بيانات حساسة ({fields_str})",
                "title_en": f"Presents form requesting sensitive fields ({fields_str})",
                "detail_ar": (
                    "يرسل النموذج البيانات إلى نطاق مختلف عن عنوان الصفحة!"
                    if dom_telemetry["cross_domain_form"]
                    else "يطلب إدخال كلمة مرور أو رمز تحقق أو بيانات بطاقة بمجرد فتح الصفحة."
                ),
                "detail_en": (
                    "Form submits entered credentials to a third-party domain."
                    if dom_telemetry["cross_domain_form"]
                    else "Page requests login credentials, OTP, or card details upon load."
                ),
            }
        )

    if is_binary_download:
        score += 30
        actions.append(
            {
                "id": "drive_by_download",
                "severity": "high",
                "observed": live_captured or bool(download_ext),
                "title_ar": f"يحاول تنزيل ملف تنفيذي أو حزمة ({download_ext or content_type})",
                "title_en": f"Triggers file/payload download ({download_ext or content_type})",
                "detail_ar": "لو شغلت الرابط مباشرة قد يبدأ بتحميل تطبيق خبيث (APK/EXE/ZIP) على جهازك. أوقفه صندوق الرمل ولم يحفظ أي ملف.",
                "detail_en": "Opening directly may trigger an unsolicited binary download (APK/EXE/archive). Blocked by sandbox.",
            }
        )

    if len(redirects) > 1 or dom_telemetry["meta_refresh_target"] or dom_telemetry["js_redirect_detected"]:
        score += 15
        actions.append(
            {
                "id": "silent_redirect",
                "severity": "medium",
                "observed": True,
                "title_ar": f"يقوم بتحويلك تلقائياً عبر {max(1, len(redirects))} محطات إلى وجهة أخرى",
                "title_en": f"Auto-redirects visitor across {max(1, len(redirects))} hop(s)",
                "detail_ar": f"الوجهة النهائية المعطلة: {defang_url(current_url)}",
                "detail_en": f"Final defanged destination: {defang_url(current_url)}",
            }
        )

    if dom_telemetry["obfuscated_js_hits"] > 0 or dom_telemetry["keylogger_or_clipboard"]:
        score += 20
        actions.append(
            {
                "id": "js_obfuscation",
                "severity": "high",
                "observed": True,
                "title_ar": "يحتوي على أكواد JavaScript مشفّرة أو مستمعة لضغطات المفاتيح/الحافظة",
                "title_en": "Contains obfuscated JavaScript or clipboard/keystroke listeners",
                "detail_ar": f"تم رصد {dom_telemetry['obfuscated_js_hits']} استدعاءات إخفاء (eval/atob) دون تنفيذ أي سطر منها.",
                "detail_en": f"Detected {dom_telemetry['obfuscated_js_hits']} obfuscation calls (eval/atob); zero code executed.",
            }
        )

    if dom_telemetry["hidden_iframes_count"] > 0:
        score += 20
        actions.append(
            {
                "id": "hidden_iframe",
                "severity": "high",
                "observed": True,
                "title_ar": f"يحمّل {dom_telemetry['hidden_iframes_count']} إطارات مخفية (Hidden Iframe)",
                "title_en": f"Embeds {dom_telemetry['hidden_iframes_count']} hidden iframe(s)",
                "detail_ar": "تُستخدم الإطارات المخفية لشن هجمات Clickjacking أو تحميل صفحات خبيثة في الخلفية.",
                "detail_en": "Hidden iframes can cloak clickjacking overlays or silent third-party payloads.",
            }
        )

    if cookies_attempted > 0:
        actions.append(
            {
                "id": "cookie_tracking",
                "severity": "low",
                "observed": True,
                "title_ar": f"حاول زرع {cookies_attempted} ملفات تعريف تتبع (Cookies)",
                "title_en": f"Attempted to set {cookies_attempted} tracking/session cookie(s)",
                "detail_ar": "تجاهل صندوق الرمل جميع الكوكيز ولم يحفظ شيئاً في متصفحك.",
                "detail_en": "All Set-Cookie headers were discarded inside the isolated sandbox.",
            }
        )

    # Predictive simulation when URL was unreachable or has high forensic risk without live HTML
    if not live_captured:
        path_low = (forensics["path"] + " " + " ".join(forensics["suspicious_params"])).lower()
        if forensics["matched_brand"] and not forensics["is_official_brand"]:
            actions.append(
                {
                    "id": "predicted_brand_phish",
                    "severity": "high",
                    "observed": False,
                    "title_ar": f"محاكاة متوقعة: يعرض صفحة مزيفة منتحلة لـ {forensics['matched_brand']}",
                    "title_en": f"Predicted Behavior: Spoofed {forensics['matched_brand']} credential portal",
                    "detail_ar": "رغم تعطل الخادم حالياً أو كونه نطاقاً وهمياً، تشير بنية الرابط لصفحة تصيّد تسرق تسجيل الدخول أو البطاقة المصرفية.",
                    "detail_en": "Even though the host did not answer live HTTP, the domain mimics an official brand to harvest logins.",
                }
            )
        if any(tok in path_low for tok in ("login", "auth", "verify", "update", "otp", "pin", "bank", "signin")):
            actions.append(
                {
                    "id": "predicted_login_trap",
                    "severity": "high",
                    "observed": False,
                    "title_ar": "محاكاة متوقعة: يطلب إدخال كلمة المرور أو رمز التحقق OTP",
                    "title_en": "Predicted Behavior: Requests password, PIN, or OTP verification",
                    "detail_ar": "المسار أو المعاملات في الرابط مصممة لاقتناص رموز المصادقة وتمريرها للمهاجم.",
                    "detail_en": "Path and query tokens indicate a credential or OTP interception trap.",
                }
            )
        if forensics["is_shortener"]:
            actions.append(
                {
                    "id": "predicted_shortener",
                    "severity": "medium",
                    "observed": False,
                    "title_ar": "محاكاة متوقعة: يعيد توجيه الضحية لوجهة مخفية خارجية",
                    "title_en": "Predicted Behavior: Forwards visitor to hidden destination",
                    "detail_ar": "الروابط المختصرة تخفي الموقع الحقيقي؛ تعذر تتبع الوجهة لأن الخادم لم يستجب.",
                    "detail_en": "Shortened URLs mask the final host; remote endpoint did not respond during probe.",
                }
            )

    if not forensics["is_https"]:
        actions.append(
            {
                "id": "insecure_http",
                "severity": "medium",
                "observed": True,
                "title_ar": "ينقل أي بيانات تدخلها عبر اتصال HTTP مكشوف غير مشفّر",
                "title_en": "Transmits any entered data over unencrypted HTTP",
                "detail_ar": "يمكن لأي طرف على نفس الشبكة (Wi-Fi عام) قراءة ما ترسله عبر هذا الرابط.",
                "detail_en": "Traffic lacks TLS encryption and can be intercepted on shared networks.",
            }
        )

    if not actions:
        actions.append(
            {
                "id": "clean_inspection",
                "severity": "safe",
                "observed": live_captured,
                "title_ar": "لم يظهر أي سلوك خبيث أو نماذج سرقة بيانات في صندوق الرمل",
                "title_en": "No malicious scripts, credential traps, or risky downloads observed",
                "detail_ar": "الصفحة لا تطلب كلمات مرور غير موثوقة ولا تحاول تنزيل ملفات خطرة.",
                "detail_en": "Inspected headers and DOM showed no credential harvesting or payload drops.",
            }
        )

    final_score = max(0, min(100, score))
    verdict = "safe" if final_score <= 29 else ("suspicious" if final_score <= 64 else "dangerous")

    execution_mode = "live_captured" if live_captured else "simulated_offline"

    return {
        "input_url": trimmed,
        "defanged_url": forensics["defanged_url"],
        "execution_mode": execution_mode,
        "sandbox_score": final_score,
        "verdict": verdict,
        "forensics": final_forensics,
        "network_trace": {
            "dns_resolved": allowed,
            "dns_ips": ips[:4],
            "dns_error": dns_error,
            "tls": tls_info,
            "redirects": redirects,
            "final_url": defang_url(current_url),
            "http_status": http_status,
            "content_type": content_type,
            "server": server_hdr,
            "cookies_attempted": cookies_attempted,
            "download_filename": download_ext,
        },
        "dom_telemetry": dom_telemetry,
        "what_it_tries_to_do": actions,
        "safety_guarantees": safety_guarantees,
    }
