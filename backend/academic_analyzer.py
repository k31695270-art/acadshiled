"""Pure-Python Academic Integrity (AI Detector + Plagiarism + Behavioral Biometrics) & DLP Scanner."""

from __future__ import annotations

import math
import re
import statistics
from typing import Any, TypedDict

from analyzer import analyze_message, normalize_arabic

AI_PHRASES_AR = [
    "مما لا شك فيه",
    "علاوة على ذلك",
    "في الختام",
    "تجدر الاشاره الي",
    "بناء علي ما سبق",
    "من ناحيه اخري",
    "يلعب دورا حيويا",
    "في عصرنا الحالي",
    "لا يمكن اغفال",
    "بشكل عام يمكن القول",
    "في نهايه المطاف",
    "تعد من اهم الركائز",
]

AI_PHRASES_EN = [
    "moreover",
    "furthermore",
    "in conclusion",
    "it is worth noting",
    "delve into",
    "comprehensive overview",
    "plays a crucial role",
    "in today's rapidly evolving",
    "on the other hand",
    "undoubtedly",
    "testament to",
    "landscape of",
]

# Built-in sample academic reference corpus for offline shingling plagiarism checks
BUILTIN_CORPUS: list[dict[str, str]] = [
    {
        "source": "IEEE Cybersecurity & Phishing Taxonomy (2025)",
        "text": (
            "Phishing attacks exploit human cognitive biases by creating artificial urgency and "
            "impersonating trusted financial institutions through homograph domains and shortened links."
        ),
    },
    {
        "source": "مجلة الجامعة التكنولوجية للأمن السيبراني (2025)",
        "text": (
            "تعتمد هجمات التصيد الإلكتروني على انتحال صفة المصارف والمؤسسات الرسمية عبر نطاقات "
            "مشابهة للخداع البصري ومطالبة الضحية بإرسال رموز التحقق المؤقتة أو بيانات البطاقة المصرفية."
        ),
    },
    {
        "source": "Academic Integrity & Stylometry Survey (2024)",
        "text": (
            "Automated text generation systems often exhibit uniform sentence length distributions, "
            "predictable transitional connectors, and reduced lexical burstiness compared to human authorship."
        ),
    },
]

SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "api_key",
        "مفتاح برمجي أو سر وصول مكشوف (API Key / Token)",
        "Exposed API Key or Access Token",
        re.compile(r"\b(?:AIza[0-9A-Za-z\-_]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "jwt_token",
        "رمز جلسة مصادقة مكشوف (JWT Token)",
        "Exposed JWT Authentication Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "iraq_phone",
        "رقم هاتف شخصي مكشوف (قد ينتهك خصوصية الطلبة)",
        "Exposed Personal Phone Number",
        re.compile(r"(?:\+?964|0)7[3-9]\d{8}\b"),
    ),
    (
        "email_pii",
        "عنوان بريد إلكتروني مكشوف",
        "Exposed Email Address (PII)",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "payment_card",
        "رقم بطاقة دفع محتمل مكشوف",
        "Potential Payment Card Number Detected",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
]


class BehavioralMetrics(TypedDict):
    keystrokes: int
    pasted_chars: int
    total_chars: int
    avg_interval_ms: float
    interval_std_ms: float


def _tokenize_words(text: str) -> list[str]:
    return re.findall(r"[\w\u0600-\u06FF]+", text.lower())


def _split_sentences(text: str) -> list[str]:
    parts = re.split(r"[.!؟?\n]+", text)
    return [p.strip() for p in parts if len(p.strip().split()) >= 3]


def _word_shingles(words: list[str], k: int = 4) -> set[tuple[str, ...]]:
    if len(words) < k:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + k]) for i in range(len(words) - k + 1)}


def _luhn_valid(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for idx, n in enumerate(nums):
        if idx % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _mask_secret(raw: str) -> str:
    clean = raw.strip()
    if len(clean) <= 6:
        return "***"
    return f"{clean[:3]}••••{clean[-3:]}"


def analyze_academic_text(
    text: str,
    reference_text: str | None = None,
    behavior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate AI generation likelihood, plagiarism overlap, and behavioral typing authenticity."""
    raw = (text or "").strip()[:15000]
    words = _tokenize_words(raw)
    word_count = len(words)
    sentences = _split_sentences(raw)

    # 1. Stylometry: Burstiness (sentence length std dev) & Vocabulary Richness (TTR)
    sent_lengths = [len(_tokenize_words(s)) for s in sentences]
    if len(sent_lengths) >= 2:
        mean_len = statistics.mean(sent_lengths)
        std_len = statistics.pstdev(sent_lengths)
        cv_len = std_len / max(1.0, mean_len)
    else:
        mean_len = float(word_count)
        std_len = 0.0
        cv_len = 0.45

    unique_words = set(words)
    ttr = round(len(unique_words) / max(1, word_count), 2)

    # 2. AI formulaic transition detection
    norm = normalize_arabic(raw)
    matched_ai_phrases: list[str] = []
    for phrase in AI_PHRASES_AR + AI_PHRASES_EN:
        norm_p = normalize_arabic(phrase)
        if norm_p and norm_p in norm:
            matched_ai_phrases.append(phrase)

    ai_score = 15  # neutral baseline
    if len(matched_ai_phrases) >= 3:
        ai_score += 45
    elif len(matched_ai_phrases) == 2:
        ai_score += 30
    elif len(matched_ai_phrases) == 1:
        ai_score += 15

    # Low sentence-length variance indicates machine uniformity
    if len(sent_lengths) >= 3 and cv_len < 0.25:
        ai_score += 22
    elif len(sent_lengths) >= 3 and cv_len > 0.48:
        ai_score -= 10

    # Repetitive vocabulary on longer essays
    if word_count >= 50 and ttr < 0.52:
        ai_score += 15
    elif word_count >= 40 and ttr >= 0.68:
        ai_score -= 8

    # 3. Plagiarism Shingling (against user-supplied reference OR built-in academic corpus)
    doc_shingles = _word_shingles(words, k=4)
    plagiarism_matches: list[dict[str, Any]] = []
    max_overlap_pct = 0

    corpus_sources = list(BUILTIN_CORPUS)
    if reference_text and reference_text.strip():
        corpus_sources.insert(
            0,
            {
                "source": "المصدر المرجعي المُرفق / Attached Reference",
                "text": reference_text.strip()[:15000],
            },
        )

    for src in corpus_sources:
        ref_words = _tokenize_words(normalize_arabic(src["text"]))
        doc_norm_words = _tokenize_words(norm)
        ref_shingles = _word_shingles(ref_words, k=4)
        doc_norm_shingles = _word_shingles(doc_norm_words, k=4)
        if not doc_norm_shingles or not ref_shingles:
            continue
        inter = doc_norm_shingles.intersection(ref_shingles)
        if inter:
            overlap_pct = min(100, round((len(inter) / len(doc_norm_shingles)) * 100))
            if overlap_pct > max_overlap_pct:
                max_overlap_pct = overlap_pct
            if overlap_pct >= 5:
                sample_phrase = " ".join(next(iter(inter)))
                plagiarism_matches.append(
                    {
                        "source": src["source"],
                        "overlap_pct": overlap_pct,
                        "sample": sample_phrase,
                    }
                )

    # 4. Behavioral Typing Biometrics evaluation
    behavior_status = "not_captured"
    behavior_score = 100
    paste_ratio = 0.0
    if behavior and isinstance(behavior, dict):
        total_chars = max(1, int(behavior.get("total_chars", len(raw))))
        pasted_chars = max(0, int(behavior.get("pasted_chars", 0)))
        keystrokes = max(0, int(behavior.get("keystrokes", 0)))
        interval_std = float(behavior.get("interval_std_ms", 0.0))
        paste_ratio = round(min(1.0, pasted_chars / total_chars), 2)

        if keystrokes >= 15 and paste_ratio < 0.25:
            # Organic human typing shows natural variance
            if interval_std >= 20:
                behavior_status = "human_verified"
                behavior_score = 94
            else:
                behavior_status = "robotic_cadence"
                behavior_score = 45
                ai_score += 15
        elif paste_ratio >= 0.65:
            behavior_status = "bulk_pasted"
            behavior_score = 35
            ai_score += 12
        elif keystrokes > 0:
            behavior_status = "mixed_input"
            behavior_score = 72

    ai_probability = max(0, min(100, ai_score))
    plagiarism_pct = max(0, min(100, max_overlap_pct))
    originality_score = max(0, min(100, round(100 - (plagiarism_pct * 0.65 + ai_probability * 0.35))))

    if originality_score >= 70:
        verdict = "authentic"
    elif originality_score >= 45:
        verdict = "review_needed"
    else:
        verdict = "flagged"

    signals: list[dict[str, str]] = []
    if matched_ai_phrases:
        signals.append(
            {
                "severity": "medium",
                "title_ar": f"رصد {len(matched_ai_phrases)} تعابير نمطية شائعة في نصوص الذكاء الاصطناعي",
                "title_en": f"Detected {len(matched_ai_phrases)} formulaic AI transition phrases",
                "detail": ", ".join(matched_ai_phrases[:4]),
            }
        )
    if len(sent_lengths) >= 3 and cv_len < 0.25:
        signals.append(
            {
                "severity": "medium",
                "title_ar": "انتظام إيقاعي مفرط في أطوال الجمل (انخفاض التنوع البشري)",
                "title_en": "Low sentence-length burstiness (uniform machine cadence)",
                "detail": f"CV={round(cv_len, 2)}",
            }
        )
    if plagiarism_matches:
        signals.append(
            {
                "severity": "high",
                "title_ar": f"تشابه نصي بنسبة {plagiarism_pct}% مع مصادر مرجعية",
                "title_en": f"{plagiarism_pct}% n-gram overlap with reference corpus",
                "detail": plagiarism_matches[0]["source"],
            }
        )
    if behavior_status == "human_verified":
        signals.append(
            {
                "severity": "safe",
                "title_ar": "البصمة السلوكية للكتابة تؤكد الإدخال البشري العضوي",
                "title_en": "Behavioral typing biometrics confirm organic human authorship",
                "detail": f"Paste ratio: {int(paste_ratio * 100)}%",
            }
        )
    elif behavior_status == "bulk_pasted":
        signals.append(
            {
                "severity": "medium",
                "title_ar": "نسبة لصق مباشر مرتفعة مقارنةً بعدد ضغطات المفاتيح",
                "title_en": "High bulk-paste ratio relative to live keystrokes",
                "detail": f"Paste ratio: {int(paste_ratio * 100)}%",
            }
        )

    return {
        "word_count": word_count,
        "sentence_count": len(sentences),
        "lexical_richness": ttr,
        "burstiness": round(cv_len, 2),
        "ai_probability": ai_probability,
        "plagiarism_pct": plagiarism_pct,
        "originality_score": originality_score,
        "verdict": verdict,
        "matched_ai_phrases": matched_ai_phrases,
        "plagiarism_matches": plagiarism_matches,
        "behavior": {
            "status": behavior_status,
            "score": behavior_score,
            "paste_ratio": paste_ratio,
        },
        "signals": signals,
        "eligible_for_certificate": originality_score >= 70 and word_count >= 15,
    }


def scan_dlp_content(text: str) -> dict[str, Any]:
    """Data Loss Prevention (DLP) & file security scanner for PII, secrets, and embedded links."""
    raw = (text or "")[:20000]
    findings: list[dict[str, str]] = []
    seen_masked: set[str] = set()

    for rule_id, title_ar, title_en, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            val = match.group(0)
            if rule_id == "payment_card":
                digits = re.sub(r"\D", "", val)
                if not _luhn_valid(digits):
                    continue
            masked = _mask_secret(val)
            key = f"{rule_id}:{masked}"
            if key in seen_masked:
                continue
            seen_masked.add(key)
            findings.append(
                {
                    "id": rule_id,
                    "title_ar": title_ar,
                    "title_en": title_en,
                    "masked_value": masked,
                    "severity": "high" if rule_id in {"api_key", "jwt_token", "payment_card"} else "medium",
                }
            )

    # Also run phishing/URL security check via analyzer.analyze_message
    cyber_res = analyze_message(raw[:5000])
    risk_score = min(100, cyber_res["score"] + len(findings) * 20)
    verdict = "safe" if risk_score <= 29 else ("suspicious" if risk_score <= 64 else "dangerous")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "dlp_findings": findings,
        "urls_found": cyber_res["urls"],
        "url_forensics": cyber_res["url_forensics"],
        "cyber_reasons": cyber_res["reasons"],
    }
