"""Scientifically calibrated Arabic & English AI-vs-Human stylometric analyzer.

Key scientific principles enforced:
1. No text-only method can definitively prove authorship; every output is explicitly
   probabilistic and includes scientific limitations.
2. Arabic and English texts use separate feature extractors, n-gram language models,
   standardized scalers, logistic weights, and out-of-fold Platt calibration.
3. Texts under 35 words, borderline probabilities [0.35, 0.65], or strongly
   conflicting human/AI cues return: "Inconclusive – لا يمكن تحديد مصدر النص بثقة."
"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter
from functools import lru_cache
from typing import Any, Literal

from ai_training_corpus import TRAIN_AR, TRAIN_EN
from evidence_engine import (
    EvidenceBundle,
    EvidenceItem,
    SourceConflict,
    build_evidence_bundle,
    make_evidence,
    make_limitation,
    utc_now_iso,
)

AiTextClassification = Literal["human_leaning", "ai_leaning", "inconclusive"]

AI_DISCOURSE_AR = [
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
    "وبالاضافه الي ذلك",
    "ومن جهه اخري",
    "وختاما",
    "في هذا السياق",
    "وعليه فان",
    "ومن ثم",
]

AI_DISCOURSE_EN = [
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
    "in summary",
    "ultimately",
    "taken together",
    "consequently",
    "nevertheless",
    "serves as a foundational",
]

PERSONAL_VOICE_AR = ["انا", "نحن", "واجبنا", "واجهنا", "اكتشفنا", "اعتقد", "بصراحه", "بالامس", "عندما", "ظننا", "اضطررنا", "لماذا"]
PERSONAL_VOICE_EN = ["i ", "we ", "our ", "my ", "honestly", "yesterday", "bug", "weird", "why ", "messy"]

TASHKEEL_RE = re.compile(r"[\u064B-\u065F\u0670\u0640\u200B-\u200D\uFEFF]")


def _norm_ar(text: str) -> str:
    cleaned = TASHKEEL_RE.sub("", text)
    for src, dst in (("أ", "ا"), ("إ", "ا"), ("آ", "ا"), ("ى", "ي"), ("ة", "ه")):
        cleaned = cleaned.replace(src, dst)
    return re.sub(r"\s+", " ", cleaned.lower()).strip()


def detect_text_language(text: str) -> Literal["ar", "en"]:
    ar_chars = len(re.findall(r"[\u0600-\u06FF]", text))
    latin_chars = len(re.findall(r"[A-Za-z]", text))
    return "ar" if ar_chars >= latin_chars else "en"


def _tokenize(text: str, lang: Literal["ar", "en"]) -> list[str]:
    norm = _norm_ar(text) if lang == "ar" else text.lower()
    return re.findall(r"[\w\u0600-\u06FF']+", norm)


def _split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!؟?\n])\s+|\n+", text.strip())
    return [p.strip() for p in parts if len(re.findall(r"[\w\u0600-\u06FF']+", p)) >= 2]


class _NgramLanguageModel:
    """Smoothed character-3gram + word-2gram statistical entropy estimator."""

    def __init__(self, texts: list[str], lang: Literal["ar", "en"]) -> None:
        self.lang = lang
        self.char_counts: Counter[str] = Counter()
        self.char_ctx: Counter[str] = Counter()
        self.word_bi: Counter[tuple[str, str]] = Counter()
        self.word_uni: Counter[str] = Counter()
        self.vocab: set[str] = set()
        self.charset: set[str] = set()

        for raw in texts:
            norm = _norm_ar(raw) if lang == "ar" else raw.lower()
            padded = f"  {norm} "
            for ch in padded:
                self.charset.add(ch)
            for i in range(2, len(padded)):
                ctx = padded[i - 2 : i]
                ch = padded[i]
                self.char_ctx[ctx] += 1
                self.char_counts[ctx + ch] += 1

            words = _tokenize(raw, lang)
            for w in words:
                self.word_uni[w] += 1
                self.vocab.add(w)
            for i in range(1, len(words)):
                self.word_bi[(words[i - 1], words[i])] += 1

        self.c_vocab = max(32, len(self.charset))
        self.w_vocab = max(50, len(self.vocab))

    def cross_entropy(self, text: str) -> float:
        norm = _norm_ar(text) if self.lang == "ar" else text.lower()
        padded = f"  {norm} "
        char_loss = 0.0
        char_n = 0
        alpha_c = 0.5
        for i in range(2, len(padded)):
            ctx = padded[i - 2 : i]
            ch = padded[i]
            num = self.char_counts.get(ctx + ch, 0) + alpha_c
            den = self.char_ctx.get(ctx, 0) + alpha_c * self.c_vocab
            char_loss -= math.log2(num / den)
            char_n += 1
        char_ce = char_loss / max(1, char_n)

        words = _tokenize(text, self.lang)
        word_loss = 0.0
        word_n = 0
        alpha_w = 0.25
        for i in range(1, len(words)):
            prev_w, curr_w = words[i - 1], words[i]
            num = self.word_bi.get((prev_w, curr_w), 0) + alpha_w
            den = self.word_uni.get(prev_w, 0) + alpha_w * self.w_vocab
            word_loss -= math.log2(num / den)
            word_n += 1
        word_ce = word_loss / max(1, word_n) if word_n else 9.5

        return round(0.55 * char_ce + 0.45 * word_ce, 4)


def _punctuation_entropy(text: str) -> float:
    marks = re.findall(r"[.,!?;:()—\-،؛؟]", text)
    if not marks:
        return 0.0
    counts = Counter(marks)
    total = len(marks)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / total
        ent -= p * math.log2(p)
    return round(ent, 4)


def extract_stylometric_features(
    text: str,
    lang: Literal["ar", "en"],
    human_lm: _NgramLanguageModel,
    ai_lm: _NgramLanguageModel,
) -> dict[str, float]:
    """Compute multi-dimensional stylometric, burstiness, entropy, and repetition metrics."""
    words = _tokenize(text, lang)
    word_count = max(1, len(words))
    sentences = _split_sentences(text)
    sent_lengths = [len(_tokenize(s, lang)) for s in sentences] or [word_count]

    mean_len = statistics.mean(sent_lengths)
    std_len = statistics.pstdev(sent_lengths) if len(sent_lengths) >= 2 else 0.0
    sent_cv = std_len / max(1.0, mean_len)

    if len(sent_lengths) >= 2:
        deltas = [abs(sent_lengths[i] - sent_lengths[i - 1]) for i in range(1, len(sent_lengths))]
        adj_delta_ratio = statistics.mean(deltas) / max(1.0, mean_len)
    else:
        adj_delta_ratio = 0.35

    unique = set(words)
    freq = Counter(words)
    root_ttr = len(unique) / math.sqrt(word_count)
    hapax_ratio = sum(1 for w, c in freq.items() if c == 1) / max(1, len(unique))

    bigrams = list(zip(words, words[1:]))
    bigram_rep = 1.0 - (len(set(bigrams)) / max(1, len(bigrams))) if bigrams else 0.0

    starters = [(_tokenize(s, lang)[0] if _tokenize(s, lang) else "") for s in sentences]
    starter_uniformity = 1.0 - (len(set(starters)) / max(1, len(starters))) if len(starters) >= 2 else 0.0

    norm = _norm_ar(text) if lang == "ar" else text.lower()
    markers = AI_DISCOURSE_AR if lang == "ar" else AI_DISCOURSE_EN
    marker_hits = sum(1 for m in markers if (_norm_ar(m) if lang == "ar" else m) in norm)
    discourse_rate = (marker_hits / word_count) * 100.0

    voice_cues = PERSONAL_VOICE_AR if lang == "ar" else PERSONAL_VOICE_EN
    voice_hits = sum(norm.count(v) for v in voice_cues) + len(re.findall(r"[!؟?—]", text))
    personal_voice_rate = (voice_hits / word_count) * 100.0

    punct_ent = _punctuation_entropy(text)

    ce_human = human_lm.cross_entropy(text)
    ce_ai = ai_lm.cross_entropy(text)
    lm_log_ratio = ce_human - ce_ai
    perplexity_proxy = min(9999.0, round(2.0 ** min(12.0, ce_ai), 2))

    return {
        "word_count": float(word_count),
        "sentence_count": float(len(sentences)),
        "sent_cv": round(sent_cv, 4),
        "adj_delta_ratio": round(adj_delta_ratio, 4),
        "root_ttr": round(root_ttr, 4),
        "hapax_ratio": round(hapax_ratio, 4),
        "bigram_rep": round(bigram_rep, 4),
        "starter_uniformity": round(starter_uniformity, 4),
        "discourse_rate": round(discourse_rate, 4),
        "personal_voice_rate": round(personal_voice_rate, 4),
        "punct_ent": round(punct_ent, 4),
        "ce_human": ce_human,
        "ce_ai": ce_ai,
        "lm_log_ratio": round(lm_log_ratio, 4),
        "perplexity_proxy": perplexity_proxy,
    }


FEATURE_KEYS = [
    "sent_cv",
    "adj_delta_ratio",
    "root_ttr",
    "hapax_ratio",
    "bigram_rep",
    "starter_uniformity",
    "discourse_rate",
    "personal_voice_rate",
    "punct_ent",
    "lm_log_ratio",
]


def _sigmoid(x: float) -> float:
    x = max(-25.0, min(25.0, x))
    return 1.0 / (1.0 + math.exp(-x))


def _fit_logistic(
    xs: list[list[float]],
    ys: list[int],
    *,
    lr: float = 0.25,
    l2: float = 0.08,
    epochs: int = 350,
) -> tuple[list[float], float]:
    dim = len(xs[0])
    weights = [0.0] * dim
    bias = 0.0
    n = max(1, len(xs))
    for _ in range(epochs):
        grad_w = [0.0] * dim
        grad_b = 0.0
        for row, y in zip(xs, ys):
            pred = _sigmoid(sum(w * v for w, v in zip(weights, row)) + bias)
            err = pred - y
            for j in range(dim):
                grad_w[j] += err * row[j]
            grad_b += err
        for j in range(dim):
            weights[j] -= lr * ((grad_w[j] / n) + l2 * weights[j])
        bias -= lr * (grad_b / n)
    return weights, bias


class _CalibratedLangModel:
    """Out-of-fold trained and Platt-calibrated stylometric classifier for one language."""

    def __init__(self, samples: list[tuple[str, int]], lang: Literal["ar", "en"]) -> None:
        self.lang = lang
        human_texts = [t for t, y in samples if y == 0]
        ai_texts = [t for t, y in samples if y == 1]

        # Build out-of-fold LM scores (leave-one-out) so LM doesn't memorize training docs
        raw_rows: list[list[float]] = []
        labels: list[int] = []
        for idx, (text, y) in enumerate(samples):
            h_sub = [t for j, (t, lbl) in enumerate(samples) if lbl == 0 and j != idx] or human_texts
            a_sub = [t for j, (t, lbl) in enumerate(samples) if lbl == 1 and j != idx] or ai_texts
            h_lm = _NgramLanguageModel(h_sub, lang)
            a_lm = _NgramLanguageModel(a_sub, lang)
            feats = extract_stylometric_features(text, lang, h_lm, a_lm)
            raw_rows.append([feats[k] for k in FEATURE_KEYS])
            labels.append(y)

        # Full training-split LM for inference on unseen inputs
        self.human_lm = _NgramLanguageModel(human_texts, lang)
        self.ai_lm = _NgramLanguageModel(ai_texts, lang)

        # Standardize features from training split only
        dim = len(FEATURE_KEYS)
        self.means = [statistics.mean(row[j] for row in raw_rows) for j in range(dim)]
        self.stds = [max(1e-4, statistics.pstdev(row[j] for row in raw_rows)) for j in range(dim)]
        scaled = [
            [(row[j] - self.means[j]) / self.stds[j] for j in range(dim)]
            for row in raw_rows
        ]

        # Fit final logistic weights on training split with L2 regularization
        self.weights, self.bias = _fit_logistic(scaled, labels, l2=0.22)

        # Out-of-fold logits for honest label-smoothed Platt calibration
        # Label smoothing (0.08 / 0.92) reflects genuine epistemic uncertainty in stylometry
        oof_logits: list[float] = []
        for idx in range(len(scaled)):
            tr_x = [row for j, row in enumerate(scaled) if j != idx]
            tr_y = [lbl for j, lbl in enumerate(labels) if j != idx]
            w_sub, b_sub = _fit_logistic(tr_x, tr_y, l2=0.22, epochs=220)
            logit = sum(w * v for w, v in zip(w_sub, scaled[idx])) + b_sub
            oof_logits.append(logit)

        platt_x = [[lg] for lg in oof_logits]
        smoothed_y = [0.92 if lbl == 1 else 0.08 for lbl in labels]
        pa, pb = _fit_logistic(platt_x, smoothed_y, lr=0.12, l2=0.25, epochs=250)  # type: ignore[arg-type]
        self.platt_a = max(0.35, min(0.95, pa[0]))
        self.platt_b = pb

        # Record out-of-fold calibration Brier score
        oof_probs = [_sigmoid(self.platt_a * lg + self.platt_b) for lg in oof_logits]
        self.oof_brier = round(
            sum((p - y) ** 2 for p, y in zip(oof_probs, labels)) / max(1, len(labels)),
            4,
        )

    def predict(self, text: str) -> tuple[float, dict[str, float]]:
        feats = extract_stylometric_features(text, self.lang, self.human_lm, self.ai_lm)
        vec = [(feats[k] - self.means[j]) / self.stds[j] for j, k in enumerate(FEATURE_KEYS)]
        raw_logit = sum(w * v for w, v in zip(self.weights, vec)) + self.bias
        prob = _sigmoid(self.platt_a * raw_logit + self.platt_b)
        return prob, feats


@lru_cache(maxsize=1)
def _get_models() -> dict[str, _CalibratedLangModel]:
    return {
        "ar": _CalibratedLangModel(TRAIN_AR, "ar"),
        "en": _CalibratedLangModel(TRAIN_EN, "en"),
    }


def analyze_ai_vs_human(text: str) -> dict[str, Any]:
    """Run scientifically honest, language-specific AI-vs-Human stylometric analysis."""
    scan_ts = utc_now_iso()
    raw = (text or "").strip()[:15000]
    lang = detect_text_language(raw)
    model = _get_models()[lang]
    prob_ai, feats = model.predict(raw)
    word_count = int(feats["word_count"])
    sentence_count = int(feats["sentence_count"])

    evidence: list[EvidenceItem] = []
    conflicts: list[SourceConflict] = []
    limitations: list[dict[str, str]] = [
        make_limitation(
            "probabilistic_stylometry_limit",
            "لا توجد أي طريقة علمية مضمونة لمعرفة الكاتب الحقيقي من النص وحده؛ النتيجة مؤشر احتمالي فقط وليست دليلاً قاطعاً، وقد تتأثر النصوص المحررة بشرياً أو المترجمة.",
            "No text-only method can reliably prove authorship; results are probabilistic indicators only and cannot distinguish polished human writing from human-edited AI with certainty.",
        ),
        make_limitation(
            "ngram_perplexity_proxy",
            "مقياس الانتروبيا والحيرة المعروض هو تقريب إحصائي لنماذج n-gram المحلية وليس حيرة نموذج لغوي عصبي ضخم.",
            "Reported cross-entropy / perplexity proxy is computed via local smoothed n-gram models rather than a neural LLM.",
        ),
    ]

    # Build transparent linguistic evidence items
    if feats["discourse_rate"] >= 2.2:
        evidence.append(
            make_evidence(
                evidence_id="formulaic_discourse_markers",
                category="discourse_markers",
                severity="medium",
                title_ar="كثافة مرتفعة في الروابط الانتقالية النمطية",
                title_en="Elevated density of formulaic discourse transitions",
                detail_ar=f"معدل الروابط النمطية: {round(feats['discourse_rate'], 2)} لكل 100 كلمة.",
                detail_en=f"Formulaic connector density: {round(feats['discourse_rate'], 2)} per 100 words.",
                source=f"calibrated_stylometry_{lang}",
                observed_value=f"{round(feats['discourse_rate'], 2)}/100w",
                timestamp=scan_ts,
            )
        )

    if sentence_count >= 3 and feats["sent_cv"] < 0.24:
        evidence.append(
            make_evidence(
                evidence_id="uniform_burstiness",
                category="burstiness",
                severity="medium",
                title_ar="تجانس إيقاعي مرتفع في أطوال الجمل (انخفاض Burstiness)",
                title_en="Low sentence-length burstiness (uniform cadence)",
                detail_ar=f"معامل التباين CV={round(feats['sent_cv'], 2)} | تغيّر الجمل المتجاورة={round(feats['adj_delta_ratio'], 2)}.",
                detail_en=f"Sentence length CV={round(feats['sent_cv'], 2)} | Adjacent shift={round(feats['adj_delta_ratio'], 2)}.",
                source=f"calibrated_stylometry_{lang}",
                observed_value=f"CV={round(feats['sent_cv'], 2)}",
                timestamp=scan_ts,
            )
        )
    elif sentence_count >= 3 and (feats["sent_cv"] >= 0.42 or feats["adj_delta_ratio"] >= 0.45):
        evidence.append(
            make_evidence(
                evidence_id="human_burstiness",
                category="burstiness",
                severity="safe",
                title_ar="تنوع إيقاعي واضح وتفاوت طبيعي بين أطوال الجمل (Burstiness)",
                title_en="Natural sentence-length burstiness and cadence shifts",
                detail_ar=f"معامل التباين CV={round(feats['sent_cv'], 2)} | تغيّر الجمل المتجاورة={round(feats['adj_delta_ratio'], 2)}.",
                detail_en=f"Sentence length CV={round(feats['sent_cv'], 2)} | Adjacent shift={round(feats['adj_delta_ratio'], 2)}.",
                source=f"calibrated_stylometry_{lang}",
                observed_value=f"CV={round(feats['sent_cv'], 2)}",
                timestamp=scan_ts,
            )
        )

    if feats["personal_voice_rate"] >= 1.5 or feats["punct_ent"] >= 1.35:
        evidence.append(
            make_evidence(
                evidence_id="human_voice_syntax",
                category="syntactic_diversity",
                severity="safe",
                title_ar="مؤشرات صوت شخصي وتنوع علامات الترقيم والاستفهام",
                title_en="Experiential voice cues and diverse syntactic punctuation",
                detail_ar=f"انتروبيا الترقيم={round(feats['punct_ent'], 2)} | مؤشرات الأسلوب الشخصي={round(feats['personal_voice_rate'], 2)}/100w.",
                detail_en=f"Punctuation entropy={round(feats['punct_ent'], 2)} | Personal voice rate={round(feats['personal_voice_rate'], 2)}/100w.",
                source=f"calibrated_stylometry_{lang}",
                observed_value=f"H={round(feats['punct_ent'], 2)}",
                timestamp=scan_ts,
            )
        )

    if feats["lm_log_ratio"] >= 0.12:
        evidence.append(
            make_evidence(
                evidence_id="ngram_ai_alignment",
                category="perplexity_proxy",
                severity="medium",
                title_ar="انخفاض حيرة النص مقارنة بنموذج الأسلوب التوليدي",
                title_en="Lower n-gram cross-entropy under baseline AI language model",
                detail_ar=f"فرق الانتروبيا (Human - AI) = {round(feats['lm_log_ratio'], 3)} bits/token.",
                detail_en=f"Cross-entropy differential (Human - AI) = {round(feats['lm_log_ratio'], 3)} bits/token.",
                source=f"ngram_lm_{lang}",
                observed_value=str(round(feats["lm_log_ratio"], 3)),
                timestamp=scan_ts,
            )
        )

    # Detect hybrid / conflicting human+AI cues (e.g. formulaic AI phrases mixed with strong human burstiness/voice)
    has_ai_cues = feats["discourse_rate"] >= 2.2 or feats["lm_log_ratio"] >= 0.15
    has_human_cues = feats["personal_voice_rate"] >= 1.5 or feats["sent_cv"] >= 0.45
    if has_ai_cues and has_human_cues:
        conflicts.append(
            {
                "topic_ar": "تعارض بين مؤشرات التوليد الآلي والأسلوب البشري (قد يكون نصاً هجيناً أو محرراً)",
                "topic_en": "Conflicting AI and human stylistic cues (possible hybrid or edited text)",
                "source_a": "discourse_&_ngram_features",
                "result_a": "ai_aligned_cues",
                "source_b": "burstiness_&_voice_features",
                "result_b": "human_variability_cues",
            }
        )

    # Strict length & uncertainty gates
    too_short = word_count < 35
    if too_short:
        limitations.insert(
            0,
            make_limitation(
                "text_too_short",
                f"النص قصير جداً ({word_count} كلمة؛ الحد الأدنى للمعايرة الموثوقة 35 كلمة).",
                f"Text is too short ({word_count} words; minimum 35 words required for calibrated scoring).",
            ),
        )
        classification: AiTextClassification = "inconclusive"
        headline_ar = "Inconclusive – لا يمكن تحديد مصدر النص بثقة."
        headline_en = "Inconclusive – Cannot determine text origin with confidence."
        calibrated = False
        calibrated_prob: float | None = None
        risk_level = "low"
    elif 0.35 <= prob_ai <= 0.65 or (conflicts and 0.25 <= prob_ai <= 0.78):
        classification = "inconclusive"
        headline_ar = "Inconclusive – لا يمكن تحديد مصدر النص بثقة."
        headline_en = "Inconclusive – Cannot determine text origin with confidence."
        calibrated = True
        calibrated_prob = round(prob_ai, 4)
        risk_level = "medium"
        limitations.insert(
            0,
            make_limitation(
                "uncertainty_band",
                "وقعت النتيجة في النطاق الحرج غير الحاسم أو رُصد تداخل بين سمات بشرية وآلية.",
                "Calibrated probability lies inside the uncertain band or shows mixed human/AI signals.",
            ),
        )
    elif prob_ai > 0.65:
        classification = "ai_leaning"
        headline_ar = "مؤشر احتمالي: يرجّح تشابهاً مع الأنماط المُولّدة آلياً (ليس دليلاً قاطعاً)"
        headline_en = "Probabilistic Indicator: Leans toward AI-generated patterns (not definitive proof)"
        calibrated = True
        calibrated_prob = round(prob_ai, 4)
        risk_level = "high" if prob_ai >= 0.78 else "medium"
    else:
        classification = "human_leaning"
        headline_ar = "مؤشر احتمالي: يرجّح اتساقاً مع التنوع الأسلوبي البشري (ليس دليلاً قاطعاً)"
        headline_en = "Probabilistic Indicator: Consistent with human stylistic variability (not definitive proof)"
        calibrated = True
        calibrated_prob = round(prob_ai, 4)
        risk_level = "minimal"

    bundle = build_evidence_bundle(
        evidence=evidence,
        risk_level=risk_level,  # type: ignore[arg-type]
        conflicts=conflicts,
        limitations=limitations,
        has_authoritative_hit=False,
        data_sufficient=not too_short,
        calibrated=calibrated,
        calibrated_probability=calibrated_prob,
        scan_timestamp=scan_ts,
    )

    return {
        "language": lang,
        "word_count": word_count,
        "sentence_count": sentence_count,
        "classification": classification,
        "headline_ar": headline_ar,
        "headline_en": headline_en,
        "is_probabilistic_only": True,
        "calibrated_ai_probability": calibrated_prob,
        "model_oof_brier": model.oof_brier,
        "metrics": {
            "perplexity_proxy": feats["perplexity_proxy"],
            "cross_entropy_human_bits": feats["ce_human"],
            "cross_entropy_ai_bits": feats["ce_ai"],
            "lm_log_ratio": feats["lm_log_ratio"],
            "burstiness_cv": feats["sent_cv"],
            "adjacent_sentence_shift": feats["adj_delta_ratio"],
            "root_ttr": feats["root_ttr"],
            "hapax_ratio": feats["hapax_ratio"],
            "bigram_repetition": feats["bigram_rep"],
            "starter_uniformity": feats["starter_uniformity"],
            "discourse_marker_rate": feats["discourse_rate"],
            "punctuation_entropy": feats["punct_ent"],
        },
        "evidence_bundle": bundle,
        "scan_timestamp": scan_ts,
    }
