"""Interactive Phishing IQ Lab powered by the Kashf Python analyzer."""

from __future__ import annotations

from typing import Any, TypedDict

from analyzer import analyze_message


class QuizScenario(TypedDict):
    id: str
    channel: str
    sender: str
    text_ar: str
    text_en: str
    is_scam: bool
    explanation_ar: str
    explanation_en: str


SCENARIOS: list[QuizScenario] = [
    {
        "id": "rafidain-otp",
        "channel": "SMS",
        "sender": "Rafidain-Alert",
        "text_ar": "تنبيه عاجل من مصرف الرافدين: سيتم إيقاف بطاقتك خلال 24 ساعة. حدث بيانات البطاقة وأرسل رمز التحقق فوراً عبر http://rafidain-verify.xyz/auth",
        "text_en": "Rafidain Bank Urgent Alert: Your card will be suspended within 24 hours. Update card details and submit your OTP at http://rafidain-verify.xyz/auth",
        "is_scam": True,
        "explanation_ar": "انتحال واضح لمصرف الرافدين: النطاق ينتهي بـ .xyz غير الرسمي، ويستخدم التهديد بالإيقاف خلال 24 ساعة مع طلب رمز التحقق.",
        "explanation_en": "Impersonates Rafidain Bank on an unofficial .xyz domain, uses 24-hour suspension pressure, and asks for your OTP.",
    },
    {
        "id": "official-zaincash-receipt",
        "channel": "SMS",
        "sender": "ZainCash",
        "text_ar": "تم استلام حوالة بمبلغ 25,000 د.ع بنجاح في محفظتك. يمكنك مراجعة سجل العمليات من تطبيق زين كاش الرسمي أو عبر https://zaincash.iq",
        "text_en": "You received 25,000 IQD in your wallet. Review your transaction history inside the official ZainCash app or at https://zaincash.iq",
        "is_scam": False,
        "explanation_ar": "رسالة إشعار طبيعية: تشير إلى النطاق الرسمي الحقيقي (zaincash.iq) ولا تطلب أي رمز سري أو دفع رسوم أو ضغط عاجل.",
        "explanation_en": "Legitimate notification: uses the authentic official domain (zaincash.iq) and makes no urgent threats or OTP requests.",
    },
    {
        "id": "parcel-customs",
        "channel": "WhatsApp",
        "sender": "+964 770 *** 991",
        "text_ar": "البريد العراقي: تعذر تسليم شحنتك لوجود رسوم جمركية بسيطة (2000 د.ع). ادفع الآن عبر bit.ly/3x9demo لتفادي إرجاع الطرد.",
        "text_en": "Iraqi Post: Delivery failed due to a small customs fee ($2). Pay immediately at bit.ly/3x9demo to avoid parcel return.",
        "is_scam": True,
        "explanation_ar": "حيلة شائعة جداً: استخدام رابط مختصر (bit.ly) لإخفاء الموقع الحقيقي وطلب رسوم رمزية لسرقة معلومات بطاقتك المصرفية.",
        "explanation_en": "Classic parcel scam: hides the destination behind a bit.ly shortener and asks for a tiny fee to harvest payment card details.",
    },
    {
        "id": "lookalike-paypal",
        "channel": "Email",
        "sender": "security@paypa1-support.com",
        "text_ar": "مبروك! ربحت 5000$ في السحب العشوائي! اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل كلمة المرور ورمز التحقق.",
        "text_en": "Congratulations! You won $5,000 in our lucky draw! Click within 24 hours http://paypa1-secure.xyz/login and confirm your password and OTP.",
        "is_scam": True,
        "explanation_ar": "تلاعب بصري في اسم النطاق (استبدال حرف l برقم 1 في paypa1)، مع إغراء بجائزة مالية وطلب كلمة المرور وOTP.",
        "explanation_en": "Typosquatting replaces 'l' with '1' in paypa1, combines an unsolicited cash prize lure, and asks for your password and OTP.",
    },
    {
        "id": "team-meeting-safe",
        "channel": "WhatsApp",
        "sender": "زميل العمل",
        "text_ar": "السلام عليكم، اجتماع الفريق الساعة 11 صباحاً لمراجعة التقرير الشهري في القاعة الرئيسية. يرجى إحضار الملاحظات.",
        "text_en": "Hi team, our monthly report review meeting is at 11:00 AM in the main room. Please bring your notes.",
        "is_scam": False,
        "explanation_ar": "رسالة عمل اعتيادية خالية تماماً من الروابط المشبوهة أو الطلبات المالية أو الاستعجال التهديدي.",
        "explanation_en": "Normal workplace message with zero suspicious links, credential requests, or artificial urgency.",
    },
    {
        "id": "guaranteed-crypto",
        "channel": "Telegram",
        "sender": "VIP Trading Bot",
        "text_ar": "فرصة استثمارية حصرية: ربح يومي مضمون 400$! حول مبلغ 100$ الآن أو أرسل بطاقة هدايا عبر https://quick-profit.click لتفعيل الحساب.",
        "text_en": "Exclusive investment: guaranteed daily profit of $400! Send $100 via wire transfer or gift card at https://quick-profit.click to activate.",
        "is_scam": True,
        "explanation_ar": "احتيال استثماري واضح: الوعود بأرباح يومية مضمونة وطلب تحويل أموال أو بطاقات هدايا عبر نطاق .click غير موثوق.",
        "explanation_en": "Investment fraud: promises guaranteed daily profits and demands wire transfers or gift cards on a high-risk .click domain.",
    },
]


def get_quiz_scenarios() -> list[dict[str, Any]]:
    """Return scenarios without exposing answers to the client."""
    return [
        {
            "id": item["id"],
            "channel": item["channel"],
            "sender": item["sender"],
            "text_ar": item["text_ar"],
            "text_en": item["text_en"],
        }
        for item in SCENARIOS
    ]


def verify_quiz_answer(scenario_id: str, user_says_scam: bool, lang: str = "ar") -> dict[str, Any]:
    """Grade user answer and attach Python analyzer forensic proof."""
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if scenario is None:
        raise ValueError("Unknown scenario id")

    sample_text = scenario["text_en"] if lang == "en" else scenario["text_ar"]
    analysis = analyze_message(sample_text)
    is_scam = scenario["is_scam"]
    correct = bool(user_says_scam) == is_scam

    return {
        "id": scenario["id"],
        "correct": correct,
        "is_scam": is_scam,
        "explanation_ar": scenario["explanation_ar"],
        "explanation_en": scenario["explanation_en"],
        "analysis": analysis,
    }
