import type { Language, ScamCategory, Verdict } from './types';

export interface LearnItem {
  id: string;
  question: string;
  answer: string;
}

export interface ExamplePreset {
  id: string;
  label: string;
  text: string;
}

export interface TranslationBundle {
  brandAr: string;
  brandEn: string;
  nav: {
    analyzer: string;
    dashboard: string;
    trending: string;
    quiz: string;
    learn: string;
    langToggle: string;
    langToggleAria: string;
    menuOpenAria: string;
    menuCloseAria: string;
  };
  hero: {
    blurredLine1: string;
    blurredLine2: string;
    typewriterText: string;
    analyzePill: string;
    reachUsPrefix: string;
    reachUsEmail: string;
    copiedLabel: string;
    headline: string;
    subtitle: string;
    tabs: {
      single: string;
      batch: string;
      urlInspector: string;
      sandbox: string;
      academic: string;
      dlp: string;
      history: string;
    };
    messageLabel: string;
    placeholder: string;
    urlLabel: string;
    urlPlaceholder: string;
    detectedUrlsLabel: string;
    analyzeButton: string;
    analyzingButton: string;
    clearButton: string;
    privacyNote: string;
    emptyError: string;
    truncatedWarning: string;
    networkError: string;
    rateLimitError: string;
    retryButton: string;
    examples: ExamplePreset[];
  };
  result: {
    riskScoreLabel: string;
    outOfHundred: string;
    categoryLabel: string;
    verdicts: Record<Verdict, string>;
    verdictSummaries: Record<Verdict, string>;
    whyTitle: string;
    noReasonsText: string;
    highlightedCopyTitle: string;
    pointsSuffix: string;
    whatToDoTitle: string;
    steps: Record<Verdict, [string, string, string]>;
    shareButton: string;
    sharingButton: string;
    copyWarningButton: string;
    copiedWarningButton: string;
    exportJsonButton: string;
    reportButton: string;
    reportingButton: string;
    reportedButton: string;
    reportError: string;
    shareFooter: string;
    forensicsTitle: string;
    defangedLabel: string;
    copyDefanged: string;
    copiedDefanged: string;
    sanitizedLabel: string;
    entropyLabel: string;
    brandMatchLabel: string;
    officialDomainLabel: string;
    impersonationLabel: string;
    liveProbeButton: string;
    liveProbingButton: string;
    dnsLabel: string;
    tlsLabel: string;
    redirectsLabel: string;
    finalUrlLabel: string;
    openSandboxButton: string;
    urlClassifications: Record<'malicious' | 'suspicious' | 'no_known_threat' | 'unknown', string>;
    noKnownThreatNote: string;
    threatIntelTitle: string;
    threatStatusLabels: Record<'hit' | 'clean' | 'not_configured' | 'unavailable' | 'error', string>;
    rdapLabel: string;
    dnsRecordsLabel: string;
    technicalDetailsTitle: string;
    suspiciousSegmentsTitle: string;
    linksVerifyTitle: string;
    scriptsLabel: string;
  };
  batch: {
    title: string;
    subtitle: string;
    placeholder: string;
    uploadTxtButton: string;
    sampleButton: string;
    scanButton: string;
    scanningButton: string;
    emptyError: string;
    totalLabel: string;
    dangerousLabel: string;
    suspiciousLabel: string;
    safeLabel: string;
    inspectSingleButton: string;
  };
  urlLab: {
    title: string;
    subtitle: string;
    inputLabel: string;
    placeholder: string;
    inspectButton: string;
    inspectingButton: string;
    emptyError: string;
  };
  urlSandbox: {
    title: string;
    subtitle: string;
    isolationNotice: string;
    inputLabel: string;
    placeholder: string;
    runButton: string;
    runningButton: string;
    emptyError: string;
    presetPhishLabel: string;
    presetApkLabel: string;
    presetSafeLabel: string;
    modeLabels: {
      live_captured: string;
      simulated_offline: string;
      blocked_ssrf: string;
      blocked_unsafe_scheme: string;
    };
    whatTitle: string;
    observedTag: string;
    predictedTag: string;
    previewTitle: string;
    previewSubtitle: string;
    previewEmptyText: string;
    previewTrapWarning: string;
    telemetryTitle: string;
    httpStatusLabel: string;
    contentTypeLabel: string;
    formsLabel: string;
    scriptsLabel: string;
    iframesLabel: string;
    cookiesLabel: string;
    redirectsTitle: string;
    guaranteesLabel: string;
  };
  history: {
    title: string;
    subtitle: string;
    clearAll: string;
    emptyTitle: string;
    emptyBody: string;
    reopenButton: string;
  };
  quiz: {
    title: string;
    subtitle: string;
    scoreLabel: string;
    progressLabel: string;
    scamButton: string;
    safeButton: string;
    correctBadge: string;
    wrongBadge: string;
    nextButton: string;
    restartButton: string;
    completedTitle: string;
    completedBody: string;
    pythonProofLabel: string;
    badgesTitle: string;
    streakLabel: string;
    badges: Array<{
      id: 'first_catch' | 'streak_three' | 'cyber_defender' | 'perfect_shield';
      title: string;
      requirement: string;
    }>;
  };
  academic: {
    title: string;
    subtitle: string;
    textLabel: string;
    textPlaceholder: string;
    refLabel: string;
    refPlaceholder: string;
    analyzeButton: string;
    analyzingButton: string;
    emptyError: string;
    sampleHumanLabel: string;
    sampleAiLabel: string;
    samplePlagiarismLabel: string;
    telemetryLabel: string;
    keystrokesLabel: string;
    pastedLabel: string;
    cadenceLabel: string;
    originalityLabel: string;
    aiProbLabel: string;
    plagiarismLabel: string;
    richnessLabel: string;
    burstinessLabel: string;
    behaviorLabel: string;
    verdicts: {
      authentic: string;
      review_needed: string;
      flagged: string;
    };
    behaviorStatuses: {
      not_captured: string;
      human_verified: string;
      robotic_cadence: string;
      bulk_pasted: string;
      mixed_input: string;
    };
    signalsTitle: string;
    plagiarismMatchesTitle: string;
    aiPhrasesTitle: string;
    certEligibleTitle: string;
    certEligibleSubtitle: string;
    certTitleLabel: string;
    certTitlePlaceholder: string;
    certAuthorLabel: string;
    certAuthorPlaceholder: string;
    certInstitutionLabel: string;
    certInstitutionPlaceholder: string;
    issueCertButton: string;
    issuingCertButton: string;
    certFormError: string;
    certIssuedTitle: string;
    certIdLabel: string;
    blockIndexLabel: string;
    docHashLabel: string;
    blockHashLabel: string;
    prevHashLabel: string;
    copyCertIdButton: string;
    copiedCertIdButton: string;
  };
  dlp: {
    title: string;
    subtitle: string;
    textLabel: string;
    textPlaceholder: string;
    uploadFileButton: string;
    sampleLeakButton: string;
    scanButton: string;
    scanningButton: string;
    emptyError: string;
    riskLabel: string;
    findingsTitle: string;
    noSecretsText: string;
    urlsTitle: string;
    cyberReasonsTitle: string;
  };
  dashboard: {
    title: string;
    subtitle: string;
    refreshButton: string;
    kpiCertificates: string;
    kpiOriginality: string;
    kpiReports: string;
    kpiChainStatus: string;
    chainValid: string;
    chainInvalid: string;
    verifierTitle: string;
    verifierPlaceholder: string;
    verifyButton: string;
    verifyingButton: string;
    verifyFoundValid: string;
    verifyFoundTampered: string;
    verifyNotFound: string;
    ledgerTitle: string;
    ledgerEmpty: string;
    colCertId: string;
    colResearch: string;
    colAuthor: string;
    colOriginality: string;
    colHash: string;
    roadmapTitle: string;
    roadmapSubtitle: string;
    roadmapStages: Array<{
      id: 'academic' | 'dlp' | 'ledger' | 'sandbox' | 'saas';
      stage: string;
      title: string;
      summary: string;
      status: string;
      actionLabel: string;
    }>;
    sandbox: {
      title: string;
      subtitle: string;
      deptLabel: string;
      deptPlaceholder: string;
      loadLabel: string;
      runButton: string;
      runningButton: string;
      exportJsonButton: string;
      totalOpsLabel: string;
      avgLatencyLabel: string;
      throughputLabel: string;
      detectionsLabel: string;
      slaOptimal: string;
      slaAcceptable: string;
      historyTitle: string;
      historyEmpty: string;
      presets: string[];
    };
    saas: {
      title: string;
      subtitle: string;
      uniLabel: string;
      uniPlaceholder: string;
      studentsLabel: string;
      facultyLabel: string;
      planLabel: string;
      plans: Record<'starter' | 'campus' | 'national', string>;
      presets: Array<{ name: string; students: number; faculty: number }>;
      previewTitle: string;
      localCostLabel: string;
      foreignCostLabel: string;
      savingsLabel: string;
      savingsIqdLabel: string;
      registerButton: string;
      registeringButton: string;
      formError: string;
      tenantsTitle: string;
      tenantsEmpty: string;
      colCode: string;
      colUniversity: string;
      colUsers: string;
      colPlan: string;
      colKey: string;
      colSavings: string;
      removeButton: string;
    };
  };
  categories: Record<ScamCategory, string>;
  trending: {
    title: string;
    subtitle: string;
    last7Days: string;
    reportsUnit: string;
    avgScoreLabel: string;
    totalReportsStat: string;
    avgRiskStat: string;
    topCategoryStat: string;
    emptyTitle: string;
    emptyBody: string;
    errorText: string;
    retryButton: string;
  };
  learn: {
    title: string;
    subtitle: string;
    items: LearnItem[];
  };
  footer: {
    disclaimer: string;
    privacyReminder: string;
  };
}

export const i18n: Record<Language, TranslationBundle> = {
  ar: {
    brandAr: 'كشف',
    brandEn: 'Kashf',
    nav: {
      analyzer: 'الفاحص',
      dashboard: 'لوحة حصانة',
      trending: 'الاحتيالات',
      quiz: 'اختبر وعيك',
      learn: 'تعلّم',
      langToggle: 'English',
      langToggleAria: 'Switch language to English',
      menuOpenAria: 'فتح القائمة',
      menuCloseAria: 'إغلاق القائمة',
    },
    hero: {
      blurredLine1: 'أهلاً بك في كشف،',
      blurredLine2: 'محلّل الرسائل والروابط المشبوهة محلياً بالبايثون',
      typewriterText: 'هل وصلتك رسالة مشبوهة؟ الصقها هنا ونكشفها لك فوراً.',
      analyzePill: 'ابدأ الفحص الآن',
      reachUsPrefix: 'تواصل معنا:',
      reachUsEmail: 'hello@kashf.iq',
      copiedLabel: 'تم النسخ',
      headline: 'منصة الفحص الأمني بالبايثون',
      subtitle: 'تحليل فوري للرسائل النصية، فحص دفعات الواتساب، وتشريح الروابط تقنياً (DNS / SSL) دون حفظ نص رسالتك.',
      tabs: {
        single: 'فحص رسالة',
        batch: 'فحص متعدد',
        urlInspector: 'تشريح رابط',
        sandbox: 'Sandbox الآمن',
        academic: 'حصانة الأكاديمية',
        dlp: 'فحص التسريب والملفات',
        history: 'السجل المحلي',
      },
      messageLabel: 'نص الرسالة المشبوهة',
      placeholder:
        'مثال: مبروك! ربحت 5000$، اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل رمز التحقق',
      urlLabel: 'رابط مشبوه (اختياري — يُملأ تلقائياً عند اكتشاف رابط)',
      urlPlaceholder: 'https://example.com',
      detectedUrlsLabel: 'الروابط المكتشفة:',
      analyzeButton: 'افحص الآن',
      analyzingButton: 'جارِ الفحص...',
      clearButton: 'مسح',
      privacyNote: 'لا نحفظ نص رسالتك. نحفظ فقط بصمة مجهولة للإحصائيات.',
      emptyError: 'يرجى لصق نص الرسالة أو إدخال رابط لفحصه أولاً.',
      truncatedWarning: 'تم تقليص النص إلى 5000 حرف كحد أقصى للفحص.',
      networkError: 'تعذر الاتصال بخادم الفحص. تأكد من تشغيل الخادم ثم أعد المحاولة.',
      rateLimitError: 'تم إرسال طلبات كثيرة خلال دقيقة واحدة. انتظر قليلاً ثم أعد المحاولة.',
      retryButton: 'إعادة المحاولة',
      examples: [
        {
          id: 'bank',
          label: 'رسالة بنك',
          text: 'تنبيه من مصرف الرافدين: سيتم إيقاف حسابك خلال 24 ساعة. يرجى تحديث رقم البطاقة ورمز التحقق فوراً عبر http://rafidain-verify.xyz/update',
        },
        {
          id: 'prize',
          label: 'جائزة وهمية',
          text: 'مبروك! ربحت 5000$ في السحب العشوائي، اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل رمز التحقق',
        },
        {
          id: 'delivery',
          label: 'رابط توصيل',
          text: 'البريد العراقي: تعذر التسليم لوجود طردك في المستودع. ادفع رسوم جمركية بسيطة عبر bit.ly/3x9demo لتأكيد العنوان فوراً.',
        },
      ],
    },
    result: {
      riskScoreLabel: 'مؤشر الخطورة',
      outOfHundred: '/ 100',
      categoryLabel: 'التصنيف',
      verdicts: {
        safe: 'آمنة غالباً',
        suspicious: 'مشبوهة',
        dangerous: 'خطيرة',
      },
      verdictSummaries: {
        safe: 'لم نرصد علامات احتيال واضحة، لكن تذكّر التحقق دائماً قبل مشاركة أي معلومة شخصية.',
        suspicious: 'تحتوي الرسالة على مؤشرات مريبة تستدعي التريث والتحقق من المصدر الرسمي.',
        dangerous: 'تحمل الرسالة عدة علامات احتيال أو تصيّد إلكتروني واضحة. تجنّب التفاعل معها.',
      },
      whyTitle: 'لماذا؟',
      noReasonsText: 'لم يتم رصد قواعد احتيال أو روابط مخادعة في هذه الرسالة.',
      highlightedCopyTitle: 'نص الرسالة مع تمييز العبارات المرصودة',
      pointsSuffix: 'نقطة',
      whatToDoTitle: 'ماذا أفعل؟',
      steps: {
        safe: [
          'تأكد من معرفة هوية المرسل قبل الرد أو فتح أي مرفق غير متوقع.',
          'لا تشارك رموز التحقق (OTP) أو كلمات المرور مع أي شخص حتى لو بدا مألوفاً.',
          'عند الشك في جهة رسمية، تواصل معها عبر موقعها أو رقمها المعروف مباشرة.',
        ],
        suspicious: [
          'لا تضغط على الرابط المرفق ولا تدخل أي بيانات شخصية أو مصرفية.',
          'تحقق من الرسالة بالاتصال بالجهة المعنية عبر رقم خدمة العملاء الرسمي.',
          'احذف الرسالة أو احظر المرسل إذا لم تكن تنتظر تواصلاً من هذا المصدر.',
        ],
        dangerous: [
          'لا تنقر على الرابط أبداً ولا ترسل رموز التحقق (OTP) أو بيانات البطاقة.',
          'احظر رقم المرسل وأبلغ عن الرسالة داخل تطبيق واتساب أو الرسائل.',
          'إذا كنت قد أدخلت بياناتك بالفعل، تواصل مع مصرفك فوراً لتجميد البطاقة وتغيير كلمة المرور.',
        ],
      },
      shareButton: 'بطاقة صورة PNG',
      sharingButton: 'جارِ التجهيز...',
      copyWarningButton: 'نسخ تحذير للعائلة',
      copiedWarningButton: 'تم نسخ التحذير',
      exportJsonButton: 'تصدير JSON',
      reportButton: 'بلّغ عن هذه الرسالة',
      reportingButton: 'جارِ الإبلاغ...',
      reportedButton: 'تم التبليغ بنجاح',
      reportError: 'تعذر إرسال البلاغ حالياً. حاول مرة أخرى.',
      shareFooter: 'النتيجة تقديرية ولا تغني عن الحذر.',
      forensicsTitle: 'التحليل الجنائي للروابط (Python URL X-Ray)',
      defangedLabel: 'رابط معطّل بأمان (Defanged)',
      copyDefanged: 'نسخ بأمان',
      copiedDefanged: 'تم النسخ',
      sanitizedLabel: 'الرابط بعد إزالة التتبع',
      entropyLabel: 'عشوائية النطاق (Entropy)',
      brandMatchLabel: 'العلامة المرتبطة',
      officialDomainLabel: 'نطاق رسمي موثق',
      impersonationLabel: 'اشتباه انتحال علامة',
      liveProbeButton: 'فحص حي بالبايثون (Threat Intel + RDAP + DNS + SSL)',
      liveProbingButton: 'جارِ الفحص الشبكي...',
      dnsLabel: 'سجل DNS / IP',
      tlsLabel: 'شهادة SSL / TLS',
      redirectsLabel: 'سلسلة إعادة التوجيه',
      finalUrlLabel: 'الوجهة النهائية',
      openSandboxButton: 'اختبار الرابط في Sandbox الآمن',
      urlClassifications: {
        malicious: 'خبيث (Malicious)',
        suspicious: 'مشبوه (Suspicious)',
        no_known_threat: 'لا يوجد تهديد معروف (No Known Threat ≠ آمن 100%)',
        unknown: 'غير معروف / بيانات غير كافية (Unknown)',
      },
      noKnownThreatNote: 'عدم وجود تطابق في القوائم المفحوصة لا يثبت أمان الرابط تماماً؛ التزم الحذر وتحقق من السياق.',
      threatIntelTitle: 'مصادر استخبارات التهديدات (Threat Intelligence Sources)',
      threatStatusLabels: {
        hit: 'تم رصد تهديد',
        clean: 'غير مدرج بالقائمة',
        not_configured: 'غير مُهيّأ (بدون مفتاح)',
        unavailable: 'غير متاح مؤقتاً',
        error: 'خطأ في الاستعلام',
      },
      rdapLabel: 'عمر النطاق (RDAP)',
      dnsRecordsLabel: 'سجلات DNS (A / MX / TXT)',
      technicalDetailsTitle: 'التفاصيل التقنية العميقة (DNS · RDAP · TLS · Unicode)',
      suspiciousSegmentsTitle: 'الجمل والمقاطع المشبوهة المستخرجة',
      linksVerifyTitle: 'روابط تتطلب فحصاً منفصلاً في قواعد التهديدات',
      scriptsLabel: 'أبجديات النطاق (Unicode Scripts)',
    },
    batch: {
      title: 'فحص الدفعات وسجلات الدردشة',
      subtitle: 'الصق عدة رسائل (افصل بينها بسطر فارغ) أو ارفع ملف محادثة (.txt) ليقوم محرك البايثون بترتيبها حسب الخطورة.',
      placeholder:
        'تنبيه من مصرف الرافدين: سيتم إيقاف حسابك عبر http://rafidain-verify.xyz\n\nمرحباً، هل الاجتماع غداً الساعة 10؟\n\nمبروك ربحت 5000$ عبر bit.ly/3x9demo أرسل رمز التحقق',
      uploadTxtButton: 'رفع ملف نصي (.txt)',
      sampleButton: 'تعبئة نماذج تجربة',
      scanButton: 'فحص الكل بالبايثون',
      scanningButton: 'جارِ فحص الدفعة...',
      emptyError: 'يرجى لصق رسالتين أو رسالة واحدة على الأقل للفحص.',
      totalLabel: 'إجمالي الرسائل',
      dangerousLabel: 'خطيرة',
      suspiciousLabel: 'مشبوهة',
      safeLabel: 'آمنة',
      inspectSingleButton: 'عرض التفاصيل',
    },
    urlLab: {
      title: 'مشرحة الروابط الحية (Python Live Inspector)',
      subtitle: 'افحص أي رابط مشبوه أو مختصر دون فتحه: كشف الانتحال، فحص DNS وشهادة SSL، وتتبع الوجهة الحقيقية للروابط المختصرة.',
      inputLabel: 'أدخل الرابط المراد تشريحه',
      placeholder: 'https://bit.ly/3x9demo أو http://paypa1-secure.xyz/login?utm_source=sms',
      inspectButton: 'تشريح وفحص حي',
      inspectingButton: 'جارِ التشريح الشبكي...',
      emptyError: 'يرجى إدخال رابط صالح للفحص.',
    },
    urlSandbox: {
      title: 'صندوق الرمل الآمن لاختبار الروابط المشبوهة (Safe URL Sandbox)',
      subtitle:
        'جرّب أي رابط مشبوه أو مختصر داخل بيئة بايثون معزولة تماماً لتشاهد ماذا سيفعل الرابط لو قمت بفتحه، دون أي خطر على جهازك أو حساباتك.',
      isolationNotice:
        'بيئة معزولة 100%: تنفيذ JavaScript معطل · صفر كوكيز · صفر تنزيلات على القرص · حظر الشبكة الداخلية (SSRF)',
      inputLabel: 'أدخل الرابط المشبوه لتجربته بأمان',
      placeholder: 'http://paypa1-secure.xyz/login?otp=required أو https://example.com',
      runButton: 'تشغيل الرابط داخل Sandbox الآمن',
      runningButton: 'جارِ العزل والتحليل...',
      emptyError: 'يرجى إدخال رابط لتشغيله داخل صندوق الرمل.',
      presetPhishLabel: 'رابط تصيّد (PayPal)',
      presetApkLabel: 'رابط تحميل خبيث (.apk)',
      presetSafeLabel: 'موقع آمن (example.com)',
      modeLabels: {
        live_captured: 'التقاط شبكي حي معزول (Live HTTP Capture)',
        simulated_offline: 'محاكاة سلوكية آمنة (النطاق غير متصل)',
        blocked_ssrf: 'تم الحظر تلقائياً (هدف شبكة داخلية SSRF)',
        blocked_unsafe_scheme: 'تم الحظر فوراً (مخطط تنفيذ كود خطر)',
      },
      whatTitle: 'ماذا سيفعل هذا الرابط لو قمت بتشغيله على جهازك؟',
      observedTag: 'مرصود فعلياً',
      predictedTag: 'سلوك متوقع',
      previewTitle: 'معاينة معزولة لمحتوى الصفحة (Zero-Execution View)',
      previewSubtitle: 'عرض نصي وبنيوي صامت لما يحاول الرابط إظهاره دون تحميل صور أو تنفيذ أكواد.',
      previewEmptyText: 'لم يُرجع الخادم محتوى نصياً مرئياً أو تعذر الوصول للنطاق.',
      previewTrapWarning: 'حقول حساسة يحاول الرابط طلبها منك:',
      telemetryTitle: 'القياس الجنائي للخادم والـ DOM',
      httpStatusLabel: 'حالة HTTP',
      contentTypeLabel: 'نوع المحتوى',
      formsLabel: 'النماذج / حقول السر',
      scriptsLabel: 'السكربتات / التشويش',
      iframesLabel: 'إطارات مخفية',
      cookiesLabel: 'محاولات الكوكيز',
      redirectsTitle: 'سلسلة التحويلات التي سلكها الرابط:',
      guaranteesLabel: 'ضمانات الأمان المفعّلة أثناء الفحص:',
    },
    history: {
      title: 'سجل الفحوصات المحلي',
      subtitle: 'يُحفظ داخل متصفحك فقط لخصوصيتك الكاملة ولا يُرسل إلى أي خادم.',
      clearAll: 'مسح السجل',
      emptyTitle: 'سجل الفحص فارغ',
      emptyBody: 'ستظهر هنا آخر الرسائل التي قمت بفحصها للرجوع إليها سريعاً.',
      reopenButton: 'إعادة الفحص',
    },
    quiz: {
      title: 'مختبر كشف التصيّد (اختبر وعيك)',
      subtitle: 'تحدٍّ تفاعلي يقدّم رسائل واقعية ويفحص إجابتك بمحرّك البايثون لكشف العلامات الخفية.',
      scoreLabel: 'النتيجة',
      progressLabel: 'السيناريو',
      scamButton: 'احتيال / تصيّد',
      safeButton: 'رسالة طبيعية آمنة',
      correctBadge: 'إجابة صحيحة',
      wrongBadge: 'انتبه — إجابة غير دقيقة',
      nextButton: 'السيناريو التالي',
      restartButton: 'إعادة الاختبار',
      completedTitle: 'أكملت تحدي الوعي الأمني',
      completedBody: 'يمكنك مراجعة النتيجة أو إعادة الاختبار لتثبيت مهارات كشف التصيّد.',
      pythonProofLabel: 'تقييم محرك البايثون:',
      badgesTitle: 'شارات التحصين السيبراني',
      streakLabel: 'سلسلة الإجابات الصحيحة',
      badges: [
        {
          id: 'first_catch',
          title: 'صيّاد التصيّد الأول',
          requirement: 'حلّ سيناريو واحد بشكل صحيح',
        },
        {
          id: 'streak_three',
          title: 'يقظة متواصلة (3×)',
          requirement: '3 إجابات صحيحة متتالية',
        },
        {
          id: 'cyber_defender',
          title: 'حارس الوعي الرقمي',
          requirement: 'إتمام الاختبار بدقة 60% فأعلى',
        },
        {
          id: 'perfect_shield',
          title: 'حصانة كاملة 100%',
          requirement: 'إجابة جميع السيناريوهات بدقة تامة',
        },
      ],
    },
    academic: {
      title: 'محرك حصانة للنزاهة الأكاديمية (AI + Plagiarism + Behavior)',
      subtitle:
        'تحليل الأسلوب اللغوي (Stylometry) لكشف النصوص المولدة آلياً، فحص الاستلال بنظام التقطيع الرباعي (4-gram)، ورصد البصمة السلوكية للكتابة لإصدار شهادة توثيق رقمية.',
      textLabel: 'نص البحث أو التقرير الأكاديمي (اكتب مباشرة لقياس بصمة الكتابة أو الصق النص)',
      textPlaceholder:
        'اكتب أو الصق هنا نص البحث أو التقرير الجامعي لفحص الأصالة العلمية ونسبة الذكاء الاصطناعي والاستلال...',
      refLabel: 'نص مرجعي للمقارنة المباشرة (اختياري)',
      refPlaceholder: 'الصق هنا فقرة من مصدر خارجي للتحقق من نسبة التطابق المباشر مع بحثك...',
      analyzeButton: 'تحليل الأصالة بالبايثون',
      analyzingButton: 'جارِ التحليل الأكاديمي...',
      emptyError: 'يرجى إدخال نص أكاديمي لا يقل عن 10 أحرف للتحليل.',
      sampleHumanLabel: 'بحث بشري أصيل',
      sampleAiLabel: 'نص مولّد آلياً',
      samplePlagiarismLabel: 'نموذج استلال',
      telemetryLabel: 'البصمة السلوكية الحية:',
      keystrokesLabel: 'ضغطات المفاتيح',
      pastedLabel: 'أحرف ملصوقة',
      cadenceLabel: 'تباين الإيقاع',
      originalityLabel: 'مؤشر الأصالة',
      aiProbLabel: 'احتمال التوليد الآلي (AI)',
      plagiarismLabel: 'نسبة الاستلال المرجعي',
      richnessLabel: 'ثراء المفردات (TTR)',
      burstinessLabel: 'التنوع الإيقاعي للجمل',
      behaviorLabel: 'تقييم البصمة السلوكية',
      verdicts: {
        authentic: 'أصيل وموثوق',
        review_needed: 'يستدعي المراجعة',
        flagged: 'استلال أو توليد آلي مرتفع',
      },
      behaviorStatuses: {
        not_captured: 'إدخال غير مقاس حياً',
        human_verified: 'إيقاع كتابة بشري عضوي',
        robotic_cadence: 'إيقاع آلي منتظم بشكل مريب',
        bulk_pasted: 'نسبة لصق مباشر مرتفعة',
        mixed_input: 'إدخال مختلط (كتابة + لصق)',
      },
      signalsTitle: 'المؤشرات الجنائية للنص (Python Stylometry)',
      plagiarismMatchesTitle: 'تطابقات الاستلال المرصودة',
      aiPhrasesTitle: 'التعابير النمطية المرصودة',
      certEligibleTitle: 'النص مؤهل لإصدار شهادة أصالة رقمية (Hash-Chain Ledger)',
      certEligibleSubtitle:
        'وثّق البحث في سجل البلوكتشين المحلي (SHA-256) للحصول على رمز تحقق جامعي غير قابل للتلاعب.',
      certTitleLabel: 'عنوان البحث أو التقرير',
      certTitlePlaceholder: 'مثال: تصميم نظام كشف التصيد الإلكتروني لطلبة الجامعات',
      certAuthorLabel: 'اسم الباحث / الطالب',
      certAuthorPlaceholder: 'مثال: علي حسين كاظم',
      certInstitutionLabel: 'الجامعة / القسم',
      certInstitutionPlaceholder: 'الجامعة التكنولوجية — قسم علوم الحاسوب',
      issueCertButton: 'إصدار شهادة البلوكتشين',
      issuingCertButton: 'جارِ التوثيق والتوقيع...',
      certFormError: 'يرجى إدخال عنوان البحث واسم الباحث لإصدار الشهادة.',
      certIssuedTitle: 'تم توثيق الشهادة في السجل غير القابل للتعديل',
      certIdLabel: 'رمز الشهادة (Certificate ID)',
      blockIndexLabel: 'رقم الكتلة',
      docHashLabel: 'بصمة المستند (Document SHA-256)',
      blockHashLabel: 'بصمة الكتلة (Block Hash)',
      prevHashLabel: 'الكتلة السابقة (Previous Hash)',
      copyCertIdButton: 'نسخ رمز الشهادة',
      copiedCertIdButton: 'تم نسخ الرمز',
    },
    dlp: {
      title: 'فاحص منع تسريب البيانات والملفات (DLP & File Shield)',
      subtitle:
        'افحص المستندات والملفات البرمجية أو التقارير قبل رفعها لاكتشاف مفاتيح API، رموز JWT، أرقام الهواتف والبطاقات، والروابط الخبيثة المضمنة.',
      textLabel: 'محتوى الملف أو النص المراد تدقيقه أمنياً',
      textPlaceholder:
        'الصق محتوى الملف أو ارفع ملفاً نصياً (.txt, .md, .json, .csv) لفحص التسريبات والروابط...',
      uploadFileButton: 'رفع ملف للفحص',
      sampleLeakButton: 'تعبئة نموذج تسريب تجريبي',
      scanButton: 'فحص التسريب والأمان بالبايثون',
      scanningButton: 'جارِ التدقيق الأمني...',
      emptyError: 'يرجى إدخال نص أو رفع ملف للفحص أولاً.',
      riskLabel: 'درجة المخاطرة الأمنية',
      findingsTitle: 'البيانات الحساسة والأسرار المكشوفة (DLP)',
      noSecretsText: 'لم يتم العثور على مفاتيح برمجية أو بيانات شخصية مكشوفة.',
      urlsTitle: 'الروابط المضمنة داخل الملف',
      cyberReasonsTitle: 'مؤشرات التصيد والمحتوى المشبوه',
    },
    dashboard: {
      title: 'لوحة قيادة منصة حصانة (AcadShield Executive Ledger)',
      subtitle:
        'متابعة حية من قاعدة بيانات SQLite لحالة السجل المشفر، الشهادات البحثية الموثقة، وبلاغات المجتمع السيبرانية وخارطة التطوير.',
      refreshButton: 'تحديث السجل',
      kpiCertificates: 'الشهادات البحثية الموثقة',
      kpiOriginality: 'متوسط الأصالة الأكاديمية',
      kpiReports: 'البلاغات السيبرانية المجهولة',
      kpiChainStatus: 'سلامة سلسلة الكتل (SHA-256)',
      chainValid: 'سلسلة متماسكة وسليمة 100%',
      chainInvalid: 'تم رصد خلل في السلسلة',
      verifierTitle: 'التحقق الفوري من صحة شهادة بحثية',
      verifierPlaceholder: 'أدخل رمز الشهادة (مثال: ACAD-0001-...) أو بصمة SHA-256',
      verifyButton: 'تحقق من الشهادة',
      verifyingButton: 'جارِ التحقق...',
      verifyFoundValid: 'شهادة موثقة وصحيحة ضمن سلسلة الكتل غير المعدّلة',
      verifyFoundTampered: 'تحذير: تطابق جزئي مع خلل في سلامة البصمة',
      verifyNotFound: 'لم يتم العثور على شهادة مطابقة لهذا الرمز أو البصمة.',
      ledgerTitle: 'أحدث الكتل الموثقة في سجل البلوكتشين',
      ledgerEmpty: 'لا توجد شهادات مصدرة بعد. يمكنك تحليل بحث وإصدار أول شهادة من تبويب "حصانة الأكاديمية".',
      colCertId: 'رمز الشهادة',
      colResearch: 'عنوان البحث',
      colAuthor: 'الباحث / المؤسسة',
      colOriginality: 'الأصالة',
      colHash: 'تجزئة الكتلة',
      roadmapTitle: 'خارطة الطريق التفاعلية لمنصة حصانة (AcadShield AI)',
      roadmapSubtitle:
        'جميع المراحل الخمس قابلة للتشغيل والاستخدام الفعلي الآن — اختر أي مرحلة لتشغيل وحدتها مباشرة أو اختبار الأداء المؤسسي.',
      roadmapStages: [
        {
          id: 'academic',
          stage: 'المرحلة 01',
          title: 'محرك التحليل الأكاديمي وكشف AI',
          summary: 'خوارزميات الأسلوب اللغوي (Stylometry) والتقطيع الرباعي (Shingling) لكشف الاستلال والتزييف الآلي بالبايثون.',
          status: 'مُفعّل',
          actionLabel: 'تشغيل المحرك الأكاديمي',
        },
        {
          id: 'dlp',
          stage: 'المرحلة 02',
          title: 'الدرع السيبراني وفاحص التسريب (DLP)',
          summary: 'تشريح الروابط (DNS/TLS/Redirects)، فحص دفعات الواتساب، ومنع تسريب الأسرار والبيانات الشخصية في الملفات.',
          status: 'مُفعّل',
          actionLabel: 'فتح فاحص التسريب DLP',
        },
        {
          id: 'ledger',
          stage: 'المرحلة 03',
          title: 'البصمة السلوكية وسجل البلوكتشين',
          summary: 'رصد إيقاع لوحة المفاتيح الحي وتوثيق الشهادات الأكاديمية بسلسلة كتل SHA-256 غير قابلة للتعديل.',
          status: 'مُفعّل',
          actionLabel: 'فحص الشهادات أعلاه',
        },
        {
          id: 'sandbox',
          stage: 'المرحلة 04',
          title: 'بيئة الاختبار الجامعية (Sandbox Pilot)',
          summary: 'التطبيق التجريبي (PoC) داخل الجامعة التكنولوجية لقياس الأداء تحت الضغط الفعلي بالتنسيق مع الحاضنة التكنولوجية.',
          status: 'بيئة PoC جاهزة',
          actionLabel: 'تشغيل اختبار الضغط',
        },
        {
          id: 'saas',
          stage: 'المرحلة 05',
          title: 'منصة SaaS وطنية للجامعات العراقية',
          summary: 'نموذج اشتراكات مؤسسي لتوطين الأمن الأكاديمي والسيبراني وخفض الاعتماد على المنصات الأجنبية المكلفة.',
          status: 'نموذج تفاعلي',
          actionLabel: 'تسجيل جامعة وحساب التوفير',
        },
      ],
      sandbox: {
        title: 'مختبر الضغط التجريبي للجامعة التكنولوجية (Stage 04 — Live Sandbox PoC)',
        subtitle:
          'اختبر قدرة محرك البايثون على معالجة دفعات متزامنة من الأبحاث الأكاديمية ورسائل التصيد والتسريبات بقياس فعلي للزمن والإنتاجية.',
        deptLabel: 'القسم / الكلية المستهدفة بالاختبار (Sandbox Cohort)',
        deptPlaceholder: 'الجامعة التكنولوجية — قسم علوم الحاسوب',
        loadLabel: 'حجم حزمة الفحص تحت الضغط',
        runButton: 'تشغيل اختبار الضغط الحي بالبايثون',
        runningButton: 'جارِ قياس الأداء...',
        exportJsonButton: 'تصدير تقرير PoC (JSON)',
        totalOpsLabel: 'إجمالي عمليات الفحص',
        avgLatencyLabel: 'متوسط زمن المعالجة',
        throughputLabel: 'سرعة المحرك',
        detectionsLabel: 'التهديدات والاستلال المرصود',
        slaOptimal: 'جاهزية ممتازة للإطلاق الجامعي (SLA Optimal)',
        slaAcceptable: 'أداء مقبول تحت الضغط العالي',
        historyTitle: 'سجل اختبارات بيئة Sandbox المحفوظة',
        historyEmpty: 'لم يتم تشغيل اختبار ضغط بعد. اضغط الزر أعلاه لقياس أداء البايثون الفعلي.',
        presets: [
          'الجامعة التكنولوجية — قسم علوم الحاسوب',
          'الجامعة التكنولوجية — هندسة الأمن السيبراني',
          'الحاضنة التكنولوجية — بيئة اختبار PoC',
        ],
      },
      saas: {
        title: 'بوابة الاشتراكات الوطنية للجامعات العراقية وحاسبة الجدوى (Stage 05 — EdTech SaaS)',
        subtitle:
          'سجّل جامعة أو كلية عراقية لتوليد مفتاح API مؤسسي وحساب التوفير السنوي مقارنةً بتكلفة المنصات الأجنبية (Turnitin وغيرها).',
        uniLabel: 'اسم الجامعة أو المؤسسة التعليمية',
        uniPlaceholder: 'مثال: الجامعة التكنولوجية',
        studentsLabel: 'عدد الطلبة',
        facultyLabel: 'عدد التدريسيين والباحثين',
        planLabel: 'باقة الاشتراك المؤسسي',
        plans: {
          starter: 'باقة الكلية / القسم (Starter)',
          campus: 'باقة الجامعة الكاملة (Campus)',
          national: 'الباقة الوزارية الوطنية (National)',
        },
        presets: [
          { name: 'الجامعة التكنولوجية', students: 12000, faculty: 650 },
          { name: 'جامعة بغداد', students: 45000, faculty: 2200 },
          { name: 'جامعة البصرة', students: 32000, faculty: 1500 },
        ],
        previewTitle: 'تقدير الجدوى الاقتصادية الفوري (بالبايثون)',
        localCostLabel: 'تكلفة منصة حصانة المحلية',
        foreignCostLabel: 'تكلفة المنصات الأجنبية المماثلة',
        savingsLabel: 'التوفير السنوي للجامعة',
        savingsIqdLabel: 'التوفير بالدينار العراقي (السعر الرسمي)',
        registerButton: 'اعتماد وتوليد مفتاح SaaS للجامعة',
        registeringButton: 'جارِ تسجيل المؤسسة...',
        formError: 'يرجى إدخال اسم الجامعة (حرفان على الأقل).',
        tenantsTitle: 'الجامعات والمؤسسات المسجلة في منصة حصانة (SQLite)',
        tenantsEmpty: 'لا توجد جامعات مسجلة بعد. استخدم النموذج أعلاه لتسجيل أول جامعة وتوليد مفتاحها.',
        colCode: 'رمز المؤسسة',
        colUniversity: 'الجامعة / المؤسسة',
        colUsers: 'الطلبة / التدريسيون',
        colPlan: 'الباقة',
        colKey: 'مفتاح API',
        colSavings: 'التوفير السنوي',
        removeButton: 'إزالة',
      },
    },
    categories: {
      phishing_bank: 'انتحال مصرفي أو جهة رسمية',
      fake_prize: 'جائزة أو سحب وهمي',
      fake_delivery: 'احتيال توصيل وطرود',
      investment_fraud: 'احتيال استثماري',
      otp_theft: 'سرقة رمز التحقق (OTP)',
      fake_job: 'عرض عمل وهمي',
      other: 'محاولة احتيال عامة',
    },
    trending: {
      title: 'الاحتيالات الرائجة',
      subtitle: 'بلاغات مجهولة الهوية خلال آخر 7 أيام — دون حفظ أي نصوص رسائل.',
      last7Days: 'آخر 7 أيام',
      reportsUnit: 'بلاغ',
      avgScoreLabel: 'متوسط الخطورة',
      totalReportsStat: 'إجمالي البلاغات (7 أيام)',
      avgRiskStat: 'متوسط الخطورة العام',
      topCategoryStat: 'النمط الأكثر انتشاراً',
      emptyTitle: 'لا توجد بلاغات مسجلة بعد',
      emptyBody: 'عند فحص رسالة مشبوهة والضغط على "بلّغ عن هذه الرسالة"، ستظهر الإحصائيات المجهولة هنا.',
      errorText: 'تعذر تحميل الإحصائيات حالياً.',
      retryButton: 'تحديث',
    },
    learn: {
      title: 'تعلّم كيف تحمي نفسك',
      subtitle: 'دليل مختصر لفهم أساليب الاحتيال الشائعة والتعامل معها بأمان.',
      items: [
        {
          id: 'phishing',
          question: 'ما هو التصيّد؟',
          answer:
            'التصيّد الإلكتروني (Phishing) هو محاولة خداعك عبر رسائل نصية أو روابط مزيفة تنتحل صفة مصرف أو شركة اتصالات أو خدمة توصيل لسرقة كلمة مرورك أو بيانات بطاقتك المصرفية.',
        },
        {
          id: 'otp',
          question: 'لماذا لا أشارك رمز OTP؟',
          answer:
            'رمز التحقق لمرة واحدة (OTP) هو بمثابة مفتاح مؤقت لحسابك البنكي أو محفظتك الإلكترونية. مشاركته مع أي شخص أو إدخاله في موقع مزيف يمنح المحتال صلاحية سحب أموالك أو الاستيلاء على حسابك فوراً.',
        },
        {
          id: 'verify-link',
          question: 'كيف أتحقق من رابط؟',
          answer:
            'اقرأ اسم النطاق بدقة قبل النقر: انتبه لتبديل الحروف مثل رقم 1 بدل حرف l أو 0 بدل o، وابتعد عن الروابط المختصرة أو النطاقات الغريبة مثل .xyz و .top، وافتح الموقع الرسمي بنفسك من المتصفح.',
        },
        {
          id: 'signs',
          question: 'علامات الرسائل الاحتيالية',
          answer:
            'تشمل العلامات المتكررة: الاستعجال والتهديد بإغلاق الحساب خلال ساعات، الوعود بجوائز لم تشارك بها، طلب رسوم رمزية لتوصيل طرد، أو طلب بيانات سرية عبر رابط خارجي.',
        },
        {
          id: 'victim',
          question: 'ماذا أفعل إذا وقعت ضحية؟',
          answer:
            'تواصل فوراً مع مصرفك أو مزود المحفظة الإلكترونية لإيقاف البطاقة أو تجميد الحساب، غيّر كلمات مرور حساباتك المهمة، فعّل التحقق بخطوتين، واحتفظ بلقطات شاشة لتقديم بلاغ رسمي لدى الجهات المختصة.',
        },
      ],
    },
    footer: {
      disclaimer: 'النتيجة تقديرية ولا تغني عن الحذر.',
      privacyReminder: 'يعمل بمحرك بايثون محلي دون خدمات مدفوعة أو تتبع.',
    },
  },
  en: {
    brandAr: 'كشف',
    brandEn: 'Kashf',
    nav: {
      analyzer: 'Analyzer',
      dashboard: 'AcadShield',
      trending: 'Trending',
      quiz: 'IQ Lab',
      learn: 'Learn',
      langToggle: 'العربية',
      langToggleAria: 'التبديل إلى اللغة العربية',
      menuOpenAria: 'Open menu',
      menuCloseAria: 'Close menu',
    },
    hero: {
      blurredLine1: 'Hey there, meet Kashf,',
      blurredLine2: 'Your Python-Powered Scam & URL Forensics Suite',
      typewriterText: 'Got a suspicious message? Paste it below and we will expose it.',
      analyzePill: 'Analyze a message',
      reachUsPrefix: 'Reach us:',
      reachUsEmail: 'hello@kashf.iq',
      copiedLabel: 'Copied',
      headline: 'Python Security & Scam Inspector',
      subtitle: 'Instant SMS/WhatsApp triage, multi-message batch scanning, and live DNS/TLS link forensics without storing your text.',
      tabs: {
        single: 'Single Message',
        batch: 'Batch Scan',
        urlInspector: 'URL X-Ray',
        sandbox: 'Safe Sandbox',
        academic: 'Academic Shield',
        dlp: 'DLP & Files',
        history: 'Local History',
      },
      messageLabel: 'Suspicious message text',
      placeholder:
        'Example: Congratulations! You won $5000, click within 24 hours http://paypa1-secure.xyz/login and send your OTP code',
      urlLabel: 'Suspicious URL (optional — auto-filled if detected)',
      urlPlaceholder: 'https://example.com',
      detectedUrlsLabel: 'Detected links:',
      analyzeButton: 'Analyze Now',
      analyzingButton: 'Analyzing...',
      clearButton: 'Clear',
      privacyNote: 'We never store your message text. Only an anonymous fingerprint is kept for statistics.',
      emptyError: 'Please paste a message or enter a link to analyze first.',
      truncatedWarning: 'Input was trimmed to the 5,000-character limit.',
      networkError: 'Could not reach the analysis server. Please check the backend and try again.',
      rateLimitError: 'Too many requests in one minute. Please wait briefly and try again.',
      retryButton: 'Try Again',
      examples: [
        {
          id: 'bank',
          label: 'Bank Alert',
          text: 'Rafidain Bank Alert: Your account will be suspended within 24 hours. Verify your card number and OTP immediately at http://rafidain-verify.xyz/update',
        },
        {
          id: 'prize',
          label: 'Fake Prize',
          text: 'مبروك! ربحت 5000$، اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل رمز التحقق',
        },
        {
          id: 'delivery',
          label: 'Delivery Link',
          text: 'Delivery failed: Your package is held pending a small customs fee. Pay via bit.ly/3x9demo within 24 hours.',
        },
      ],
    },
    result: {
      riskScoreLabel: 'Risk Score',
      outOfHundred: '/ 100',
      categoryLabel: 'Category',
      verdicts: {
        safe: 'Likely Safe',
        suspicious: 'Suspicious',
        dangerous: 'Dangerous',
      },
      verdictSummaries: {
        safe: 'No strong scam patterns were detected, though you should always verify unfamiliar senders.',
        suspicious: 'Several warning signs appeared. Pause and verify through official channels before acting.',
        dangerous: 'Clear phishing or scam indicators detected. Do not click links or share any codes.',
      },
      whyTitle: 'Why?',
      noReasonsText: 'No phishing rules or deceptive link patterns were triggered.',
      highlightedCopyTitle: 'Message copy with detected phrases highlighted',
      pointsSuffix: 'pts',
      whatToDoTitle: 'What should I do?',
      steps: {
        safe: [
          'Confirm you know the sender before replying or opening unexpected attachments.',
          'Never share OTP codes or passwords even if a message appears familiar.',
          'When unsure about a bank or service, contact them through their official app or number.',
        ],
        suspicious: [
          'Do not click the link or enter personal or banking details.',
          'Verify the claim directly using the organization’s official customer service number.',
          'Delete the message and block the sender if you were not expecting it.',
        ],
        dangerous: [
          'Never open the link or share OTP codes, PINs, or card numbers.',
          'Block the sender and report the message inside WhatsApp or your SMS app.',
          'If you already submitted details, contact your bank immediately to freeze your card and change passwords.',
        ],
      },
      shareButton: 'PNG Card',
      sharingButton: 'Preparing...',
      copyWarningButton: 'Copy Warning',
      copiedWarningButton: 'Warning Copied',
      exportJsonButton: 'Export JSON',
      reportButton: 'Report This Message',
      reportingButton: 'Reporting...',
      reportedButton: 'Reported Anonymously',
      reportError: 'Could not submit report right now. Please try again.',
      shareFooter: 'This result is advisory and does not replace caution.',
      forensicsTitle: 'Python URL Forensics (X-Ray)',
      defangedLabel: 'Safe Defanged URL',
      copyDefanged: 'Copy Safe',
      copiedDefanged: 'Copied',
      sanitizedLabel: 'Tracking-Stripped URL',
      entropyLabel: 'Domain Entropy',
      brandMatchLabel: 'Matched Brand',
      officialDomainLabel: 'Verified Official Domain',
      impersonationLabel: 'Suspected Impersonation',
      liveProbeButton: 'Run Live Python Probe (Threat Intel + RDAP + DNS + SSL)',
      liveProbingButton: 'Probing Network...',
      dnsLabel: 'DNS / IP Records',
      tlsLabel: 'SSL / TLS Certificate',
      redirectsLabel: 'Redirect Chain',
      finalUrlLabel: 'Final Destination',
      openSandboxButton: 'Test in Safe Sandbox',
      urlClassifications: {
        malicious: 'Malicious',
        suspicious: 'Suspicious',
        no_known_threat: 'No Known Threat (≠ Guaranteed Safe)',
        unknown: 'Unknown / Insufficient Evidence',
      },
      noKnownThreatNote: 'No Known Threat only means no match in checked feeds; it does not prove a URL is 100% safe.',
      threatIntelTitle: 'Threat Intelligence Sources',
      threatStatusLabels: {
        hit: 'Threat Hit',
        clean: 'No Match',
        not_configured: 'Not Configured',
        unavailable: 'Unavailable',
        error: 'Lookup Error',
      },
      rdapLabel: 'Domain Age (RDAP)',
      dnsRecordsLabel: 'DNS Records (A / MX / TXT)',
      technicalDetailsTitle: 'Technical Analysis Details (DNS · RDAP · TLS · Unicode)',
      suspiciousSegmentsTitle: 'Extracted Suspicious Sentences / Segments',
      linksVerifyTitle: 'Links Requiring Separate Threat-Intel Verification',
      scriptsLabel: 'Unicode Scripts',
    },
    batch: {
      title: 'Batch & Chat-Log Scanner',
      subtitle: 'Paste multiple messages (separated by a blank line) or upload a .txt WhatsApp export to rank threats with Python.',
      placeholder:
        'Rafidain Bank Alert: Account suspended at http://rafidain-verify.xyz\n\nHi team, see you at the 10am standup.\n\nCongratulations you won $5000! Claim at bit.ly/3x9demo and send OTP',
      uploadTxtButton: 'Upload .txt File',
      sampleButton: 'Load Sample Batch',
      scanButton: 'Scan Batch in Python',
      scanningButton: 'Scanning Batch...',
      emptyError: 'Please paste or upload at least one message to scan.',
      totalLabel: 'Total Scanned',
      dangerousLabel: 'Dangerous',
      suspiciousLabel: 'Suspicious',
      safeLabel: 'Safe',
      inspectSingleButton: 'Inspect Details',
    },
    urlLab: {
      title: 'Live Python URL X-Ray',
      subtitle: 'Inspect any link safely without opening it: typosquatting analysis, DNS & TLS inspection, and short-link redirect tracing.',
      inputLabel: 'Enter suspicious URL',
      placeholder: 'https://bit.ly/3x9demo or http://paypa1-secure.xyz/login?utm_source=sms',
      inspectButton: 'Inspect & Probe Live',
      inspectingButton: 'Probing Link...',
      emptyError: 'Please enter a valid URL to inspect.',
    },
    urlSandbox: {
      title: 'Isolated Safe URL Sandbox',
      subtitle:
        'Safely detonate any suspicious link inside an isolated Python sandbox to inspect what the page would do if opened — without exposing your browser, cookies, or files.',
      isolationNotice:
        '100% Isolated: JavaScript Disabled · Zero Cookies Stored · Zero Disk Downloads · SSRF Guard Active',
      inputLabel: 'Enter suspicious URL to test safely',
      placeholder: 'http://paypa1-secure.xyz/login?otp=required or https://example.com',
      runButton: 'Detonate in Safe Sandbox',
      runningButton: 'Isolating & Analyzing...',
      emptyError: 'Please enter a URL to run in the safe sandbox.',
      presetPhishLabel: 'Phishing Trap (PayPal)',
      presetApkLabel: 'Malicious Download (.apk)',
      presetSafeLabel: 'Safe Site (example.com)',
      modeLabels: {
        live_captured: 'Live Isolated HTTP Capture',
        simulated_offline: 'Safe Behavioral Simulation (Host Unreachable)',
        blocked_ssrf: 'Blocked Automatically (Private/Internal IP)',
        blocked_unsafe_scheme: 'Blocked Immediately (Executable URI Scheme)',
      },
      whatTitle: 'What This Link Would Do If Opened',
      observedTag: 'Observed',
      predictedTag: 'Predicted',
      previewTitle: 'Inert Sandbox Preview (Zero-Execution View)',
      previewSubtitle: 'Passive text and form-field extraction without executing scripts or loading remote media.',
      previewEmptyText: 'No visible page text returned or host is offline.',
      previewTrapWarning: 'Sensitive fields this page attempts to collect:',
      telemetryTitle: 'HTTP & DOM Telemetry',
      httpStatusLabel: 'HTTP Status',
      contentTypeLabel: 'Content-Type',
      formsLabel: 'Forms / Password Inputs',
      scriptsLabel: 'Scripts / Obfuscated',
      iframesLabel: 'Hidden Iframes',
      cookiesLabel: 'Cookie Attempts',
      redirectsTitle: 'Observed Redirect Path:',
      guaranteesLabel: 'Active Sandbox Protections:',
    },
    history: {
      title: 'Local Scan History',
      subtitle: 'Stored exclusively in your browser localStorage — never uploaded to any server.',
      clearAll: 'Clear History',
      emptyTitle: 'No local scans yet',
      emptyBody: 'Messages you analyze will appear here locally for quick reference.',
      reopenButton: 'Load & Re-scan',
    },
    quiz: {
      title: 'Phishing IQ Lab',
      subtitle: 'Test your instincts on realistic SMS, WhatsApp, and email scenarios backed by the Python risk engine.',
      scoreLabel: 'Score',
      progressLabel: 'Scenario',
      scamButton: 'Scam / Phishing',
      safeButton: 'Legitimate / Safe',
      correctBadge: 'Correct',
      wrongBadge: 'Watch out — Incorrect',
      nextButton: 'Next Scenario',
      restartButton: 'Restart Quiz',
      completedTitle: 'Awareness Challenge Complete',
      completedBody: 'Review your accuracy or restart to sharpen your phishing detection instincts.',
      pythonProofLabel: 'Python Engine Verdict:',
      badgesTitle: 'Cyber Awareness Badges',
      streakLabel: 'Current Streak',
      badges: [
        {
          id: 'first_catch',
          title: 'First Catch',
          requirement: 'Verify 1 scenario accurately',
        },
        {
          id: 'streak_three',
          title: 'Triple Vigilance (3x)',
          requirement: '3 consecutive correct calls',
        },
        {
          id: 'cyber_defender',
          title: 'Digital Defender',
          requirement: 'Finish a round with >= 60% accuracy',
        },
        {
          id: 'perfect_shield',
          title: '100% AcadShield',
          requirement: 'Score 100% across all scenarios',
        },
      ],
    },
    academic: {
      title: 'AcadShield Academic Integrity Engine (AI + Plagiarism + Behavior)',
      subtitle:
        'Python stylometry to spot formulaic AI generation, 4-gram shingling plagiarism detection, live keystroke biometrics, and tamper-evident certificate issuance.',
      textLabel: 'Research paper or essay text (type live for keystroke biometrics or paste text)',
      textPlaceholder:
        'Type or paste an academic report or research abstract to evaluate originality, AI probability, and reference overlap...',
      refLabel: 'Reference corpus excerpt for direct comparison (optional)',
      refPlaceholder: 'Paste a source passage here to test direct 4-gram overlap against your submission...',
      analyzeButton: 'Run Academic Analysis in Python',
      analyzingButton: 'Analyzing Manuscript...',
      emptyError: 'Please enter at least 10 characters of academic text to analyze.',
      sampleHumanLabel: 'Authentic Research',
      sampleAiLabel: 'AI-Style Essay',
      samplePlagiarismLabel: 'Plagiarized Draft',
      telemetryLabel: 'Live Keystroke Telemetry:',
      keystrokesLabel: 'Keystrokes',
      pastedLabel: 'Pasted chars',
      cadenceLabel: 'Cadence std',
      originalityLabel: 'Originality Score',
      aiProbLabel: 'AI Likelihood',
      plagiarismLabel: 'Plagiarism Overlap',
      richnessLabel: 'Lexical Richness (TTR)',
      burstinessLabel: 'Sentence Burstiness',
      behaviorLabel: 'Behavioral Biometrics',
      verdicts: {
        authentic: 'Authentic & Original',
        review_needed: 'Needs Editorial Review',
        flagged: 'High AI or Plagiarism Signal',
      },
      behaviorStatuses: {
        not_captured: 'Not captured live',
        human_verified: 'Organic human cadence verified',
        robotic_cadence: 'Suspiciously uniform keystroke cadence',
        bulk_pasted: 'High bulk-paste ratio detected',
        mixed_input: 'Mixed typing & pasting',
      },
      signalsTitle: 'Python Stylometry & Integrity Signals',
      plagiarismMatchesTitle: 'Matched Reference Sources',
      aiPhrasesTitle: 'Formulaic Transition Phrases',
      certEligibleTitle: 'Eligible for Tamper-Evident Authenticity Certificate',
      certEligibleSubtitle:
        'Anchor this manuscript in the local SHA-256 hash-chain ledger and generate a verifiable academic certificate ID.',
      certTitleLabel: 'Research / Report Title',
      certTitlePlaceholder: 'e.g., Hybrid Phishing Detection for University Portals',
      certAuthorLabel: 'Researcher / Student Name',
      certAuthorPlaceholder: 'e.g., Ali Hussein Kadhim',
      certInstitutionLabel: 'University / Department',
      certInstitutionPlaceholder: 'University of Technology — Computer Science',
      issueCertButton: 'Issue Blockchain Certificate',
      issuingCertButton: 'Signing Ledger Block...',
      certFormError: 'Please enter both research title and author name.',
      certIssuedTitle: 'Certificate Anchored to Immutable Hash Chain',
      certIdLabel: 'Certificate ID',
      blockIndexLabel: 'Block #',
      docHashLabel: 'Document SHA-256',
      blockHashLabel: 'Block Hash',
      prevHashLabel: 'Previous Block Hash',
      copyCertIdButton: 'Copy Certificate ID',
      copiedCertIdButton: 'Copied ID',
    },
    dlp: {
      title: 'Data Loss Prevention & File Security Scanner (DLP)',
      subtitle:
        'Audit drafts, code snippets, or university datasets before sharing to catch leaked API keys, JWTs, personal phone numbers, emails, card numbers, and phishing URLs.',
      textLabel: 'File contents or text to audit',
      textPlaceholder:
        'Paste text or upload a file (.txt, .md, .json, .csv) to scan for PII, secrets, and embedded phishing links...',
      uploadFileButton: 'Upload File',
      sampleLeakButton: 'Load Sample Leak',
      scanButton: 'Run DLP & Cyber Scan',
      scanningButton: 'Auditing Content...',
      emptyError: 'Please enter text or upload a file to scan first.',
      riskLabel: 'Composite Security Risk',
      findingsTitle: 'Exposed Secrets & Sensitive Data (DLP)',
      noSecretsText: 'No exposed API keys, tokens, payment cards, or PII patterns found.',
      urlsTitle: 'Embedded URLs Extracted',
      cyberReasonsTitle: 'Phishing & Cyber Risk Signals',
    },
    dashboard: {
      title: 'AcadShield Executive Ledger & Roadmap',
      subtitle:
        'Live SQLite telemetry combining cryptographic authenticity certificates, anonymous cyber reports, instant certificate lookup, and the institutional rollout roadmap.',
      refreshButton: 'Refresh Ledger',
      kpiCertificates: 'Verified Certificates',
      kpiOriginality: 'Avg Research Originality',
      kpiReports: 'Anonymous Cyber Reports',
      kpiChainStatus: 'Hash-Chain Integrity',
      chainValid: 'Cryptographic Chain Valid',
      chainInvalid: 'Chain Integrity Warning',
      verifierTitle: 'Instant Certificate Verification Lookup',
      verifierPlaceholder: 'Enter Certificate ID (e.g. ACAD-0001-...) or SHA-256 hash',
      verifyButton: 'Verify Certificate',
      verifyingButton: 'Verifying...',
      verifyFoundValid: 'Authentic certificate verified against unbroken SHA-256 chain',
      verifyFoundTampered: 'Warning: Record matched but chain validation failed',
      verifyNotFound: 'No matching certificate found for this ID or digest.',
      ledgerTitle: 'Recent Tamper-Evident Ledger Blocks',
      ledgerEmpty: 'No certificates issued yet. Analyze a manuscript under Academic Shield to anchor the first block.',
      colCertId: 'Cert ID',
      colResearch: 'Research Title',
      colAuthor: 'Author / Institution',
      colOriginality: 'Originality',
      colHash: 'Block Digest',
      roadmapTitle: 'AcadShield AI Interactive Platform Modules (Stages 01–05)',
      roadmapSubtitle:
        'Every roadmap stage is live and interactive — launch any verification tool directly or run the University Sandbox benchmark and Iraqi EdTech SaaS console below.',
      roadmapStages: [
        {
          id: 'academic',
          stage: 'Stage 01',
          title: 'Academic Stylometry & AI Detector',
          summary: 'Pure-Python lexical burstiness, formulaic phrase detection, and 4-gram shingling plagiarism verification.',
          status: 'Active',
          actionLabel: 'Open Academic Engine',
        },
        {
          id: 'dlp',
          stage: 'Stage 02',
          title: 'Cyber Phishing & DLP File Shield',
          summary: 'Live DNS/TLS/Redirect forensics, WhatsApp batch triage, and secret/PII leakage prevention before upload.',
          status: 'Active',
          actionLabel: 'Open DLP & File Shield',
        },
        {
          id: 'ledger',
          stage: 'Stage 03',
          title: 'Behavioral Biometrics & Hash-Chain Ledger',
          summary: 'Keystroke cadence telemetry paired with tamper-evident SQLite SHA-256 authenticity certificates.',
          status: 'Active',
          actionLabel: 'Verify Certificates Above',
        },
        {
          id: 'sandbox',
          stage: 'Stage 04',
          title: 'University Sandbox Pilot (PoC)',
          summary: 'Controlled campus benchmark at the University of Technology measuring real Python throughput under load.',
          status: 'Interactive PoC',
          actionLabel: 'Launch Stress Benchmark',
        },
        {
          id: 'saas',
          stage: 'Stage 05',
          title: 'National EdTech SaaS Rollout',
          summary: 'Multi-tenant Iraqi university onboarding with live ROI savings against foreign platform licenses.',
          status: 'Live Console',
          actionLabel: 'Open University SaaS',
        },
      ],
      sandbox: {
        title: 'University of Technology Sandbox Stress Console (Stage 04 — Live PoC)',
        subtitle:
          'Execute a real multi-engine Python load test across academic stylometry, phishing triage, and DLP scans to measure campus throughput.',
        deptLabel: 'Pilot Department / Sandbox Cohort',
        deptPlaceholder: 'University of Technology — Computer Science',
        loadLabel: 'Stress Batch Operations',
        runButton: 'Run Live Python Stress Benchmark',
        runningButton: 'Benchmarking Python Engine...',
        exportJsonButton: 'Export PoC Report (JSON)',
        totalOpsLabel: 'Engine Checks Executed',
        avgLatencyLabel: 'Avg Latency / Check',
        throughputLabel: 'Throughput',
        detectionsLabel: 'AI / Cyber / DLP Caught',
        slaOptimal: 'Campus PoC SLA Optimal',
        slaAcceptable: 'Acceptable Latency Under Load',
        historyTitle: 'Saved SQLite Sandbox Runs',
        historyEmpty: 'No benchmark runs recorded yet. Trigger a stress run above to measure live Python performance.',
        presets: [
          'University of Technology — Computer Science',
          'University of Technology — Cybersecurity Engineering',
          'Tech Incubator — Campus PoC Sandbox',
        ],
      },
      saas: {
        title: 'Iraqi Universities National SaaS & Economic ROI Console (Stage 05)',
        subtitle:
          'Onboard an Iraqi university tenant into SQLite, generate an institutional API key prefix, and compute annual savings versus foreign software licenses.',
        uniLabel: 'University / Institution Name',
        uniPlaceholder: 'e.g., University of Technology',
        studentsLabel: 'Students Count',
        facultyLabel: 'Faculty & Researchers',
        planLabel: 'Institutional SaaS Tier',
        plans: {
          starter: 'Department Starter',
          campus: 'Full Campus',
          national: 'National Ministry Consortium',
        },
        presets: [
          { name: 'University of Technology', students: 12000, faculty: 650 },
          { name: 'University of Baghdad', students: 45000, faculty: 2200 },
          { name: 'University of Basrah', students: 32000, faculty: 1500 },
        ],
        previewTitle: 'Live Annual Economic Impact Preview',
        localCostLabel: 'AcadShield Local Cost',
        foreignCostLabel: 'Foreign Platform Benchmark',
        savingsLabel: 'Annual Institutional Savings',
        savingsIqdLabel: 'Estimated IQD Savings (Official Rate)',
        registerButton: 'Provision University SaaS Tenant',
        registeringButton: 'Provisioning Tenant...',
        formError: 'Please enter a valid university name (at least 2 characters).',
        tenantsTitle: 'Provisioned Iraqi Universities (SQLite)',
        tenantsEmpty: 'No university tenants onboarded yet. Register an institution above to generate its SaaS key.',
        colCode: 'Tenant Code',
        colUniversity: 'Institution',
        colUsers: 'Students / Faculty',
        colPlan: 'Tier',
        colKey: 'API Key Prefix',
        colSavings: 'Annual Savings',
        removeButton: 'Remove',
      },
    },
    categories: {
      phishing_bank: 'Bank or Authority Phishing',
      fake_prize: 'Fake Prize or Lottery',
      fake_delivery: 'Fake Delivery Scam',
      investment_fraud: 'Investment Fraud',
      otp_theft: 'OTP Code Theft',
      fake_job: 'Fake Job Offer',
      other: 'General Suspicious Activity',
    },
    trending: {
      title: 'Trending Scams',
      subtitle: 'Anonymous community reports over the last 7 days — no message text stored.',
      last7Days: 'Last 7 days',
      reportsUnit: 'reports',
      avgScoreLabel: 'Avg risk',
      totalReportsStat: 'Total Reports (7d)',
      avgRiskStat: 'Average Threat Score',
      topCategoryStat: 'Top Pattern',
      emptyTitle: 'No reports recorded yet',
      emptyBody: 'Once users analyze a suspicious text and submit an anonymous report, 7-day trends appear here.',
      errorText: 'Could not load trending statistics.',
      retryButton: 'Refresh',
    },
    learn: {
      title: 'Learn How to Stay Safe',
      subtitle: 'Practical guidance on spotting and avoiding common messaging scams.',
      items: [
        {
          id: 'phishing',
          question: 'What is phishing?',
          answer:
            'Phishing is an attempt to trick you via fake SMS, WhatsApp messages, or lookalike links impersonating banks, telecoms, or couriers to steal your passwords or payment cards.',
        },
        {
          id: 'otp',
          question: 'Why should I never share an OTP?',
          answer:
            'A One-Time Password (OTP) acts as a live key to your bank account or wallet. Giving it to someone or typing it into a fake site lets attackers transfer funds or take over your account immediately.',
        },
        {
          id: 'verify-link',
          question: 'How do I verify a link?',
          answer:
            'Inspect the domain carefully: watch out for character swaps like 1 instead of l or 0 instead of o, avoid URL shorteners or risky extensions like .xyz and .top, and type the official site manually.',
        },
        {
          id: 'signs',
          question: 'Common signs of scam messages',
          answer:
            'Watch for artificial urgency threatening suspension within hours, unexpected lottery prizes, small customs fee demands for a package, or requests for confidential codes over external links.',
        },
        {
          id: 'victim',
          question: 'What should I do if I fell for a scam?',
          answer:
            'Contact your bank or mobile wallet provider immediately to freeze cards or accounts, change passwords everywhere you reused them, enable two-factor authentication, and save screenshots to file an official report.',
        },
      ],
    },
    footer: {
      disclaimer: 'This result is advisory and does not replace caution.',
      privacyReminder: 'Powered by local Python analysis with zero paid APIs or tracking.',
    },
  },
};
