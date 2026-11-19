"""Stdlib JSON bridge so the Express dev server executes the exact Python analyzer & SQLite DB."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from academic_analyzer import analyze_academic_text, scan_dlp_content  # noqa: E402
from analyzer import analyze_batch, analyze_message  # noqa: E402
from blockchain import (  # noqa: E402
    get_dashboard_summary,
    issue_certificate,
    verify_certificate,
)
from db import get_community_stats, get_trending, init_db, save_report  # noqa: E402
from quiz import get_quiz_scenarios, verify_quiz_answer  # noqa: E402
from saas_sandbox import (  # noqa: E402
    delete_saas_tenant,
    list_saas_tenants,
    list_sandbox_runs,
    register_saas_tenant,
    run_sandbox_benchmark,
)
from evaluate_models import run_all_evaluations  # noqa: E402
from url_inspector import probe_url_live  # noqa: E402
from url_sandbox import detonate_url_in_sandbox  # noqa: E402


def main() -> int:
    init_db()
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    action = payload.get("action")

    if action == "analyze":
        result = analyze_message(
            payload.get("text", ""),
            payload.get("url"),
            use_auxiliary_llm=bool(payload.get("use_auxiliary_llm", False)),
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "analyze_batch":
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            messages = []
        result = analyze_batch([str(m) for m in messages])
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "inspect_url":
        raw_url = str(payload.get("url", "")).strip()
        if not raw_url:
            print(json.dumps({"error": "url is required"}))
            return 1
        result = probe_url_live(
            raw_url,
            include_intel=bool(payload.get("include_intel", True)),
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "sandbox_url":
        raw_url = str(payload.get("url", "")).strip()
        if not raw_url:
            print(json.dumps({"error": "url is required"}))
            return 1
        result = detonate_url_in_sandbox(raw_url)
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "academic_analyze":
        result = analyze_academic_text(
            text=str(payload.get("text", "")),
            reference_text=payload.get("reference_text"),
            behavior=payload.get("behavior"),
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "dlp_scan":
        result = scan_dlp_content(str(payload.get("text", "")))
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "cert_issue":
        result = issue_certificate(
            title=str(payload.get("title", "")),
            author=str(payload.get("author", "")),
            institution=str(payload.get("institution", "")),
            text=str(payload.get("text", "")),
            originality_score=int(payload.get("originality_score", 0)),
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "cert_verify":
        result = verify_certificate(str(payload.get("query", "")))
        print(json.dumps(result, ensure_ascii=False))
        return 0

    if action == "dashboard":
        print(json.dumps(get_dashboard_summary(), ensure_ascii=False))
        return 0

    if action == "sandbox_benchmark":
        res = run_sandbox_benchmark(
            department=str(payload.get("department", "")),
            load_size=int(payload.get("load_size", 30)),
        )
        print(json.dumps(res, ensure_ascii=False))
        return 0

    if action == "sandbox_runs":
        print(json.dumps({"history": list_sandbox_runs()}, ensure_ascii=False))
        return 0

    if action == "saas_register":
        res = register_saas_tenant(
            university_name=str(payload.get("university_name", "")),
            student_count=int(payload.get("student_count", 1000)),
            faculty_count=int(payload.get("faculty_count", 50)),
            plan_tier=str(payload.get("plan_tier", "campus")),
        )
        print(json.dumps(res, ensure_ascii=False))
        return 0

    if action == "saas_list":
        print(json.dumps(list_saas_tenants(), ensure_ascii=False))
        return 0

    if action == "saas_delete":
        res = delete_saas_tenant(str(payload.get("tenant_code", "")))
        print(json.dumps(res, ensure_ascii=False))
        return 0

    if action == "quiz":
        print(json.dumps({"scenarios": get_quiz_scenarios()}, ensure_ascii=False))
        return 0

    if action == "quiz_verify":
        res = verify_quiz_answer(
            scenario_id=str(payload.get("id", "")),
            user_says_scam=bool(payload.get("is_scam", False)),
            lang=str(payload.get("lang", "ar")),
        )
        print(json.dumps(res, ensure_ascii=False))
        return 0

    if action == "report":
        res = save_report(
            category=str(payload.get("category", "other")),
            score=int(payload.get("score", 0)),
            fingerprint=str(payload.get("fingerprint", "")),
        )
        print(json.dumps(res, ensure_ascii=False))
        return 0

    if action == "trending":
        items = get_trending()
        stats = get_community_stats()
        print(json.dumps({"items": items, "stats": stats}, ensure_ascii=False))
        return 0

    if action == "evaluate":
        print(json.dumps(run_all_evaluations(), ensure_ascii=False))
        return 0

    print(json.dumps({"error": "unknown action"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
