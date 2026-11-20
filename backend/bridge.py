"""Stdlib JSON bridge so the Express dev server executes the exact Python analyzer & SQLite DB."""

from __future__ import annotations

import json
import re
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
from db import check_rate_limit, get_community_stats, get_trending, init_db, save_report  # noqa: E402
from dev_console import (  # noqa: E402
    DevAuthError,
    authenticate_token,
    bootstrap_owner,
    claim_invite,
    create_invite,
    delete_domain_rule,
    get_dev_overview,
    get_public_config,
    get_runtime_settings,
    login_developer,
    update_developer_access,
    update_runtime_settings,
    upsert_domain_rule,
)
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

_RATE_LIMITED_ACTIONS = {
    "analyze",
    "analyze_batch",
    "inspect_url",
    "sandbox_url",
    "academic_analyze",
    "dlp_scan",
    "cert_issue",
    "sandbox_benchmark",
    "saas_register",
    "saas_delete",
    "report",
    "evaluate",
    "dev_bootstrap",
    "dev_login",
    "dev_invite_claim",
    "dev_settings_update",
    "dev_domain_add",
    "dev_domain_delete",
    "dev_invite_create",
    "dev_user_update",
}
_TENANT_CODE_RE = re.compile(r"^IQ-UNI-\d{3,6}$")


def main() -> int:
    init_db()
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    action = payload.get("action")
    client_ip = str(payload.get("_client_ip") or "").strip()

    try:
        if client_ip and action in _RATE_LIMITED_ACTIONS:
            if not check_rate_limit(f"api:{client_ip}", max_requests=30, window_seconds=60.0):
                print(
                    json.dumps(
                        {
                            "_http_error": True,
                            "status_code": 429,
                            "detail": "تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.",
                        },
                        ensure_ascii=False,
                    )
                )
                return 0

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
                print(json.dumps({"_http_error": True, "status_code": 400, "detail": "url is required"}))
                return 0
            settings = get_runtime_settings()
            include_intel = bool(payload.get("include_intel", True)) and bool(
                settings.get("enable_live_threat_intel", True)
            )
            result = probe_url_live(raw_url, include_intel=include_intel)
            print(json.dumps(result, ensure_ascii=False))
            return 0

        if action == "sandbox_url":
            settings = get_runtime_settings()
            if not settings.get("enable_url_sandbox", True):
                print(
                    json.dumps(
                        {
                            "_http_error": True,
                            "status_code": 503,
                            "detail": "Safe URL Sandbox is currently disabled by administrator settings.",
                        }
                    )
                )
                return 0
            raw_url = str(payload.get("url", "")).strip()
            if not raw_url:
                print(json.dumps({"_http_error": True, "status_code": 400, "detail": "url is required"}))
                return 0
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
            raw_score = int(payload.get("originality_score", 0))
            if raw_score < 0 or raw_score > 100:
                print(
                    json.dumps(
                        {
                            "_http_error": True,
                            "status_code": 400,
                            "detail": "originality_score must be between 0 and 100",
                        }
                    )
                )
                return 0
            result = issue_certificate(
                title=str(payload.get("title", "")),
                author=str(payload.get("author", "")),
                institution=str(payload.get("institution", "")),
                text=str(payload.get("text", "")),
                originality_score=raw_score,
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
            tenant_code = str(payload.get("tenant_code", "")).strip()
            if not _TENANT_CODE_RE.match(tenant_code):
                print(
                    json.dumps(
                        {
                            "_http_error": True,
                            "status_code": 400,
                            "detail": "Invalid tenant code format",
                        }
                    )
                )
                return 0
            res = delete_saas_tenant(tenant_code)
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

        if action == "public_config":
            print(json.dumps(get_public_config(), ensure_ascii=False))
            return 0

        if action == "dev_bootstrap":
            res = bootstrap_owner(
                name=str(payload.get("name", "")),
                email=str(payload.get("email", "")),
                password=str(payload.get("password", "")),
                bootstrap_key=payload.get("bootstrap_key"),
            )
            print(json.dumps(res, ensure_ascii=False))
            return 0

        if action == "dev_login":
            res = login_developer(
                email=str(payload.get("email", "")),
                password=str(payload.get("password", "")),
            )
            print(json.dumps(res, ensure_ascii=False))
            return 0

        if action == "dev_invite_claim":
            res = claim_invite(
                invite_token=str(payload.get("invite_token", "")),
                name=str(payload.get("name", "")),
                email=str(payload.get("email", "")),
                password=str(payload.get("password", "")),
            )
            print(json.dumps(res, ensure_ascii=False))
            return 0

        if action == "dev_overview":
            actor = authenticate_token(payload.get("auth_header"), ("owner", "editor", "viewer"))
            print(json.dumps(get_dev_overview(actor), ensure_ascii=False))
            return 0

        if action == "dev_settings_update":
            actor = authenticate_token(payload.get("auth_header"), ("owner", "editor"))
            updates = payload.get("settings") if isinstance(payload.get("settings"), dict) else {}
            updated = update_runtime_settings(actor, updates)
            print(json.dumps({"settings": updated}, ensure_ascii=False))
            return 0

        if action == "dev_domain_add":
            actor = authenticate_token(payload.get("auth_header"), ("owner", "editor"))
            rules = upsert_domain_rule(
                actor,
                domain=str(payload.get("domain", "")),
                rule_type=str(payload.get("rule_type", "blocklist")),
                note=str(payload.get("note", "")),
            )
            print(json.dumps({"domain_rules": rules}, ensure_ascii=False))
            return 0

        if action == "dev_domain_delete":
            actor = authenticate_token(payload.get("auth_header"), ("owner", "editor"))
            rules = delete_domain_rule(actor, domain=str(payload.get("domain", "")))
            print(json.dumps({"domain_rules": rules}, ensure_ascii=False))
            return 0

        if action == "dev_invite_create":
            actor = authenticate_token(payload.get("auth_header"), ("owner",))
            invite = create_invite(
                actor,
                role=str(payload.get("role", "viewer")),
                note=str(payload.get("note", "")),
            )
            print(json.dumps(invite, ensure_ascii=False))
            return 0

        if action == "dev_user_update":
            actor = authenticate_token(payload.get("auth_header"), ("owner",))
            updated_user = update_developer_access(
                actor,
                target_user_id=int(payload.get("target_user_id", 0)),
                role=payload.get("role"),
                active=payload.get("active"),
            )
            print(json.dumps({"user": updated_user}, ensure_ascii=False))
            return 0

        print(json.dumps({"_http_error": True, "status_code": 400, "detail": "unknown action"}))
        return 0
    except DevAuthError as exc:
        print(
            json.dumps(
                {
                    "_http_error": True,
                    "status_code": exc.status_code,
                    "detail": str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 0
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "_http_error": True,
                    "status_code": 400,
                    "detail": str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
