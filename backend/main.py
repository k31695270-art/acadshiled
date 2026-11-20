"""FastAPI server for Kashf × AcadShield AI academic & cybersecurity platform."""

from __future__ import annotations

import re
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from academic_analyzer import analyze_academic_text, scan_dlp_content
from analyzer import analyze_batch, analyze_message
from blockchain import get_dashboard_summary, issue_certificate, verify_certificate
from db import check_rate_limit, get_community_stats, get_trending, init_db, save_report
from dev_console import (
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
from evaluate_models import run_all_evaluations
from quiz import get_quiz_scenarios, verify_quiz_answer
from saas_sandbox import (
    delete_saas_tenant,
    list_saas_tenants,
    list_sandbox_runs,
    register_saas_tenant,
    run_sandbox_benchmark,
)
from url_inspector import probe_url_live
from url_sandbox import detonate_url_in_sandbox

RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60.0

app = FastAPI(title="Kashf × AcadShield API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

_TENANT_CODE_RE = re.compile(r"^IQ-UNI-\d{3,6}$")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    url: str | None = Field(default=None, max_length=2000)
    use_auxiliary_llm: bool = False


class BatchAnalyzeRequest(BaseModel):
    messages: list[str] = Field(..., min_length=1, max_length=25)


class InspectUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2000)
    include_intel: bool = True


class AcademicAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=15000)
    reference_text: str | None = Field(default=None, max_length=15000)
    behavior: dict[str, Any] | None = None


class DlpScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)


class CertificateIssueRequest(BaseModel):
    title: str = Field(..., min_length=2, max_length=160)
    author: str = Field(..., min_length=2, max_length=100)
    institution: str = Field(default="الجامعة التكنولوجية", max_length=120)
    text: str = Field(..., min_length=10, max_length=15000)
    originality_score: int = Field(..., ge=0, le=100)


class QuizVerifyRequest(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    is_scam: bool
    lang: str = Field(default="ar", max_length=4)


class ReportRequest(BaseModel):
    category: str = Field(..., min_length=1, max_length=64)
    score: int = Field(..., ge=0, le=100)
    fingerprint: str = Field(..., min_length=8, max_length=64)


class SandboxBenchmarkRequest(BaseModel):
    department: str = Field(default="الجامعة التكنولوجية — قسم علوم الحاسوب", max_length=140)
    load_size: int = Field(default=30, ge=6, le=90)


class SaasTenantRequest(BaseModel):
    university_name: str = Field(..., min_length=2, max_length=140)
    student_count: int = Field(..., ge=50, le=500000)
    faculty_count: int = Field(..., ge=5, le=50000)
    plan_tier: str = Field(default="campus", max_length=20)


class DevBootstrapRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., min_length=4, max_length=140)
    password: str = Field(..., min_length=8, max_length=128)
    bootstrap_key: str | None = Field(default=None, max_length=128)


class DevLoginRequest(BaseModel):
    email: str = Field(..., min_length=4, max_length=140)
    password: str = Field(..., min_length=1, max_length=128)


class DevInviteClaimRequest(BaseModel):
    invite_token: str = Field(..., min_length=6, max_length=160)
    name: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., min_length=4, max_length=140)
    password: str = Field(..., min_length=8, max_length=128)


class DevInviteCreateRequest(BaseModel):
    role: str = Field(default="viewer", max_length=16)
    note: str = Field(default="", max_length=140)


class DevDomainRuleRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=180)
    rule_type: str = Field(default="blocklist", max_length=16)
    note: str = Field(default="", max_length=140)


class DevUserUpdateRequest(BaseModel):
    role: str | None = Field(default=None, max_length=16)
    active: bool | None = None


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def _check_rate_limit(client_ip: str) -> None:
    allowed = check_rate_limit(
        f"api:{client_ip}",
        max_requests=RATE_LIMIT_MAX_REQUESTS,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.",
        )


@app.get("/api/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Message text is required")
    return analyze_message(text, payload.url, use_auxiliary_llm=payload.use_auxiliary_llm)


@app.post("/api/analyze-batch")
def analyze_batch_endpoint(payload: BatchAnalyzeRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    cleaned = [m.strip() for m in payload.messages if m and m.strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="At least one non-empty message is required")
    return analyze_batch(cleaned[:25])


@app.post("/api/inspect-url")
def inspect_url_endpoint(payload: InspectUrlRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    settings = get_runtime_settings()
    include_intel = bool(payload.include_intel) and bool(settings.get("enable_live_threat_intel", True))
    return probe_url_live(payload.url.strip(), include_intel=include_intel)


@app.post("/api/sandbox-url")
def sandbox_url_endpoint(payload: InspectUrlRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    settings = get_runtime_settings()
    if not settings.get("enable_url_sandbox", True):
        raise HTTPException(
            status_code=503,
            detail="Safe URL Sandbox is currently disabled by administrator settings.",
        )
    return detonate_url_in_sandbox(payload.url.strip())


@app.post("/api/academic/analyze")
def academic_analyze_endpoint(payload: AcademicAnalyzeRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return analyze_academic_text(payload.text, payload.reference_text, payload.behavior)


@app.post("/api/dlp/scan")
def dlp_scan_endpoint(payload: DlpScanRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return scan_dlp_content(payload.text)


@app.post("/api/certificates/issue")
def cert_issue_endpoint(payload: CertificateIssueRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        return issue_certificate(
            title=payload.title,
            author=payload.author,
            institution=payload.institution,
            text=payload.text,
            originality_score=payload.originality_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/certificates/verify")
def cert_verify_endpoint(q: str = ""):
    return verify_certificate(q)


@app.get("/api/dashboard")
def dashboard_endpoint():
    return get_dashboard_summary()


@app.post("/api/sandbox/benchmark")
def sandbox_benchmark_endpoint(payload: SandboxBenchmarkRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return run_sandbox_benchmark(payload.department, payload.load_size)


@app.get("/api/sandbox/runs")
def sandbox_runs_endpoint():
    return {"history": list_sandbox_runs()}


@app.get("/api/saas/tenants")
def saas_list_endpoint():
    return list_saas_tenants()


@app.post("/api/saas/tenants")
def saas_register_endpoint(payload: SaasTenantRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        return register_saas_tenant(
            university_name=payload.university_name,
            student_count=payload.student_count,
            faculty_count=payload.faculty_count,
            plan_tier=payload.plan_tier,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/saas/tenants/{tenant_code}")
def saas_delete_endpoint(tenant_code: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    cleaned = tenant_code.strip()
    if not _TENANT_CODE_RE.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid tenant code format")
    return delete_saas_tenant(cleaned)


@app.get("/api/quiz")
def quiz_list():
    return {"scenarios": get_quiz_scenarios()}


@app.post("/api/quiz/verify")
def quiz_verify(payload: QuizVerifyRequest):
    try:
        return verify_quiz_answer(payload.id, payload.is_scam, payload.lang)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/report")
def report(payload: ReportRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return save_report(
        category=payload.category,
        score=payload.score,
        fingerprint=payload.fingerprint,
    )


@app.get("/api/trending")
def trending():
    return {"items": get_trending(), "stats": get_community_stats()}


@app.get("/api/evaluation")
def evaluation_endpoint(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    return run_all_evaluations()


@app.get("/api/public-config")
def public_config_endpoint():
    return get_public_config()


@app.post("/api/dev/bootstrap")
def dev_bootstrap_endpoint(payload: DevBootstrapRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        return bootstrap_owner(
            name=payload.name,
            email=payload.email,
            password=payload.password,
            bootstrap_key=payload.bootstrap_key,
        )
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/dev/login")
def dev_login_endpoint(payload: DevLoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        return login_developer(email=payload.email, password=payload.password)
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/dev/invite/claim")
def dev_invite_claim_endpoint(payload: DevInviteClaimRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        return claim_invite(
            invite_token=payload.invite_token,
            name=payload.name,
            email=payload.email,
            password=payload.password,
        )
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.get("/api/dev/overview")
def dev_overview_endpoint(request: Request):
    try:
        actor = authenticate_token(
            request.headers.get("authorization"),
            ("owner", "editor", "viewer"),
        )
        return get_dev_overview(actor)
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.put("/api/dev/settings")
def dev_settings_update_endpoint(payload: dict[str, Any], request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        actor = authenticate_token(
            request.headers.get("authorization"),
            ("owner", "editor"),
        )
        return {"settings": update_runtime_settings(actor, payload)}
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/dev/domain-rules")
def dev_domain_add_endpoint(payload: DevDomainRuleRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        actor = authenticate_token(
            request.headers.get("authorization"),
            ("owner", "editor"),
        )
        return {
            "domain_rules": upsert_domain_rule(
                actor,
                domain=payload.domain,
                rule_type=payload.rule_type,
                note=payload.note,
            )
        }
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.delete("/api/dev/domain-rules/{domain}")
def dev_domain_delete_endpoint(domain: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        actor = authenticate_token(
            request.headers.get("authorization"),
            ("owner", "editor"),
        )
        return {"domain_rules": delete_domain_rule(actor, domain=domain)}
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/dev/invites")
def dev_invite_create_endpoint(payload: DevInviteCreateRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        actor = authenticate_token(request.headers.get("authorization"), ("owner",))
        return create_invite(actor, role=payload.role, note=payload.note)
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.patch("/api/dev/users/{user_id}")
def dev_user_update_endpoint(user_id: int, payload: DevUserUpdateRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    try:
        actor = authenticate_token(request.headers.get("authorization"), ("owner",))
        return {
            "user": update_developer_access(
                actor,
                target_user_id=user_id,
                role=payload.role,
                active=payload.active,
            )
        }
    except DevAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
