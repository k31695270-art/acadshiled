"""FastAPI server for Kashf × AcadShield AI academic & cybersecurity platform."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from academic_analyzer import analyze_academic_text, scan_dlp_content
from analyzer import analyze_batch, analyze_message
from blockchain import get_dashboard_summary, issue_certificate, verify_certificate
from db import get_community_stats, get_trending, init_db, save_report
from quiz import get_quiz_scenarios, verify_quiz_answer
from saas_sandbox import (
    delete_saas_tenant,
    list_saas_tenants,
    list_sandbox_runs,
    register_saas_tenant,
    run_sandbox_benchmark,
)
from url_inspector import probe_url_live

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
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

_rate_buckets: dict[str, Deque[float]] = defaultdict(deque)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    url: str | None = Field(default=None, max_length=2000)


class BatchAnalyzeRequest(BaseModel):
    messages: list[str] = Field(..., min_length=1, max_length=25)


class InspectUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2000)


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


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def _check_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail="تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.",
        )
    bucket.append(now)


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
    return analyze_message(text, payload.url)


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
    return probe_url_live(payload.url.strip())


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
def cert_issue_endpoint(payload: CertificateIssueRequest):
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
def sandbox_benchmark_endpoint(payload: SandboxBenchmarkRequest):
    return run_sandbox_benchmark(payload.department, payload.load_size)


@app.get("/api/sandbox/runs")
def sandbox_runs_endpoint():
    return {"history": list_sandbox_runs()}


@app.get("/api/saas/tenants")
def saas_list_endpoint():
    return list_saas_tenants()


@app.post("/api/saas/tenants")
def saas_register_endpoint(payload: SaasTenantRequest):
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
def saas_delete_endpoint(tenant_code: str):
    return delete_saas_tenant(tenant_code)


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
def report(payload: ReportRequest):
    return save_report(
        category=payload.category,
        score=payload.score,
        fingerprint=payload.fingerprint,
    )


@app.get("/api/trending")
def trending():
    return {"items": get_trending(), "stats": get_community_stats()}
