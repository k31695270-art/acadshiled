"""SQLite persistence for anonymous scam reports and 7-day trending aggregates."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import TypedDict

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent / "kashf.db")
SECONDS_IN_DAY = 86400
DEDUP_WINDOW_SECONDS = SECONDS_IN_DAY
TRENDING_DAYS = 7

VALID_CATEGORIES = {
    "phishing_bank",
    "fake_prize",
    "fake_delivery",
    "investment_fraud",
    "otp_theft",
    "fake_job",
    "other",
}


class TrendingItem(TypedDict):
    category: str
    count: int
    avg_score: int
    daily: list[int]


def get_db_path() -> str:
    return os.environ.get("KASHF_DB_PATH", DEFAULT_DB_PATH)


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | None = None) -> None:
    """Create the reports table and timestamp index if they do not exist."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                category TEXT NOT NULL,
                score INTEGER NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts)")
        conn.commit()


def save_report(
    category: str,
    score: int,
    fingerprint: str,
    now: float | None = None,
    db_path: str | None = None,
) -> dict[str, bool]:
    """Save an anonymous report; deduplicate identical fingerprints within 24 hours."""
    init_db(db_path)
    ts_now = now if now is not None else time.time()
    clean_category = category if category in VALID_CATEGORIES else "other"
    clean_score = max(0, min(100, int(score)))
    clean_fp = (fingerprint or "").strip().lower()[:16]
    if not clean_fp:
        raise ValueError("fingerprint is required")

    cutoff = ts_now - DEDUP_WINDOW_SECONDS
    with get_connection(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM reports WHERE fingerprint = ? AND ts >= ? LIMIT 1",
            (clean_fp, cutoff),
        ).fetchone()

        if existing is not None:
            return {"ok": True, "deduplicated": True}

        conn.execute(
            "INSERT INTO reports (fingerprint, category, score, ts) VALUES (?, ?, ?, ?)",
            (clean_fp, clean_category, clean_score, ts_now),
        )
        conn.commit()
    return {"ok": True, "deduplicated": False}


def get_trending(
    now: float | None = None,
    db_path: str | None = None,
) -> list[TrendingItem]:
    """Return last-7-days report counts and daily sparkline buckets per category."""
    init_db(db_path)
    ts_now = now if now is not None else time.time()
    window_start = ts_now - (TRENDING_DAYS * SECONDS_IN_DAY)

    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT category, score, ts FROM reports WHERE ts >= ? ORDER BY ts ASC",
            (window_start,),
        ).fetchall()

    grouped: dict[str, dict[str, object]] = {}
    for row in rows:
        cat = str(row["category"])
        score = int(row["score"])
        ts = float(row["ts"])

        if cat not in grouped:
            grouped[cat] = {
                "count": 0,
                "score_sum": 0,
                "daily": [0] * TRENDING_DAYS,
            }

        entry = grouped[cat]
        entry["count"] = int(entry["count"]) + 1  # type: ignore[arg-type]
        entry["score_sum"] = int(entry["score_sum"]) + score  # type: ignore[arg-type]

        # Day bucket: 0 = oldest (6 days ago), 6 = most recent 24h
        days_ago = int((ts_now - ts) // SECONDS_IN_DAY)
        bucket = max(0, min(TRENDING_DAYS - 1, (TRENDING_DAYS - 1) - days_ago))
        daily_list: list[int] = entry["daily"]  # type: ignore[assignment]
        daily_list[bucket] += 1

    results: list[TrendingItem] = []
    for cat, entry in grouped.items():
        count = int(entry["count"])  # type: ignore[arg-type]
        score_sum = int(entry["score_sum"])  # type: ignore[arg-type]
        daily_list = entry["daily"]  # type: ignore[assignment]
        results.append(
            {
                "category": cat,
                "count": count,
                "avg_score": round(score_sum / count) if count > 0 else 0,
                "daily": daily_list,
            }
        )

    results.sort(key=lambda item: item["count"], reverse=True)
    return results


def get_community_stats(
    now: float | None = None,
    db_path: str | None = None,
) -> dict[str, object]:
    """Return high-level 7-day community statistics without exposing message contents."""
    items = get_trending(now=now, db_path=db_path)
    total_reports = sum(item["count"] for item in items)
    if total_reports == 0:
        return {
            "total_reports": 0,
            "active_categories": 0,
            "avg_score": 0,
            "top_category": None,
        }

    weighted_sum = sum(item["count"] * item["avg_score"] for item in items)
    return {
        "total_reports": total_reports,
        "active_categories": len(items),
        "avg_score": round(weighted_sum / total_reports),
        "top_category": items[0]["category"],
    }

