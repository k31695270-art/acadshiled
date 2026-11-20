"""Comprehensive security, concurrency, edge-case, and bridge integration audit suite."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

import academic_analyzer  # noqa: E402
import ai_detector  # noqa: E402
import ai_training_corpus  # noqa: E402
import analyzer  # noqa: E402
import blockchain  # noqa: E402
import db  # noqa: E402
import eval_datasets  # noqa: E402
import evaluate_models  # noqa: E402
import saas_sandbox  # noqa: E402
import url_inspector  # noqa: E402
import url_sandbox  # noqa: E402


def _make_temp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    return path


def _cleanup_temp_db(path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = f"{path}{suffix}"
        if os.path.exists(candidate):
            os.remove(candidate)


class SecurityAuditTestSuite(unittest.TestCase):
    # 1. SSRF, Unsafe Schemes, DNS-Rebinding Redirect Trap & 4-State Honesty
    def test_ssrf_private_ips_schemes_and_localhost_port(self) -> None:
        ssrf_targets = [
            "http://127.0.0.1/admin",
            "http://[::1]:8080/secret",
            "http://[::ffff:127.0.0.1]/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/internal",
            "http://10.0.0.5/login",
            "localhost:3000",
        ]
        for target in ssrf_targets:
            probe = url_inspector.probe_url_live(target, include_intel=False)
            self.assertFalse(probe["dns"]["resolved"], f"Expected SSRF block for {target}")
            self.assertEqual(probe["classification"], "malicious", f"Expected malicious classification for {target}")

            sbx = url_sandbox.detonate_url_in_sandbox(target)
            self.assertEqual(sbx["execution_mode"], "blocked_ssrf", f"Expected blocked_ssrf for {target}")
            self.assertEqual(sbx["verdict"], "dangerous")

        for scheme_target in ["ftp://127.0.0.1/file", "gopher://localhost:6379/_INFO", "javascript:alert(1)"]:
            sbx = url_sandbox.detonate_url_in_sandbox(scheme_target)
            self.assertEqual(sbx["execution_mode"], "blocked_unsafe_scheme", f"Expected blocked_unsafe_scheme for {scheme_target}")
            self.assertEqual(sbx["verdict"], "dangerous")

            probe = url_inspector.probe_url_live(scheme_target, include_intel=False)
            self.assertFalse(probe["dns"]["resolved"])
            self.assertEqual(probe["classification"], "malicious")

    def test_redirect_to_loopback_blocked_and_unseen_tls_domain_stays_unknown(self) -> None:
        # Redirect trap: public hop -> 302 Location: http://127.0.0.1/admin
        def fake_resolve(host: str):
            if host == "public-redirector.example":
                return True, ["93.184.216.34"], None
            return False, [], f"Blocked non-public/internal IP address: 127.0.0.1"

        with patch.object(url_inspector, "_resolve_public_host", side_effect=fake_resolve), patch.object(
            url_inspector,
            "lookup_dns_records",
            return_value={"available": True, "a": ["93.184.216.34"], "mx": [], "txt": [], "has_spf": False, "error": None},
        ), patch.object(
            url_inspector,
            "lookup_rdap_domain_age",
            return_value={"available": False, "domain": "public-redirector.example", "age_days": None, "error": "skipped"},
        ), patch.object(
            url_inspector, "_inspect_tls", return_value={"available": True, "valid": True, "issuer": "Test CA", "days_remaining": 60}
        ), patch.object(
            url_inspector,
            "_pinned_http_request",
            return_value=(302, {"Location": "http://127.0.0.1/admin"}, b""),
        ):
            probe = url_inspector.probe_url_live("https://public-redirector.example/go", include_intel=False)
            self.assertEqual(probe["classification"], "malicious")
            self.assertTrue(any(ev["id"] == "ssrf_redirect_blocked" for ev in probe["evidence_bundle"]["evidence"]))

            sbx = url_sandbox.detonate_url_in_sandbox("https://public-redirector.example/go")
            self.assertEqual(sbx["execution_mode"], "blocked_ssrf")
            self.assertEqual(sbx["verdict"], "dangerous")
            self.assertTrue(any(act["id"] == "ssrf_redirect_blocked" for act in sbx["what_it_tries_to_do"]))

        # Unseen non-official domain with valid TLS + NO threat-intel hit -> MUST be 'unknown', not 'no_known_threat'
        with patch.object(url_inspector, "_resolve_public_host", return_value=(True, ["93.184.216.34"], None)), patch.object(
            url_inspector,
            "lookup_dns_records",
            return_value={"available": True, "a": ["93.184.216.34"], "mx": [], "txt": [], "has_spf": False, "error": None},
        ), patch.object(
            url_inspector,
            "lookup_rdap_domain_age",
            return_value={"available": True, "domain": "brandnew-unseen-portal.com", "age_days": 120, "registered_at": "2026-07-01T00:00:00Z"},
        ), patch.object(
            url_inspector, "_inspect_tls", return_value={"available": True, "valid": True, "issuer": "Let's Encrypt", "days_remaining": 80}
        ), patch.object(
            url_inspector, "_pinned_http_request", return_value=(200, {}, b"")
        ):
            unseen_probe = url_inspector.probe_url_live("https://brandnew-unseen-portal.com/", include_intel=False)
            self.assertEqual(unseen_probe["classification"], "unknown")

    # 2. SQLite Concurrency & Hash-Chain Tampering Detection
    def test_concurrent_hash_chain_certificates_and_tamper_detection(self) -> None:
        temp_db = _make_temp_db()
        try:
            def issue_one(idx: int):
                return blockchain.issue_certificate(
                    title=f"Concurrent Research Paper #{idx}",
                    author=f"Researcher {idx}",
                    institution="University of Technology",
                    text=f"Original academic manuscript content block number {idx} covering cybersecurity defenses.",
                    originality_score=90,
                    db_path=temp_db,
                )

            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(issue_one, range(10)))

            indices = sorted(r["block_index"] for r in results)
            self.assertEqual(indices, list(range(1, 11)))
            self.assertTrue(blockchain.verify_chain_integrity(db_path=temp_db))

            # Tamper with row #3 in SQLite and prove chain integrity catches it
            with sqlite3.connect(temp_db) as conn:
                conn.execute("UPDATE ledger_blocks SET originality_score = 99 WHERE block_index = 3")
                conn.commit()
            self.assertFalse(blockchain.verify_chain_integrity(db_path=temp_db))
        finally:
            _cleanup_temp_db(temp_db)

    def test_concurrent_saas_registration_and_persistent_rate_limit(self) -> None:
        temp_db = _make_temp_db()
        try:
            def reg_one(idx: int):
                return saas_sandbox.register_saas_tenant(
                    university_name=f"Iraqi University #{idx}",
                    student_count=4000 + idx * 100,
                    faculty_count=200 + idx * 10,
                    plan_tier="campus",
                    db_path=temp_db,
                )

            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(reg_one, range(6)))

            listed = saas_sandbox.list_saas_tenants(db_path=temp_db)
            self.assertEqual(listed["summary"]["tenant_count"], 6)

            # Sliding-window persistent rate limiter in SQLite
            for _ in range(5):
                self.assertTrue(db.check_rate_limit("api:10.1.2.3", max_requests=5, window_seconds=60.0, now=1000.0, db_path=temp_db))
            self.assertFalse(db.check_rate_limit("api:10.1.2.3", max_requests=5, window_seconds=60.0, now=1010.0, db_path=temp_db))
            # Allowed again once window expires
            self.assertTrue(db.check_rate_limit("api:10.1.2.3", max_requests=5, window_seconds=60.0, now=1065.0, db_path=temp_db))
        finally:
            _cleanup_temp_db(temp_db)

    # 3. Message Analyzer Edge Cases & Secure Gemini Header Usage
    def test_message_edge_cases_and_gemini_header(self) -> None:
        # 1) Legit bank OTP reminder without phishing URL -> safe
        res1 = analyzer.analyze_message("رمز التحقق الخاص بك هو 482910. لا تشارك هذا الرمز مع أي شخص حتى موظفي البنك.")
        self.assertEqual(res1["verdict"], "safe")

        # 2) Isolated benign word ('عاجل' / 'مجاني') in campus notice -> safe
        res2 = analyzer.analyze_message("تنويه عاجل: محاضرة مجانية لطلبة قسم علوم الحاسوب غداً الساعة العاشرة في القاعة الرئيسية.")
        self.assertEqual(res2["verdict"], "safe")

        # 3) Iraqi dialect ZainCash/Asiacell wallet freeze + recharge coercion -> suspicious/dangerous
        res3 = analyzer.analyze_message("تنبيه: تم تجميد محفظتك مؤقتاً، يرجى التحويل أو حول رصيد لتفعيل الحساب فوراً.")
        self.assertIn(res3["verdict"], {"suspicious", "dangerous"})

        # 4) Subtle BEC invoice routing change
        res4 = analyzer.analyze_message("Please use the updated invoice and wire funds to our new settlement account before 4pm today.")
        self.assertIn(res4["verdict"], {"suspicious", "dangerous"})

        # 5) Fake courier + shortener
        res5 = analyzer.analyze_message("تعذر تسليم الطرد، يرجى دفع رسوم بسيطة عبر bit.ly/3x9demo لتأكيد التوصيل.")
        self.assertIn(res5["verdict"], {"suspicious", "dangerous"})

        # 6) Official PayPal domain notification -> safe
        res6 = analyzer.analyze_message("Review your monthly statement inside https://www.paypal.com/activity anytime.")
        self.assertEqual(res6["verdict"], "safe")

        # 7) Gemini API key must be sent via x-goog-api-key header, NEVER query parameter
        captured_req = {}

        class _FakeGeminiResp:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _n: int = -1):
                return json.dumps({"candidates": [{"content": {"parts": [{"text": json.dumps({"cue_detected": False, "summary_ar": "سليم", "summary_en": "Benign"})}]}}]}).encode("utf-8")

        def fake_urlopen(req, timeout=4.0):
            captured_req["url"] = req.full_url
            captured_req["headers"] = {k.lower(): v for k, v in req.header_items()}
            return _FakeGeminiResp()

        with patch.dict(os.environ, {"GEMINI_API_KEY": "secret-test-gemini-key"}), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            aux = analyzer._run_optional_gemini_auxiliary("رسالة تجربة آمنة")
            self.assertTrue(aux["used"])
            self.assertNotIn("secret-test-gemini-key", captured_req["url"])
            self.assertEqual(captured_req["headers"].get("x-goog-api-key"), "secret-test-gemini-key")

    # 4. DLP True Positives & False Positive Protection
    def test_dlp_true_and_false_positives(self) -> None:
        leaky_doc = (
            "DB_PASSWORD=SuperSecretPass123\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Authorization: Bearer tok_9876543210abcdef_real_secret\n"
            "OPENAI=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456\n"
            "SLACK=xoxb-1234567890-123456789012-abcdefghij\n"
            "STRIPE=sk_live_51AbCdEfGhIjKlMnOpQrSt123456\n"
            "JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.sig_xyz123\n"
            "VISA=4532015112830366\n"
        )
        res = academic_analyzer.scan_dlp_content(leaky_doc)
        ids = {f["id"] for f in res["dlp_findings"]}
        self.assertTrue({"env_secret", "private_key", "bearer_token", "api_key", "jwt_token", "payment_card"}.issubset(ids))
        serialized = json.dumps(res)
        self.assertNotIn("SuperSecretPass123", serialized)
        self.assertNotIn("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456", serialized)
        self.assertNotIn("4532015112830366", serialized)

        # Invalid Luhn 16-digit tracking/student ID should NOT trigger payment_card
        benign_doc = "Student Reference Tracking Number: 4532015112830367 recorded in registry."
        res_clean = academic_analyzer.scan_dlp_content(benign_doc)
        clean_ids = {f["id"] for f in res_clean["dlp_findings"]}
        self.assertNotIn("payment_card", clean_ids)

    # 5. AI Detector Originality Honesty, Limitations & Train/Eval Disjointness
    def test_academic_short_text_no_fake_penalty_and_limitations(self) -> None:
        short_res = academic_analyzer.analyze_academic_text(
            "هذه جملة بحثية قصيرة جدا لفحص الأصالة بدون استلال."
        )
        self.assertIsNone(short_res["ai_probability"])
        self.assertEqual(short_res["originality_score"], 100)
        lim_codes = {item["code"] for item in short_res["ai_detection"]["evidence_bundle"]["limitations"]}
        self.assertIn("small_calibration_corpus", lim_codes)
        self.assertIn("offline_plagiarism_scope", lim_codes)

        # Disjointness between training and evaluation corpora
        train_texts = {text.strip() for text, _ in (ai_training_corpus.TRAIN_AR + ai_training_corpus.TRAIN_EN)}
        eval_texts = {item["text"].strip() for item in eval_datasets.AI_EVAL_SET}
        self.assertEqual(train_texts.intersection(eval_texts), set())

        eval_report = evaluate_models.run_all_evaluations()
        self.assertGreaterEqual(eval_report["url_analyzer"]["accuracy"], 0.85)
        self.assertGreaterEqual(eval_report["message_analyzer"]["accuracy"], 0.85)
        self.assertGreaterEqual(eval_report["ai_detector"]["accuracy"], 0.8)

    # 6. End-to-End bridge.py Stdin JSON + Persistent 429 Enforcement
    def test_bridge_e2e_actions_and_rate_limit(self) -> None:
        temp_db = _make_temp_db()
        try:
            env = {**os.environ, "KASHF_DB_PATH": temp_db}

            def call_bridge(payload: dict) -> dict:
                proc = subprocess.run(
                    [sys.executable, str(BACKEND_DIR / "bridge.py")],
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=15,
                    check=True,
                )
                return json.loads(proc.stdout)

            analyze_res = call_bridge({"action": "analyze", "text": "مبروك ربحت 5000$ عبر http://paypa1-secure.xyz/login"})
            self.assertEqual(analyze_res["verdict"], "dangerous")

            sbx_res = call_bridge({"action": "sandbox_url", "url": "http://127.0.0.1:8080/admin"})
            self.assertEqual(sbx_res["execution_mode"], "blocked_ssrf")

            dlp_res = call_bridge({"action": "dlp_scan", "text": "SECRET_KEY=top_secret_val_999"})
            self.assertGreaterEqual(len(dlp_res["dlp_findings"]), 1)

            acad_res = call_bridge({"action": "academic_analyze", "text": "نص أكاديمي قصير لاختبار جسر البايثون والتكامل."})
            self.assertIn("originality_score", acad_res)

            cert = call_bridge({
                "action": "cert_issue",
                "title": "Bridge Integration Study",
                "author": "Test Researcher",
                "institution": "University of Technology",
                "text": "Research manuscript text for bridge integration certificate issuance verification.",
                "originality_score": 91,
            })
            self.assertTrue(cert["cert_id"].startswith("ACAD-0001-"))

            verify = call_bridge({"action": "cert_verify", "query": cert["cert_id"]})
            self.assertTrue(verify["found"])
            self.assertTrue(verify["chain_valid"])

            quiz = call_bridge({"action": "quiz"})
            self.assertEqual(len(quiz["scenarios"]), 20)

            rep = call_bridge({"action": "report", "category": "otp_theft", "score": 85, "fingerprint": "abc12345def67890"})
            self.assertTrue(rep["ok"])
            self.assertFalse(rep["deduplicated"])

            tr = call_bridge({"action": "trending"})
            self.assertGreaterEqual(tr["stats"]["total_reports"], 1)

            # Verify rate limit triggers 429 on 31st request from same _client_ip across bridge calls
            with db.get_connection(temp_db) as conn:
                now = __import__("time").time()
                conn.executemany(
                    "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
                    [("api:198.51.100.77", now) for _ in range(30)],
                )
                conn.commit()
            limited = call_bridge({"action": "analyze", "_client_ip": "198.51.100.77", "text": "hello world"})
            self.assertTrue(limited.get("_http_error"))
            self.assertEqual(limited.get("status_code"), 429)
        finally:
            _cleanup_temp_db(temp_db)


if __name__ == "__main__":
    unittest.main(verbosity=2)
