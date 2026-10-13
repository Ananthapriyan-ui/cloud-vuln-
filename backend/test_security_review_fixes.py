import unittest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import database
import models
import security
from config import Settings
from main import app
from ssrf_protection import (
    is_safe_public_ip,
    validate_public_url,
    validate_public_hostname_or_ip,
)


class TestSecurityReviewFindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.db = database.SessionLocal()

        # Create two test users
        cls.user1_email = "tester1@cloudvuln-security.io"
        cls.user2_email = "tester2@cloudvuln-security.io"

        cls.user1 = cls.db.query(models.User).filter(models.User.email == cls.user1_email).first()
        if not cls.user1:
            cls.user1 = models.User(
                email=cls.user1_email,
                full_name="Security Tester 1",
                hashed_password=security.get_password_hash("SecretPassword123!"),
                is_active=True,
            )
            cls.db.add(cls.user1)
            cls.db.commit()
            cls.db.refresh(cls.user1)

        cls.user2 = cls.db.query(models.User).filter(models.User.email == cls.user2_email).first()
        if not cls.user2:
            cls.user2 = models.User(
                email=cls.user2_email,
                full_name="Security Tester 2",
                hashed_password=security.get_password_hash("SecretPassword123!"),
                is_active=True,
            )
            cls.db.add(cls.user2)
            cls.db.commit()
            cls.db.refresh(cls.user2)

        cls.user1_token = security.create_access_token(data={"sub": cls.user1.email})
        cls.user2_token = security.create_access_token(data={"sub": cls.user2.email})
        cls.user1_headers = {"Authorization": f"Bearer {cls.user1_token}"}
        cls.user2_headers = {"Authorization": f"Bearer {cls.user2_token}"}

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # ─────────────────────────────────────────────────────────────
    # Finding 1: Google OAuth login cannot be forged
    # ─────────────────────────────────────────────────────────────
    def test_finding1_oauth_sync_rejects_missing_tokens(self):
        """Sending raw email without provider token must be rejected."""
        resp = self.client.post("/api/auth/oauth-sync", json={"email": "victim@example.com"})
        self.assertEqual(resp.status_code, 422)

    def test_finding1_oauth_sync_rejects_invalid_provider_token(self):
        """Forged or invalid provider token must return 401 Unauthorized."""
        resp = self.client.post("/api/auth/oauth-sync", json={"provider_token": "fake-forged-google-token-12345"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Failed to verify OAuth identity", resp.json().get("detail", ""))

    @patch("security.verify_oauth_provider_token")
    def test_finding1_oauth_sync_success_with_verified_token(self, mock_verify):
        """Server-side verified token must safely issue JWT for verified identity."""
        mock_verify.return_value = {
            "email": "verified-user@cloudvuln-security.io",
            "full_name": "Verified Google User",
            "provider": "google",
        }
        resp = self.client.post("/api/auth/oauth-sync", json={"id_token": "valid-simulated-token"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], "verified-user@cloudvuln-security.io")

    # ─────────────────────────────────────────────────────────────
    # Finding 2: Scan and report data requires auth and per-user scoping
    # ─────────────────────────────────────────────────────────────
    def test_finding2_unauthenticated_requests_blocked(self):
        """Unauthenticated access to scans, reports, and dashboard must return 401."""
        endpoints = [
            ("GET", "/api/dashboard/summary"),
            ("GET", "/api/dashboard/risk-statistics"),
            ("GET", "/api/dashboard/recent-scans"),
            ("GET", "/api/dashboard/activity"),
            ("GET", "/api/scans"),
            ("GET", "/api/scans/comparison-options"),
            ("GET", "/api/scans/trend"),
            ("GET", "/api/reports"),
        ]
        for method, url in endpoints:
            if method == "GET":
                resp = self.client.get(url)
            else:
                resp = self.client.post(url)
            self.assertEqual(resp.status_code, 401, f"Endpoint {url} was not protected (got {resp.status_code})")

    def test_finding2_per_user_scan_isolation(self):
        """Scans belonging to User 1 must not be accessible or deletable by User 2."""
        # Create scan for User 1
        create_resp = self.client.post(
            "/api/scans",
            headers=self.user1_headers,
            json={
                "target": "https://example.com",
                "provider": "AWS",
                "scan_type": "OWASP",
                "status": "passed",
                "risk_score": 1.5,
            },
        )
        self.assertEqual(create_resp.status_code, 201)
        scan_ref = create_resp.json()["scan_ref"]

        # User 1 can view it
        user1_view = self.client.get(f"/api/scans/{scan_ref}", headers=self.user1_headers)
        self.assertEqual(user1_view.status_code, 200)

        # User 2 CANNOT view it (returns 404)
        user2_view = self.client.get(f"/api/scans/{scan_ref}", headers=self.user2_headers)
        self.assertEqual(user2_view.status_code, 404)

        # User 2 CANNOT view report for it
        user2_report = self.client.get(f"/api/reports/{scan_ref}", headers=self.user2_headers)
        self.assertEqual(user2_report.status_code, 404)

        # User 2 CANNOT delete it
        user2_del = self.client.delete(f"/api/scans/{scan_ref}", headers=self.user2_headers)
        self.assertEqual(user2_del.status_code, 404)

        # User 1 CAN delete their own scan
        user1_del = self.client.delete(f"/api/scans/{scan_ref}", headers=self.user1_headers)
        self.assertEqual(user1_del.status_code, 200)

    # ─────────────────────────────────────────────────────────────
    # Finding 3: SSRF Protection
    # ─────────────────────────────────────────────────────────────
    def test_finding3_ssrf_rejects_private_and_metadata_ips(self):
        """SSRF protection must block private, loopback, and metadata IPs."""
        blocked_targets = [
            "127.0.0.1",
            "localhost",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "http://127.0.0.1:8000/admin",
            "http://localhost:3000",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "ftp://127.0.0.1",
        ]
        for target in blocked_targets:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    validate_public_url(target)

    def test_finding3_unauthenticated_analysis_blocked(self):
        """Analysis endpoints must require authentication."""
        resp = self.client.post("/api/analysis/target", json={"target_url": "https://example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_finding3_authenticated_ssrf_attempt_rejected(self):
        """Authenticated caller attempting SSRF against private IP must be rejected."""
        resp = self.client.post(
            "/api/analysis/target",
            headers=self.user1_headers,
            json={"target_url": "http://127.0.0.1:8000"},
        )
        self.assertEqual(resp.status_code, 422)  # Pydantic validation rejected URL

    def test_finding3_is_safe_public_ip(self):
        """is_safe_public_ip returns True for public IPs and False for internal/reserved."""
        self.assertTrue(is_safe_public_ip("8.8.8.8"))
        self.assertTrue(is_safe_public_ip("1.1.1.1"))
        self.assertFalse(is_safe_public_ip("127.0.0.1"))
        self.assertFalse(is_safe_public_ip("169.254.169.254"))
        self.assertFalse(is_safe_public_ip("10.0.0.5"))
        self.assertFalse(is_safe_public_ip("192.168.0.1"))
        self.assertFalse(is_safe_public_ip("::1"))

    # ─────────────────────────────────────────────────────────────
    # Finding 4: Insecure built-in JWT defaults prohibited in production
    # ─────────────────────────────────────────────────────────────
    def test_finding4_production_rejects_default_or_weak_jwt_secrets(self):
        """Settings must fail fast at startup in production if default/weak secrets are used."""
        # 1. Default secret in production mode
        with self.assertRaises(ValueError) as cm:
            Settings(
                APP_ENV="production",
                SECRET_KEY="cloudvuln-secops-super-secret-jwt-key-2026-prod-grade-change-me",
                REFRESH_SECRET_KEY="a-secure-random-64-character-refresh-secret-key-prod-0012345",
            )
        self.assertIn("CRITICAL SECURITY CONFIGURATION ERROR", str(cm.exception))

        # 2. Too short secret in production mode
        with self.assertRaises(ValueError) as cm2:
            Settings(
                APP_ENV="production",
                SECRET_KEY="short-secret-key",
                REFRESH_SECRET_KEY="a-secure-random-64-character-refresh-secret-key-prod-0012345",
            )
        self.assertIn("CRITICAL SECURITY CONFIGURATION ERROR", str(cm2.exception))

        # 3. Strong unique secrets in production mode succeed
        prod_settings = Settings(
            APP_ENV="production",
            SECRET_KEY="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            REFRESH_SECRET_KEY="9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        )
        self.assertEqual(prod_settings.APP_ENV, "production")


if __name__ == "__main__":
    unittest.main()
