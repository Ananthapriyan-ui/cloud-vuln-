import unittest
import database
import models
import scan_comparator
import report_generator

class TestScanComparisonIntegration(unittest.TestCase):
    def setUp(self):
        self.db = database.SessionLocal()
        import json
        mock_data_1 = {
            "target": "example.com",
            "security_score": 70,
            "cve_findings": [{"cve_id": "CVE-2023-1111", "severity": "High", "cvss_score": 7.5, "title": "Old Issue"}],
            "owasp_summary": {"findings": [{"owasp_id": "A01:2025", "status": "Failed", "severity": "High"}]},
            "headers_summary": {"checks": [{"name": "Content-Security-Policy", "present": False}]},
            "ssl_summary": {"tls_version": "TLSv1.2", "is_valid": True}
        }
        mock_data_2 = {
            "target": "example.com",
            "security_score": 90,
            "cve_findings": [],
            "owasp_summary": {"findings": [{"owasp_id": "A01:2025", "status": "Passed", "severity": "Passed"}]},
            "headers_summary": {"checks": [{"name": "Content-Security-Policy", "present": True}]},
            "ssl_summary": {"tls_version": "TLSv1.3", "is_valid": True}
        }
        self.prev_scan = models.Scan(
            scan_ref="TEST-PREV", target="example.com", status="high",
            critical_count=0, high_count=1, medium_count=0, low_count=0,
            risk_score=3.0, scan_data=json.dumps(mock_data_1)
        )
        self.latest_scan = models.Scan(
            scan_ref="TEST-LATEST", target="example.com", status="passed",
            critical_count=0, high_count=0, medium_count=0, low_count=0,
            risk_score=1.0, scan_data=json.dumps(mock_data_2)
        )

    def tearDown(self):
        self.db.close()

    def test_comparison_calculation(self):
        prev = self.prev_scan
        latest = self.latest_scan
        result = scan_comparator.compare_scans_data(prev, latest)

        # 1. Summary validation
        summary = result["summary"]
        self.assertIn("security_status", summary)
        self.assertIn("status_category", summary)
        self.assertIn(summary["status_category"], ["improved", "degraded", "neutral"])
        self.assertEqual(summary["score_difference"], summary["latest_security_score"] - summary["previous_security_score"])

        # 2. Severity validation
        sev = result["severity_comparison"]
        for k in ["critical", "high", "medium", "low", "total"]:
            self.assertIn(k, sev)
            self.assertEqual(sev[k]["change"], sev[k]["latest"] - sev[k]["previous"])

        # 3. Lifecycle validation
        vulns = result["vulnerability_changes"]
        self.assertIn("fixed", vulns)
        self.assertIn("new", vulns)
        self.assertIn("persistent", vulns)

        # 4. OWASP validation
        owasp = result["owasp_comparison"]
        self.assertEqual(len(owasp), 10)

        # 5. Headers & SSL
        self.assertIn("header_comparison", result)
        self.assertIn("ssl_comparison", result)

    def test_trend_calculation(self):
        trend = scan_comparator.get_real_scan_trend(self.db)
        self.assertIn("has_sufficient_data", trend)
        self.assertIn("security_trend", trend)
        self.assertIn("severity_trend", trend)

    def test_reports_generation(self):
        prev = self.prev_scan
        latest = self.latest_scan
        result = scan_comparator.compare_scans_data(prev, latest)
        
        html_report = report_generator.generate_comparison_html_report(result)
        self.assertIn("<!DOCTYPE html>", html_report)
        self.assertIn("CloudVuln Security Comparison Report", html_report)

        csv_report = report_generator.generate_comparison_csv_report(result)
        self.assertIn("CloudVuln Scan Comparison & Security Trend Report", csv_report)
        self.assertIn("Previous Security Score", csv_report)

if __name__ == "__main__":
    unittest.main()
