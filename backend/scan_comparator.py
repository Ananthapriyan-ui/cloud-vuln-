import json
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
import models

def parse_scan_data(scan: models.Scan) -> Dict[str, Any]:
    """Safely parse JSON scan_data or reconstruct baseline from relational records."""
    data: Dict[str, Any] = {}
    if scan.scan_data:
        try:
            data = json.loads(scan.scan_data)
        except Exception:
            data = {}
    
    # Fill in fallback/default top-level fields from the scan model if missing in json
    if "security_score" not in data:
        calc_score = max(0, min(100, int(100 - (scan.risk_score * 10))))
        data["security_score"] = calc_score
    
    if "risk_level" not in data:
        data["risk_level"] = scan.status.capitalize() if scan.status else "Medium"

    if "critical_count" not in data:
        data["critical_count"] = scan.critical_count
    if "high_count" not in data:
        data["high_count"] = scan.high_count
    if "medium_count" not in data:
        data["medium_count"] = scan.medium_count
    if "low_count" not in data:
        data["low_count"] = scan.low_count

    return data


def compare_scans_data(prev_scan: models.Scan, latest_scan: models.Scan) -> Dict[str, Any]:
    """
    Compare two real completed scans.
    All data is computed strictly from the actual scan records.
    """
    prev_data = parse_scan_data(prev_scan)
    latest_data = parse_scan_data(latest_scan)

    # ──────────────────────────────────────────────
    # 1. Security Score & Status Comparison
    # ──────────────────────────────────────────────
    prev_score = int(prev_data.get("security_score", 0))
    latest_score = int(latest_data.get("security_score", 0))
    score_diff = latest_score - prev_score

    if prev_score > 0:
        pct_change = round(((latest_score - prev_score) / prev_score) * 100, 1)
    else:
        pct_change = 0.0

    # Status classification logic
    if score_diff > 3:
        security_status = "Security Improved"
        status_category = "improved"
    elif score_diff < -3:
        security_status = "Security Degraded"
        status_category = "degraded"
    else:
        crit_diff = latest_scan.critical_count - prev_scan.critical_count
        high_diff = latest_scan.high_count - prev_scan.high_count
        if crit_diff < 0 or (crit_diff == 0 and high_diff < 0):
            security_status = "Security Improved"
            status_category = "improved"
        elif crit_diff > 0 or (crit_diff == 0 and high_diff > 0):
            security_status = "Security Degraded"
            status_category = "degraded"
        else:
            security_status = "No Significant Change"
            status_category = "neutral"

    # ──────────────────────────────────────────────
    # 2. Severity Comparison
    # ──────────────────────────────────────────────
    critical_change = latest_scan.critical_count - prev_scan.critical_count
    high_change = latest_scan.high_count - prev_scan.high_count
    medium_change = latest_scan.medium_count - prev_scan.medium_count
    low_change = latest_scan.low_count - prev_scan.low_count

    prev_total = prev_scan.critical_count + prev_scan.high_count + prev_scan.medium_count + prev_scan.low_count
    latest_total = latest_scan.critical_count + latest_scan.high_count + latest_scan.medium_count + latest_scan.low_count
    total_change = latest_total - prev_total

    severity_comparison = {
        "critical": {"previous": prev_scan.critical_count, "latest": latest_scan.critical_count, "change": critical_change},
        "high":     {"previous": prev_scan.high_count,     "latest": latest_scan.high_count,     "change": high_change},
        "medium":   {"previous": prev_scan.medium_count,   "latest": latest_scan.medium_count,   "change": medium_change},
        "low":      {"previous": prev_scan.low_count,      "latest": latest_scan.low_count,      "change": low_change},
        "total":    {"previous": prev_total,                "latest": latest_total,                "change": total_change},
    }

    # ──────────────────────────────────────────────
    # 3. Vulnerability Change Analysis (Fixed, New, Persistent)
    # ──────────────────────────────────────────────
    def extract_findings_list(scan: models.Scan, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        
        # Pull from OWASP findings inside scan_data
        owasp_findings = (data.get("owasp_summary") or {}).get("findings") or []
        for f in owasp_findings:
            if f.get("status") in ["Failed", "Warning", "Critical", "High", "Medium", "Low"]:
                findings.append({
                    "id": f.get("owasp_id") or f.get("category"),
                    "cve_id": f.get("related_cve"),
                    "title": f.get("title") or f.get("category"),
                    "severity": f.get("severity") or "Medium",
                    "component": f.get("affected_component") or "Application",
                    "category": f.get("category") or "OWASP Top 10",
                    "description": f.get("description") or "",
                    "recommendation": f.get("recommendation") or "",
                    "type": "owasp"
                })

        # Pull from CVE findings inside scan_data
        cve_findings = data.get("cve_findings") or []
        for c in cve_findings:
            cve_id = c.get("cve_id")
            if not any(f.get("cve_id") == cve_id for f in findings if cve_id):
                findings.append({
                    "id": cve_id,
                    "cve_id": cve_id,
                    "title": f"Vulnerability {cve_id}: {c.get('description', '')[:80]}...",
                    "severity": (c.get("severity") or "High").capitalize(),
                    "component": "Server Software",
                    "category": "Known CVE",
                    "cvss_score": c.get("cvss_score"),
                    "description": c.get("description") or "",
                    "published_date": c.get("published_date") or "",
                    "reference_url": c.get("reference_url") or "",
                    "type": "cve"
                })

        # Pull from relational Vulnerability table if empty
        if not findings and scan.vulnerabilities:
            for v in scan.vulnerabilities:
                findings.append({
                    "id": v.cve_id or f"VULN-{v.id}",
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity.capitalize(),
                    "component": v.component,
                    "category": "Cloud / Host Finding",
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "recommendation": v.remediation,
                    "type": "database"
                })

        return findings

    prev_findings = extract_findings_list(prev_scan, prev_data)
    latest_findings = extract_findings_list(latest_scan, latest_data)

    def finding_key(f: Dict[str, Any]) -> str:
        if f.get("cve_id"):
            return f"cve::{f['cve_id'].strip().upper()}"
        if f.get("id"):
            return f"id::{f['id'].strip().lower()}"
        return f"title::{f.get('title', '').strip().lower()}::{f.get('component', '').strip().lower()}"

    prev_map = {finding_key(f): f for f in prev_findings}
    latest_map = {finding_key(f): f for f in latest_findings}

    fixed_vulnerabilities: List[Dict[str, Any]] = []
    new_vulnerabilities: List[Dict[str, Any]] = []
    persistent_vulnerabilities: List[Dict[str, Any]] = []

    for k, f in prev_map.items():
        if k in latest_map:
            persistent_vulnerabilities.append({
                **latest_map[k],
                "previous_severity": f.get("severity"),
                "latest_severity": latest_map[k].get("severity"),
                "status": "Persistent",
            })
        else:
            fixed_vulnerabilities.append({
                **f,
                "status": "Fixed"
            })

    for k, f in latest_map.items():
        if k not in prev_map:
            new_vulnerabilities.append({
                **f,
                "status": "New"
            })

    # ──────────────────────────────────────────────
    # 4. OWASP Top 10 Comparison
    # ──────────────────────────────────────────────
    STANDARD_OWASP_CATEGORIES = [
        {"owasp_id": "A01:2025", "category": "Broken Access Control"},
        {"owasp_id": "A04:2025", "category": "Cryptographic Failures"},
        {"owasp_id": "A05:2025", "category": "Injection"},
        {"owasp_id": "A06:2025", "category": "Insecure Design"},
        {"owasp_id": "A02:2025", "category": "Security Misconfiguration"},
        {"owasp_id": "A03:2025", "category": "Software Supply Chain Failures"},
        {"owasp_id": "A07:2025", "category": "Authentication Failures"},
        {"owasp_id": "A08:2025", "category": "Software or Data Integrity Failures"},
        {"owasp_id": "A09:2025", "category": "Security Logging & Alerting Failures"},
        {"owasp_id": "A10:2025", "category": "Mishandling of Exceptional Conditions"},
    ]

    prev_owasp_list = (prev_data.get("owasp_summary") or {}).get("findings") or []
    latest_owasp_list = (latest_data.get("owasp_summary") or {}).get("findings") or []

    def get_owasp_item(findings: List[Dict], cat_id: str, cat_name: str) -> Optional[Dict]:
        for item in findings:
            if item.get("owasp_id") == cat_id or (item.get("category") and cat_name.lower() in item.get("category").lower()):
                return item
        return None

    owasp_comparison: List[Dict[str, Any]] = []
    owasp_improvements_count = 0
    owasp_regressions_count = 0

    for cat in STANDARD_OWASP_CATEGORIES:
        p_item = get_owasp_item(prev_owasp_list, cat["owasp_id"], cat["category"])
        l_item = get_owasp_item(latest_owasp_list, cat["owasp_id"], cat["category"])

        p_status = p_item.get("status", "Unable to Verify") if p_item else "Unable to Verify"
        l_status = l_item.get("status", "Unable to Verify") if l_item else "Unable to Verify"

        p_sev = p_item.get("severity", "Unable to Verify") if p_item else "Unable to Verify"
        l_sev = l_item.get("severity", "Unable to Verify") if l_item else "Unable to Verify"

        bad_statuses = ["Failed", "Warning", "Critical", "High", "Medium", "Low"]
        is_p_bad = p_status in bad_statuses
        is_l_bad = l_status in bad_statuses

        if p_status == "Unable to Verify" and l_status == "Unable to Verify":
            change_type = "Unable to Verify"
        elif is_p_bad and not is_l_bad and l_status == "Passed":
            change_type = "Improvement"
            owasp_improvements_count += 1
        elif not is_p_bad and is_l_bad:
            change_type = "New Issue"
            owasp_regressions_count += 1
        elif is_p_bad and is_l_bad:
            change_type = "Persistent Issue"
        elif p_status == "Passed" and l_status == "Passed":
            change_type = "Clean / Maintained"
        else:
            change_type = "No Change"

        owasp_comparison.append({
            "owasp_id": cat["owasp_id"],
            "category": cat["category"],
            "previous_status": p_status,
            "latest_status": l_status,
            "previous_severity": p_sev,
            "latest_severity": l_sev,
            "change_type": change_type,
            "previous_evidence": p_item.get("evidence", "") if p_item else "",
            "latest_evidence": l_item.get("evidence", "") if l_item else "",
            "recommendation": (l_item or p_item or {}).get("recommendation", "")
        })

    # ──────────────────────────────────────────────
    # 5. CVE Comparison
    # ──────────────────────────────────────────────
    prev_cves = {c.get("cve_id"): c for c in (prev_data.get("cve_findings") or []) if c.get("cve_id")}
    latest_cves = {c.get("cve_id"): c for c in (latest_data.get("cve_findings") or []) if c.get("cve_id")}

    new_cves: List[Dict[str, Any]] = []
    fixed_cves: List[Dict[str, Any]] = []
    persistent_cves: List[Dict[str, Any]] = []

    for cve_id, c in latest_cves.items():
        if cve_id not in prev_cves:
            new_cves.append({
                "cve_id": cve_id,
                "cvss_score": c.get("cvss_score"),
                "severity": c.get("severity"),
                "description": c.get("description"),
                "published_date": c.get("published_date"),
                "reference_url": c.get("reference_url"),
                "status": "New"
            })
        else:
            prev_c = prev_cves[cve_id]
            persistent_cves.append({
                "cve_id": cve_id,
                "previous_cvss": prev_c.get("cvss_score"),
                "latest_cvss": c.get("cvss_score"),
                "previous_severity": prev_c.get("severity"),
                "latest_severity": c.get("severity"),
                "description": c.get("description"),
                "published_date": c.get("published_date"),
                "reference_url": c.get("reference_url"),
                "status": "Persistent"
            })

    for cve_id, c in prev_cves.items():
        if cve_id not in latest_cves:
            fixed_cves.append({
                "cve_id": cve_id,
                "cvss_score": c.get("cvss_score"),
                "severity": c.get("severity"),
                "description": c.get("description"),
                "published_date": c.get("published_date"),
                "reference_url": c.get("reference_url"),
                "status": "Fixed"
            })

    cve_comparison = {
        "new_cves": new_cves,
        "fixed_cves": fixed_cves,
        "persistent_cves": persistent_cves,
        "total_new": len(new_cves),
        "total_fixed": len(fixed_cves),
        "total_persistent": len(persistent_cves),
    }

    # ──────────────────────────────────────────────
    # 6. HTTP Security Header Trend
    # ──────────────────────────────────────────────
    prev_headers_list = (prev_data.get("headers_summary") or {}).get("checks") or []
    latest_headers_list = (latest_data.get("headers_summary") or {}).get("checks") or []

    prev_hdr_map = {h.get("name"): h for h in prev_headers_list if h.get("name")}
    latest_hdr_map = {h.get("name"): h for h in latest_headers_list if h.get("name")}

    STANDARD_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    headers_fixed: List[Dict[str, Any]] = []
    headers_newly_missing: List[Dict[str, Any]] = []
    headers_still_missing: List[Dict[str, Any]] = []
    headers_remained_secure: List[Dict[str, Any]] = []

    for hdr_name in STANDARD_HEADERS:
        p_hdr = prev_hdr_map.get(hdr_name, {})
        l_hdr = latest_hdr_map.get(hdr_name, {})

        p_present = p_hdr.get("present", False)
        l_present = l_hdr.get("present", False)

        header_info = {
            "name": hdr_name,
            "previous_present": p_present,
            "latest_present": l_present,
            "previous_value": p_hdr.get("value", "Missing"),
            "latest_value": l_hdr.get("value", "Missing"),
            "risk_if_missing": l_hdr.get("risk_if_missing") or p_hdr.get("risk_if_missing") or "Security Misconfiguration",
            "recommendation": l_hdr.get("recommendation") or p_hdr.get("recommendation") or f"Configure {hdr_name} header."
        }

        if not p_present and l_present:
            header_info["status"] = "Fixed"
            headers_fixed.append(header_info)
        elif p_present and not l_present:
            header_info["status"] = "Newly Missing"
            headers_newly_missing.append(header_info)
        elif not p_present and not l_present:
            header_info["status"] = "Still Missing"
            headers_still_missing.append(header_info)
        else:
            header_info["status"] = "Remained Secure"
            headers_remained_secure.append(header_info)

    header_comparison = {
        "fixed": headers_fixed,
        "newly_missing": headers_newly_missing,
        "still_missing": headers_still_missing,
        "remained_secure": headers_remained_secure,
        "previous_score": (prev_data.get("headers_summary") or {}).get("score", 0),
        "latest_score": (latest_data.get("headers_summary") or {}).get("score", 0),
    }

    # ──────────────────────────────────────────────
    # 7. SSL / TLS Trend
    # ──────────────────────────────────────────────
    prev_ssl = prev_data.get("ssl_summary") or {}
    latest_ssl = latest_data.get("ssl_summary") or {}

    p_valid = prev_ssl.get("is_valid", True)
    l_valid = latest_ssl.get("is_valid", True)
    p_tls = prev_ssl.get("tls_version", "TLSv1.3")
    l_tls = latest_ssl.get("tls_version", "TLSv1.3")

    if (not p_valid and l_valid) or (p_tls in ["TLSv1", "TLSv1.1"] and l_tls in ["TLSv1.2", "TLSv1.3"]):
        ssl_status = "Improved"
    elif (p_valid and not l_valid) or (p_tls in ["TLSv1.2", "TLSv1.3"] and l_tls in ["TLSv1", "TLSv1.1"]):
        ssl_status = "Degraded"
    else:
        ssl_status = "Unchanged"

    ssl_comparison = {
        "previous_cert_status": prev_ssl.get("cert_status", "Valid"),
        "latest_cert_status": latest_ssl.get("cert_status", "Valid"),
        "previous_issuer": prev_ssl.get("issuer", "Not Available"),
        "latest_issuer": latest_ssl.get("issuer", "Not Available"),
        "previous_expiry": prev_ssl.get("expiry_date", "Not Available"),
        "latest_expiry": latest_ssl.get("expiry_date", "Not Available"),
        "previous_days_left": prev_ssl.get("days_until_expiration", 0),
        "latest_days_left": latest_ssl.get("days_until_expiration", 0),
        "previous_tls_version": p_tls,
        "latest_tls_version": l_tls,
        "previous_is_valid": p_valid,
        "latest_is_valid": l_valid,
        "status": ssl_status,
        "recommendations": latest_ssl.get("recommendations", [])
    }

    # ──────────────────────────────────────────────
    # 8. Consolidated Summary Card Output
    # ──────────────────────────────────────────────
    summary = {
        "security_status": security_status,
        "status_category": status_category,
        "previous_security_score": prev_score,
        "latest_security_score": latest_score,
        "score_difference": score_diff,
        "percentage_change": pct_change,
        "findings_fixed_count": len(fixed_vulnerabilities),
        "new_findings_count": len(new_vulnerabilities),
        "persistent_findings_count": len(persistent_vulnerabilities),
        "critical_change": critical_change,
        "high_change": high_change,
        "medium_change": medium_change,
        "low_change": low_change,
        "owasp_improvements": owasp_improvements_count,
        "owasp_regressions": owasp_regressions_count,
        "cve_improvements": len(fixed_cves),
        "cve_regressions": len(new_cves),
        "header_improvements": len(headers_fixed),
        "header_regressions": len(headers_newly_missing),
        "tls_status": ssl_status,
    }

    return {
        "previous_scan": {
            "id": prev_scan.id,
            "scan_ref": prev_scan.scan_ref,
            "target": prev_scan.target,
            "provider": prev_scan.provider,
            "scan_type": prev_scan.scan_type,
            "status": prev_scan.status,
            "risk_score": prev_scan.risk_score,
            "security_score": prev_score,
            "risk_level": prev_data.get("risk_level", prev_scan.status.capitalize()),
            "critical_count": prev_scan.critical_count,
            "high_count": prev_scan.high_count,
            "medium_count": prev_scan.medium_count,
            "low_count": prev_scan.low_count,
            "total_findings": prev_total,
            "duration": prev_scan.duration,
            "created_at": prev_scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if prev_scan.created_at else "",
        },
        "latest_scan": {
            "id": latest_scan.id,
            "scan_ref": latest_scan.scan_ref,
            "target": latest_scan.target,
            "provider": latest_scan.provider,
            "scan_type": latest_scan.scan_type,
            "status": latest_scan.status,
            "risk_score": latest_scan.risk_score,
            "security_score": latest_score,
            "risk_level": latest_data.get("risk_level", latest_scan.status.capitalize()),
            "critical_count": latest_scan.critical_count,
            "high_count": latest_scan.high_count,
            "medium_count": latest_scan.medium_count,
            "low_count": latest_scan.low_count,
            "total_findings": latest_total,
            "duration": latest_scan.duration,
            "created_at": latest_scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if latest_scan.created_at else "",
        },
        "summary": summary,
        "severity_comparison": severity_comparison,
        "vulnerability_changes": {
            "fixed": fixed_vulnerabilities,
            "new": new_vulnerabilities,
            "persistent": persistent_vulnerabilities,
        },
        "owasp_comparison": owasp_comparison,
        "cve_comparison": cve_comparison,
        "header_comparison": header_comparison,
        "ssl_comparison": ssl_comparison,
    }


def get_real_scan_trend(db: Session, target: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch all real completed scans from the database and calculate chronological trend data.
    """
    query = db.query(models.Scan).filter(models.Scan.status != "running")
    if target and target.strip():
        query = query.filter(models.Scan.target == target.strip())

    scans = query.order_by(models.Scan.created_at.asc()).all()

    if not scans or len(scans) < 2:
        return {
            "has_sufficient_data": False,
            "message": "At least two completed scans are required to display a security trend.",
            "total_scans": len(scans) if scans else 0,
            "security_trend": [],
            "severity_trend": []
        }

    security_trend = []
    severity_trend = []

    for s in scans:
        date_str = s.created_at.strftime("%b %d, %H:%M") if s.created_at else s.scan_ref
        scan_data = parse_scan_data(s)
        sec_score = scan_data.get("security_score")
        if sec_score is None:
            sec_score = max(0, min(100, int(100 - (s.risk_score * 10))))

        security_trend.append({
            "scan_ref": s.scan_ref,
            "target": s.target,
            "date": date_str,
            "security_score": sec_score,
            "risk_score": s.risk_score,
        })

        severity_trend.append({
            "scan_ref": s.scan_ref,
            "target": s.target,
            "date": date_str,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "total": s.critical_count + s.high_count + s.medium_count + s.low_count,
        })

    return {
        "has_sufficient_data": True,
        "total_scans": len(scans),
        "security_trend": security_trend,
        "severity_trend": severity_trend,
    }
