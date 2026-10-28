"""
CloudVuln — Real Scanner Modules
─────────────────────────────────
1. DNS Security Checker     → live DNS queries via dnspython
2. Dependency Vuln Scanner  → NVD REST API CVE look-ups for packages
3. Cookie Security Checker  → live HTTP cookie attribute inspection
"""

import datetime
import json
import re
import socket
import urllib.parse
import urllib.request
import http.cookiejar
from typing import Any, Dict, List, Optional

import os
import sys

# Ensure backend directory is in sys.path
_backend_dir = os.path.dirname(os.path.abspath(__file__))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from ssrf_protection import validate_public_url, validate_public_hostname_or_ip, SafeRedirectHandler

# ─────────────────────────────────────────────────
# Helper: extract clean domain from user input
# ─────────────────────────────────────────────────

def _extract_domain(target: str) -> str:
    """Extract bare domain from URL or hostname string."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path
    else:
        domain = target
    domain = domain.split(":")[0].split("/")[0].strip().lower()
    return domain


# ═══════════════════════════════════════════════════
# MODULE 1: DNS SECURITY CHECKER
# ═══════════════════════════════════════════════════

def analyze_dns_security(target: str, dkim_selector: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform real DNS lookups for A, AAAA, MX, NS, TXT, CAA, DNSSEC,
    SPF, DMARC, and optionally DKIM records.  Every result comes from
    actual DNS resolution — no mock data.
    """
    import dns.resolver
    import dns.rdatatype
    import dns.dnssec
    import dns.name
    import dns.flags

    domain = _extract_domain(target)
    if not domain:
        return {"error": True, "message": "Invalid or empty domain"}

    start_time = datetime.datetime.now(datetime.timezone.utc)
    findings: List[Dict[str, Any]] = []
    records_summary: Dict[str, Any] = {}
    overall_score = 100
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    resolver = dns.resolver.Resolver()
    # Ensure reliable, fast resolution on all operating systems
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    resolver.timeout = 4
    resolver.lifetime = 8

    # ── A Records ──
    try:
        answers = resolver.resolve(domain, "A")
        a_records = [str(rdata) for rdata in answers]
        records_summary["A"] = a_records
        findings.append({
            "check": "A Records",
            "status": "Found",
            "severity": "Informational",
            "records": a_records,
            "description": f"{len(a_records)} IPv4 address(es) resolved.",
        })
    except dns.resolver.NoAnswer:
        records_summary["A"] = []
        findings.append({"check": "A Records", "status": "Not Found", "severity": "Informational", "records": [], "description": "No A records found."})
    except dns.resolver.NXDOMAIN:
        return {
            "domain": domain, "status": "Error", "error": True,
            "message": f"Domain '{domain}' does not exist (NXDOMAIN).",
            "security_score": 0, "risk_level": "Critical",
            "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except Exception as e:
        records_summary["A"] = []
        findings.append({"check": "A Records", "status": "Error", "severity": "Low", "records": [], "description": f"Unable to resolve A records: {e}"})

    # ── AAAA Records ──
    try:
        answers = resolver.resolve(domain, "AAAA")
        aaaa_records = [str(rdata) for rdata in answers]
        records_summary["AAAA"] = aaaa_records
        findings.append({"check": "AAAA Records", "status": "Found", "severity": "Informational", "records": aaaa_records, "description": f"{len(aaaa_records)} IPv6 address(es) resolved."})
    except Exception:
        records_summary["AAAA"] = []
        findings.append({"check": "AAAA Records", "status": "Not Found", "severity": "Informational", "records": [], "description": "No AAAA records found. Consider adding IPv6 support."})

    # ── MX Records ──
    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = [{"priority": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")} for rdata in answers]
        records_summary["MX"] = mx_records
        findings.append({"check": "MX Records", "status": "Found", "severity": "Informational", "records": mx_records, "description": f"{len(mx_records)} mail exchanger(s) configured."})
    except Exception:
        records_summary["MX"] = []
        findings.append({"check": "MX Records", "status": "Not Found", "severity": "Low", "records": [], "description": "No MX records found."})

    # ── NS Records ──
    try:
        answers = resolver.resolve(domain, "NS")
        ns_records = [str(rdata).rstrip(".") for rdata in answers]
        records_summary["NS"] = ns_records
        findings.append({"check": "NS Records", "status": "Found", "severity": "Informational", "records": ns_records, "description": f"{len(ns_records)} authoritative nameserver(s)."})
    except Exception:
        records_summary["NS"] = []
        findings.append({"check": "NS Records", "status": "Warning", "severity": "Medium", "records": [], "description": "Unable to resolve NS records."})
        medium_count += 1
        overall_score -= 5

    # ── TXT Records ──
    txt_records = []
    try:
        answers = resolver.resolve(domain, "TXT")
        txt_records = [str(rdata).strip('"') for rdata in answers]
        records_summary["TXT"] = txt_records
        findings.append({"check": "TXT Records", "status": "Found", "severity": "Informational", "records": txt_records, "description": f"{len(txt_records)} TXT record(s) found."})
    except Exception:
        records_summary["TXT"] = []
        findings.append({"check": "TXT Records", "status": "Not Found", "severity": "Informational", "records": [], "description": "No TXT records found."})

    # ── CAA Records ──
    try:
        answers = resolver.resolve(domain, "CAA")
        caa_records = [str(rdata) for rdata in answers]
        records_summary["CAA"] = caa_records
        findings.append({"check": "CAA Records", "status": "Found", "severity": "Informational", "records": caa_records, "description": f"CAA policy restricts certificate issuance. {len(caa_records)} record(s)."})
    except Exception:
        records_summary["CAA"] = []
        findings.append({
            "check": "CAA Records", "status": "Missing", "severity": "Medium",
            "records": [], "description": "No CAA records found. Any CA can issue certificates for this domain.",
            "recommendation": "Add CAA DNS records to restrict which Certificate Authorities can issue certificates for your domain."
        })
        medium_count += 1
        overall_score -= 5

    # ── DNSSEC Validation ──
    dnssec_status = "Unable to Verify"
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        if answers:
            dnssec_status = "Enabled"
            findings.append({"check": "DNSSEC", "status": "Enabled", "severity": "Informational", "records": [dnssec_status], "description": "DNSSEC keys (DNSKEY) found for domain."})
        else:
            dnssec_status = "Disabled"
    except dns.resolver.NoAnswer:
        dnssec_status = "Disabled"
    except dns.resolver.NXDOMAIN:
        dnssec_status = "Disabled"
    except Exception:
        dnssec_status = "Unable to Verify"

    if dnssec_status == "Disabled":
        findings.append({
            "check": "DNSSEC", "status": "Disabled", "severity": "Medium",
            "records": [], "description": "DNSSEC is not enabled. DNS responses can be spoofed.",
            "recommendation": "Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks."
        })
        medium_count += 1
        overall_score -= 8
    elif dnssec_status == "Unable to Verify":
        findings.append({
            "check": "DNSSEC", "status": "Unable to Verify", "severity": "Low",
            "records": [], "description": "Could not determine DNSSEC status.",
        })

    records_summary["DNSSEC"] = dnssec_status

    # ── SPF Record Check ──
    spf_record = None
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            spf_record = txt
            break

    if spf_record:
        spf_issues = []
        if "+all" in spf_record:
            spf_issues.append("SPF uses '+all' which allows ANY server to send mail — effectively disabling SPF protection.")
            high_count += 1
            overall_score -= 15
        elif "~all" in spf_record:
            spf_issues.append("SPF uses '~all' (soft fail). Consider '-all' for strict enforcement.")
            low_count += 1
            overall_score -= 3
        elif "?all" in spf_record:
            spf_issues.append("SPF uses '?all' (neutral). This provides no actual protection.")
            medium_count += 1
            overall_score -= 8
        elif "-all" in spf_record:
            pass  # Strict — good

        findings.append({
            "check": "SPF Record", "status": "Found", "severity": "High" if spf_issues and "+all" in spf_record else ("Medium" if spf_issues else "Informational"),
            "records": [spf_record],
            "description": f"SPF record present. {' '.join(spf_issues)}" if spf_issues else "SPF record found with strict enforcement.",
            "recommendation": "Use '-all' mechanism for strict SPF enforcement." if spf_issues else None,
        })
    else:
        findings.append({
            "check": "SPF Record", "status": "Missing", "severity": "High",
            "records": [], "description": "No SPF record found. Email spoofing is possible.",
            "recommendation": "Add an SPF TXT record (e.g. 'v=spf1 include:_spf.google.com -all') to authorize legitimate mail servers."
        })
        high_count += 1
        overall_score -= 12

    records_summary["SPF"] = spf_record or "Not Found"

    # ── DMARC Record Check ──
    dmarc_record = None
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt_val = str(rdata).strip('"')
            if txt_val.lower().startswith("v=dmarc1"):
                dmarc_record = txt_val
                break
    except Exception:
        pass

    if dmarc_record:
        dmarc_issues = []
        if "p=none" in dmarc_record.lower():
            dmarc_issues.append("DMARC policy is 'none' — emails failing authentication are still delivered.")
            low_count += 1
            overall_score -= 5
        findings.append({
            "check": "DMARC Record", "status": "Found",
            "severity": "Low" if dmarc_issues else "Informational",
            "records": [dmarc_record],
            "description": f"DMARC record present. {' '.join(dmarc_issues)}" if dmarc_issues else "DMARC record found with enforcement policy.",
            "recommendation": "Consider upgrading DMARC policy to 'quarantine' or 'reject'." if dmarc_issues else None,
        })
    else:
        findings.append({
            "check": "DMARC Record", "status": "Missing", "severity": "High",
            "records": [], "description": "No DMARC record found. Email authentication results are not enforced.",
            "recommendation": "Add a DMARC TXT record at _dmarc.<domain> (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com')."
        })
        high_count += 1
        overall_score -= 12

    records_summary["DMARC"] = dmarc_record or "Not Found"

    # ── DKIM Record Check (optional selector) ──
    dkim_record = None
    dkim_selector_used = dkim_selector or "default"
    if dkim_selector:
        try:
            answers = resolver.resolve(f"{dkim_selector}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt_val = str(rdata).strip('"')
                if "v=dkim1" in txt_val.lower() or "p=" in txt_val.lower():
                    dkim_record = txt_val
                    break
        except Exception:
            pass

    if dkim_selector:
        if dkim_record:
            findings.append({
                "check": f"DKIM Record (selector: {dkim_selector})", "status": "Found", "severity": "Informational",
                "records": [dkim_record], "description": f"DKIM record found for selector '{dkim_selector}'.",
            })
        else:
            findings.append({
                "check": f"DKIM Record (selector: {dkim_selector})", "status": "Not Found", "severity": "Medium",
                "records": [], "description": f"No DKIM record at '{dkim_selector}._domainkey.{domain}'.",
                "recommendation": "Verify the DKIM selector name and ensure DKIM is configured with your email provider."
            })
            medium_count += 1
            overall_score -= 5
    else:
        # Try common selectors: google, default, selector1, selector2, k1
        common_selectors = ["google", "default", "selector1", "selector2", "k1", "mail"]
        found_selector = None
        for sel in common_selectors:
            try:
                answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                for rdata in answers:
                    txt_val = str(rdata).strip('"')
                    if "p=" in txt_val.lower():
                        dkim_record = txt_val
                        found_selector = sel
                        break
                if found_selector:
                    break
            except Exception:
                continue

        if found_selector:
            findings.append({
                "check": f"DKIM Record (auto-detected: {found_selector})", "status": "Found", "severity": "Informational",
                "records": [dkim_record], "description": f"DKIM record auto-detected with selector '{found_selector}'.",
            })
            dkim_selector_used = found_selector
        else:
            findings.append({
                "check": "DKIM Record", "status": "Unable to Verify", "severity": "Low",
                "records": [], "description": "Could not auto-detect DKIM. Provide a specific selector for verification.",
                "recommendation": "Provide the DKIM selector used by your email provider for accurate verification."
            })

    records_summary["DKIM"] = {"selector": dkim_selector_used, "record": dkim_record or "Not Found"}

    # ── Calculate overall score ──
    overall_score = max(0, min(100, overall_score))
    if critical_count > 0:
        risk_level = "Critical"
    elif high_count > 0:
        risk_level = "High"
    elif medium_count > 0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Build recommendations
    recommendations = []
    for f in findings:
        if f.get("recommendation"):
            recommendations.append(f["recommendation"])
    if not recommendations:
        recommendations.append("DNS security configuration appears adequate. Continue monitoring regularly.")

    duration = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()

    return {
        "scan_type": "DNS Security Checker",
        "domain": domain,
        "ip_address": records_summary.get("A", ["Unavailable"])[0] if records_summary.get("A") else "Unavailable",
        "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "Completed",
        "security_score": overall_score,
        "risk_level": risk_level,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "duration": f"{duration:.1f}s",
        "records_summary": records_summary,
        "findings": findings,
        "recommendations": recommendations,
    }


# ═══════════════════════════════════════════════════
# MODULE 2: DEPENDENCY VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════

def _query_nvd_for_package(package_name: str, package_version: str = "", ecosystem: Optional[str] = "npm") -> List[Dict[str, Any]]:
    """
    Query NIST NVD API v2.0 for real CVEs matching a package name.
    Returns actual CVE results only — never fabricated data.
    """
    import config
    results = []
    eco_val = ecosystem or "npm"
    keyword = f"{package_name} {package_version}".strip()
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=5"

    headers = {"User-Agent": "CloudVuln-Scanner/2.0"}
    if config.settings.NVD_API_KEY:
        headers["apiKey"] = config.settings.NVD_API_KEY

    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for vuln in (data.get("vulnerabilities") or [])[:5]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            descriptions = cve.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break
            if not desc_text and descriptions:
                desc_text = descriptions[0].get("value", "")

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "Unknown"
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "Unknown")
                    break

            published = cve.get("published", "")[:10]
            refs = cve.get("references", [])
            ref_url = refs[0].get("url", "") if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity.capitalize() if severity else "Unknown",
                "description": desc_text[:500],
                "published_date": published,
                "reference_url": ref_url,
                "package": package_name,
                "version": package_version,
                "ecosystem": ecosystem,
            })
    except Exception:
        pass

    return results


def _parse_package_list(package_list_text: str) -> List[Dict[str, str]]:
    """
    Parse user-provided dependency list.  Supports formats:
    - package@version  (npm style)
    - package==version (pip style)
    - package>=version (pip style)
    - package:version  (generic)
    - package version  (space-separated)
    - just package name alone
    """
    packages = []
    for line in package_list_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # npm: react@18.2.0
        if "@" in line and not line.startswith("@"):
            parts = line.rsplit("@", 1)
            packages.append({"name": parts[0].strip(), "version": parts[1].strip() if len(parts) > 1 else ""})
        # pip: flask==2.3.0 or flask>=2.3.0
        elif "==" in line:
            parts = line.split("==", 1)
            packages.append({"name": parts[0].strip(), "version": parts[1].strip()})
        elif ">=" in line:
            parts = line.split(">=", 1)
            packages.append({"name": parts[0].strip(), "version": parts[1].split(",")[0].strip()})
        elif "<=" in line:
            parts = line.split("<=", 1)
            packages.append({"name": parts[0].strip(), "version": parts[1].split(",")[0].strip()})
        # colon separated
        elif ":" in line:
            parts = line.split(":", 1)
            packages.append({"name": parts[0].strip(), "version": parts[1].strip()})
        # space separated (only if second token looks like a version)
        elif " " in line:
            parts = line.split(None, 1)
            if len(parts) == 2 and re.match(r"[\d.]", parts[1]):
                packages.append({"name": parts[0].strip(), "version": parts[1].strip()})
            else:
                packages.append({"name": parts[0].strip(), "version": ""})
        else:
            packages.append({"name": line, "version": ""})

    return packages[:20]  # Cap at 20 packages to prevent abuse


def analyze_dependencies(package_list_text: str, ecosystem: Optional[str] = "auto") -> Dict[str, Any]:
    """
    Scan user-provided dependencies against the NVD database for
    known CVEs.  Returns only real, verified vulnerability data.
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)
    packages = _parse_package_list(package_list_text)

    if not packages:
        return {
            "scan_type": "Dependency Vulnerability Scanner",
            "status": "Error",
            "error": True,
            "message": "No packages provided. Enter one package per line (e.g. 'react@18.2.0' or 'flask==2.3.0').",
            "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "security_score": 0,
            "risk_level": "Unknown",
        }

    all_vulns: List[Dict[str, Any]] = []
    scanned_packages: List[Dict[str, Any]] = []
    overall_score = 100
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for pkg in packages:
        pkg_name = pkg["name"]
        pkg_version = pkg.get("version", "")
        eco: str = ecosystem if (ecosystem and ecosystem != "auto") else ("npm" if "@" in package_list_text else "pip")
        vulns = _query_nvd_for_package(pkg_name, pkg_version, eco)

        pkg_status = "No Known Vulnerabilities" if not vulns else f"{len(vulns)} CVE(s) Found"
        scanned_packages.append({
            "name": pkg_name,
            "version": pkg_version or "latest",
            "ecosystem": eco,
            "status": pkg_status,
            "vulnerability_count": len(vulns),
            "vulnerabilities": vulns,
        })

        for v in vulns:
            sev = (v.get("severity") or "").upper()
            if sev == "CRITICAL":
                critical_count += 1
                overall_score -= 20
            elif sev == "HIGH":
                high_count += 1
                overall_score -= 12
            elif sev == "MEDIUM":
                medium_count += 1
                overall_score -= 5
            elif sev == "LOW":
                low_count += 1
                overall_score -= 2

        all_vulns.extend(vulns)

        # NVD rate limit: ~5 requests/30s without API key
        import time
        time.sleep(0.8)

    overall_score = max(0, min(100, overall_score))
    if critical_count > 0:
        risk_level = "Critical"
    elif high_count > 0:
        risk_level = "High"
    elif medium_count > 0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    recommendations = []
    if critical_count > 0:
        recommendations.append("Immediately update packages with CRITICAL severity CVEs to patched versions.")
    if high_count > 0:
        recommendations.append("Prioritize updates for packages with HIGH severity vulnerabilities.")
    if medium_count > 0:
        recommendations.append("Plan updates for packages with MEDIUM severity findings in the next release cycle.")
    if not all_vulns:
        recommendations.append("No known vulnerabilities detected. Continue monitoring with automated CI/CD dependency scanning.")

    duration = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()

    return {
        "scan_type": "Dependency Vulnerability Scanner",
        "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "Completed",
        "security_score": overall_score,
        "risk_level": risk_level,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "total_packages_scanned": len(scanned_packages),
        "total_vulnerabilities_found": len(all_vulns),
        "duration": f"{duration:.1f}s",
        "packages": scanned_packages,
        "all_vulnerabilities": all_vulns,
        "recommendations": recommendations,
    }


# ═══════════════════════════════════════════════════
# MODULE 3: COOKIE SECURITY CHECKER
# ═══════════════════════════════════════════════════

def analyze_cookies(target_url: str) -> Dict[str, Any]:
    """
    Make a real HTTP request to the target URL and inspect all
    Set-Cookie headers for security attributes (Secure, HttpOnly,
    SameSite, Path, Domain, Max-Age/Expires).
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)

    # Normalize URL
    url = target_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        validated_url = validate_public_url(url)
    except ValueError as e:
        return {
            "scan_type": "Cookie Security Checker",
            "target": url, "status": "Error", "error": True,
            "message": f"Target blocked (SSRF protection): {e}",
            "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "security_score": 0, "risk_level": "Unknown",
        }

    parsed = urllib.parse.urlparse(validated_url)
    target_clean = parsed.netloc or parsed.path.split("/")[0]

    # Use a cookie jar to capture all cookies
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        SafeRedirectHandler(),
    )

    set_cookie_headers = []
    try:
        req = urllib.request.Request(validated_url, headers={
            "User-Agent": "CloudVuln-CookieAuditor/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        resp = opener.open(req, timeout=8)

        # Capture raw Set-Cookie headers
        raw_headers = resp.headers.items() if hasattr(resp.headers, 'items') else []
        for hdr_name, hdr_val in raw_headers:
            if hdr_name.lower() == "set-cookie":
                set_cookie_headers.append(hdr_val)

        resp.close()
    except Exception as e:
        return {
            "scan_type": "Cookie Security Checker",
            "target": target_clean, "status": "Error", "error": True,
            "message": f"Failed to reach target: {e}",
            "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "security_score": 0, "risk_level": "Unknown",
        }

    # Parse each Set-Cookie header
    cookies_analysis: List[Dict[str, Any]] = []
    overall_score = 100
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    if not set_cookie_headers:
        # No cookies set — this is generally fine
        duration = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()
        return {
            "scan_type": "Cookie Security Checker",
            "target": target_clean,
            "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "status": "Completed",
            "security_score": 100,
            "risk_level": "Low",
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "total_cookies": 0,
            "cookies": [],
            "recommendations": ["No cookies were set by the server. No cookie-based risks detected."],
            "duration": f"{duration:.1f}s",
        }

    for raw_cookie in set_cookie_headers:
        parts = raw_cookie.split(";")
        name_val = parts[0].strip()
        eq_idx = name_val.find("=")
        if eq_idx == -1:
            continue
        cookie_name = name_val[:eq_idx].strip()
        cookie_value = name_val[eq_idx + 1:].strip()

        attributes: Dict[str, Any] = {}
        for attr_str in parts[1:]:
            attr_str = attr_str.strip()
            if "=" in attr_str:
                key, val = attr_str.split("=", 1)
                attributes[key.strip().lower()] = val.strip()
            else:
                attributes[attr_str.strip().lower()] = True

        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes
        samesite_val = attributes.get("samesite", None)
        has_samesite = samesite_val is not None
        has_path = "path" in attributes
        has_domain = "domain" in attributes
        has_expiry = "expires" in attributes or "max-age" in attributes

        issues = []
        cookie_severity = "Informational"

        # Check for Secure flag
        if not has_secure:
            issues.append({
                "attribute": "Secure",
                "status": "Missing",
                "severity": "High",
                "description": "Cookie transmitted over insecure HTTP connections. Vulnerable to man-in-the-middle interception.",
                "recommendation": "Add the 'Secure' flag to ensure cookie is only sent over HTTPS."
            })
            high_count += 1
            overall_score -= 10
            cookie_severity = "High"

        # Check for HttpOnly flag
        if not has_httponly:
            issues.append({
                "attribute": "HttpOnly",
                "status": "Missing",
                "severity": "High",
                "description": "Cookie accessible via JavaScript (document.cookie). Vulnerable to XSS-based cookie theft.",
                "recommendation": "Add the 'HttpOnly' flag to prevent JavaScript access to this cookie."
            })
            high_count += 1
            overall_score -= 10
            if cookie_severity not in ("Critical",):
                cookie_severity = "High"

        # Check for SameSite attribute
        if not has_samesite:
            issues.append({
                "attribute": "SameSite",
                "status": "Missing",
                "severity": "Medium",
                "description": "No SameSite attribute. Cookie may be sent in cross-site requests, increasing CSRF risk.",
                "recommendation": "Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate CSRF attacks."
            })
            medium_count += 1
            overall_score -= 5
            if cookie_severity not in ("Critical", "High"):
                cookie_severity = "Medium"
        elif isinstance(samesite_val, str) and samesite_val.lower() == "none":
            if not has_secure:
                issues.append({
                    "attribute": "SameSite",
                    "status": "Misconfigured",
                    "severity": "High",
                    "description": "SameSite=None requires the Secure flag, which is missing.",
                    "recommendation": "Add the 'Secure' flag when using 'SameSite=None'."
                })
                high_count += 1
                overall_score -= 8
                cookie_severity = "High"

        # Check for __Secure- or __Host- prefix conventions
        if cookie_name.startswith("__Secure-") and not has_secure:
            issues.append({
                "attribute": "__Secure- Prefix",
                "status": "Violation",
                "severity": "High",
                "description": f"Cookie '{cookie_name}' uses __Secure- prefix but lacks the Secure flag.",
                "recommendation": "Cookies with __Secure- prefix must include the Secure attribute."
            })
            high_count += 1
            overall_score -= 8

        if cookie_name.startswith("__Host-"):
            if not has_secure or has_domain or attributes.get("path") != "/":
                issues.append({
                    "attribute": "__Host- Prefix",
                    "status": "Violation",
                    "severity": "High",
                    "description": f"Cookie '{cookie_name}' uses __Host- prefix but violates requirements (must be Secure, no Domain, Path=/).",
                    "recommendation": "Ensure __Host- cookies have Secure flag, no Domain attribute, and Path=/."
                })
                high_count += 1
                overall_score -= 8

        if not issues:
            issues.append({
                "attribute": "All Checks",
                "status": "Passed",
                "severity": "Informational",
                "description": "Cookie has appropriate security attributes configured.",
            })
            cookie_severity = "Passed"

        cookies_analysis.append({
            "name": cookie_name,
            "value_preview": cookie_value[:20] + "..." if len(cookie_value) > 20 else cookie_value,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": str(samesite_val) if samesite_val else "Not Set",
            "path": attributes.get("path", "Not Set"),
            "domain": attributes.get("domain", "Not Set"),
            "expires": attributes.get("expires", attributes.get("max-age", "Session")),
            "severity": cookie_severity,
            "issues": issues,
        })

    overall_score = max(0, min(100, overall_score))
    if critical_count > 0:
        risk_level = "Critical"
    elif high_count > 0:
        risk_level = "High"
    elif medium_count > 0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    recommendations = []
    if high_count > 0:
        recommendations.append("Add 'Secure' and 'HttpOnly' flags to all session and authentication cookies.")
    if medium_count > 0:
        recommendations.append("Set 'SameSite=Lax' or 'SameSite=Strict' on all cookies to prevent CSRF attacks.")
    if not recommendations:
        recommendations.append("All cookies have proper security attributes. Maintain current configuration.")

    duration = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds()

    return {
        "scan_type": "Cookie Security Checker",
        "target": target_clean,
        "scan_timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "Completed",
        "security_score": overall_score,
        "risk_level": risk_level,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "total_cookies": len(cookies_analysis),
        "cookies": cookies_analysis,
        "recommendations": recommendations,
        "duration": f"{duration:.1f}s",
    }
