import socket
import ssl
import datetime
import urllib.parse
import urllib.request
import json
import time
from typing import Dict, List, Any, Optional

def get_target_ip(hostname: str) -> str:
    """Resolve domain or hostname to IP address using system DNS resolver."""
    try:
        if "://" in hostname:
            hostname = urllib.parse.urlparse(hostname).netloc
        hostname = hostname.split(":")[0].strip()
        if not hostname:
            return "Unavailable"
        return socket.gethostbyname(hostname)
    except Exception:
        return "Unavailable"

def analyze_ssl(target_url: str) -> Dict[str, Any]:
    """Inspect live SSL/TLS certificate details and security posture without mock data."""
    formatted_url = target_url if "://" in target_url else f"https://{target_url}"
    parsed = urllib.parse.urlparse(formatted_url)
    hostname = (parsed.netloc or parsed.path).split(":")[0].strip()
    port = 443

    recommendations = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
                version = ssock.version()

                # Extract Issuer
                issuer_dict: Dict[str, str] = {}
                raw_issuer = cert.get('issuer')
                if isinstance(raw_issuer, (list, tuple)):
                    for rdn in raw_issuer:
                        if isinstance(rdn, (list, tuple)) and rdn and isinstance(rdn[0], (list, tuple)) and len(rdn[0]) == 2:
                            key, val = rdn[0]
                            issuer_dict[str(key)] = str(val)

                issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or "Unknown Issuer"

                # Expiry check
                not_after_str = cert.get('notAfter')
                now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                if isinstance(not_after_str, str):
                    try:
                        expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_until_exp = (expiry_date - now_utc).days
                        expiry_date_str = expiry_date.strftime('%Y-%m-%d')
                    except Exception:
                        days_until_exp = 0
                        expiry_date_str = not_after_str
                else:
                    days_until_exp = 0
                    expiry_date_str = "Not Available"

                is_valid = days_until_exp > 0
                if days_until_exp < 0:
                    recommendations.append(f"CRITICAL: Certificate expired {-days_until_exp} days ago. Renew immediately.")
                elif days_until_exp < 30:
                    recommendations.append(f"Certificate expires in {days_until_exp} days. Schedule automated ACME renewal.")
                else:
                    recommendations.append(f"Certificate validity is active ({days_until_exp} days remaining). Maintain automated renewal cycle.")

                if version in ["TLSv1", "TLSv1.1"]:
                    recommendations.append(f"Deprecated TLS version ({version}) detected. Mandate TLS 1.2 or TLS 1.3.")
                elif version:
                    recommendations.append(f"Modern TLS protocol active ({version}).")

                cipher_name = cipher[0] if cipher and isinstance(cipher, tuple) else "Not Available"

                return {
                    "cert_status": "Valid" if is_valid else "Expired",
                    "issuer": issuer_name,
                    "expiry_date": expiry_date_str,
                    "tls_version": version or "Unknown",
                    "cipher": cipher_name,
                    "is_valid": is_valid,
                    "days_until_expiration": max(days_until_exp, 0),
                    "recommendations": recommendations
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "cert_status": "Invalid / Untrusted",
            "issuer": "Untrusted / Self-Signed",
            "expiry_date": "Not Available",
            "tls_version": "TLS Handshake Failed",
            "cipher": "Not Available",
            "is_valid": False,
            "days_until_expiration": 0,
            "recommendations": [f"SSL certificate verification failed: {e.verify_message}. Install a valid certificate from a recognized Certificate Authority."]
        }
    except Exception as e:
        return {
            "cert_status": "Unable to Verify",
            "issuer": "Not Available",
            "expiry_date": "Not Available",
            "tls_version": "Not Available",
            "cipher": "Not Available",
            "is_valid": False,
            "days_until_expiration": 0,
            "recommendations": [f"TLS connection on port 443 failed: {str(e)}. Target host may not support HTTPS or is blocking connections."]
        }

def analyze_headers(target_url: str) -> Dict[str, Any]:
    """Check presence and value of standard HTTP security headers using live response inspection."""
    formatted_url = target_url if "://" in target_url else f"https://{target_url}"
    
    header_definitions = [
        {
            "name": "Content-Security-Policy",
            "risk_if_missing": "High Risk - Permits unauthorized script execution and cross-site scripting (XSS).",
            "recommendation": "Define a robust Content-Security-Policy (CSP) limiting script-src and object-src to trusted sources."
        },
        {
            "name": "Strict-Transport-Security",
            "risk_if_missing": "Medium Risk - Allows HTTP downgrade attacks and SSL stripping.",
            "recommendation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains."
        },
        {
            "name": "X-Frame-Options",
            "risk_if_missing": "Medium Risk - Site can be framed inside malicious parent contexts (Clickjacking).",
            "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN header."
        },
        {
            "name": "X-Content-Type-Options",
            "risk_if_missing": "Low Risk - Client browser may execute assets as incorrect MIME types (MIME-sniffing).",
            "recommendation": "Add X-Content-Type-Options: nosniff header."
        },
        {
            "name": "Referrer-Policy",
            "risk_if_missing": "Low Risk - URLs with sensitive query parameters may leak in HTTP Referer.",
            "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin."
        },
        {
            "name": "Permissions-Policy",
            "risk_if_missing": "Info - Unrestricted browser hardware API access (Camera, Microphone, Geolocation).",
            "recommendation": "Specify Permissions-Policy: camera=(), microphone=(), geolocation=()."
        }
    ]

    checks = []
    passed_count = 0

    try:
        req = urllib.request.Request(
            formatted_url,
            headers={'User-Agent': 'CloudVuln-Security-Auditor/2.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            
            for h in header_definitions:
                h_key = h["name"].lower()
                val = resp_headers.get(h_key)
                present = val is not None
                if present:
                    passed_count += 1

                checks.append({
                    "name": h["name"],
                    "present": present,
                    "value": val if present else "Missing",
                    "risk_if_missing": h["risk_if_missing"],
                    "recommendation": h["recommendation"]
                })
    except Exception as e:
        # If target fails to respond, report actual error status without generating fake headers
        for h in header_definitions:
            checks.append({
                "name": h["name"],
                "present": False,
                "value": "Unable to Verify",
                "risk_if_missing": f"Probe failed: {str(e)}",
                "recommendation": h["recommendation"]
            })

    total_count = len(header_definitions)
    score = int((passed_count / total_count) * 100) if total_count > 0 else 0

    return {
        "score": score,
        "passed_count": passed_count,
        "total_count": total_count,
        "checks": checks
    }

def query_nvd_cve(keyword: str) -> List[Dict[str, Any]]:
    """Fetch live CVE records matching software or product name from official NVD REST API v2.0."""
    keyword_clean = keyword.strip()
    if not keyword_clean or len(keyword_clean) < 2:
        return []

    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword_clean)}&resultsPerPage=6"
        headers = {'User-Agent': 'CloudVuln-SecOps-Auditor/2.0'}

        try:
            import config as _config
            nvd_key = (_config.settings.NVD_API_KEY or "").strip()
            if nvd_key:
                headers['apiKey'] = nvd_key
        except Exception:
            pass

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=6) as response:
            data = json.loads(response.read().decode('utf-8'))
            cve_items = data.get("vulnerabilities", [])
            
            results = []
            for item in cve_items:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                descriptions = cve_obj.get("descriptions", [])
                desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
                pub_date = cve_obj.get("published", "")[:10]

                # Extract CVSS Metrics
                metrics = cve_obj.get("metrics", {})
                cvss_data = None
                if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})

                if cvss_data:
                    score = float(cvss_data.get("baseScore", 5.0))
                    severity = str(cvss_data.get("baseSeverity", "HIGH")).lower()
                else:
                    score = 5.0
                    severity = "medium"

                results.append({
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "severity": severity,
                    "description": desc,
                    "published_date": pub_date,
                    "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
            
            return results
    except Exception:
        # Do NOT return fake or sample CVEs if NVD is unreachable or query has no matches
        return []

def analyze_whois(target_url: str) -> Dict[str, Any]:
    """Retrieve actual domain registration and RDAP information without fake dates."""
    formatted_url = target_url if "://" in target_url else f"http://{target_url}"
    parsed = urllib.parse.urlparse(formatted_url)
    domain = (parsed.netloc or parsed.path).split(":")[0].strip()

    # If domain is an IP address or localhost, RDAP is not applicable
    is_ip = False
    try:
        socket.inet_aton(domain)
        is_ip = True
    except OSError:
        pass

    if is_ip or domain in ("localhost", "127.0.0.1", ""):
        return {
            "registrar": "Local / Private IP Target",
            "creation_date": "Not Available",
            "expiry_date": "Not Available",
            "name_servers": [],
            "domain_status": ["Private/Local"],
            "raw_text": f"RDAP domain registry lookup is not applicable for IP addresses or local target: {domain}"
        }

    try:
        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        req = urllib.request.Request(
            rdap_url,
            headers={'User-Agent': 'CloudVuln-WHOIS-Auditor/2.0', 'Accept': 'application/rdap+json'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            
            registrar = "Not Available"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [[]])[1]
                    for item in vcard:
                        if item[0] == "fn":
                            registrar = item[3]
                            break

            creation_date = "Not Available"
            expiry_date = "Not Available"
            events = data.get("events", [])
            for evt in events:
                action = evt.get("eventAction")
                date_str = evt.get("eventDate", "")[:10]
                if action in ["registration", "created"] and date_str:
                    creation_date = date_str
                elif action in ["expiration", "expires"] and date_str:
                    expiry_date = date_str

            name_servers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")]
            status_list = data.get("status", [])

            return {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiry_date": expiry_date,
                "name_servers": name_servers,
                "domain_status": status_list if isinstance(status_list, list) else [str(status_list)],
                "raw_text": f"RDAP domain record for {domain} retrieved successfully."
            }
    except Exception as e:
        return {
            "registrar": "Not Available",
            "creation_date": "Not Available",
            "expiry_date": "Not Available",
            "name_servers": [],
            "domain_status": ["Unavailable"],
            "raw_text": f"RDAP domain registration record unavailable for {domain}: {str(e)}"
        }

def analyze_ports(target_url_or_host: str, port_list: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Perform authorized network port scanning against target.
    Probes standard common services and returns actual open/closed status.
    """
    hostname = target_url_or_host
    if "://" in hostname:
        hostname = urllib.parse.urlparse(hostname).netloc
    hostname = hostname.split(":")[0].strip()

    ip_address = get_target_ip(hostname)
    if ip_address == "Unavailable":
        return {
            "target": hostname,
            "ip_address": "Resolution Failed",
            "open_ports_count": 0,
            "closed_ports_count": 0,
            "total_scanned": 0,
            "ports": [],
            "status": f"Unable to resolve hostname '{hostname}'",
            "scan_duration": "0s"
        }

    # Standard common ports to assess
    standard_ports = port_list or [
        21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 
        993, 995, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 27017
    ]

    service_names = {
        21: ("FTP", "High"),
        22: ("SSH", "Low"),
        25: ("SMTP", "Medium"),
        53: ("DNS", "Low"),
        80: ("HTTP", "Low"),
        110: ("POP3", "Medium"),
        143: ("IMAP", "Medium"),
        443: ("HTTPS", "Info"),
        465: ("SMTPS", "Low"),
        587: ("Submission", "Low"),
        993: ("IMAPS", "Low"),
        995: ("POP3S", "Low"),
        3000: ("Node/React Dev", "Medium"),
        3306: ("MySQL Database", "High"),
        5432: ("PostgreSQL Database", "High"),
        6379: ("Redis Cache", "Critical"),
        8000: ("HTTP-Alt", "Medium"),
        8080: ("HTTP-Proxy / WebApp", "Medium"),
        8443: ("HTTPS-Alt", "Low"),
        27017: ("MongoDB Database", "Critical")
    }

    start_time = time.time()
    port_results = []
    open_count = 0
    closed_count = 0

    for port in standard_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            res = s.connect_ex((ip_address, port))
            if res == 0:
                open_count += 1
                svc, risk = service_names.get(port, ("Unknown Service", "Medium"))
                port_results.append({
                    "port": port,
                    "state": "Open",
                    "service": svc,
                    "risk_level": risk
                })
            else:
                closed_count += 1
        except Exception:
            closed_count += 1
        finally:
            s.close()

    duration_sec = round(time.time() - start_time, 2)

    return {
        "target": hostname,
        "ip_address": ip_address,
        "open_ports_count": open_count,
        "closed_ports_count": closed_count,
        "total_scanned": len(standard_ports),
        "ports": port_results,
        "status": "Completed",
        "scan_duration": f"{duration_sec}s"
    }

def analyze_owasp_top10(target_url: str) -> Dict[str, Any]:
    """
    Perform a defensive OWASP Top 10:2025 security assessment on target.
    Evaluates HTTP response headers, TLS posture, cookie security flags, server banners,
    and NVD CVE associations strictly mapped to the official OWASP Top 10:2025 taxonomy.
    Unverifiable categories return 'Unable to Verify'.
    """
    formatted_url = target_url if "://" in target_url else f"https://{target_url}"
    parsed = urllib.parse.urlparse(formatted_url)
    domain = (parsed.netloc or parsed.path).split(":")[0].strip()

    ssl_info = analyze_ssl(target_url)
    headers_info = analyze_headers(target_url)

    resp_headers: Dict[str, str] = {}
    cookies_headers: List[str] = []
    server_banner = ""
    target_reachable = False

    try:
        req = urllib.request.Request(
            formatted_url,
            headers={'User-Agent': 'CloudVuln-OWASP-Auditor/2.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            target_reachable = True
            for k, v in resp.headers.items():
                resp_headers[k.lower()] = v
                if k.lower() == 'set-cookie':
                    cookies_headers.append(v)
            server_banner = resp_headers.get("server") or resp_headers.get("x-powered-by") or ""
    except Exception:
        # Do NOT forge fake banners or fake headers on exception
        target_reachable = False
        server_banner = ""

    # Real CVE query only if a real server technology was detected
    cve_records: List[Dict[str, Any]] = []
    if server_banner:
        tech_keyword = server_banner.split("/")[0] if "/" in server_banner else server_banner
        if len(tech_keyword) > 2:
            cve_records = query_nvd_cve(tech_keyword)

    findings = []
    is_https = formatted_url.startswith("https://")

    # A01:2025 – Broken Access Control
    if not target_reachable:
        findings.append({
            "owasp_id": "A01:2025",
            "category": "Broken Access Control",
            "title": "Access Control Verification Inconclusive",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Target endpoint could not be reached over HTTP/HTTPS to evaluate public access control boundaries.",
            "evidence": f"Connection to {formatted_url} timed out or was refused.",
            "affected_component": "Network Transport Boundary",
            "impact": "Boundary access control directives could not be inspected passively.",
            "recommendation": "Ensure target host is reachable and accepts HTTP/HTTPS traffic.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"
        })
    else:
        cors_origin = resp_headers.get("access-control-allow-origin")
        if cors_origin == "*":
            findings.append({
                "owasp_id": "A01:2025",
                "category": "Broken Access Control",
                "title": "Wildcard CORS Access Control Policy Detected",
                "status": "Failed",
                "severity": "High",
                "description": "The Access-Control-Allow-Origin header is set to wildcard '*', permitting untrusted external web origins to read response payloads.",
                "evidence": f"Access-Control-Allow-Origin: {cors_origin}",
                "affected_component": "HTTP Response Headers / CORS Policy",
                "impact": "Enables cross-origin data exposure if authenticated data is served without strict origin checks.",
                "recommendation": "Restrict CORS policy to explicitly trusted origin domains instead of wildcard '*'.",
                "cvss_score": 7.5,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"
            })
        elif not is_https:
            findings.append({
                "owasp_id": "A01:2025",
                "category": "Broken Access Control",
                "title": "Unencrypted HTTP Transport Endpoint",
                "status": "Failed",
                "severity": "High",
                "description": "Target endpoint operates over unencrypted HTTP protocol without enforced TLS transport encryption.",
                "evidence": f"URL Scheme: {parsed.scheme}",
                "affected_component": "Transport Layer",
                "impact": "Transmitted session identifiers, tokens, and data are exposed to interception on public networks.",
                "recommendation": "Enforce HTTP-to-HTTPS redirection and mandate TLS 1.2+ across all routes.",
                "cvss_score": 7.5,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"
            })
        else:
            findings.append({
                "owasp_id": "A01:2025",
                "category": "Broken Access Control",
                "title": "Access Control Transport Policy Compliant",
                "status": "Passed",
                "severity": "Passed",
                "description": "Transport channel mandates TLS encryption and no permissive wildcard CORS policies were identified on public headers.",
                "evidence": f"Target HTTPS URL: {formatted_url}, CORS: {cors_origin or 'Not Set / Restricted'}",
                "affected_component": "HTTP Response Headers",
                "impact": "None observed on public transport headers.",
                "recommendation": "Maintain granular role-based access control (RBAC) on internal application routes.",
                "cvss_score": 0.0,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/"
            })

    # A02:2025 – Security Misconfiguration
    if not target_reachable:
        findings.append({
            "owasp_id": "A02:2025",
            "category": "Security Misconfiguration",
            "title": "Security Configuration Audit Inconclusive",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Target did not respond to passive HTTP probe; security headers could not be verified.",
            "evidence": "Probe timed out or connection was refused.",
            "affected_component": "Web Server Hardening",
            "impact": "Cannot assess presence of essential hardening headers.",
            "recommendation": "Verify web server availability and probe response.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"
        })
    else:
        missing_sec_headers = []
        for h in ["x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]:
            if h not in resp_headers:
                missing_sec_headers.append(h)

        if server_banner or missing_sec_headers:
            findings.append({
                "owasp_id": "A02:2025",
                "category": "Security Misconfiguration",
                "title": "Security Headers Missing or Version Banner Disclosed",
                "status": "Failed" if len(missing_sec_headers) >= 2 else "Warning",
                "severity": "Medium",
                "description": "Web server discloses software version metadata or omits standard security hardening response headers.",
                "evidence": f"Server Banner: '{server_banner or 'None'}', Missing Headers: {', '.join(missing_sec_headers) if missing_sec_headers else 'None'}",
                "affected_component": "HTTP Response Headers / Web Server Configuration",
                "impact": "Discloses technology stack and increases vulnerability to clickjacking or MIME confusion attacks.",
                "recommendation": "Suppress Server and X-Powered-By banners; configure X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.",
                "cvss_score": 5.3,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"
            })
        else:
            findings.append({
                "owasp_id": "A02:2025",
                "category": "Security Misconfiguration",
                "title": "Security Headers Configured & Server Banner Suppressed",
                "status": "Passed",
                "severity": "Passed",
                "description": "Standard security response headers are configured and no sensitive software version banners were disclosed.",
                "evidence": "X-Frame-Options and X-Content-Type-Options detected; Server banner suppressed.",
                "affected_component": "Web Server Config",
                "impact": "Information disclosure minimized.",
                "recommendation": "Maintain hardening policies across deployments.",
                "cvss_score": 0.0,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"
            })

    # A03:2025 – Software Supply Chain Failures
    top_cve = cve_records[0] if cve_records else None
    if top_cve and top_cve.get("cvss_score", 0) >= 7.0:
        findings.append({
            "owasp_id": "A03:2025",
            "category": "Software Supply Chain Failures",
            "title": f"Known CVEs Identified in Software Component ({top_cve.get('cve_id')})",
            "status": "Failed",
            "severity": top_cve.get("severity", "High").capitalize(),
            "description": "Identified component version matches public high-severity CVE records in the National Vulnerability Database (NVD).",
            "evidence": f"Component: {server_banner}, Identified CVE: {top_cve.get('cve_id')} (CVSS {top_cve.get('cvss_score')})",
            "affected_component": f"Exposed Component ({top_cve.get('cve_id')})",
            "impact": "Exposed vulnerable third-party components enable remote exploitation.",
            "recommendation": f"Upgrade affected package to a patched version resolving {top_cve.get('cve_id')}.",
            "cvss_score": top_cve.get("cvss_score"),
            "related_cve": top_cve.get("cve_id"),
            "reference": top_cve.get("reference_url") or "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"
        })
    elif server_banner:
        findings.append({
            "owasp_id": "A03:2025",
            "category": "Software Supply Chain Failures",
            "title": "No Critical Outdated Component CVEs Identified",
            "status": "Passed",
            "severity": "Passed",
            "description": f"Live NVD lookup for detected software stack '{server_banner}' returned no active critical CVE matches.",
            "evidence": f"Audited software stack: {server_banner}",
            "affected_component": "Server Software Components",
            "impact": "Component stack appears up to date against current NVD baseline.",
            "recommendation": "Integrate automated Dependency-Check and SBOM tracking in CI/CD pipeline.",
            "cvss_score": 0.0,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"
        })
    else:
        findings.append({
            "owasp_id": "A03:2025",
            "category": "Software Supply Chain Failures",
            "title": "Software Supply Chain Dependencies Unverified",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Server banners and application dependencies are suppressed or unidentifiable from external boundary inspection.",
            "evidence": "No software version banners or package manifests exposed externally.",
            "affected_component": "Application Dependencies",
            "impact": "Internal software dependencies require static analysis (SAST) or Software Bill of Materials (SBOM) review.",
            "recommendation": "Scan application build dependencies with automated SBOM tools.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"
        })

    # A04:2025 – Cryptographic Failures
    has_hsts = "strict-transport-security" in resp_headers
    tls_ver = ssl_info.get("tls_version", "Not Available")
    is_cert_valid = ssl_info.get("is_valid", False)

    if not is_https:
        findings.append({
            "owasp_id": "A04:2025",
            "category": "Cryptographic Failures",
            "title": "Missing Transport Layer Encryption (Cleartext HTTP)",
            "status": "Failed",
            "severity": "High",
            "description": "Target operates over unencrypted HTTP, failing basic transport cryptographic requirements.",
            "evidence": f"Target scheme: {parsed.scheme}",
            "affected_component": "Transport Layer",
            "impact": "All transmitted data is unencrypted and vulnerable to eavesdropping and manipulation.",
            "recommendation": "Install an SSL/TLS certificate and mandate HTTPS across all endpoints.",
            "cvss_score": 7.5,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"
        })
    elif not is_cert_valid or tls_ver in ["TLSv1", "TLSv1.1"] or not has_hsts:
        findings.append({
            "owasp_id": "A04:2025",
            "category": "Cryptographic Failures",
            "title": "Cryptographic Protection Deficiencies Identified",
            "status": "Failed" if not is_cert_valid else "Warning",
            "severity": "High" if not is_cert_valid else "Medium",
            "description": "Assessment detected weak or missing cryptographic controls on the target transport channel.",
            "evidence": f"TLS Version: {tls_ver}, Cert Status: {ssl_info.get('cert_status')}, HSTS Header: {'Present' if has_hsts else 'Missing'}",
            "affected_component": "SSL/TLS Configuration & Headers",
            "impact": "Exposes traffic to SSL stripping, protocol downgrade attacks, and interception.",
            "recommendation": "Configure Strict-Transport-Security (HSTS max-age=31536000) and ensure valid TLS 1.2+ certificate.",
            "cvss_score": 6.5,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"
        })
    else:
        findings.append({
            "owasp_id": "A04:2025",
            "category": "Cryptographic Failures",
            "title": "Strong TLS Cryptographic Configuration Verified",
            "status": "Passed",
            "severity": "Passed",
            "description": "Target employs a valid TLS certificate with modern protocol version and HSTS directive.",
            "evidence": f"Protocol: {tls_ver}, Issuer: {ssl_info.get('issuer')}, HSTS: {resp_headers.get('strict-transport-security')}",
            "affected_component": "SSL/TLS Transport Engine",
            "impact": "Encrypted communication channels protect confidentiality and integrity.",
            "recommendation": "Maintain automated certificate renewal and monitor cipher hygiene.",
            "cvss_score": 0.0,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"
        })

    # A05:2025 – Injection
    has_csp = "content-security-policy" in resp_headers
    if not target_reachable:
        findings.append({
            "owasp_id": "A05:2025",
            "category": "Injection",
            "title": "Injection Defenses Inconclusive",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Target response could not be retrieved to verify injection defenses.",
            "evidence": "Target unreachable during probe.",
            "affected_component": "HTTP Response Headers",
            "impact": "Injection mitigation posture cannot be validated passively.",
            "recommendation": "Deploy a strict Content-Security-Policy header restricting script-src and object-src.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A05_2025-Injection/"
        })
    elif not has_csp:
        findings.append({
            "owasp_id": "A05:2025",
            "category": "Injection",
            "title": "Missing Content Security Policy (Cross-Site Scripting Injection Risk)",
            "status": "Warning",
            "severity": "High",
            "description": "Content-Security-Policy (CSP) header is absent from HTTP response headers.",
            "evidence": "Header 'Content-Security-Policy' is absent from server response.",
            "affected_component": "HTTP Response Headers / Browser Sandbox",
            "impact": "Client browser has no script execution restrictions, increasing risk of Cross-Site Scripting (XSS).",
            "recommendation": "Deploy a strict Content-Security-Policy header restricting script-src, object-src, and base-uri.",
            "cvss_score": 7.2,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A05_2025-Injection/"
        })
    else:
        findings.append({
            "owasp_id": "A05:2025",
            "category": "Injection",
            "title": "Content Security Policy Header Configured",
            "status": "Passed",
            "severity": "Passed",
            "description": "Server supplies a Content-Security-Policy header to restrict untrusted script execution.",
            "evidence": f"CSP Value: {(resp_headers.get('content-security-policy') or '')[:80]}...",
            "affected_component": "HTTP Response Headers",
            "impact": "Restricts untrusted script injection execution in client browsers.",
            "recommendation": "Periodically audit CSP directives to avoid unsafe-inline or wildcard origins.",
            "cvss_score": 0.0,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A05_2025-Injection/"
        })

    # A06:2025 – Insecure Design
    findings.append({
        "owasp_id": "A06:2025",
        "category": "Insecure Design",
        "title": "Architecture & Threat Model Design Verification",
        "status": "Unable to Verify",
        "severity": "Unable to Verify",
        "description": "Architectural design flaws, threat modeling gaps, and business logic flaws require threat modeling reviews and authenticated source audits.",
        "evidence": "Passive network inspection cannot reliably evaluate internal application business workflows.",
        "affected_component": "Application Architecture / Business Logic",
        "impact": "Design-level vulnerabilities cannot be identified through passive boundary checks alone.",
        "recommendation": "Perform formal threat modeling, secure design reviews, and authenticated logic audits.",
        "cvss_score": None,
        "related_cve": None,
        "reference": "https://owasp.org/Top10/A06_2025-Insecure_Design/"
    })

    # A07:2025 – Authentication Failures
    if not target_reachable:
        findings.append({
            "owasp_id": "A07:2025",
            "category": "Authentication Failures",
            "title": "Authentication Session Controls Inconclusive",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Target unreachable; session cookie security directives could not be retrieved.",
            "evidence": "No response received from target.",
            "affected_component": "Session Management",
            "impact": "Cannot assess session cookie flags.",
            "recommendation": "Ensure session cookies enforce Secure, HttpOnly, and SameSite directives.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A07_2025-Authentication_Failures/"
        })
    else:
        insecure_cookies = []
        for c in cookies_headers:
            c_lower = c.lower()
            if "secure" not in c_lower or "httponly" not in c_lower:
                insecure_cookies.append(c)

        if insecure_cookies:
            findings.append({
                "owasp_id": "A07:2025",
                "category": "Authentication Failures",
                "title": "Session Cookies Missing Security Directives (Secure / HttpOnly)",
                "status": "Failed",
                "severity": "Medium",
                "description": "HTTP response Set-Cookie header lacks essential 'Secure' or 'HttpOnly' flags.",
                "evidence": f"Set-Cookie Header: {insecure_cookies[0][:60]}...",
                "affected_component": "HTTP Session Management / Cookies",
                "impact": "Session cookies can be stolen via XSS (missing HttpOnly) or intercepted over unencrypted channels (missing Secure).",
                "recommendation": "Append 'Secure; HttpOnly; SameSite=Lax' directives to all session authorization cookies.",
                "cvss_score": 6.1,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A07_2025-Authentication_Failures/"
            })
        else:
            findings.append({
                "owasp_id": "A07:2025",
                "category": "Authentication Failures",
                "title": "Authentication Session Transport Controls Verified",
                "status": "Passed",
                "severity": "Passed",
                "description": "No insecure session cookies without Secure/HttpOnly flags were detected on public HTTP headers.",
                "evidence": "Public HTTP response headers checked for unflagged Set-Cookie directives.",
                "affected_component": "Session Token Transport",
                "impact": "Protects session cookies from client script access and cleartext interception.",
                "recommendation": "Enforce multi-factor authentication (MFA) and strong password rules on authentication endpoints.",
                "cvss_score": 0.0,
                "related_cve": None,
                "reference": "https://owasp.org/Top10/A07_2025-Authentication_Failures/"
            })

    # A08:2025 – Software or Data Integrity Failures
    if not target_reachable:
        findings.append({
            "owasp_id": "A08:2025",
            "category": "Software or Data Integrity Failures",
            "title": "Integrity Directives Inconclusive",
            "status": "Unable to Verify",
            "severity": "Unable to Verify",
            "description": "Target did not respond; asset integrity directives could not be inspected.",
            "evidence": "Target unreachable during inspection.",
            "affected_component": "Client-Side Asset Delivery",
            "impact": "Cannot assess asset integrity controls.",
            "recommendation": "Implement Subresource Integrity (SRI) on external scripts and link tags.",
            "cvss_score": None,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/"
        })
    elif not has_csp:
        findings.append({
            "owasp_id": "A08:2025",
            "category": "Software or Data Integrity Failures",
            "title": "Unverified Third-Party Asset Integrity Posture",
            "status": "Warning",
            "severity": "Low",
            "description": "Lack of Content-Security-Policy or Subresource Integrity (SRI) posture allows untrusted remote asset execution.",
            "evidence": "CSP script-src policy missing on target HTTP response.",
            "affected_component": "Client-Side Asset Delivery",
            "impact": "Risk of compromised third-party CDN libraries injecting malicious payloads.",
            "recommendation": "Implement Subresource Integrity (SRI) hashes on external scripts and restrict CSP script sources.",
            "cvss_score": 3.7,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/"
        })
    else:
        findings.append({
            "owasp_id": "A08:2025",
            "category": "Software or Data Integrity Failures",
            "title": "Software Asset Integrity Directives Active",
            "status": "Passed",
            "severity": "Passed",
            "description": "Target provides script execution boundaries via HTTP security policy headers.",
            "evidence": f"CSP directive present on {domain}",
            "affected_component": "Asset Loading Policy",
            "impact": "Reduces unauthorized script manipulation risks.",
            "recommendation": "Sign build artifacts and verify integrity hashes across CI/CD distribution pipelines.",
            "cvss_score": 0.0,
            "related_cve": None,
            "reference": "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/"
        })

    # A09:2025 – Security Logging & Alerting Failures
    findings.append({
        "owasp_id": "A09:2025",
        "category": "Security Logging & Alerting Failures",
        "title": "Centralized Security Logging & Auditing Baseline",
        "status": "Unable to Verify",
        "severity": "Unable to Verify",
        "description": "Internal security logging, SIEM ingestion, log retention, and real-time alert thresholds cannot be evaluated via passive boundary checks.",
        "evidence": "Internal log management pipeline requires internal SecOps infrastructure audit.",
        "affected_component": "Logging & Monitoring / SIEM Pipeline",
        "impact": "Delayed breach detection and insufficient audit trails if logging is inactive.",
        "recommendation": "Ensure all API requests, authentication attempts, and privilege escalations stream to an immutable SIEM platform.",
        "cvss_score": None,
        "related_cve": None,
        "reference": "https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/"
    })

    # A10:2025 – Mishandling of Exceptional Conditions
    findings.append({
        "owasp_id": "A10:2025",
        "category": "Mishandling of Exceptional Conditions",
        "title": "Exception Handling & Error Disclosure Inspection",
        "status": "Unable to Verify",
        "severity": "Unable to Verify",
        "description": "Verifying internal exception handling, stack trace suppression, and error handling resilience requires authenticated test payloads.",
        "evidence": "Non-destructive passive scan does not submit malformed payloads to trigger exception conditions.",
        "affected_component": "Backend Exception Handling / Error Handlers",
        "impact": "Unhandled exceptions could leak internal server stack traces or cause denial of service.",
        "recommendation": "Implement centralized exception handlers and ensure generic error pages are returned to clients.",
        "cvss_score": None,
        "related_cve": None,
        "reference": "https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/"
    })

    passed_count = sum(1 for f in findings if f["status"] == "Passed")
    failed_count = sum(1 for f in findings if f["status"] == "Failed")
    warning_count = sum(1 for f in findings if f["status"] == "Warning")
    unverifiable_count = sum(1 for f in findings if f["status"] == "Unable to Verify")

    crit_c = sum(1 for f in findings if f["severity"] == "Critical")
    high_c = sum(1 for f in findings if f["severity"] == "High")
    med_c = sum(1 for f in findings if f["severity"] == "Medium")
    low_c = sum(1 for f in findings if f["severity"] == "Low")

    overall_score = max(0, 100 - (crit_c * 25 + high_c * 15 + med_c * 8 + low_c * 3 + warning_count * 5))
    if overall_score >= 85:
        risk_level = "Low"
    elif overall_score >= 70:
        risk_level = "Medium"
    elif overall_score >= 50:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return {
        "total_checks": len(findings),
        "passed_checks": passed_count,
        "failed_checks": failed_count,
        "warnings_count": warning_count,
        "unable_to_verify_count": unverifiable_count,
        "critical_count": crit_c,
        "high_count": high_c,
        "medium_count": med_c,
        "low_count": low_c,
        "overall_score": overall_score,
        "risk_level": risk_level,
        "findings": findings
    }

def calculate_security_score(
    ssl_summary: Dict[str, Any],
    headers_summary: Dict[str, Any],
    cve_findings: List[Dict[str, Any]],
    whois_summary: Dict[str, Any],
    ports_summary: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Calculate an overall deterministic security score from 0-100 based on actual findings.
    Scoring Formula:
      Base Score: 100
      - Headers Penalty: up to 35 pts (CSP: -12, HSTS: -10, X-Frame: -8, X-Content-Type: -5, Referrer: -4, Permissions: -3)
      - SSL/TLS Penalty: up to 35 pts (Invalid/Expired: -35, Expiring <14d: -15, Expiring <30d: -5, Deprecated TLS: -15)
      - CVSS CVE Penalty: up to 35 pts (Critical CVSS>=9.0: -15 ea, High CVSS>=7.0: -10 ea, Med CVSS>=4.0: -5 ea)
      - Open High-Risk Ports: up to 20 pts (Redis/MongoDB: -10 ea, MySQL/Postgres exposed: -5 ea)
    Deterministic: identical inputs guarantee identical outputs.
    """
    base_score = 100
    
    header_weights = {
        "Content-Security-Policy": 12,
        "Strict-Transport-Security": 10,
        "X-Frame-Options": 8,
        "X-Content-Type-Options": 5,
        "Referrer-Policy": 4,
        "Permissions-Policy": 3
    }
    header_penalty = 0
    missing_headers = []
    for chk in headers_summary.get("checks", []):
        if not chk.get("present"):
            hname = chk.get("name")
            missing_headers.append(hname)
            header_penalty += header_weights.get(hname, 4)
    header_penalty = min(35, header_penalty)

    ssl_penalty = 0
    ssl_issues = []
    if not ssl_summary.get("is_valid", False):
        ssl_penalty += 35
        ssl_issues.append("SSL/TLS Certificate is EXPIRED or INVALID.")
    else:
        days_left = ssl_summary.get("days_until_expiration", 90)
        if days_left < 14:
            ssl_penalty += 15
            ssl_issues.append(f"Certificate expires in {days_left} days.")
        elif days_left < 30:
            ssl_penalty += 5
            ssl_issues.append(f"Certificate expires in {days_left} days.")

    tls_ver = ssl_summary.get("tls_version", "Unknown")
    if tls_ver in ["TLSv1", "TLSv1.1"]:
        ssl_penalty += 15
        ssl_issues.append(f"Deprecated protocol version ({tls_ver}) enabled.")

    ssl_penalty = min(35, ssl_penalty)

    cvss_penalty = 0
    critical_cves = 0
    high_cves = 0
    medium_cves = 0
    low_cves = 0

    for cve in cve_findings:
        cvss = float(cve.get("cvss_score", 5.0))
        sev = str(cve.get("severity", "")).lower()
        if cvss >= 9.0 or sev == "critical":
            critical_cves += 1
            cvss_penalty += 15
        elif cvss >= 7.0 or sev == "high":
            high_cves += 1
            cvss_penalty += 10
        elif cvss >= 4.0 or sev == "medium":
            medium_cves += 1
            cvss_penalty += 5
        else:
            low_cves += 1
            cvss_penalty += 2

    cvss_penalty = min(35, cvss_penalty)

    # Ports penalty
    ports_penalty = 0
    if ports_summary:
        for p in ports_summary.get("ports", []):
            risk = p.get("risk_level", "").lower()
            if risk == "critical":
                ports_penalty += 10
            elif risk == "high":
                ports_penalty += 5
    ports_penalty = min(20, ports_penalty)

    overall_score = max(0, min(100, base_score - header_penalty - ssl_penalty - cvss_penalty - ports_penalty))

    if overall_score >= 85:
        risk_level = "Low"
    elif overall_score >= 70:
        risk_level = "Medium"
    elif overall_score >= 50:
        risk_level = "High"
    else:
        risk_level = "Critical"

    critical_count = critical_cves + (1 if not ssl_summary.get("is_valid") else 0) + (1 if "Content-Security-Policy" in missing_headers else 0)
    high_count = high_cves + (1 if "Strict-Transport-Security" in missing_headers else 0) + (1 if "X-Frame-Options" in missing_headers else 0)
    medium_count = medium_cves + (1 if "X-Content-Type-Options" in missing_headers else 0) + (1 if "Referrer-Policy" in missing_headers else 0)
    low_count = low_cves + (1 if "Permissions-Policy" in missing_headers else 0)

    exec_summary = (
        f"Automated security posture analysis completed for target environment. "
        f"Overall Security Score: {overall_score}/100 ({risk_level.upper()} RISK). "
        f"Identified {critical_count} Critical, {high_count} High, {medium_count} Medium, and {low_count} Low vulnerability findings. "
    )
    if missing_headers:
        exec_summary += f"Missing HTTP headers: {', '.join(missing_headers[:3])}. "
    if ssl_issues:
        exec_summary += f"SSL/TLS posture: {' '.join(ssl_issues)} "
    elif ssl_summary.get("is_valid"):
        exec_summary += f"SSL/TLS certificate status: Valid ({ssl_summary.get('issuer', 'Valid CA')}, {tls_ver}). "
    if whois_summary.get("registrar") and whois_summary.get("registrar") != "Not Available":
        exec_summary += f"Domain registered via {whois_summary.get('registrar')} (expiry: {whois_summary.get('expiry_date', 'N/A')})."

    return {
        "security_score": overall_score,
        "risk_level": risk_level,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "executive_summary": exec_summary
    }

def perform_security_analysis(target_url: str) -> Dict[str, Any]:
    """Execute complete multi-module real security assessment for a target."""
    target_clean = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    ip_addr = get_target_ip(target_clean)
    
    ssl_summary = analyze_ssl(target_url)
    headers_summary = analyze_headers(target_url)
    whois_summary = analyze_whois(target_url)
    owasp_summary = analyze_owasp_top10(target_url)
    ports_summary = analyze_ports(target_clean)

    # Search CVEs for detected server banner if present
    cve_findings: List[Dict[str, Any]] = []
    # Check if OWASP or headers detected a banner
    try:
        req = urllib.request.Request(
            target_url if "://" in target_url else f"https://{target_url}",
            headers={'User-Agent': 'CloudVuln-Auditor/2.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            banner = resp.headers.get("Server") or resp.headers.get("X-Powered-By") or ""
            if banner:
                tech = banner.split("/")[0] if "/" in banner else banner
                if len(tech) > 2:
                    cve_findings = query_nvd_cve(tech)
    except Exception:
        cve_findings = []

    score_data = calculate_security_score(ssl_summary, headers_summary, cve_findings, whois_summary, ports_summary)

    recommendations = []
    if not ssl_summary.get("is_valid"):
        recommendations.append("Renew or install a valid SSL/TLS certificate from a trusted Certificate Authority.")
    
    for chk in headers_summary.get("checks", []):
        if not chk.get("present") and chk.get("value") != "Unable to Verify":
            recommendations.append(f"Configure HTTP Header: {chk['name']}. {chk['recommendation']}")

    if ports_summary.get("open_ports_count", 0) > 0:
        open_p_nums = [str(p["port"]) for p in ports_summary.get("ports", [])]
        recommendations.append(f"Audit exposed open ports ({', '.join(open_p_nums)}) and restrict ingress access via firewall or Security Groups.")

    if cve_findings:
        recommendations.append("Apply vendor security patches for software dependencies with known public CVEs.")

    if not recommendations:
        recommendations.append("Maintain existing security posture and automated periodic vulnerability scanning.")

    return {
        "target": target_clean,
        "ip_address": ip_addr,
        "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "Completed",
        "risk_level": score_data["risk_level"],
        "security_score": score_data["security_score"],
        "critical_count": score_data["critical_count"],
        "high_count": score_data["high_count"],
        "medium_count": score_data["medium_count"],
        "low_count": score_data["low_count"],
        "executive_summary": score_data["executive_summary"],
        "whois_summary": whois_summary,
        "owasp_summary": owasp_summary,
        "ssl_summary": ssl_summary,
        "headers_summary": headers_summary,
        "ports_summary": ports_summary,
        "cve_findings": cve_findings,
        "recommendations": recommendations
    }
