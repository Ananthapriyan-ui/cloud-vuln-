import io
import datetime
import html as html_module
from typing import Dict, Any, List

def _esc(val) -> str:
    if val is None:
        return "Not Available"
    return html_module.escape(str(val))

def _val(val, fallback="Not Available") -> str:
    if val is None or str(val).strip() == "":
        return fallback
    return str(val)

def _severity_badge_style(severity: str) -> str:
    sev = severity.upper() if severity else ""
    if "CRITICAL" in sev:
        return "background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;"
    if "HIGH" in sev:
        return "background:rgba(249,115,22,0.2);color:#fb923c;border:1px solid #f97316;"
    if "MEDIUM" in sev:
        return "background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid #f59e0b;"
    if "LOW" in sev:
        return "background:rgba(96,165,250,0.2);color:#93c5fd;border:1px solid #60a5fa;"
    if "PASS" in sev or "INFO" in sev:
        return "background:rgba(16,185,129,0.2);color:#34d399;border:1px solid #10b981;"
    if "WARN" in sev:
        return "background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid #f59e0b;"
    return "background:rgba(100,116,139,0.2);color:#94a3b8;border:1px solid #64748b;"

def _status_badge_style(status: str) -> str:
    s = (status or "").upper()
    if s in ("PASSED", "PASS"):
        return "background:rgba(16,185,129,0.2);color:#34d399;border:1px solid #10b981;"
    if s in ("FAILED", "FAIL"):
        return "background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;"
    if s in ("WARNING", "WARN"):
        return "background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid #f59e0b;"
    if "VERIFY" in s or "UNABLE" in s:
        return "background:rgba(100,116,139,0.2);color:#94a3b8;border:1px solid #64748b;"
    return "background:rgba(100,116,139,0.2);color:#94a3b8;border:1px solid #64748b;"

def _risk_color(risk_score) -> str:
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        return "#34d399"
    if score >= 9.0:
        return "#f87171"
    if score >= 7.0:
        return "#fb923c"
    if score >= 4.0:
        return "#fbbf24"
    return "#34d399"

def _build_whois_section(whois: Dict) -> str:
    if not whois:
        return ""
    registrar = _esc(whois.get("registrar"))
    creation = _esc(whois.get("creation_date"))
    expiry = _esc(whois.get("expiry_date"))
    ns_raw = whois.get("name_servers") or []
    ns = ", ".join(_esc(n) for n in ns_raw) if ns_raw else "Not Available"
    status_raw = whois.get("domain_status") or []
    domain_status = ", ".join(_esc(s) for s in status_raw) if status_raw else "Not Available"
    return (
        '<div class="section-title">&#127760; WHOIS Domain Registration</div>'
        '<div class="info-box">'
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;width:180px;border-bottom:1px solid #1e293b;">Registrar</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{registrar}</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;">Creation Date</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{creation}</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;">Expiry Date</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{expiry}</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;">Name Servers</td><td style="padding:6px 10px;font-family:monospace;color:#38bdf8;border-bottom:1px solid #1e293b;">{ns}</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;">Domain Status</td><td style="padding:6px 10px;">{domain_status}</td></tr>'
        '</table></div>'
    )

def _build_ssl_section(ssl_data: Dict) -> str:
    if not ssl_data:
        return ""
    cert_status = _esc(ssl_data.get("cert_status"))
    issuer = _esc(ssl_data.get("issuer"))
    expiry = _esc(ssl_data.get("expiry_date"))
    tls_ver = _esc(ssl_data.get("tls_version"))
    days_left = _val(ssl_data.get("days_until_expiration"), "Not Available")
    is_valid = ssl_data.get("is_valid", True)
    recs = ssl_data.get("recommendations") or []
    badge_style = "background:rgba(16,185,129,0.2);color:#34d399;border:1px solid #10b981;" if is_valid else "background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;"
    recs_html = "".join(f'<li style="margin-bottom:4px;color:#94a3b8;">{_esc(r)}</li>' for r in recs)
    recs_block = f'<div style="margin-top:12px;"><div style="font-size:12px;color:#94a3b8;margin-bottom:6px;">Recommendations:</div><ul style="padding-left:20px;margin:0;font-size:12px;">{recs_html}</ul></div>' if recs else ""
    return (
        '<div class="section-title">&#128274; SSL / TLS Certificate Audit</div>'
        '<div class="info-box">'
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;width:180px;border-bottom:1px solid #1e293b;">Certificate Status</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:700;{badge_style}">{cert_status}</span></td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;">Issuer</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{issuer}</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;border-bottom:1px solid #1e293b;">Expiry Date</td><td style="padding:6px 10px;border-bottom:1px solid #1e293b;">{expiry} ({days_left} days remaining)</td></tr>'
        f'<tr><td style="padding:6px 10px;color:#94a3b8;">TLS Version</td><td style="padding:6px 10px;font-family:monospace;color:#38bdf8;">{tls_ver}</td></tr>'
        '</table>'
        f'{recs_block}'
        '</div>'
    )

def _build_headers_section(headers: Dict) -> str:
    if not headers:
        return ""
    score = _val(headers.get("score"), "N/A")
    passed = _val(headers.get("passed_count"), "0")
    total = _val(headers.get("total_count"), "0")
    checks = headers.get("checks") or []
    rows = ""
    for c in checks:
        present = c.get("present", False)
        pstyle = "background:rgba(16,185,129,0.2);color:#34d399;border:1px solid #10b981;" if present else "background:rgba(239,68,68,0.2);color:#f87171;border:1px solid #ef4444;"
        ptext = "Present" if present else "Missing"
        val_raw = c.get("value")
        value_cell = f'<span style="font-family:monospace;font-size:11px;color:#38bdf8;">{_esc(val_raw)}</span>' if val_raw else '<span style="color:#64748b;">&#8212;</span>'
        rows += (
            f'<tr>'
            f'<td style="padding:8px 12px;font-family:monospace;font-size:12px;font-weight:bold;color:#00f3ff;border-bottom:1px solid #1e293b;">{_esc(c.get("name"))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:700;{pstyle}">{ptext}</span></td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #1e293b;">{value_cell}</td>'
            f'<td style="padding:8px 12px;color:#94a3b8;font-size:12px;border-bottom:1px solid #1e293b;">{_esc(c.get("risk_if_missing"))}</td>'
            f'<td style="padding:8px 12px;color:#94a3b8;font-size:12px;border-bottom:1px solid #1e293b;">{_esc(c.get("recommendation"))}</td>'
            f'</tr>'
        )
    th = '<th style="padding:10px 12px;text-align:left;color:#94a3b8;font-family:monospace;font-size:11px;text-transform:uppercase;border-bottom:1px solid #1e293b;">'
    return (
        '<div class="section-title">&#128737; HTTP Security Headers Analysis</div>'
        f'<div class="info-box" style="margin-bottom:16px;"><div style="display:flex;justify-content:space-between;align-items:center;"><span style="color:#00f3ff;font-weight:bold;">Headers Score: {score}/100</span><span style="color:#94a3b8;font-size:13px;">{passed} / {total} headers present</span></div></div>'
        '<div style="overflow-x:auto;margin-bottom:24px;"><table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="background:#161f33;">{th}Header</th>{th}Status</th>{th}Value</th>{th}Risk if Missing</th>{th}Recommendation</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )

def _build_owasp_section(owasp: Dict) -> str:
    if not owasp:
        return ""
    total = _val(owasp.get("total_checks"), "0")
    passed = _val(owasp.get("passed_checks"), "0")
    failed = _val(owasp.get("failed_checks"), "0")
    warnings = _val(owasp.get("warnings_count"), "0")
    unable = _val(owasp.get("unable_to_verify_count"), "0")
    overall = _val(owasp.get("overall_score"), "N/A")
    risk = _val(owasp.get("risk_level"), "Unknown")
    findings: List[Dict] = owasp.get("findings") or []
    rows = ""
    for f in findings:
        status = f.get("status", "Unknown")
        severity = f.get("severity", "Unknown")
        sstyle = _status_badge_style(status)
        sevstyle = _severity_badge_style(severity)
        rows += (
            f'<tr>'
            f'<td style="padding:10px 12px;font-family:monospace;font-weight:bold;color:#00f3ff;border-bottom:1px solid #1e293b;font-size:12px;">{_esc(f.get("owasp_id"))}</td>'
            f'<td style="padding:10px 12px;border-bottom:1px solid #1e293b;font-size:12px;"><strong>{_esc(f.get("category"))}</strong></td>'
            f'<td style="padding:10px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:700;{sstyle}">{_esc(status)}</span></td>'
            f'<td style="padding:10px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:700;{sevstyle}">{_esc(severity)}</span></td>'
            f'<td style="padding:10px 12px;color:#e2e8f0;border-bottom:1px solid #1e293b;font-size:12px;">{_esc(f.get("title"))}</td>'
            f'<td style="padding:10px 12px;color:#94a3b8;border-bottom:1px solid #1e293b;font-size:12px;">{_esc(f.get("recommendation"))}</td>'
            f'</tr>'
        )
    if not rows:
        rows = '<tr><td colspan="6" style="padding:20px;text-align:center;color:#64748b;">No OWASP findings recorded for this scan.</td></tr>'
    th = '<th style="padding:10px 12px;text-align:left;color:#94a3b8;font-family:monospace;font-size:11px;text-transform:uppercase;border-bottom:1px solid #1e293b;">'
    return (
        '<div class="section-title">&#9888; OWASP Top 10 Security Assessment</div>'
        '<div class="info-box" style="margin-bottom:16px;">'
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center;">'
        f'<div><div style="font-size:22px;font-weight:900;color:#34d399;">{passed}</div><div style="font-size:11px;color:#94a3b8;">Passed</div></div>'
        f'<div><div style="font-size:22px;font-weight:900;color:#f87171;">{failed}</div><div style="font-size:11px;color:#94a3b8;">Failed</div></div>'
        f'<div><div style="font-size:22px;font-weight:900;color:#fbbf24;">{warnings}</div><div style="font-size:11px;color:#94a3b8;">Warnings</div></div>'
        f'<div><div style="font-size:22px;font-weight:900;color:#94a3b8;">{unable}</div><div style="font-size:11px;color:#94a3b8;">Unable to Verify</div></div>'
        '</div>'
        f'<div style="margin-top:12px;text-align:center;font-size:13px;color:#94a3b8;">Overall OWASP Score: <strong style="color:#00f3ff;">{overall}/100</strong> | Risk Level: <strong style="color:#fbbf24;">{_esc(risk)}</strong> | Total Checks: {total}</div>'
        '</div>'
        '<div style="overflow-x:auto;margin-bottom:24px;"><table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="background:#161f33;">{th}OWASP ID</th>{th}Category</th>{th}Status</th>{th}Severity</th>{th}Finding</th>{th}Recommendation</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )

def _build_owasp_detail_section(owasp: Dict) -> str:
    if not owasp:
        return ""
    findings: List[Dict] = owasp.get("findings") or []
    if not findings:
        return ""
    cards = ""
    for f in findings:
        status = f.get("status", "Unknown")
        severity = f.get("severity", "Unknown")
        sevstyle = _severity_badge_style(severity)
        evidence = _esc(f.get("evidence") or "Not Available")
        description = _esc(f.get("description") or "Not Available")
        affected = _esc(f.get("affected_component") or "Not Available")
        impact = _esc(f.get("impact") or "Not Available")
        recommendation = _esc(f.get("recommendation") or "Not Available")
        cve = _esc(f.get("related_cve") or "Not Available")
        cvss = _val(f.get("cvss_score"), "Not Available")
        reference = f.get("reference") or ""
        owasp_id = _esc(f.get("owasp_id") or "")
        category = _esc(f.get("category") or "")
        title = _esc(f.get("title") or "")
        sev_up = severity.upper()
        border_color = "#ef4444" if "CRITICAL" in sev_up else ("#f97316" if "HIGH" in sev_up else ("#f59e0b" if "MEDIUM" in sev_up else ("#60a5fa" if "LOW" in sev_up else ("#10b981" if "PASS" in status.upper() else "#64748b"))))
        ref_html = f'<div style="margin-top:10px;font-size:11px;color:#64748b;">Reference: <a href="{html_module.escape(reference)}" style="color:#38bdf8;">{html_module.escape(reference)}</a></div>' if reference else ""
        cards += (
            f'<div style="border:1px solid {border_color}33;border-left:4px solid {border_color};border-radius:10px;background:#0d1424;padding:18px;margin-bottom:16px;">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap;">'
            f'<span style="font-family:monospace;font-weight:bold;color:#00f3ff;font-size:13px;">{owasp_id}</span>'
            f'<span style="font-size:13px;font-weight:bold;color:#e2e8f0;">{category}</span>'
            f'<span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:700;{sevstyle}">{_esc(severity)}</span>'
            f'<span style="margin-left:auto;font-size:12px;color:#94a3b8;">{_esc(status)}</span>'
            f'</div>'
            f'<div style="font-size:14px;font-weight:700;color:#f1f5f9;margin-bottom:12px;">{title}</div>'
            f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;font-size:12px;">'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">Description</div><div style="color:#cbd5e1;line-height:1.6;">{description}</div></div>'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">Evidence</div><div style="color:#cbd5e1;font-family:monospace;background:#04070d;padding:8px;border-radius:6px;border:1px solid rgba(0,243,255,0.15);">{evidence}</div></div>'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">Affected Component</div><div style="color:#38bdf8;font-family:monospace;">{affected}</div></div>'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">Impact</div><div style="color:#cbd5e1;">{impact}</div></div>'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">CVSS Score / Related CVE</div><div style="color:#fbbf24;font-family:monospace;">{cvss} &nbsp;|&nbsp; {cve}</div></div>'
            f'<div><div style="color:#64748b;text-transform:uppercase;font-size:10px;font-family:monospace;margin-bottom:4px;">Recommendation</div><div style="color:#34d399;">{recommendation}</div></div>'
            f'</div>'
            f'{ref_html}'
            f'</div>'
        )
    return (
        '<div class="section-title">&#128269; OWASP Finding Details</div>'
        f'<div style="margin-bottom:24px;">{cards}</div>'
    )

def _build_cve_section(cve_findings: List[Dict]) -> str:
    if not cve_findings:
        return ""
    rows = ""
    for c in cve_findings:
        severity = c.get("severity", "Unknown")
        sevstyle = _severity_badge_style(severity)
        cve_id = _esc(c.get("cve_id") or "Not Available")
        cvss = _val(c.get("cvss_score"), "N/A")
        description = _esc(c.get("description") or "Not Available")
        published = _esc(c.get("published_date") or "Not Available")
        ref_url = c.get("reference_url") or ""
        ref_cell = f'<a href="{html_module.escape(ref_url)}" style="color:#38bdf8;font-size:11px;font-family:monospace;">NVD &#8599;</a>' if ref_url else '<span style="color:#64748b;">N/A</span>'
        rows += (
            f'<tr>'
            f'<td style="padding:10px 12px;font-family:monospace;font-weight:bold;color:#f87171;border-bottom:1px solid #1e293b;font-size:12px;">{cve_id}</td>'
            f'<td style="padding:10px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:3px 10px;border-radius:9999px;font-size:11px;font-weight:700;{sevstyle}">{_esc(severity)}</span></td>'
            f'<td style="padding:10px 12px;font-family:monospace;font-weight:bold;color:#fbbf24;border-bottom:1px solid #1e293b;font-size:13px;">{_esc(cvss)}</td>'
            f'<td style="padding:10px 12px;color:#cbd5e1;font-size:12px;max-width:300px;border-bottom:1px solid #1e293b;">{description}</td>'
            f'<td style="padding:10px 12px;color:#64748b;font-size:12px;border-bottom:1px solid #1e293b;">{published}</td>'
            f'<td style="padding:10px 12px;border-bottom:1px solid #1e293b;">{ref_cell}</td>'
            f'</tr>'
        )
    th = '<th style="padding:10px 12px;text-align:left;color:#94a3b8;font-family:monospace;font-size:11px;text-transform:uppercase;border-bottom:1px solid #1e293b;">'
    return (
        f'<div class="section-title">&#128308; CVE / NVD Vulnerability Findings ({len(cve_findings)})</div>'
        '<div style="overflow-x:auto;margin-bottom:24px;"><table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="background:#161f33;">{th}CVE ID</th>{th}Severity</th>{th}CVSS</th>{th}Description</th>{th}Published</th>{th}Reference</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )

def _build_recommendations_section(recommendations: List[str]) -> str:
    if not recommendations:
        return ""
    items = "".join(
        f'<li style="padding:8px 0;border-bottom:1px solid #1e293b;color:#94a3b8;font-size:13px;"><span style="color:#34d399;margin-right:8px;">&#8594;</span>{_esc(r)}</li>'
        for r in recommendations
    )
    return (
        '<div class="section-title">&#9989; Priority Recommendations</div>'
        f'<ul style="list-style:none;padding:0;margin-bottom:24px;">{items}</ul>'
    )


def _build_ports_section(ports_data: Dict) -> str:
    if not ports_data or not ports_data.get("ports"):
        return ""
    ports = ports_data.get("ports", [])
    open_c = ports_data.get("open_ports_count", len(ports))
    total_c = ports_data.get("total_scanned", len(ports))
    rows = ""
    for p in ports:
        port_num = p.get("port")
        state = p.get("state", "Open")
        svc = p.get("service", "Unknown")
        risk = p.get("risk_level", "Low")
        rstyle = _severity_badge_style(risk)
        rows += (
            f'<tr>'
            f'<td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#00f3ff;border-bottom:1px solid #1e293b;">{port_num}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #1e293b;"><span style="color:#34d399;font-weight:bold;">{state}</span></td>'
            f'<td style="padding:8px 12px;font-size:12px;color:#e2e8f0;border-bottom:1px solid #1e293b;">{_esc(svc)}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #1e293b;"><span style="display:inline-block;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:700;{rstyle}">{_esc(risk)}</span></td>'
            f'</tr>'
        )
    th = '<th style="padding:10px 12px;text-align:left;color:#94a3b8;font-family:monospace;font-size:11px;text-transform:uppercase;border-bottom:1px solid #1e293b;">'
    return (
        f'<div class="section-title">&#128421; Port Scanner Assessment ({open_c} Open of {total_c} Scanned)</div>'
        '<div style="overflow-x:auto;margin-bottom:24px;"><table style="width:100%;border-collapse:collapse;">'
        f'<thead><tr style="background:#161f33;">{th}Port</th>{th}State</th>{th}Service</th>{th}Risk Level</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )

CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: linear-gradient(135deg, #060b14 0%, #090d1e 100%);
    color: #e2e8f0;
    min-height: 100vh;
    padding: 40px 20px;
}
.container {
    max-width: 1080px;
    margin: 0 auto;
    background: #0a1020;
    border: 1px solid rgba(0, 243, 255, 0.2);
    border-radius: 20px;
    padding: 40px;
    box-shadow: 0 0 60px rgba(0, 243, 255, 0.06), 0 20px 60px rgba(0,0,0,0.6);
}
.report-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 24px;
    margin-bottom: 32px;
    gap: 20px;
    flex-wrap: wrap;
}
.brand-logo { font-size: 28px; font-weight: 900; color: #00f3ff; letter-spacing: -1px; text-shadow: 0 0 20px rgba(0,243,255,0.4); }
.brand-sub { font-size: 12px; color: #64748b; font-family: monospace; margin-top: 4px; letter-spacing: 1px; }
.report-id-block { text-align: right; }
.report-id { font-family: monospace; font-size: 13px; color: #94a3b8; }
.report-id strong { color: #00f3ff; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
.meta-item { background: #0d1424; border: 1px solid #1e293b; border-radius: 12px; padding: 14px 18px; }
.meta-label { font-size: 10px; text-transform: uppercase; font-family: monospace; color: #64748b; margin-bottom: 4px; letter-spacing: 0.5px; }
.meta-value { font-size: 13px; color: #e2e8f0; font-weight: 600; }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
.summary-card { background: #0d1424; border: 1px solid #1e293b; border-radius: 14px; padding: 20px; text-align: center; }
.summary-card .count { font-size: 36px; font-weight: 900; line-height: 1; margin-bottom: 6px; }
.summary-card .label { font-size: 11px; color: #64748b; text-transform: uppercase; font-family: monospace; }
.exec-summary { background: rgba(0,243,255,0.04); border: 1px solid rgba(0,243,255,0.25); border-left: 4px solid #00f3ff; border-radius: 12px; padding: 20px 24px; margin-bottom: 32px; font-size: 13px; line-height: 1.8; color: #cbd5e1; }
.exec-summary-label { font-size: 10px; font-family: monospace; font-weight: 700; color: #00f3ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
.section-title { font-size: 16px; font-weight: 700; color: #f1f5f9; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-top: 32px; }
.info-box { background: #0d1424; border: 1px solid #1e293b; border-radius: 12px; padding: 18px 20px; margin-bottom: 24px; font-size: 13px; line-height: 1.7; }
.report-footer { text-align: center; font-size: 11px; color: #334155; margin-top: 48px; border-top: 1px solid #1e293b; padding-top: 24px; line-height: 1.8; }
.report-footer strong { color: #64748b; }
a { color: #38bdf8; }
@media (max-width: 640px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
"""

def generate_html_report(scan_data: Dict[str, Any]) -> str:
    scan_ref = _esc(scan_data.get("scan_ref") or "Unknown")
    target = _esc(scan_data.get("target") or "Unknown")
    provider = _esc(scan_data.get("provider") or scan_data.get("cloud_provider") or "Not Available")
    risk_score_raw = scan_data.get("risk_score") or 0.0
    risk_score = _val(risk_score_raw, "0.0")
    status = _esc((scan_data.get("status") or "unknown").upper())
    critical_count = int(scan_data.get("critical_count") or 0)
    high_count = int(scan_data.get("high_count") or 0)
    medium_count = int(scan_data.get("medium_count") or 0)
    low_count = int(scan_data.get("low_count") or 0)
    total_issues = critical_count + high_count + medium_count + low_count
    created_at = _esc(scan_data.get("created_at") or scan_data.get("executed_at") or "Not Available")
    duration = _esc(scan_data.get("duration") or "Not Available")

    parsed: Dict = scan_data.get("scan_data") or {}
    security_score = _val(parsed.get("security_score"), "Not Available")
    ip_address = _esc(parsed.get("ip_address") or "Not Available")
    scan_timestamp = _esc(parsed.get("scan_timestamp") or created_at)
    risk_level = _esc(parsed.get("risk_level") or scan_data.get("status") or "Unknown")
    exec_summary = _esc(parsed.get("executive_summary") or f"Automated Security Posture Analysis for target {target}. Risk Score: {risk_score}/10.")
    scan_types_raw = parsed.get("scan_types") or []
    scan_type_from_db = scan_data.get("scan_type") or "Security Assessment"
    scan_types_display = _esc(", ".join(scan_types_raw)) if scan_types_raw else _esc(scan_type_from_db)

    whois = parsed.get("whois_summary") or {}
    ssl_data = parsed.get("ssl_summary") or {}
    headers = parsed.get("headers_summary") or {}
    ports_data = parsed.get("ports_summary") or {}
    owasp = parsed.get("owasp_summary") or {}
    cve_findings: List[Dict] = parsed.get("cve_findings") or []
    recommendations: List[str] = parsed.get("recommendations") or []

    whois_html = _build_whois_section(whois) if whois else ""
    ssl_html = _build_ssl_section(ssl_data) if ssl_data else ""
    headers_html = _build_headers_section(headers) if headers else ""
    ports_html = _build_ports_section(ports_data) if ports_data else ""
    owasp_summary_html = _build_owasp_section(owasp) if owasp else ""
    owasp_detail_html = _build_owasp_detail_section(owasp) if owasp else ""
    cve_html = _build_cve_section(cve_findings) if cve_findings else ""
    recs_html = _build_recommendations_section(recommendations) if recommendations else ""

    risk_color = _risk_color(risk_score_raw)
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status_border = "#ef4444" if "CRITICAL" in status else ("#f97316" if "HIGH" in status else ("#f59e0b" if "MEDIUM" in status else "#10b981"))

    status_badge = (
        f'<span style="display:inline-block;padding:6px 16px;border-radius:9999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-top:6px;'
        f'background:rgba(239,68,68,0.15);border:1px solid {status_border};color:{status_border};">{status}</span>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudVuln Security Report - {scan_ref}</title>
<style>{CSS}
.c-critical {{ color: #f87171; }}
.c-high {{ color: #fb923c; }}
.c-medium {{ color: #fbbf24; }}
.c-low {{ color: #60a5fa; }}
</style>
</head>
<body>
<div class="container">
<div class="report-header">
  <div>
    <div class="brand-logo">&#9729; CloudVuln</div>
    <div class="brand-sub">SECURITY ASSESSMENT REPORT</div>
  </div>
  <div class="report-id-block">
    <div class="report-id">Report ID: <strong>{scan_ref}</strong></div>
    <div class="report-id" style="margin-top:4px;">Target: <strong style="color:#e2e8f0;">{target}</strong></div>
    <div class="report-id" style="margin-top:4px;">Provider: <strong style="color:#94a3b8;">{provider}</strong></div>
    {status_badge}
  </div>
</div>
<div class="meta-grid">
  <div class="meta-item"><div class="meta-label">IP Address</div><div class="meta-value" style="font-family:monospace;color:#38bdf8;">{ip_address}</div></div>
  <div class="meta-item"><div class="meta-label">Scan Date</div><div class="meta-value">{scan_timestamp}</div></div>
  <div class="meta-item"><div class="meta-label">Duration</div><div class="meta-value">{duration}</div></div>
  <div class="meta-item"><div class="meta-label">Scan Modules</div><div class="meta-value" style="font-size:11px;">{scan_types_display}</div></div>
  <div class="meta-item"><div class="meta-label">Security Score</div><div class="meta-value" style="color:#34d399;font-size:18px;font-weight:900;">{security_score}/100</div></div>
  <div class="meta-item"><div class="meta-label">Risk Level</div><div class="meta-value">{risk_level}</div></div>
  <div class="meta-item"><div class="meta-label">Total Findings</div><div class="meta-value" style="color:#f87171;">{total_issues}</div></div>
  <div class="meta-item"><div class="meta-label">Generated At</div><div class="meta-value" style="font-size:11px;font-family:monospace;">{generated_at}</div></div>
</div>
<div class="summary-grid">
  <div class="summary-card" style="border-color:rgba(239,68,68,0.3);"><div class="count c-critical">{critical_count}</div><div class="label">Critical</div></div>
  <div class="summary-card" style="border-color:rgba(249,115,22,0.3);"><div class="count c-high">{high_count}</div><div class="label">High</div></div>
  <div class="summary-card" style="border-color:rgba(245,158,11,0.3);"><div class="count c-medium">{medium_count}</div><div class="label">Medium</div></div>
  <div class="summary-card" style="border-color:rgba(96,165,250,0.3);"><div class="count c-low">{low_count}</div><div class="label">Low</div></div>
</div>
<div class="exec-summary">
  <div class="exec-summary-label">Executive Summary &amp; Posture Evaluation</div>
  {exec_summary}
</div>
{whois_html}
{ssl_html}
{headers_html}
{ports_html}
{owasp_summary_html}
{owasp_detail_html}
{cve_html}
{recs_html}
<div class="report-footer">
  <div>Generated by <strong>CloudVuln Security Engine v2.0</strong></div>
  <div>Report ID: <strong>{scan_ref}</strong> | Target: <strong>{target}</strong></div>
  <div>Execution: <strong>{scan_timestamp}</strong> | Generated: <strong>{generated_at}</strong></div>
  <div style="margin-top:8px;color:#1e293b;">This report is confidential and intended solely for authorized security personnel.</div>
</div>
</div>
</body>
</html>"""


def generate_csv_report(scan_data: Dict[str, Any]) -> str:
    import csv
    parsed = scan_data.get("scan_data") or {}
    owasp = parsed.get("owasp_summary") or {}
    findings = owasp.get("findings") or []
    cve_findings = parsed.get("cve_findings") or []
    headers_info = parsed.get("headers_summary") or {}
    ssl_info = parsed.get("ssl_summary") or {}
    ports_info = parsed.get("ports_summary") or {}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CloudVuln Security Assessment Report"])
    writer.writerow([])
    writer.writerow(["Assessment Metadata", "Value"])
    writer.writerow(["Scan Reference", scan_data.get("scan_ref", "")])
    writer.writerow(["Target", scan_data.get("target", "")])
    writer.writerow(["Provider", scan_data.get("provider", scan_data.get("cloud_provider", ""))])
    writer.writerow(["Security Score", parsed.get("security_score", "N/A")])
    writer.writerow(["Risk Score", scan_data.get("risk_score", "")])
    writer.writerow(["Status", scan_data.get("status", "")])
    writer.writerow(["Critical Count", scan_data.get("critical_count", 0)])
    writer.writerow(["High Count", scan_data.get("high_count", 0)])
    writer.writerow(["Medium Count", scan_data.get("medium_count", 0)])
    writer.writerow(["Low Count", scan_data.get("low_count", 0)])
    writer.writerow(["Execution Date", scan_data.get("created_at", scan_data.get("executed_at", ""))])
    writer.writerow([])

    # HTTP Security Headers
    if headers_info.get("checks"):
        writer.writerow(["HTTP Security Headers Analysis"])
        writer.writerow(["Header Name", "Status", "Configured Value", "Risk if Missing", "Recommendation"])
        for h in headers_info["checks"]:
            writer.writerow([h.get("name",""), "Present" if h.get("present") else "Missing", h.get("value",""), h.get("risk_if_missing",""), h.get("recommendation","")])
        writer.writerow([])

    # SSL / TLS Certificate
    if ssl_info:
        writer.writerow(["SSL / TLS Configuration Audit"])
        writer.writerow(["Property", "Value"])
        writer.writerow(["Certificate Status", ssl_info.get("cert_status", "")])
        writer.writerow(["Issuer", ssl_info.get("issuer", "")])
        writer.writerow(["Expiry Date", ssl_info.get("expiry_date", "")])
        writer.writerow(["TLS Protocol Version", ssl_info.get("tls_version", "")])
        writer.writerow([])

    # Port Scanner
    if ports_info.get("ports"):
        writer.writerow(["Port Scanner Assessment"])
        writer.writerow(["Port", "State", "Service Name", "Risk Level"])
        for p in ports_info["ports"]:
            writer.writerow([p.get("port",""), p.get("state",""), p.get("service",""), p.get("risk_level","")])
        writer.writerow([])

    # OWASP Top 10:2025
    if findings:
        writer.writerow(["OWASP Top 10:2025 Findings"])
        writer.writerow(["OWASP ID", "Category", "Title", "Status", "Severity", "Description", "Evidence", "Affected Component", "Impact", "Recommendation", "CVSS Score", "Related CVE", "Reference"])
        for f in findings:
            writer.writerow([f.get("owasp_id",""), f.get("category",""), f.get("title",""), f.get("status",""), f.get("severity",""), f.get("description",""), f.get("evidence",""), f.get("affected_component",""), f.get("impact",""), f.get("recommendation",""), f.get("cvss_score",""), f.get("related_cve",""), f.get("reference","")])
        writer.writerow([])

    # CVE Findings
    if cve_findings:
        writer.writerow(["CVE / NVD Findings"])
        writer.writerow(["CVE ID", "Severity", "CVSS Score", "Description", "Published Date", "Reference URL"])
        for c in cve_findings:
            writer.writerow([c.get("cve_id",""), c.get("severity",""), c.get("cvss_score",""), c.get("description",""), c.get("published_date",""), c.get("reference_url","")])
    return output.getvalue()


def generate_comparison_html_report(comparison: Dict[str, Any]) -> str:
    """Generate professional HTML comparison report between two real scans."""
    prev = comparison.get("previous_scan", {})
    latest = comparison.get("latest_scan", {})
    summary = comparison.get("summary", {})
    severity = comparison.get("severity_comparison", {})
    vuln_changes = comparison.get("vulnerability_changes", {})
    owasp_list = comparison.get("owasp_comparison", [])
    cve_comp = comparison.get("cve_comparison", {})
    header_comp = comparison.get("header_comparison", {})
    ssl_comp = comparison.get("ssl_comparison", {})

    prev_ref = _esc(prev.get("scan_ref", "Previous Scan"))
    latest_ref = _esc(latest.get("scan_ref", "Latest Scan"))
    target = _esc(latest.get("target") or prev.get("target") or "Unknown Target")

    prev_score = summary.get("previous_security_score", 0)
    latest_score = summary.get("latest_security_score", 0)
    score_diff = summary.get("score_difference", 0)
    pct_change = summary.get("percentage_change", 0.0)
    security_status = _esc(summary.get("security_status", "No Significant Change"))

    status_color = "#34d399" if "Improved" in security_status else ("#f87171" if "Degraded" in security_status else "#94a3b8")
    status_badge = (
        f'<span style="display:inline-block;padding:6px 16px;border-radius:9999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;'
        f'background:rgba(255,255,255,0.05);border:1px solid {status_color};color:{status_color};">{security_status}</span>'
    )

    diff_color = "#34d399" if score_diff > 0 else ("#f87171" if score_diff < 0 else "#94a3b8")
    diff_prefix = "+" if score_diff > 0 else ""

    # Severity Matrix HTML
    crit = severity.get("critical", {})
    high = severity.get("high", {})
    med = severity.get("medium", {})
    low = severity.get("low", {})
    tot = severity.get("total", {})

    def _delta_badge(change: int) -> str:
        if change < 0:
            return f'<span style="color:#34d399;font-weight:bold;">{change} (Reduced)</span>'
        elif change > 0:
            return f'<span style="color:#f87171;font-weight:bold;">+{change} (Increased)</span>'
        return '<span style="color:#94a3b8;">0 (Unchanged)</span>'

    severity_table_html = f"""
    <div class="section-title">&#128202; Severity &amp; Finding Delta Matrix</div>
    <div class="info-box">
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="border-bottom:1px solid #334155;color:#94a3b8;text-align:left;">
            <th style="padding:8px 10px;">Severity Level</th>
            <th style="padding:8px 10px;">Previous ({prev_ref})</th>
            <th style="padding:8px 10px;">Latest ({latest_ref})</th>
            <th style="padding:8px 10px;">Change / Impact</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom:1px solid #1e293b;"><td style="padding:8px 10px;color:#f87171;font-weight:bold;">Critical</td><td style="padding:8px 10px;">{crit.get('previous', 0)}</td><td style="padding:8px 10px;">{crit.get('latest', 0)}</td><td style="padding:8px 10px;">{_delta_badge(crit.get('change', 0))}</td></tr>
          <tr style="border-bottom:1px solid #1e293b;"><td style="padding:8px 10px;color:#fb923c;font-weight:bold;">High</td><td style="padding:8px 10px;">{high.get('previous', 0)}</td><td style="padding:8px 10px;">{high.get('latest', 0)}</td><td style="padding:8px 10px;">{_delta_badge(high.get('change', 0))}</td></tr>
          <tr style="border-bottom:1px solid #1e293b;"><td style="padding:8px 10px;color:#fbbf24;font-weight:bold;">Medium</td><td style="padding:8px 10px;">{med.get('previous', 0)}</td><td style="padding:8px 10px;">{med.get('latest', 0)}</td><td style="padding:8px 10px;">{_delta_badge(med.get('change', 0))}</td></tr>
          <tr style="border-bottom:1px solid #1e293b;"><td style="padding:8px 10px;color:#60a5fa;font-weight:bold;">Low</td><td style="padding:8px 10px;">{low.get('previous', 0)}</td><td style="padding:8px 10px;">{low.get('latest', 0)}</td><td style="padding:8px 10px;">{_delta_badge(low.get('change', 0))}</td></tr>
          <tr style="font-weight:bold;background:rgba(255,255,255,0.02);"><td style="padding:8px 10px;color:#f1f5f9;">Total Findings</td><td style="padding:8px 10px;">{tot.get('previous', 0)}</td><td style="padding:8px 10px;">{tot.get('latest', 0)}</td><td style="padding:8px 10px;">{_delta_badge(tot.get('change', 0))}</td></tr>
        </tbody>
      </table>
    </div>
    """

    # Vulnerability Change Analysis (Fixed, New, Persistent)
    fixed = vuln_changes.get("fixed", [])
    new = vuln_changes.get("new", [])
    persistent = vuln_changes.get("persistent", [])

    def _render_vuln_list(items: List[Dict], badge_color: str, title: str) -> str:
        if not items:
            return f'<div style="color:#64748b;font-size:12px;padding:8px 0;">No {title.lower()} findings.</div>'
        rows = []
        for it in items:
            cve = _esc(it.get("cve_id") or it.get("id") or "FINDING")
            t = _esc(it.get("title", ""))
            sev = _esc(it.get("severity", "Medium"))
            comp = _esc(it.get("component", "Application"))
            rows.append(
                f'<div style="padding:8px 12px;background:#090d16;border:1px solid #1e293b;border-radius:8px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;">'
                f'<div><span style="font-family:monospace;font-size:11px;color:{badge_color};font-weight:bold;margin-right:8px;">{cve}</span>'
                f'<span style="font-size:12px;color:#e2e8f0;">{t}</span>'
                f'<div style="font-size:11px;color:#64748b;margin-top:2px;">Component: {comp}</div></div>'
                f'<span style="font-size:11px;padding:2px 8px;border-radius:4px;{_severity_badge_style(sev)}">{sev}</span>'
                f'</div>'
            )
        return "".join(rows)

    vuln_change_html = f"""
    <div class="section-title">&#128269; Vulnerability Lifecycle Analysis</div>
    <div class="meta-grid" style="grid-template-columns: repeat(3, 1fr);">
      <div class="meta-item" style="border-top:3px solid #34d399;">
        <div class="meta-label" style="color:#34d399;">Fixed Vulnerabilities ({len(fixed)})</div>
        <div style="margin-top:10px;">{_render_vuln_list(fixed, '#34d399', 'Fixed')}</div>
      </div>
      <div class="meta-item" style="border-top:3px solid #f87171;">
        <div class="meta-label" style="color:#f87171;">New Vulnerabilities ({len(new)})</div>
        <div style="margin-top:10px;">{_render_vuln_list(new, '#f87171', 'New')}</div>
      </div>
      <div class="meta-item" style="border-top:3px solid #fbbf24;">
        <div class="meta-label" style="color:#fbbf24;">Persistent Vulnerabilities ({len(persistent)})</div>
        <div style="margin-top:10px;">{_render_vuln_list(persistent, '#fbbf24', 'Persistent')}</div>
      </div>
    </div>
    """

    # OWASP Top 10 Comparison HTML
    owasp_rows = []
    for ow in owasp_list:
        chg = ow.get("change_type", "No Change")
        chg_color = "#34d399" if chg == "Improvement" else ("#f87171" if chg == "New Issue" else ("#fbbf24" if chg == "Persistent Issue" else "#94a3b8"))
        owasp_rows.append(
            f'<tr style="border-bottom:1px solid #1e293b;">'
            f'<td style="padding:8px 10px;font-family:monospace;color:#38bdf8;">{_esc(ow.get("owasp_id"))}</td>'
            f'<td style="padding:8px 10px;font-weight:600;">{_esc(ow.get("category"))}</td>'
            f'<td style="padding:8px 10px;"><span style="display:inline-block;padding:2px 8px;border-radius:9999px;font-size:10px;{_status_badge_style(ow.get("previous_status"))}">{_esc(ow.get("previous_status"))}</span></td>'
            f'<td style="padding:8px 10px;"><span style="display:inline-block;padding:2px 8px;border-radius:9999px;font-size:10px;{_status_badge_style(ow.get("latest_status"))}">{_esc(ow.get("latest_status"))}</span></td>'
            f'<td style="padding:8px 10px;color:{chg_color};font-weight:600;">{_esc(chg)}</td>'
            f'</tr>'
        )

    owasp_table_html = f"""
    <div class="section-title">&#128737; OWASP Top 10 Security Posture Comparison</div>
    <div class="info-box">
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead>
          <tr style="border-bottom:1px solid #334155;color:#94a3b8;text-align:left;">
            <th style="padding:8px 10px;">ID</th>
            <th style="padding:8px 10px;">OWASP Category</th>
            <th style="padding:8px 10px;">Previous Status</th>
            <th style="padding:8px 10px;">Latest Status</th>
            <th style="padding:8px 10px;">Posture Evolution</th>
          </tr>
        </thead>
        <tbody>
          {"".join(owasp_rows)}
        </tbody>
      </table>
    </div>
    """

    # HTTP Headers & SSL/TLS section
    hdr_fixed = header_comp.get("fixed", [])
    hdr_new_missing = header_comp.get("newly_missing", [])
    hdr_still_missing = header_comp.get("still_missing", [])
    hdr_secure = header_comp.get("remained_secure", [])

    header_summary_text = f"Headers Fixed: {len(hdr_fixed)} | Newly Missing: {len(hdr_new_missing)} | Still Missing: {len(hdr_still_missing)} | Remained Secure: {len(hdr_secure)}"

    headers_ssl_html = f"""
    <div class="section-title">&#128272; HTTP Security Headers &amp; SSL/TLS Audit Comparison</div>
    <div class="meta-grid" style="grid-template-columns: 1fr 1fr;">
      <div class="meta-item">
        <div class="meta-label">HTTP Security Headers Trend</div>
        <div style="font-size:12px;color:#e2e8f0;margin-top:6px;line-height:1.6;">
          <div><strong>Previous Header Score:</strong> {header_comp.get('previous_score', 0)}% &rarr; <strong>Latest Score:</strong> {header_comp.get('latest_score', 0)}%</div>
          <div style="color:#94a3b8;margin-top:4px;">{header_summary_text}</div>
          <div style="margin-top:8px;">
            <span style="display:inline-block;padding:2px 8px;margin:2px;border-radius:4px;background:rgba(16,185,129,0.1);color:#34d399;font-size:11px;">Fixed: {len(hdr_fixed)}</span>
            <span style="display:inline-block;padding:2px 8px;margin:2px;border-radius:4px;background:rgba(239,68,68,0.1);color:#f87171;font-size:11px;">Newly Missing: {len(hdr_new_missing)}</span>
            <span style="display:inline-block;padding:2px 8px;margin:2px;border-radius:4px;background:rgba(245,158,11,0.1);color:#fbbf24;font-size:11px;">Still Missing: {len(hdr_still_missing)}</span>
            <span style="display:inline-block;padding:2px 8px;margin:2px;border-radius:4px;background:rgba(56,189,248,0.1);color:#38bdf8;font-size:11px;">Secure: {len(hdr_secure)}</span>
          </div>
        </div>
      </div>
      <div class="meta-item">
        <div class="meta-label">SSL / TLS Certificate Posture</div>
        <div style="font-size:12px;color:#e2e8f0;margin-top:6px;line-height:1.6;">
          <div><strong>SSL Evolution:</strong> <span style="color:#34d399;font-weight:bold;">{_esc(ssl_comp.get('status', 'Unchanged'))}</span></div>
          <div><strong>Previous:</strong> {_esc(ssl_comp.get('previous_cert_status'))} ({_esc(ssl_comp.get('previous_tls_version'))}, {_esc(ssl_comp.get('previous_days_left'))} days left)</div>
          <div><strong>Latest:</strong> {_esc(ssl_comp.get('latest_cert_status'))} ({_esc(ssl_comp.get('latest_tls_version'))}, {_esc(ssl_comp.get('latest_days_left'))} days left)</div>
          <div style="color:#94a3b8;font-size:11px;margin-top:4px;">Issuer: {_esc(ssl_comp.get('latest_issuer'))}</div>
        </div>
      </div>
    </div>
    """

    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudVuln Security Comparison Report - {prev_ref} vs {latest_ref}</title>
<style>{CSS}
.c-critical {{ color: #f87171; }}
.c-high {{ color: #fb923c; }}
.c-medium {{ color: #fbbf24; }}
.c-low {{ color: #60a5fa; }}
</style>
</head>
<body>
<div class="container">
<div class="report-header">
  <div>
    <div class="brand-logo">&#9729; CloudVuln</div>
    <div class="brand-sub">SCAN COMPARISON &amp; SECURITY TREND REPORT</div>
  </div>
  <div class="report-id-block">
    <div class="report-id">Target: <strong style="color:#e2e8f0;">{target}</strong></div>
    <div class="report-id" style="margin-top:4px;">Comparing: <strong>{prev_ref}</strong> &rarr; <strong>{latest_ref}</strong></div>
    <div style="margin-top:8px;">{status_badge}</div>
  </div>
</div>

<div class="summary-grid">
  <div class="summary-card" style="border-color:rgba(56,189,248,0.3);">
    <div class="count" style="color:#38bdf8;">{prev_score} <span style="font-size:18px;color:#64748b;">&rarr;</span> {latest_score}</div>
    <div class="label">Security Score (0-100)</div>
    <div style="font-size:12px;margin-top:6px;color:{diff_color};font-weight:bold;">{diff_prefix}{score_diff} pts ({pct_change}%)</div>
  </div>
  <div class="summary-card" style="border-color:rgba(16,185,129,0.3);">
    <div class="count" style="color:#34d399;">{len(fixed)}</div>
    <div class="label">Findings Fixed</div>
    <div style="font-size:11px;margin-top:6px;color:#64748b;">Resolved in latest scan</div>
  </div>
  <div class="summary-card" style="border-color:rgba(239,68,68,0.3);">
    <div class="count" style="color:#f87171;">{len(new)}</div>
    <div class="label">New Findings</div>
    <div style="font-size:11px;margin-top:6px;color:#64748b;">Introduced since previous</div>
  </div>
  <div class="summary-card" style="border-color:rgba(245,158,11,0.3);">
    <div class="count" style="color:#fbbf24;">{len(persistent)}</div>
    <div class="label">Persistent Findings</div>
    <div style="font-size:11px;margin-top:6px;color:#64748b;">Remaining unmitigated</div>
  </div>
</div>

{severity_table_html}
{vuln_change_html}
{owasp_table_html}
{headers_ssl_html}

<div class="report-footer">
  <div>Generated by <strong>CloudVuln Security Comparison Engine v2.0</strong></div>
  <div>Comparing: <strong>{prev_ref}</strong> ({prev.get('created_at','')}) vs <strong>{latest_ref}</strong> ({latest.get('created_at','')})</div>
  <div>Report Generated At: <strong>{generated_at}</strong></div>
  <div style="margin-top:8px;color:#1e293b;">Confidential SecOps Differential Audit Artifact.</div>
</div>
</div>
</body>
</html>"""


def generate_comparison_csv_report(comparison: Dict[str, Any]) -> str:
    """Export comparison report diff matrix in CSV format."""
    import csv
    output = io.StringIO()
    writer = csv.writer(output)

    prev = comparison.get("previous_scan", {})
    latest = comparison.get("latest_scan", {})
    summary = comparison.get("summary", {})
    severity = comparison.get("severity_comparison", {})
    vuln_changes = comparison.get("vulnerability_changes", {})
    owasp_list = comparison.get("owasp_comparison", [])
    cve_comp = comparison.get("cve_comparison", {})
    header_comp = comparison.get("header_comparison", {})

    writer.writerow(["CloudVuln Scan Comparison & Security Trend Report"])
    writer.writerow([])
    writer.writerow(["Comparison Metrics", "Value"])
    writer.writerow(["Target", latest.get("target", "")])
    writer.writerow(["Previous Scan Reference", prev.get("scan_ref", "")])
    writer.writerow(["Previous Scan Date", prev.get("created_at", "")])
    writer.writerow(["Previous Security Score", summary.get("previous_security_score", 0)])
    writer.writerow(["Latest Scan Reference", latest.get("scan_ref", "")])
    writer.writerow(["Latest Scan Date", latest.get("created_at", "")])
    writer.writerow(["Latest Security Score", summary.get("latest_security_score", 0)])
    writer.writerow(["Score Difference", summary.get("score_difference", 0)])
    writer.writerow(["Percentage Change", f"{summary.get('percentage_change', 0.0)}%"])
    writer.writerow(["Security Evolution Status", summary.get("security_status", "")])
    writer.writerow([])

    writer.writerow(["Severity Breakdown", "Previous Count", "Latest Count", "Change"])
    for sev in ["critical", "high", "medium", "low", "total"]:
        data = severity.get(sev, {})
        writer.writerow([sev.capitalize(), data.get("previous", 0), data.get("latest", 0), data.get("change", 0)])
    writer.writerow([])

    writer.writerow(["Vulnerability Lifecycle Category", "Count"])
    writer.writerow(["Fixed Vulnerabilities", len(vuln_changes.get("fixed", []))])
    writer.writerow(["New Vulnerabilities", len(vuln_changes.get("new", []))])
    writer.writerow(["Persistent Vulnerabilities", len(vuln_changes.get("persistent", []))])
    writer.writerow([])

    if vuln_changes.get("fixed"):
        writer.writerow(["Fixed Vulnerabilities List"])
        writer.writerow(["ID / CVE", "Title", "Severity", "Component", "Category"])
        for v in vuln_changes["fixed"]:
            writer.writerow([v.get("cve_id") or v.get("id"), v.get("title"), v.get("severity"), v.get("component"), v.get("category")])
        writer.writerow([])

    if vuln_changes.get("new"):
        writer.writerow(["New Vulnerabilities List"])
        writer.writerow(["ID / CVE", "Title", "Severity", "Component", "Category"])
        for v in vuln_changes["new"]:
            writer.writerow([v.get("cve_id") or v.get("id"), v.get("title"), v.get("severity"), v.get("component"), v.get("category")])
        writer.writerow([])

    if owasp_list:
        writer.writerow(["OWASP Top 10 Comparison"])
        writer.writerow(["OWASP ID", "Category", "Previous Status", "Latest Status", "Change Type", "Recommendation"])
        for ow in owasp_list:
            writer.writerow([ow.get("owasp_id"), ow.get("category"), ow.get("previous_status"), ow.get("latest_status"), ow.get("change_type"), ow.get("recommendation")])
        writer.writerow([])

    return output.getvalue()