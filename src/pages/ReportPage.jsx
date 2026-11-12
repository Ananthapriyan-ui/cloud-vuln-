import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FileText,
  Download,
  Share2,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  ShieldCheck,
  ArrowLeft,
  Server,
  Lock,
  Globe,
  Eye,
  AlertCircle,
  Network,
  Package,
  Cookie,
  CheckCircle2,
  XCircle,
  AlertTriangle
} from 'lucide-react';
import { Card, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { useToast } from '../components/ui/Toast';
import { PageSkeleton } from '../components/ui/Loader';
import api, { formatScanDate } from '../lib/api';

export const ReportPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { addToast } = useToast();

  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [isPreviewModalOpen, setIsPreviewModalOpen] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchReport = async () => {
      setLoading(true);
      setError(null);
      try {
        const scanRef = id || '1';
        const data = await api.getReport(scanRef);
        setReportData(data);
      } catch (e) {
        console.error('Failed to fetch report from API', e);
        setError(e.message || 'Report not found or failed to load.');
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [id]);

  const rawExecutedAt = reportData?.executed_at || reportData?.created_at;
  const reportMeta = {
    scanId: reportData?.scan_ref || id || 'Unknown',
    target: reportData?.target || 'Unknown Target',
    cloudProvider: reportData?.cloud_provider || 'AWS US-East-1',
    executedAt: rawExecutedAt ? formatScanDate(rawExecutedAt) : 'Not Available',
    duration: reportData?.duration || '1m 30s',
    criticalCount: reportData?.critical_count || 0,
    highCount: reportData?.high_count || 0,
    mediumCount: reportData?.medium_count || 0,
    lowCount: reportData?.low_count || 0,
    overallScore: reportData?.risk_score || 0,
    securityScore: reportData?.scan_data?.security_score || 85,
    riskLevel: reportData?.status ? reportData.status.toUpperCase() : 'PASS'
  };

  const executiveSummary =
    reportData?.scan_data?.executive_summary ||
    `Automated security posture analysis completed for ${reportMeta.target}. Overall calculated risk score: ${reportMeta.overallScore}/10.`;

  const portsSummary = reportData?.scan_data?.ports_summary || null;
  const headersSummary = reportData?.scan_data?.headers_summary || null;
  const whoisSummary = reportData?.scan_data?.whois_summary || null;
  const dnsSummary = reportData?.scan_data?.dns_summary || (reportData?.scan_data?.scan_type === 'DNS Security Checker' || reportData?.scan_data?.records_summary ? reportData.scan_data : null);
  const cookieSummary = reportData?.scan_data?.cookie_summary || (reportData?.scan_data?.scan_type === 'Cookie Security Checker' || reportData?.scan_data?.cookies ? reportData.scan_data : null);
  const dependencySummary = reportData?.scan_data?.dependency_summary || (reportData?.scan_data?.scan_type === 'Dependency Vulnerability Scanner' || reportData?.scan_data?.packages ? reportData.scan_data : null);
  const owaspFindings = Array.isArray(reportData?.scan_data?.owasp_summary?.findings)
    ? reportData.scan_data.owasp_summary.findings
    : [];
  const sslSummary = reportData?.scan_data?.ssl_summary || null;
  const vulnerabilities = Array.isArray(reportData?.scan_data?.cve_findings)
    ? reportData.scan_data.cve_findings
    : [];

  const handleCopy = (text, itemKey) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(itemKey);
    addToast('Remediation command copied to clipboard', 'info');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDownload = async (format = 'html') => {
    addToast(`Generating and downloading ${format.toUpperCase()} report...`, 'info');
    try {
      const downloadUrl = api.getReportDownloadUrl(reportMeta.scanId, format);
      const token = localStorage.getItem('cloudvuln_access_token');
      const res = await fetch(downloadUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });

      if (!res.ok) throw new Error('Failed to generate report file');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `CLOUDVULN_Report_${reportMeta.scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
      addToast(`${format.toUpperCase()} Report downloaded successfully!`, 'success');
    } catch (err) {
      console.error(err);
      addToast(`Failed to download report: ${err.message}`, 'error');
    }
  };

  const handleOpenHtmlPreviewInTab = () => {
    const htmlUrl = api.getReportHtmlUrl(reportMeta.scanId);
    window.open(htmlUrl, '_blank');
  };

  if (loading) return <PageSkeleton />;

  if (error || !reportData) {
    return (
      <div className="space-y-6">
        <button
          onClick={() => navigate('/history')}
          className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scan History</span>
        </button>
        <Card className="border-rose-500/40">
          <CardContent className="p-8 text-center space-y-4">
            <AlertCircle className="w-12 h-12 text-rose-400 mx-auto" />
            <h3 className="text-lg font-bold text-slate-100">Unable to Load Report</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">{error || 'Report dataset is not available.'}</p>
            <Button variant="primary" onClick={() => navigate('/history')}>
              View Scan History
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 print:hidden">
        <button
          onClick={() => navigate('/history')}
          className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scan History</span>
        </button>

        <div className="flex items-center flex-wrap gap-3">
          <Button
            variant="outline"
            icon={Eye}
            onClick={() => setIsPreviewModalOpen(true)}
          >
            View HTML Report
          </Button>
          <Button
            variant="outline"
            icon={Download}
            onClick={() => handleDownload('csv')}
          >
            Download CSV Report
          </Button>
          <Button
            variant="primary"
            icon={Download}
            onClick={() => handleDownload('html')}
          >
            Download HTML Report
          </Button>
        </div>
      </div>

      {/* Report Summary Header Card */}
      <Card className="border-cyan-500/30">
        <CardContent className="p-6 space-y-6">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 border-b border-slate-800 pb-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Badge variant={reportMeta.riskLevel === 'CRITICAL' ? 'critical' : reportMeta.riskLevel === 'HIGH' ? 'high' : 'success'} size="sm" dot>
                  {reportMeta.riskLevel} AUDIT
                </Badge>
                <span className="text-xs font-mono text-slate-400">ID: {reportMeta.scanId}</span>
              </div>
              <h2 className="text-2xl font-black text-slate-100">{reportMeta.target}</h2>
              <p className="text-xs text-slate-300 flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                <span>{reportMeta.cloudProvider}</span>
                <span className="text-slate-600">•</span>
                <span>Scanned on {reportMeta.executedAt} ({reportMeta.duration})</span>
              </p>
            </div>

            {/* Score Box */}
            <div className="flex items-center gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800 shrink-0">
              <div className="text-center">
                <span className="block text-[10px] font-mono uppercase text-slate-400">Security Score</span>
                <span className="text-3xl font-black text-emerald-400">{reportMeta.securityScore}/100</span>
              </div>
              <div className="w-px h-10 bg-slate-800" />
              <div className="space-y-1 text-xs">
                <div className="flex items-center gap-2">
                  <Badge variant="critical" size="sm">{reportMeta.criticalCount} Critical</Badge>
                  <Badge variant="high" size="sm">{reportMeta.highCount} High</Badge>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="medium" size="sm">{reportMeta.mediumCount} Medium</Badge>
                  <Badge variant="info" size="sm">{reportMeta.lowCount} Low</Badge>
                </div>
              </div>
            </div>
          </div>

          {/* Executive Summary Box */}
          <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-2">
            <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Executive Summary & Posture Evaluation
            </span>
            <p className="text-xs text-slate-300 leading-relaxed">{executiveSummary}</p>
          </div>

          {/* DNS Security Checker Report Section */}
          {dnsSummary && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-sky-400 flex items-center gap-1.5">
                  <Network className="w-4 h-4" /> DNS Security &amp; Email Authentication (SPF / DMARC / DKIM / DNSSEC)
                </span>
                <Badge variant={dnsSummary.security_score >= 80 ? 'success' : dnsSummary.security_score >= 60 ? 'warning' : 'critical'} size="sm">
                  DNS Score: {dnsSummary.security_score ?? 100}/100
                </Badge>
              </div>

              {/* Records Breakdown Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">SPF Record</span>
                  <p className="text-slate-200 truncate">{dnsSummary.records_summary?.SPF || 'Not Found'}</p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">DMARC Record</span>
                  <p className="text-slate-200 truncate">{dnsSummary.records_summary?.DMARC || 'Not Found'}</p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">DNSSEC Status</span>
                  <p className={dnsSummary.records_summary?.DNSSEC === 'Enabled' ? 'text-emerald-400' : 'text-amber-400'}>
                    {dnsSummary.records_summary?.DNSSEC || 'Disabled'}
                  </p>
                </div>
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">DKIM Status</span>
                  <p className="text-slate-200 truncate">{dnsSummary.records_summary?.DKIM?.record ? 'Configured' : 'Auto-check completed'}</p>
                </div>
              </div>

              {/* Findings Table */}
              {Array.isArray(dnsSummary.findings) && dnsSummary.findings.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                      <tr>
                        <th className="p-2.5">Check</th>
                        <th className="p-2.5">Status</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Observation / Evidence</th>
                        <th className="p-2.5">Recommendation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {dnsSummary.findings.map((f, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/40">
                          <td className="p-2.5 font-bold text-sky-400">{f.check}</td>
                          <td className="p-2.5">
                            <Badge variant={f.status === 'Found' || f.status === 'Enabled' ? 'success' : f.status === 'Missing' || f.status === 'Error' ? 'critical' : 'warning'} size="sm">
                              {f.status}
                            </Badge>
                          </td>
                          <td className="p-2.5 text-slate-300">{f.severity}</td>
                          <td className="p-2.5 text-slate-300 font-sans max-w-xs">{f.description}</td>
                          <td className="p-2.5 text-slate-400 font-sans max-w-xs">{f.recommendation || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Dependency Vulnerability Scanner Report Section */}
          {dependencySummary && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                  <Package className="w-4 h-4" /> Dependency Vulnerability Audit (OSV / NIST NVD v2.0)
                </span>
                <Badge variant={dependencySummary.critical_count > 0 ? 'critical' : dependencySummary.high_count > 0 ? 'high' : 'success'} size="sm">
                  {dependencySummary.total_vulnerabilities_found || dependencySummary.all_vulnerabilities?.length || 0} CVEs / Advisories Found
                </Badge>
              </div>

              {/* Packages Table */}
              {Array.isArray(dependencySummary.packages) && dependencySummary.packages.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                      <tr>
                        <th className="p-2.5">Package</th>
                        <th className="p-2.5">Version</th>
                        <th className="p-2.5">Ecosystem</th>
                        <th className="p-2.5">Status</th>
                        <th className="p-2.5">Identified CVEs &amp; Advisories</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {dependencySummary.packages.map((pkg, idx) => {
                        const vulns = pkg.vulnerabilities || [];
                        return (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-2.5 font-bold text-cyan-400">{pkg.package || pkg.name}</td>
                            <td className="p-2.5 text-slate-200">{pkg.version || 'unspecified'}</td>
                            <td className="p-2.5 text-slate-400 uppercase">{pkg.ecosystem}</td>
                            <td className="p-2.5">
                              <Badge variant={vulns.length > 0 ? 'critical' : 'success'} size="sm">
                                {vulns.length > 0 ? `${vulns.length} VULN` : 'CLEAN'}
                              </Badge>
                            </td>
                            <td className="p-2.5 text-slate-300 font-sans">
                              {vulns.length > 0 ? (
                                <div className="space-y-1">
                                  {vulns.map((v, vIdx) => (
                                    <div key={vIdx} className="text-xs">
                                      <span className="font-mono font-bold text-rose-400">{v.cve_id}</span>{' '}
                                      <span className="text-slate-400">({v.severity || 'Medium'}, CVSS {v.cvss_score || 'N/A'}):</span>{' '}
                                      <span className="text-slate-300">{v.description?.slice(0, 100)}...</span>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-emerald-400 font-mono text-xs">No Known Vulnerabilities</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Cookie Security Checker Report Section */}
          {cookieSummary && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-amber-400 flex items-center gap-1.5">
                  <Cookie className="w-4 h-4" /> HTTP Set-Cookie Security Directives Audit
                </span>
                <Badge variant={cookieSummary.security_score >= 80 ? 'success' : cookieSummary.security_score >= 60 ? 'warning' : 'critical'} size="sm">
                  Cookie Score: {cookieSummary.security_score ?? 100}/100
                </Badge>
              </div>

              {Array.isArray(cookieSummary.cookies) && cookieSummary.cookies.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                      <tr>
                        <th className="p-2.5">Cookie Name</th>
                        <th className="p-2.5">Secure</th>
                        <th className="p-2.5">HttpOnly</th>
                        <th className="p-2.5">SameSite</th>
                        <th className="p-2.5">Scope</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Observed Issues</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {cookieSummary.cookies.map((c, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/40">
                          <td className="p-2.5 font-bold text-amber-400">{c.name}</td>
                          <td className="p-2.5">
                            <Badge variant={c.secure ? 'success' : 'critical'} size="sm">
                              {c.secure ? 'SECURE' : 'MISSING'}
                            </Badge>
                          </td>
                          <td className="p-2.5">
                            <Badge variant={c.httponly ? 'success' : 'critical'} size="sm">
                              {c.httponly ? 'HTTPONLY' : 'MISSING'}
                            </Badge>
                          </td>
                          <td className="p-2.5 text-slate-300">{c.samesite}</td>
                          <td className="p-2.5 text-slate-400">{c.domain} ({c.path})</td>
                          <td className="p-2.5">
                            <Badge variant={(c.severity || 'low').toLowerCase()} size="sm">
                              {c.severity || 'LOW'}
                            </Badge>
                          </td>
                          <td className="p-2.5 text-slate-300 font-sans max-w-xs">
                            {c.issues?.length > 0 ? (
                              <ul className="space-y-0.5 text-rose-300">
                                {c.issues.map((iss, iIdx) => (
                                  <li key={iIdx}>• {typeof iss === 'object' ? (iss.description || iss.attribute) : iss}</li>
                                ))}
                              </ul>
                            ) : (
                              <span className="text-emerald-400 font-mono">Properly Protected</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 text-xs font-mono text-slate-400 bg-slate-900/50 rounded-lg">
                  No cookies were set by the target server. No cookie-related vulnerabilities detected.
                </div>
              )}
            </div>
          )}

          {/* OWASP Top 10 Assessment Findings Card */}
          {owaspFindings.length > 0 && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4" /> OWASP Top 10 Security Assessment Breakdown
                </span>
                <Badge variant="cyan" size="sm">OWASP Top 10:2025 Standard</Badge>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                    <tr>
                      <th className="p-2.5">OWASP ID</th>
                      <th className="p-2.5">Category</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5">Severity</th>
                      <th className="p-2.5">Finding Title</th>
                      <th className="p-2.5">Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {owaspFindings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="p-2.5 font-bold text-cyan-400">{f.owasp_id || f.id || 'N/A'}</td>
                        <td className="p-2.5 text-slate-200">{f.category || 'N/A'}</td>
                        <td className="p-2.5">
                          <Badge variant={f.status === 'Passed' ? 'success' : f.status === 'Failed' ? 'critical' : f.status === 'Warning' ? 'warning' : 'ghost'} size="sm">
                            {f.status || 'N/A'}
                          </Badge>
                        </td>
                        <td className="p-2.5 text-slate-300">{f.severity || 'N/A'}</td>
                        <td className="p-2.5 text-slate-300 font-sans">{f.title || 'N/A'}</td>
                        <td className="p-2.5 text-slate-400 font-sans">{f.recommendation || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* HTTP Security Headers Breakdown */}
          {Array.isArray(headersSummary?.findings) && headersSummary.findings.length > 0 && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                  <Lock className="w-4 h-4" /> HTTP Security Headers Audit
                </span>
                <Badge variant={headersSummary.grade === 'A' ? 'success' : headersSummary.grade === 'B' ? 'info' : 'warning'} size="sm">
                  Grade {headersSummary.grade || 'N/A'} ({headersSummary.present_count || 0}/{headersSummary.total_checked || 0} Present)
                </Badge>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                    <tr>
                      <th className="p-2.5">Header</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5">Severity</th>
                      <th className="p-2.5">Observed Value</th>
                      <th className="p-2.5">Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {headersSummary.findings.map((h, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="p-2.5 font-bold text-slate-200">{h.header}</td>
                        <td className="p-2.5">
                          <Badge variant={h.present ? 'success' : 'critical'} size="sm">
                            {h.present ? 'Present' : 'Missing'}
                          </Badge>
                        </td>
                        <td className="p-2.5 text-slate-300">{h.severity || 'Medium'}</td>
                        <td className="p-2.5 text-slate-400 font-sans truncate max-w-xs">{h.value || 'None'}</td>
                        <td className="p-2.5 text-slate-400 font-sans">{h.recommendation || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Port Scanner Breakdown */}
          {portsSummary && (
            <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-mono text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                  <Server className="w-4 h-4" /> Authorized Port Probing Audit
                </span>
                <Badge variant={portsSummary.risk_level === 'CRITICAL' ? 'critical' : portsSummary.risk_level === 'HIGH' ? 'high' : 'success'} size="sm">
                  {portsSummary.open_ports_count} Open Ports ({portsSummary.risk_level || 'LOW'} Risk)
                </Badge>
              </div>

              {Array.isArray(portsSummary.open_ports) && portsSummary.open_ports.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800 bg-slate-900">
                      <tr>
                        <th className="p-2.5">Port</th>
                        <th className="p-2.5">Service</th>
                        <th className="p-2.5">State</th>
                        <th className="p-2.5">Severity</th>
                        <th className="p-2.5">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {portsSummary.open_ports.map((p, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/40">
                          <td className="p-2.5 font-bold text-cyan-400">{p.port}</td>
                          <td className="p-2.5 text-slate-200">{p.service}</td>
                          <td className="p-2.5"><Badge variant="warning" size="sm">OPEN</Badge></td>
                          <td className="p-2.5 text-slate-300">{p.severity || 'Medium'}</td>
                          <td className="p-2.5 text-slate-400 font-sans">{p.description || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-4 text-xs font-mono text-slate-400 bg-slate-900/50 rounded-lg">
                  No open high-risk perimeter ports detected on common service ports (total probed: {portsSummary.total_probed || 20}).
                </div>
              )}
            </div>
          )}

          {/* Module Summaries: WHOIS & SSL/TLS */}
          {(whoisSummary || sslSummary) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* WHOIS Summary Card */}
              {whoisSummary && (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5" /> WHOIS Domain Registration
                    </span>
                    <Badge variant="info" size="sm">ACTIVE</Badge>
                  </div>
                  <div className="space-y-1 text-slate-300">
                    <p>Registrar: <span className="text-slate-100 font-semibold">{whoisSummary.registrar || 'Not Available'}</span></p>
                    <p>Created: <span className="font-mono text-slate-200">{whoisSummary.creation_date || whoisSummary.creationDate || 'Not Available'}</span> | Expires: <span className="font-mono text-slate-200">{whoisSummary.expiry_date || whoisSummary.expiryDate || 'Not Available'}</span></p>
                    {whoisSummary.name_servers && (
                      <p className="text-[11px] font-mono text-cyan-300">NS: {whoisSummary.name_servers.join(', ')}</p>
                    )}
                  </div>
                </div>
              )}

              {/* SSL/TLS Summary */}
              {sslSummary && (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5" /> SSL / TLS Configuration Audit
                    </span>
                    <Badge variant="success" size="sm">{sslSummary.tls_version || 'TLS 1.3'}</Badge>
                  </div>
                  <p className="text-xs text-slate-300">
                    Issuer: <span className="text-slate-100 font-semibold">{sslSummary.issuer || 'Not Available'}</span> ({sslSummary.days_until_expiration ?? sslSummary.days_left ?? 0} days remaining)
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Vulnerability List Section */}
          {vulnerabilities.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span>Detected Security Vulnerabilities ({vulnerabilities.length})</span>
              </h3>

              <div className="space-y-3">
                {vulnerabilities.map((item, idx) => {
                  const itemKey = item.cve_id || item.id || `vuln-${idx}`;
                  const isExpanded = expandedId === itemKey;
                  return (
                    <div
                      key={itemKey}
                      className={`rounded-xl border transition-all ${
                        isExpanded
                          ? 'bg-slate-900/90 border-cyan-500/40 shadow-[0_0_20px_rgba(0,243,255,0.08)]'
                          : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div
                        onClick={() => setExpandedId(isExpanded ? null : itemKey)}
                        className="p-4 flex items-center justify-between gap-4 cursor-pointer"
                      >
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          <Badge variant={item.severity ? item.severity.toLowerCase() : 'high'} size="sm">
                            CVSS {item.cvss_score ?? item.cvss ?? 'N/A'}
                          </Badge>
                          <span className="font-mono text-xs font-bold text-cyan-400 shrink-0">
                            {item.cve_id || item.id}
                          </span>
                          <h4 className="text-sm font-semibold text-slate-200 truncate">
                            {item.title || item.description || 'Finding'}
                          </h4>
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="hidden md:inline text-xs font-mono text-slate-400">
                            {item.component || 'Target Component'}
                          </span>
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="p-5 pt-0 border-t border-slate-800/80 space-y-4 text-xs">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                            <div>
                              <span className="font-mono text-slate-400 uppercase text-[10px]">Description</span>
                              <p className="text-slate-300 mt-1 leading-relaxed">{item.description || 'Not Available'}</p>
                            </div>
                            <div>
                              <span className="font-mono text-slate-400 uppercase text-[10px]">Published Date / Ref</span>
                              <p className="font-mono text-slate-300 mt-1 bg-slate-950 p-2 rounded border border-slate-800">
                                {item.published_date || item.reference_url || 'Not Available'}
                              </p>
                            </div>
                          </div>

                          {(item.remediation || item.remediationCmd) && (
                            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="font-mono font-semibold text-emerald-400 flex items-center gap-1.5">
                                  <ShieldCheck className="w-4 h-4" /> Recommended SecOps Remediation
                                </span>
                                {item.remediationCmd && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleCopy(item.remediationCmd, itemKey);
                                    }}
                                    className="text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-mono text-[11px]"
                                  >
                                    {copiedId === itemKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                    <span>{copiedId === itemKey ? 'Copied!' : 'Copy Fix Command'}</span>
                                  </button>
                                )}
                              </div>
                              <p className="text-slate-300">{item.remediation || 'Upgrade target component to patched version.'}</p>
                              {item.remediationCmd && (
                                <div className="p-2.5 rounded-lg bg-black font-mono text-cyan-300 text-[11px] overflow-x-auto border border-cyan-500/20">
                                  $ {item.remediationCmd}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* HTML Report Preview Modal */}
      <Modal
        isOpen={isPreviewModalOpen}
        onClose={() => setIsPreviewModalOpen(false)}
        title={`HTML Report Preview – ${reportMeta.scanId}`}
        subtitle={`Generated report for target: ${reportMeta.target}`}
        className="max-w-5xl w-full"
        footer={
          <>
            <Button variant="secondary" onClick={() => setIsPreviewModalOpen(false)}>
              Close Preview
            </Button>
            <Button variant="outline" icon={Globe} onClick={handleOpenHtmlPreviewInTab}>
              Open in New Tab
            </Button>
            <Button variant="primary" icon={Download} onClick={() => handleDownload('html')}>
              Download HTML Report
            </Button>
          </>
        }
      >
        <div className="w-full h-[70vh] bg-slate-950 rounded-xl overflow-hidden border border-slate-800">
          <iframe
            src={api.getReportHtmlUrl(reportMeta.scanId)}
            title="Generated HTML Security Audit Report"
            className="w-full h-full border-0"
          />
        </div>
      </Modal>
    </div>
  );
};