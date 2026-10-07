import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Globe,
  Lock,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Layers,
  Server,
  RefreshCw,
  Info,
  Download,
  Terminal,
  Activity,
  ChevronRight,
  Eye,
  X
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Badge } from '../components/ui/Badge';
import { Skeleton } from '../components/ui/Loader';
import { useToast } from '../components/ui/Toast';

export const ScannerPage = () => {
  const navigate = useNavigate();
  const { addToast } = useToast();

  const SCAN_OPTIONS = [
    { id: 'CVE Lookup', label: 'CVE Lookup', desc: 'Query NIST National Vulnerability Database (NVD v2.0) for live CVE records.' },
    { id: 'HTTP Security Headers Check', label: 'HTTP Security Headers Check', desc: 'Audit response security headers (CSP, HSTS, X-Frame-Options, etc.).' },
    { id: 'SSL/TLS Checker', label: 'SSL/TLS Checker', desc: 'Verify certificate validity, protocol versions (TLS 1.2/1.3), and ciphers.' },
    { id: 'Port Scanner', label: 'Port Scanner', desc: 'Inspect open network ports and services exposed on authorized target.' },
    { id: 'OWASP Top 10', label: 'OWASP Top 10:2025', desc: 'Defensive security assessment mapping findings against official OWASP Top 10:2025 categories.' },
    { id: 'WHOIS Lookup', label: 'WHOIS Lookup', desc: 'Retrieve domain registration, registrar info, and authoritative name servers.' }
  ];

  const [selectedScanType, setSelectedScanType] = useState('OWASP Top 10');
  const [targetUrl, setTargetUrl] = useState('');
  const [cveSearchKeyword, setCveSearchKeyword] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isSearchingCve, setIsSearchingCve] = useState(false);

  // Security Analysis Results State
  const [analysisResult, setAnalysisResult] = useState(null);
  const [cveResults, setCveResults] = useState([]);
  const [activeEvidenceModal, setActiveEvidenceModal] = useState(null);
  const [lastScanRef, setLastScanRef] = useState(null);

  // Conduct Security Posture Analysis
  const handleAnalyzeTarget = async (e) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) {
      addToast('Please specify a valid target domain or URL', 'error');
      return;
    }

    setIsAnalyzing(true);
    addToast(`Initiating ${selectedScanType} Assessment on ${targetUrl}...`, 'info');

    try {
      const token = localStorage.getItem('cloudvuln_access_token');
      const response = await fetch('/api/analysis/target', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ target_url: targetUrl })
      });

      if (response.ok) {
        const data = await response.json();
        setAnalysisResult(data);
        setCveResults(data.cve_findings || []);
        addToast(`${selectedScanType} assessment completed successfully!`, 'success');

        // Persist scan run in database
        try {
          const scanRes = await fetch('/api/scans', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              target: data.target,
              provider: 'AWS US-East-1',
              scan_type: selectedScanType,
              status: data.risk_level === 'Low' ? 'passed' : data.risk_level.toLowerCase(),
              critical_count: data.critical_count || 0,
              high_count: data.high_count || 0,
              medium_count: data.medium_count || 0,
              low_count: data.low_count || 0,
              risk_score: parseFloat(((100 - (data.security_score || 100)) / 10).toFixed(1)),
              duration: '1m 20s',
              scan_data: JSON.stringify(data)
            })
          });
          if (scanRes.ok) {
            const savedScan = await scanRes.json();
            if (savedScan && savedScan.scan_ref) {
              setLastScanRef(savedScan.scan_ref);
            }
          }
        } catch (e) {
          console.warn('Failed to auto-save scan record', e);
        }
      } else {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server returned status ${response.status}: Failed to complete assessment.`);
      }
    } catch (error) {
      console.error("Target assessment failed", error);
      addToast(error.message || "Target assessment failed. Check target URL and network connectivity.", "error");
      setAnalysisResult(null);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // NVD CVE Keyword Lookup
  const handleSearchCve = async (e) => {
    if (e) e.preventDefault();
    if (!cveSearchKeyword) return;

    setIsSearchingCve(true);
    try {
      const token = localStorage.getItem('cloudvuln_access_token');
      const res = await fetch(`/api/cve/search?query=${encodeURIComponent(cveSearchKeyword)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setCveResults(data);
        addToast(`Found ${data.length} NVD CVE records for '${cveSearchKeyword}'`, 'info');
      }
    } catch (err) {
      console.warn('CVE search fallback', err);
    } finally {
      setIsSearchingCve(false);
    }
  };

  const activeOption = SCAN_OPTIONS.find((opt) => opt.id === selectedScanType) || SCAN_OPTIONS[4];

  return (
    <div className="space-y-6">
      {/* Top Banner / Analysis Trigger */}
      <div className="p-6 rounded-2xl bg-linear-to-r from-slate-900 via-cyan-950/40 to-slate-900 border border-cyan-500/30 shadow-[0_0_30px_rgba(0,243,255,0.08)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
          </div>
          <h2 className="text-xl sm:text-2xl font-black text-slate-100">
            Security Target Assessment &amp; Vulnerability Scanner
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl">
            {activeOption.desc}
          </p>
        </div>

        <form onSubmit={handleAnalyzeTarget} className="flex items-center gap-2 w-full md:w-auto">
          <Input
            placeholder="Target domain or URL (e.g. example.com)..."
            icon={Globe}
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            disabled={isAnalyzing}
            className="w-full md:w-72"
          />
          <Button
            type="submit"
            variant="primary"
            icon={RefreshCw}
            disabled={isAnalyzing}
            className="shrink-0"
          >
            {isAnalyzing ? 'Scanning...' : 'Run Scan'}
          </Button>
        </form>
      </div>
      <Card className="border-cyan-500/20">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
            {SCAN_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                onClick={() => setSelectedScanType(opt.id)}
                className={`px-4 py-2.5 rounded-xl font-mono text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-2 border ${
                  selectedScanType === opt.id
                    ? 'bg-cyan-500/15 border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(0,243,255,0.15)]'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                {opt.id === 'OWASP Top 10' && <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />}
                {opt.id === 'CVE Lookup' && <Layers className="w-3.5 h-3.5 text-amber-400" />}
                {opt.id === 'HTTP Security Headers Check' && <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                {opt.id === 'SSL/TLS Checker' && <Lock className="w-3.5 h-3.5 text-purple-400" />}
                {opt.id === 'Port Scanner' && <Server className="w-3.5 h-3.5 text-rose-400" />}
                {opt.id === 'WHOIS Lookup' && <Globe className="w-3.5 h-3.5 text-blue-400" />}
                <span>{opt.label}</span>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Pristine Ready State when no scan has been run */}
      {!analysisResult && !isAnalyzing && (
        <Card className="border-cyan-500/20 bg-slate-900/40">
          <CardContent className="p-12 text-center space-y-4 max-w-xl mx-auto">
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mx-auto shadow-[0_0_25px_rgba(0,243,255,0.15)]">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-lg font-bold text-slate-100">Ready to Analyze Target</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Enter a target domain, hostname, or IP address in the search field above and click <span className="text-cyan-400 font-semibold">Run Scan</span> to execute live multi-vector vulnerability checks including OWASP Top 10, SSL/TLS, and HTTP Security Headers.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Target Security Summary Card */}
      {analysisResult && (
        <Card className="border-cyan-500/30">
          <CardContent className="p-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Target Resource</span>
                <p className="text-base font-extrabold font-mono text-cyan-400 truncate">{analysisResult.target}</p>
                <span className="text-[11px] text-slate-500 font-mono">IP: {analysisResult.ip_address}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Scan Timestamp</span>
                <p className="text-sm font-semibold text-slate-200">{analysisResult.scan_timestamp}</p>
                <span className="text-[11px] text-emerald-400 font-mono">Duration: {analysisResult.duration || '1m 20s'}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Security Score</span>
                <p className={`text-2xl font-black ${analysisResult.security_score >= 85 ? 'text-emerald-400' : analysisResult.security_score >= 70 ? 'text-amber-400' : 'text-rose-400'}`}>
                  {analysisResult.security_score} / 100
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Risk Level</span>
                <div>
                  <Badge variant={analysisResult.risk_level.toLowerCase()} size="md">
                    {analysisResult.risk_level.toUpperCase()} RISK
                  </Badge>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Vulnerability Breakdown</span>
                <div className="flex items-center gap-1 text-xs font-mono">
                  <span className="text-rose-400 font-bold">{analysisResult.critical_count || 0} Crit</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-orange-400 font-bold">{analysisResult.high_count || 2} High</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-amber-400 font-bold">{analysisResult.medium_count || 2} Med</span>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  icon={FileText}
                  onClick={() => navigate(`/reports/${lastScanRef || '1'}`)}
                >
                  View Report
                </Button>
                <a
                  href={`/api/reports/${lastScanRef || '1'}/download?format=html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2 rounded-xl bg-slate-900 border border-slate-700 text-cyan-400 hover:border-cyan-400 transition-all"
                  title="Download HTML Report"
                >
                  <Download className="w-4 h-4" />
                </a>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* OWASP Top 10 Assessment Module */}
      {(selectedScanType === 'OWASP Top 10' || selectedScanType === 'Full Audit') && (
        <Card className="border-cyan-500/30 shadow-[0_0_20px_rgba(0,243,255,0.05)]">
          <CardHeader>
            <CardTitle icon={ShieldAlert} subtitle="Official OWASP Top 10:2025 Web Security Assessment & Verification Matrix">
              OWASP Top 10:2025 Security Assessment Results
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {isAnalyzing ? (
              <Skeleton className="h-64 w-full" />
            ) : analysisResult?.owasp_summary ? (
              <>
                {/* OWASP Summary Cards */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Total Checks</span>
                    <p className="text-xl font-bold font-mono text-slate-100">{analysisResult.owasp_summary.total_checks}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-emerald-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-emerald-400 uppercase">Passed Checks</span>
                    <p className="text-xl font-bold font-mono text-emerald-400">{analysisResult.owasp_summary.passed_checks}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-rose-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-rose-400 uppercase">Failed Checks</span>
                    <p className="text-xl font-bold font-mono text-rose-400">{analysisResult.owasp_summary.failed_checks}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-amber-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-amber-400 uppercase">Warnings</span>
                    <p className="text-xl font-bold font-mono text-amber-400">{analysisResult.owasp_summary.warnings_count}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-700 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Unable to Verify</span>
                    <p className="text-xl font-bold font-mono text-slate-400">{analysisResult.owasp_summary.unable_to_verify_count}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase">OWASP Score</span>
                    <p className="text-xl font-bold font-mono text-cyan-400">{analysisResult.owasp_summary.overall_score}/100</p>
                  </div>
                </div>

                {/* OWASP Table */}
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="p-3.5">OWASP ID</th>
                        <th className="p-3.5">Category</th>
                        <th className="p-3.5">Status</th>
                        <th className="p-3.5">Severity</th>
                        <th className="p-3.5">Finding Title</th>
                        <th className="p-3.5">Recommendation</th>
                        <th className="p-3.5 text-right">Evidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 bg-slate-950/60">
                      {analysisResult.owasp_summary.findings.map((f, i) => (
                        <tr
                          key={i}
                          className="hover:bg-slate-900/50 transition-colors cursor-pointer"
                          onClick={() => setActiveEvidenceModal(f)}
                        >
                          <td className="p-3.5 font-mono font-bold text-cyan-400 whitespace-nowrap">
                            {f.owasp_id}
                          </td>
                          <td className="p-3.5 font-semibold text-slate-200 whitespace-nowrap">
                            {f.category}
                          </td>
                          <td className="p-3.5 whitespace-nowrap">
                            <Badge
                              variant={
                                f.status === 'Passed'
                                  ? 'success'
                                  : f.status === 'Failed'
                                  ? 'critical'
                                  : f.status === 'Warning'
                                  ? 'warning'
                                  : 'ghost'
                              }
                              size="sm"
                            >
                              {f.status}
                            </Badge>
                          </td>
                          <td className="p-3.5 whitespace-nowrap font-mono text-xs">
                            <span
                              className={
                                f.severity === 'Critical'
                                  ? 'text-rose-400 font-bold'
                                  : f.severity === 'High'
                                  ? 'text-orange-400 font-bold'
                                  : f.severity === 'Medium'
                                  ? 'text-amber-300 font-semibold'
                                  : f.severity === 'Passed'
                                  ? 'text-emerald-400'
                                  : 'text-slate-400'
                              }
                            >
                              {f.severity}
                            </span>
                          </td>
                          <td className="p-3.5 text-slate-300 font-medium max-w-xs truncate">
                            {f.title}
                          </td>
                          <td className="p-3.5 text-slate-400 max-w-xs truncate">
                            {f.recommendation}
                          </td>
                          <td className="p-3.5 text-right whitespace-nowrap">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveEvidenceModal(f);
                              }}
                              className="px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 text-[11px] font-mono inline-flex items-center gap-1"
                            >
                              <Eye className="w-3 h-3" /> Details
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* Port Scanner Module */}
      {(selectedScanType === 'Port Scanner' || selectedScanType === 'OWASP Top 10') && (
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={Server} subtitle="Authorized socket probe of perimeter network services">
              Authorized Port Scanner
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isAnalyzing ? (
              <Skeleton className="h-48 w-full" />
            ) : analysisResult?.ports_summary ? (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Total Probed</span>
                    <p className="text-xl font-bold font-mono text-slate-100">{analysisResult.ports_summary.total_probed}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Open Ports</span>
                    <p className="text-xl font-bold font-mono text-amber-400">{analysisResult.ports_summary.open_ports_count}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Closed / Filtered</span>
                    <p className="text-xl font-bold font-mono text-slate-300">{analysisResult.ports_summary.closed_ports_count}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Perimeter Risk</span>
                    <div>
                      <Badge variant={analysisResult.ports_summary.risk_level === 'CRITICAL' ? 'critical' : analysisResult.ports_summary.risk_level === 'HIGH' ? 'high' : 'success'} size="sm">
                        {analysisResult.ports_summary.risk_level}
                      </Badge>
                    </div>
                  </div>
                </div>

                {analysisResult.ports_summary.open_ports?.length > 0 ? (
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                        <tr>
                          <th className="p-3">Port</th>
                          <th className="p-3">Service</th>
                          <th className="p-3">State</th>
                          <th className="p-3">Severity</th>
                          <th className="p-3">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 font-mono text-xs">
                        {analysisResult.ports_summary.open_ports.map((p, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-3 font-bold text-cyan-400">{p.port}</td>
                            <td className="p-3 text-slate-200">{p.service}</td>
                            <td className="p-3"><Badge variant="warning" size="sm">OPEN</Badge></td>
                            <td className="p-3 text-slate-300">{p.severity || 'Medium'}</td>
                            <td className="p-3 text-slate-400 font-sans">{p.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-400">
                    No open perimeter ports identified on authorized target (probed 20 standard ports).
                  </div>
                )}
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* WHOIS Information Module */}
      {(selectedScanType === 'WHOIS Lookup' || selectedScanType === 'OWASP Top 10') && (
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={Globe} subtitle="Domain registration, registrar details & name server audit">
              WHOIS Information Module
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isAnalyzing ? (
              <Skeleton className="h-48 w-full" />
            ) : analysisResult?.whois_summary ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Domain Registrar</span>
                    <p className="text-xs font-bold text-cyan-300 truncate">{analysisResult.whois_summary.registrar}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Creation Date</span>
                    <p className="text-xs font-mono text-slate-200">{analysisResult.whois_summary.creation_date}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Expiration Date</span>
                    <p className="text-xs font-mono text-slate-200">{analysisResult.whois_summary.expiry_date}</p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Domain Status</span>
                    <div className="flex flex-wrap gap-1">
                      {analysisResult.whois_summary.domain_status?.map((st, i) => (
                        <Badge key={i} variant="info" size="sm">
                          {st}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                  <span className="text-[11px] font-mono font-semibold text-slate-400 uppercase">Authoritative Name Servers</span>
                  <div className="flex flex-wrap gap-2">
                    {analysisResult.whois_summary.name_servers?.map((ns, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-md bg-slate-900 border border-cyan-500/20 font-mono text-xs text-cyan-400">
                        {ns}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* Grid: SSL/TLS & HTTP Security Headers */}
      {(selectedScanType === 'SSL/TLS Checker' || selectedScanType === 'HTTP Security Headers Check' || selectedScanType === 'OWASP Top 10') && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* SSL/TLS Configuration Summary */}
          <Card className="border-cyan-500/20">
            <CardHeader>
              <CardTitle icon={Lock} subtitle="Transport Layer Security audit & certificate validity">
                SSL / TLS Configuration Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {isAnalyzing ? (
                <Skeleton className="h-48 w-full" />
              ) : analysisResult ? (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">Certificate Status</span>
                      <div>
                        <Badge variant={analysisResult.ssl_summary.is_valid ? 'success' : 'critical'} size="sm">
                          {analysisResult.ssl_summary.cert_status}
                        </Badge>
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">TLS Protocol Version</span>
                      <p className="text-sm font-bold font-mono text-slate-100">{analysisResult.ssl_summary.tls_version}</p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">Certificate Issuer</span>
                      <p className="text-xs font-semibold text-cyan-300 truncate">{analysisResult.ssl_summary.issuer}</p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">Expires On</span>
                      <p className="text-xs font-mono text-slate-200">
                        {analysisResult.ssl_summary.expiry_date} ({analysisResult.ssl_summary.days_until_expiration} days left)
                      </p>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/20 space-y-2">
                    <span className="text-xs font-mono font-semibold text-cyan-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" /> Recommended TLS Best Practices
                    </span>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {analysisResult.ssl_summary.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-cyan-400 shrink-0">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </>
              ) : null}
            </CardContent>
          </Card>

          {/* HTTP Security Headers Summary */}
          <Card className="border-cyan-500/20">
            <CardHeader>
              <CardTitle icon={ShieldAlert} subtitle="Audit of HTTP response security directives">
                HTTP Security Headers Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {isAnalyzing ? (
                <Skeleton className="h-48 w-full" />
              ) : analysisResult ? (
                <>
                  <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-slate-800">
                    <div className="space-y-0.5">
                      <span className="text-xs font-semibold text-slate-300">Header Security Score</span>
                      <p className="text-[11px] text-slate-400">
                        {analysisResult.headers_summary.passed_count} of {analysisResult.headers_summary.total_count} recommended security headers configured
                      </p>
                    </div>
                    <span className="text-xl font-extrabold font-mono text-cyan-400">
                      {analysisResult.headers_summary.score}%
                    </span>
                  </div>

                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {analysisResult.headers_summary.checks.map((chk) => (
                      <div
                        key={chk.name}
                        className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                      >
                        <div className="space-y-1 flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            {chk.present ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            ) : (
                              <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                            )}
                            <span className="font-mono font-bold text-slate-200 truncate">{chk.name}</span>
                          </div>
                          {!chk.present ? (
                            <p className="text-[11px] text-rose-300/90 leading-tight">{chk.risk_if_missing}</p>
                          ) : (
                            <p className="text-[11px] font-mono text-cyan-400/80 truncate">Value: {chk.value}</p>
                          )}
                        </div>
                        <Badge variant={chk.present ? 'success' : 'critical'} size="sm">
                          {chk.present ? 'PASS' : 'MISSING'}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
            </CardContent>
          </Card>
        </div>
      )}

      {/* CVE Information Viewer */}
      {(selectedScanType === 'CVE Lookup' || selectedScanType === 'OWASP Top 10') && (
        <Card className="border-cyan-500/20">
          <CardHeader action={
            <form onSubmit={handleSearchCve} className="flex items-center gap-2">
              <Input
                placeholder="Search software / product (e.g. OpenSSL, Tomcat)..."
                icon={Search}
                value={cveSearchKeyword}
                onChange={(e) => setCveSearchKeyword(e.target.value)}
                disabled={isSearchingCve}
                className="w-64"
              />
              <Button type="submit" variant="secondary" size="sm" disabled={isSearchingCve}>
                {isSearchingCve ? 'Searching...' : 'NVD Lookup'}
              </Button>
            </form>
          }>
            <CardTitle icon={Layers} subtitle="Real-time public CVE records from NIST National Vulnerability Database (NVD API v2.0)">
              CVE Vulnerability Viewer
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {cveResults.map((cve) => (
                <div
                  key={cve.cve_id}
                  className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-3 hover:border-cyan-500/40 transition-all"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-extrabold text-sm text-cyan-400">{cve.cve_id}</span>
                      <Badge variant={cve.severity.toLowerCase()} size="sm">
                        CVSS {cve.cvss_score}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed line-clamp-3">
                      {cve.description}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Published: {cve.published_date}</span>
                    <a
                      href={cve.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      <span>NVD Ref</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Recommendations & Risk Guidelines */}
      {analysisResult && (
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={Activity} subtitle="Consolidated hardening roadmap & remediation steps">
              Security Recommendations & Best Practice Guidelines
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {analysisResult.recommendations.map((rec, index) => (
              <div
                key={index}
                className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3 text-xs"
              >
                <span className="p-1 rounded-md bg-cyan-500/10 text-cyan-400 font-mono font-bold shrink-0">
                  #{index + 1}
                </span>
                <p className="text-slate-200 leading-relaxed pt-0.5">{rec}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Detailed Evidence Modal */}
      {activeEvidenceModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-500/40 rounded-2xl p-6 max-w-2xl w-full space-y-4 shadow-[0_0_50px_rgba(0,243,255,0.15)] relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setActiveEvidenceModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-100 p-1 rounded-lg bg-slate-800"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <Badge variant="cyan" size="md">{activeEvidenceModal.owasp_id}</Badge>
              <h3 className="text-lg font-bold text-slate-100">{activeEvidenceModal.category}</h3>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] font-mono text-slate-400 uppercase">Finding Title</span>
              <p className="text-sm font-semibold text-cyan-300">{activeEvidenceModal.title}</p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Status</span>
                <div>
                  <Badge variant={activeEvidenceModal.status === 'Passed' ? 'success' : activeEvidenceModal.status === 'Failed' ? 'critical' : 'warning'}>
                    {activeEvidenceModal.status}
                  </Badge>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Severity</span>
                <p className="font-bold text-slate-200">{activeEvidenceModal.severity}</p>
              </div>
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-[10px] font-mono text-slate-400 uppercase">Description</span>
              <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-xl border border-slate-800">{activeEvidenceModal.description}</p>
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">Verification Evidence</span>
              <div className="p-3 rounded-xl bg-slate-950 border border-cyan-500/30 font-mono text-xs text-cyan-300 whitespace-pre-wrap">
                {activeEvidenceModal.evidence}
              </div>
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-[10px] font-mono text-slate-400 uppercase">Affected Component</span>
              <p className="text-slate-300 font-mono bg-slate-950 p-2.5 rounded-xl border border-slate-800">{activeEvidenceModal.affected_component}</p>
            </div>

            <div className="space-y-1 text-xs">
              <span className="text-[10px] font-mono text-emerald-400 uppercase font-semibold">Recommendation</span>
              <p className="text-slate-200 bg-slate-950 p-3 rounded-xl border border-emerald-500/20">{activeEvidenceModal.recommendation}</p>
            </div>

            {activeEvidenceModal.reference && (
              <div className="pt-2 border-t border-slate-800 flex justify-end">
                <a
                  href={activeEvidenceModal.reference}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                >
                  <span>OWASP Reference Guidelines</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
