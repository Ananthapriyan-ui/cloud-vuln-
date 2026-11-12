import React, { useState } from 'react';
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
  X,
  Network,
  Package,
  Cookie,
  HelpCircle,
  Check,
  FileCode
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
    { id: 'OWASP Top 10', label: 'OWASP Top 10:2025', desc: 'Defensive security assessment mapping findings against official OWASP Top 10:2025 categories.' },
    { id: 'DNS Security Checker', label: 'DNS Security Checker', desc: 'Real DNS queries for A, AAAA, MX, NS, TXT, CAA, DNSSEC, SPF, DMARC, and DKIM email authentication records.' },
    { id: 'Dependency Scanner', label: 'Dependency Scanner', desc: 'Audit open-source software libraries and packages against live NIST NVD CVE records.' },
    { id: 'Cookie Security Checker', label: 'Cookie Security Checker', desc: 'Inspect live HTTP Set-Cookie response headers for Secure, HttpOnly, and SameSite directives.' },
    { id: 'CVE Lookup', label: 'CVE Lookup', desc: 'Query NIST National Vulnerability Database (NVD v2.0) for live CVE records.' },
    { id: 'HTTP Security Headers Check', label: 'HTTP Security Headers Check', desc: 'Audit response security headers (CSP, HSTS, X-Frame-Options, etc.).' },
    { id: 'SSL/TLS Checker', label: 'SSL/TLS Checker', desc: 'Verify certificate validity, protocol versions (TLS 1.2/1.3), and ciphers.' },
    { id: 'Port Scanner', label: 'Port Scanner', desc: 'Inspect open network ports and services exposed on authorized target.' },
    { id: 'WHOIS Lookup', label: 'WHOIS Lookup', desc: 'Retrieve domain registration, registrar info, and authoritative name servers.' }
  ];

  const [selectedScanType, setSelectedScanType] = useState('OWASP Top 10');
  const [targetUrl, setTargetUrl] = useState('');
  const [dkimSelector, setDkimSelector] = useState('');
  const [packageListInput, setPackageListInput] = useState('lodash@4.17.20\naxios@0.21.1\nexpress@4.16.0');
  const [ecosystemInput, setEcosystemInput] = useState('npm');
  const [cveSearchKeyword, setCveSearchKeyword] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isSearchingCve, setIsSearchingCve] = useState(false);

  // Security Analysis Results State
  const [analysisResult, setAnalysisResult] = useState(null);
  const [cveResults, setCveResults] = useState([]);
  const [activeEvidenceModal, setActiveEvidenceModal] = useState(null);
  const [lastScanRef, setLastScanRef] = useState(null);

  // Conduct Security Posture Analysis (Supports all scanners)
  const handleAnalyzeTarget = async (e) => {
    if (e) e.preventDefault();

    let endpoint = '/api/analysis/target';
    let requestBody = {};
    let targetIdentifier = targetUrl.trim();

    if (selectedScanType === 'DNS Security Checker') {
      if (!targetIdentifier) {
        addToast('Please enter a target domain (e.g. google.com)', 'error');
        return;
      }
      endpoint = '/api/analysis/dns';
      requestBody = {
        domain: targetIdentifier,
        dkim_selector: dkimSelector.trim() || undefined
      };
    } else if (selectedScanType === 'Dependency Scanner') {
      const pkgText = packageListInput.trim();
      if (!pkgText) {
        addToast('Please enter packages or dependencies to scan (e.g. lodash@4.17.20)', 'error');
        return;
      }
      endpoint = '/api/analysis/dependencies';
      requestBody = {
        package_list: pkgText,
        ecosystem: ecosystemInput
      };
      targetIdentifier = `${ecosystemInput.toUpperCase()} (${pkgText.split('\n').filter(Boolean).length} packages)`;
    } else if (selectedScanType === 'Cookie Security Checker') {
      if (!targetIdentifier) {
        addToast('Please enter a target URL (e.g. https://example.com)', 'error');
        return;
      }
      endpoint = '/api/analysis/cookies';
      requestBody = { target_url: targetIdentifier };
    } else {
      if (!targetIdentifier) {
        addToast('Please specify a valid target domain or URL', 'error');
        return;
      }
      endpoint = '/api/analysis/target';
      requestBody = { target_url: targetIdentifier };
    }

    setIsAnalyzing(true);
    addToast(`Initiating ${selectedScanType} Assessment...`, 'info');

    try {
      const token = localStorage.getItem('cloudvuln_access_token');
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const data = await response.json();
        setAnalysisResult(data);

        if (selectedScanType === 'Dependency Scanner') {
          setCveResults(data.all_vulnerabilities || []);
        } else if (data.cve_findings) {
          setCveResults(data.cve_findings);
        }

        addToast(`${selectedScanType} completed successfully!`, 'success');

        // Persist scan in DB
        try {
          const scanRes = await fetch('/api/scans', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              target: data.target || data.domain || targetIdentifier,
              provider: selectedScanType === 'Dependency Scanner' ? 'Software Supply Chain' : 'Perimeter / Endpoint',
              scan_type: selectedScanType,
              status: (data.risk_level || 'Low') === 'Low' ? 'passed' : (data.risk_level || 'Low').toLowerCase(),
              critical_count: data.critical_count || 0,
              high_count: data.high_count || 0,
              medium_count: data.medium_count || 0,
              low_count: data.low_count || 0,
              risk_score: parseFloat(((100 - (data.security_score ?? 100)) / 10).toFixed(1)),
              duration: data.duration || '1m 20s',
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
      console.error("Assessment failed", error);
      addToast(error.message || "Assessment failed. Check inputs and network connectivity.", "error");
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

  const activeOption = SCAN_OPTIONS.find((opt) => opt.id === selectedScanType) || SCAN_OPTIONS[0];

  return (
    <div className="space-y-6">
      {/* Top Banner / Assessment Configuration */}
      <div className="p-6 rounded-2xl bg-linear-to-r from-slate-900 via-cyan-950/40 to-slate-900 border border-cyan-500/30 shadow-[0_0_30px_rgba(0,243,255,0.08)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-black text-slate-100">
            Security Target Assessment &amp; Vulnerability Scanner
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl mt-1">
            {activeOption.desc}
          </p>
        </div>

        {/* Input Bar for URL / Domain Scanners */}
        {selectedScanType !== 'Dependency Scanner' ? (
          <form onSubmit={handleAnalyzeTarget} className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <Input
              placeholder={
                selectedScanType === 'DNS Security Checker'
                  ? 'Domain (e.g. google.com)...'
                  : selectedScanType === 'Cookie Security Checker'
                  ? 'URL (e.g. https://example.com)...'
                  : 'Target domain or URL (e.g. example.com)...'
              }
              icon={Globe}
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isAnalyzing}
              className="w-full sm:w-64 md:w-72"
            />

            {selectedScanType === 'DNS Security Checker' && (
              <Input
                placeholder="DKIM selector (optional)..."
                value={dkimSelector}
                onChange={(e) => setDkimSelector(e.target.value)}
                disabled={isAnalyzing}
                className="w-full sm:w-36 text-xs font-mono"
                title="Leave empty to auto-detect standard selectors (google, default, k1, selector1)"
              />
            )}

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
        ) : (
          <Button
            onClick={handleAnalyzeTarget}
            variant="primary"
            icon={RefreshCw}
            disabled={isAnalyzing}
            className="shrink-0"
          >
            {isAnalyzing ? 'Auditing Packages...' : 'Run Dependency Scan'}
          </Button>
        )}
      </div>

      {/* Dependency Input Card (Only shown when Dependency Scanner is active) */}
      {selectedScanType === 'Dependency Scanner' && (
        <Card className="border-cyan-500/30 bg-slate-900/60">
          <CardHeader>
            <CardTitle icon={Package} subtitle="Supply Chain Security: Paste package manifest or individual packages to audit against NIST NVD v2.0">
              Dependency Manifest &amp; Package Input
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Target Ecosystem:</span>
                <select
                  value={ecosystemInput}
                  onChange={(e) => setEcosystemInput(e.target.value)}
                  disabled={isAnalyzing}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400"
                >
                  <option value="npm">npm (Node.js / JavaScript)</option>
                  <option value="pypi">PyPI (Python pip / requirements.txt)</option>
                  <option value="maven">Maven (Java)</option>
                  <option value="golang">Go (Go Modules)</option>
                  <option value="rubygems">RubyGems (Ruby)</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setEcosystemInput('npm');
                    setPackageListInput('lodash@4.17.20\naxios@0.21.1\nexpress@4.16.0\nminimist@1.2.5');
                  }}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-cyan-400 border border-slate-700 transition-all"
                >
                  Load NPM Sample
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEcosystemInput('pypi');
                    setPackageListInput('urllib3@1.26.4\nflask@1.1.2\nrequests@2.25.1\njinja2@2.11.2');
                  }}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-amber-400 border border-slate-700 transition-all"
                >
                  Load Python Sample
                </button>
                <button
                  type="button"
                  onClick={() => setPackageListInput('')}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-slate-400 border border-slate-700 transition-all"
                >
                  Clear
                </button>
              </div>
            </div>

            <textarea
              rows={4}
              value={packageListInput}
              onChange={(e) => setPackageListInput(e.target.value)}
              disabled={isAnalyzing}
              placeholder="Enter packages line by line (e.g. lodash@4.17.20 or flask==1.1.2) or paste package.json / requirements.txt..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 resize-y"
            />
            <p className="text-[11px] text-slate-400 font-mono">
              Accepts format: <span className="text-cyan-400">package@version</span>, <span className="text-cyan-400">package==version</span>, or raw package names. Each package is queried directly against live NIST NVD CVE database.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Module Selector Navigation Tabs */}
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
                {opt.id === 'DNS Security Checker' && <Network className="w-3.5 h-3.5 text-sky-400" />}
                {opt.id === 'Dependency Scanner' && <Package className="w-3.5 h-3.5 text-emerald-400" />}
                {opt.id === 'Cookie Security Checker' && <Cookie className="w-3.5 h-3.5 text-amber-400" />}
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
              {selectedScanType === 'DNS Security Checker' && <Network className="w-8 h-8 text-sky-400" />}
              {selectedScanType === 'Dependency Scanner' && <Package className="w-8 h-8 text-emerald-400" />}
              {selectedScanType === 'Cookie Security Checker' && <Cookie className="w-8 h-8 text-amber-400" />}
              {selectedScanType !== 'DNS Security Checker' && selectedScanType !== 'Dependency Scanner' && selectedScanType !== 'Cookie Security Checker' && (
                <ShieldCheck className="w-8 h-8" />
              )}
            </div>
            <div className="space-y-1.5">
              <h3 className="text-lg font-bold text-slate-100">
                Ready to Run {selectedScanType}
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                {selectedScanType === 'DNS Security Checker' &&
                  'Enter a target domain above and click Run Scan to audit live DNS records, SPF, DMARC, DKIM, and DNSSEC.'}
                {selectedScanType === 'Dependency Scanner' &&
                  'Enter package names with versions in the manifest box above and click Run Dependency Scan to search NIST NVD v2.0 for live CVEs.'}
                {selectedScanType === 'Cookie Security Checker' &&
                  'Enter a target URL above and click Run Scan to inspect Set-Cookie response directives for Secure, HttpOnly, and SameSite.'}
                {selectedScanType !== 'DNS Security Checker' && selectedScanType !== 'Dependency Scanner' && selectedScanType !== 'Cookie Security Checker' &&
                  'Enter a target domain, hostname, or IP address in the search field above and click Run Scan to execute live multi-vector vulnerability checks.'}
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
                <p className="text-base font-extrabold font-mono text-cyan-400 truncate">
                  {analysisResult.target || analysisResult.domain || (analysisResult.scan_type === 'Dependency Vulnerability Scanner' ? `${analysisResult.total_packages_scanned} Packages` : 'Target')}
                </p>
                <span className="text-[11px] text-slate-500 font-mono">
                  {analysisResult.ip_address ? `IP: ${analysisResult.ip_address}` : (analysisResult.scan_type || 'Perimeter Scan')}
                </span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Scan Timestamp</span>
                <p className="text-sm font-semibold text-slate-200">{analysisResult.scan_timestamp}</p>
                <span className="text-[11px] text-emerald-400 font-mono">Duration: {analysisResult.duration || '1.2s'}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Security Score</span>
                <p className={`text-2xl font-black ${(analysisResult.security_score ?? 100) >= 85 ? 'text-emerald-400' : (analysisResult.security_score ?? 100) >= 70 ? 'text-amber-400' : 'text-rose-400'}`}>
                  {analysisResult.security_score ?? 100} / 100
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Risk Level</span>
                <div>
                  <Badge variant={(analysisResult.risk_level || 'Low').toLowerCase()} size="md">
                    {(analysisResult.risk_level || 'LOW').toUpperCase()} RISK
                  </Badge>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Vulnerability Breakdown</span>
                <div className="flex items-center gap-1 text-xs font-mono">
                  <span className="text-rose-400 font-bold">{analysisResult.critical_count || 0} Crit</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-orange-400 font-bold">{analysisResult.high_count || 0} High</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-amber-400 font-bold">{analysisResult.medium_count || 0} Med</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-blue-400 font-bold">{analysisResult.low_count || 0} Low</span>
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

      {/* ─────────────────────────────────────────────────────────── */}
      {/* MODULE 1: DNS SECURITY CHECKER RESULTS                      */}
      {/* ─────────────────────────────────────────────────────────── */}
      {(selectedScanType === 'DNS Security Checker' || analysisResult?.records_summary) && (
        <Card className="border-cyan-500/30 shadow-[0_0_20px_rgba(0,243,255,0.05)]">
          <CardHeader>
            <CardTitle icon={Network} subtitle="Live DNS Record Resolution & Email Authentication Directives (SPF, DMARC, DKIM, DNSSEC, CAA)">
              DNS Security Assessment &amp; Authentication Records
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {isAnalyzing ? (
              <Skeleton className="h-64 w-full" />
            ) : analysisResult?.records_summary ? (
              <>
                {/* DNS Security Mechanisms Highlights */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* SPF */}
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">SPF Policy</span>
                      <Badge variant={analysisResult.records_summary.SPF?.includes('v=spf1') ? 'success' : 'critical'} size="sm">
                        {analysisResult.records_summary.SPF?.includes('v=spf1') ? 'CONFIGURED' : 'MISSING'}
                      </Badge>
                    </div>
                    <p className="text-xs font-mono text-cyan-300 truncate" title={analysisResult.records_summary.SPF}>
                      {analysisResult.records_summary.SPF || 'Not Configured'}
                    </p>
                  </div>

                  {/* DMARC */}
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">DMARC Policy</span>
                      <Badge variant={analysisResult.records_summary.DMARC && analysisResult.records_summary.DMARC !== 'Not Found' ? 'success' : 'critical'} size="sm">
                        {analysisResult.records_summary.DMARC && analysisResult.records_summary.DMARC !== 'Not Found' ? 'PROTECTED' : 'MISSING'}
                      </Badge>
                    </div>
                    <p className="text-xs font-mono text-amber-300 truncate" title={analysisResult.records_summary.DMARC}>
                      {analysisResult.records_summary.DMARC || 'Not Configured'}
                    </p>
                  </div>

                  {/* DKIM */}
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">DKIM Key</span>
                      <Badge
                        variant={
                          analysisResult.records_summary.DKIM?.record && analysisResult.records_summary.DKIM?.record !== 'Not Found'
                            ? 'success'
                            : 'warning'
                        }
                        size="sm"
                      >
                        {analysisResult.records_summary.DKIM?.record && analysisResult.records_summary.DKIM?.record !== 'Not Found'
                          ? 'VERIFIED'
                          : 'UNVERIFIED'}
                      </Badge>
                    </div>
                    <p className="text-xs font-mono text-slate-300 truncate">
                      Selector: {analysisResult.records_summary.DKIM?.selector || 'default'}
                    </p>
                  </div>

                  {/* DNSSEC */}
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">DNSSEC Status</span>
                      <Badge variant={analysisResult.records_summary.DNSSEC?.status === 'Signed' ? 'success' : 'ghost'} size="sm">
                        {analysisResult.records_summary.DNSSEC?.status || 'Unsigned'}
                      </Badge>
                    </div>
                    <p className="text-xs font-mono text-slate-400 truncate">
                      {analysisResult.records_summary.DNSSEC?.description || 'Zone not signed'}
                    </p>
                  </div>
                </div>

                {/* Standard DNS Records Overview (A, AAAA, MX, NS) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* IPv4 / IPv6 & Nameservers */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5" /> Authoritative Name Servers &amp; IPs
                    </span>
                    <div className="space-y-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">A Records (IPv4): </span>
                        <span className="text-emerald-400">{analysisResult.records_summary.A?.join(', ') || 'None'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">AAAA Records (IPv6): </span>
                        <span className="text-slate-300">{analysisResult.records_summary.AAAA?.join(', ') || 'None'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Name Servers (NS): </span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {analysisResult.records_summary.NS?.map((ns, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[11px]">
                              {ns}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Mail Exchangers (MX) & CAA */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5" /> Mail Exchangers (MX) &amp; CAA Directives
                    </span>
                    <div className="space-y-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">MX Exchangers: </span>
                        {analysisResult.records_summary.MX?.length > 0 ? (
                          <div className="space-y-1 mt-1">
                            {analysisResult.records_summary.MX.map((mx, idx) => (
                              <div key={idx} className="text-slate-300 flex items-center gap-2">
                                <span className="text-amber-400 font-bold">[{mx.priority}]</span>
                                <span>{mx.exchange}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-500">No MX configured</span>
                        )}
                      </div>
                      <div className="pt-1">
                        <span className="text-slate-500">CAA Records: </span>
                        <span className="text-slate-300">{analysisResult.records_summary.CAA?.join(', ') || 'No CAA restrictions configured'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* DNS Findings Table */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-slate-300">
                    DNS Security Findings &amp; Hardening Directives
                  </h4>
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                        <tr>
                          <th className="p-3.5">Check</th>
                          <th className="p-3.5">Status</th>
                          <th className="p-3.5">Severity</th>
                          <th className="p-3.5">Verification Details</th>
                          <th className="p-3.5">Recommendation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80 bg-slate-950/60 font-mono text-xs">
                        {analysisResult.findings?.map((f, i) => (
                          <tr key={i} className="hover:bg-slate-900/40">
                            <td className="p-3.5 font-bold text-cyan-400 whitespace-nowrap">{f.check}</td>
                            <td className="p-3.5 whitespace-nowrap">
                              <Badge
                                variant={
                                  f.status === 'Found'
                                    ? 'success'
                                    : f.status === 'Missing'
                                    ? 'critical'
                                    : f.status === 'Unable to Verify'
                                    ? 'ghost'
                                    : 'warning'
                                }
                                size="sm"
                              >
                                {f.status}
                              </Badge>
                            </td>
                            <td className="p-3.5 whitespace-nowrap">
                              <span
                                className={
                                  f.severity === 'Critical'
                                    ? 'text-rose-400 font-bold'
                                    : f.severity === 'High'
                                    ? 'text-orange-400 font-bold'
                                    : f.severity === 'Medium'
                                    ? 'text-amber-300'
                                    : f.severity === 'Low'
                                    ? 'text-blue-300'
                                    : 'text-slate-400'
                                }
                              >
                                {f.severity}
                              </span>
                            </td>
                            <td className="p-3.5 font-sans text-slate-200 max-w-sm">{f.description}</td>
                            <td className="p-3.5 font-sans text-slate-400 max-w-sm">{f.recommendation || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* MODULE 2: DEPENDENCY VULNERABILITY SCANNER RESULTS          */}
      {/* ─────────────────────────────────────────────────────────── */}
      {(selectedScanType === 'Dependency Scanner' || analysisResult?.packages) && (
        <Card className="border-cyan-500/30 shadow-[0_0_20px_rgba(0,243,255,0.05)]">
          <CardHeader>
            <CardTitle icon={Package} subtitle="Software Composition Analysis (SCA) & NIST NVD v2.0 CVE Cross-Referencing">
              Dependency Security Assessment &amp; Vulnerability Matrix
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {isAnalyzing ? (
              <Skeleton className="h-64 w-full" />
            ) : analysisResult?.packages ? (
              <>
                {/* Metric Summary Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Packages Scanned</span>
                    <p className="text-xl font-bold font-mono text-slate-100">{analysisResult.total_packages_scanned || analysisResult.packages.length}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-rose-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-rose-400 uppercase">CVEs Identified</span>
                    <p className="text-xl font-bold font-mono text-rose-400">{analysisResult.total_vulnerabilities_found || 0}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-amber-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-amber-400 uppercase">Risk Level</span>
                    <p className="text-xl font-bold font-mono text-amber-400">{analysisResult.risk_level || 'Low'}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase">Supply Chain Score</span>
                    <p className="text-xl font-bold font-mono text-cyan-400">{analysisResult.security_score ?? 100}/100</p>
                  </div>
                </div>

                {/* Scanned Packages Breakdown Table */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-slate-300">
                    Scanned Packages &amp; Vulnerability Status
                  </h4>
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                        <tr>
                          <th className="p-3.5">Package</th>
                          <th className="p-3.5">Version</th>
                          <th className="p-3.5">Ecosystem</th>
                          <th className="p-3.5">Status</th>
                          <th className="p-3.5">CVE Count</th>
                          <th className="p-3.5">Identified Vulnerabilities</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80 bg-slate-950/60 font-mono text-xs">
                        {(Array.isArray(analysisResult.packages) ? analysisResult.packages : []).map((pkg, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-3.5 font-bold text-cyan-400">{pkg.package}</td>
                            <td className="p-3.5 text-slate-200">{pkg.version || 'Unspecified'}</td>
                            <td className="p-3.5 text-slate-400 uppercase">{pkg.ecosystem}</td>
                            <td className="p-3.5">
                              <Badge variant={pkg.vulnerabilities?.length > 0 ? 'critical' : 'success'} size="sm">
                                {pkg.vulnerabilities?.length > 0 ? 'VULNERABLE' : 'CLEAN'}
                              </Badge>
                            </td>
                            <td className="p-3.5 font-bold text-slate-200">{pkg.vulnerabilities?.length || 0}</td>
                            <td className="p-3.5 font-sans text-xs">
                              {pkg.vulnerabilities?.length > 0 ? (
                                <div className="flex flex-wrap gap-1.5">
                                  {pkg.vulnerabilities.map((v, vIdx) => (
                                    <span
                                      key={vIdx}
                                      className="px-2 py-0.5 rounded bg-rose-950/80 border border-rose-500/30 text-rose-300 font-mono text-[11px]"
                                    >
                                      {v.cve_id} ({v.severity})
                                    </span>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-emerald-400 font-mono">No known CVEs</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Detailed CVE Findings Cards */}
                {analysisResult.all_vulnerabilities?.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-mono font-bold uppercase text-slate-300">
                      Live NIST NVD v2.0 CVE Findings
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {(Array.isArray(analysisResult.all_vulnerabilities) ? analysisResult.all_vulnerabilities : []).map((cve, i) => (
                        <div
                          key={i}
                          className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-3 hover:border-cyan-500/40 transition-all"
                        >
                          <div className="space-y-2">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono font-extrabold text-sm text-cyan-400">{cve.cve_id}</span>
                              <Badge variant={(cve.severity || 'Medium').toLowerCase()} size="sm">
                                CVSS {cve.cvss_score || 'N/A'}
                              </Badge>
                            </div>
                            <p className="text-xs text-slate-300 leading-relaxed line-clamp-3">
                              {cve.description}
                            </p>
                          </div>
                          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                            <span>Pkg: <strong className="text-cyan-300">{cve.package}</strong></span>
                            {cve.reference_url && (
                              <a
                                href={cve.reference_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-400 hover:underline flex items-center gap-1"
                              >
                                <span>NVD Ref</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* ─────────────────────────────────────────────────────────── */}
      {/* MODULE 3: COOKIE SECURITY CHECKER RESULTS                   */}
      {/* ─────────────────────────────────────────────────────────── */}
      {(selectedScanType === 'Cookie Security Checker' || analysisResult?.cookies) && (
        <Card className="border-cyan-500/30 shadow-[0_0_20px_rgba(0,243,255,0.05)]">
          <CardHeader>
            <CardTitle icon={Cookie} subtitle="Live HTTP Set-Cookie Security Flags Audit (Secure, HttpOnly, SameSite, Scope & Expiry)">
              Cookie Security Directives &amp; Session Protection Audit
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {isAnalyzing ? (
              <Skeleton className="h-64 w-full" />
            ) : Array.isArray(analysisResult?.cookies) ? (
              <>
                {/* Metric Summary Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Total Cookies</span>
                    <p className="text-xl font-bold font-mono text-slate-100">{analysisResult.total_cookies || analysisResult.cookies.length}</p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-emerald-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-emerald-400 uppercase">Secure Cookies</span>
                    <p className="text-xl font-bold font-mono text-emerald-400">
                      {analysisResult.cookies.filter((c) => c.secure).length} / {analysisResult.cookies.length}
                    </p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-amber-500/20 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-amber-400 uppercase">HttpOnly Cookies</span>
                    <p className="text-xl font-bold font-mono text-amber-400">
                      {analysisResult.cookies.filter((c) => c.httponly).length} / {analysisResult.cookies.length}
                    </p>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-0.5 text-center">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase">Cookie Score</span>
                    <p className="text-xl font-bold font-mono text-cyan-400">{analysisResult.security_score ?? 100}/100</p>
                  </div>
                </div>

                {/* Cookies Inspection Table */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-slate-300">
                    Inspected Cookies &amp; Directive Compliance
                  </h4>
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                        <tr>
                          <th className="p-3.5">Cookie Name</th>
                          <th className="p-3.5">Secure</th>
                          <th className="p-3.5">HttpOnly</th>
                          <th className="p-3.5">SameSite</th>
                          <th className="p-3.5">Scope (Domain / Path)</th>
                          <th className="p-3.5">Risk Level</th>
                          <th className="p-3.5">Identified Issues</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80 bg-slate-950/60 font-mono text-xs">
                        {analysisResult.cookies.map((cookie, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-3.5 font-bold text-cyan-400">{cookie.name}</td>
                            <td className="p-3.5">
                              {cookie.secure ? (
                                <Badge variant="success" size="sm">SECURE</Badge>
                              ) : (
                                <Badge variant="critical" size="sm">MISSING</Badge>
                              )}
                            </td>
                            <td className="p-3.5">
                              {cookie.httponly ? (
                                <Badge variant="success" size="sm">HTTPONLY</Badge>
                              ) : (
                                <Badge variant="critical" size="sm">MISSING</Badge>
                              )}
                            </td>
                            <td className="p-3.5">
                              <span className={cookie.samesite !== 'Not Set' ? 'text-cyan-300' : 'text-amber-400'}>
                                {cookie.samesite}
                              </span>
                            </td>
                            <td className="p-3.5 text-slate-400">{cookie.domain} ({cookie.path})</td>
                            <td className="p-3.5">
                              <Badge variant={(cookie.severity || 'Low').toLowerCase()} size="sm">
                                {cookie.severity || 'LOW'}
                              </Badge>
                            </td>
                            <td className="p-3.5 font-sans text-xs text-slate-300 max-w-xs">
                              {cookie.issues?.length > 0 ? (
                                <ul className="space-y-0.5 text-rose-300">
                                  {cookie.issues.map((iss, iIdx) => (
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
                </div>
              </>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* OWASP Top 10 Assessment Module */}
      {(selectedScanType === 'OWASP Top 10' || selectedScanType === 'Full Audit') && (
        <Card className="border-cyan-500/30 shadow-[0_0_20px_rgba(0,243,255,0.05)]">
          <CardHeader>
            <CardTitle icon={ShieldAlert} subtitle="Official OWASP Top 10:2025 Web Security Assessment &amp; Verification Matrix">
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
                      {(Array.isArray(analysisResult.owasp_summary.findings) ? analysisResult.owasp_summary.findings : []).map((f, i) => (
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
                        {(Array.isArray(analysisResult.ports_summary?.open_ports) ? analysisResult.ports_summary.open_ports : []).map((p, idx) => (
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
                    No open perimeter ports identified on authorized target (probed standard service ports).
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
                        <Badge variant={analysisResult.ssl_summary?.is_valid ? 'success' : 'critical'} size="sm">
                          {analysisResult.ssl_summary?.cert_status || 'Unknown'}
                        </Badge>
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">TLS Protocol Version</span>
                      <p className="text-sm font-bold font-mono text-slate-100">{analysisResult.ssl_summary?.tls_version || 'N/A'}</p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">Certificate Issuer</span>
                      <p className="text-xs font-semibold text-cyan-300 truncate">{analysisResult.ssl_summary?.issuer || 'N/A'}</p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase">Expires On</span>
                      <p className="text-xs font-mono text-slate-200">
                        {analysisResult.ssl_summary?.expiry_date || 'N/A'} ({analysisResult.ssl_summary?.days_until_expiration || 0} days left)
                      </p>
                    </div>
                  </div>

                  {analysisResult.ssl_summary?.recommendations?.length > 0 && (
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
                  )}
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
              ) : analysisResult?.headers_summary ? (
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
                    {(Array.isArray(analysisResult.headers_summary.checks) ? analysisResult.headers_summary.checks : []).map((chk) => (
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
                      <Badge variant={(cve.severity || 'Medium').toLowerCase()} size="sm">
                        CVSS {cve.cvss_score || 'N/A'}
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
      {analysisResult?.recommendations?.length > 0 && (
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={Activity} subtitle="Consolidated hardening roadmap & remediation steps">
              Security Recommendations &amp; Best Practice Guidelines
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
