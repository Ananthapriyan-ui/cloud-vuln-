import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  GitCompare, ArrowRight, ShieldCheck, ShieldAlert, AlertTriangle,
  TrendingUp, TrendingDown, Minus, CheckCircle2, XCircle, Download,
  RefreshCw, FileText, Layers, Lock, Globe, Server, Activity,
  ChevronDown, ChevronUp, Check, ExternalLink, HelpCircle
} from 'lucide-react';
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { PageSkeleton } from '../components/ui/Loader';
import { useToast } from '../components/ui/Toast';
import api, { formatScanDate } from '../lib/api';

const ChartTooltipStyle = {
  backgroundColor: '#0d1424',
  borderColor: 'rgba(0,243,255,0.3)',
  borderRadius: '8px',
  fontSize: '11px',
  color: '#e2e8f0',
};

export const ScanComparisonPage = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { addToast } = useToast();

  const [options, setOptions] = useState([]);
  const [loadingOptions, setLoadingOptions] = useState(true);
  const [selectedPrev, setSelectedPrev] = useState('');
  const [selectedLatest, setSelectedLatest] = useState('');

  const [comparison, setComparison] = useState(null);
  const [comparing, setComparing] = useState(false);
  const [compareError, setCompareError] = useState(null);

  const [trendData, setTrendData] = useState(null);
  const [loadingTrend, setLoadingTrend] = useState(false);

  const [activeTab, setActiveTab] = useState('overview'); // overview, owasp, cve, headers, ssl
  const [vulnFilter, setVulnFilter] = useState('all'); // all, fixed, new, persistent

  // Fetch real scan options from backend
  const fetchOptions = useCallback(async () => {
    setLoadingOptions(true);
    try {
      const data = await api.getComparisonOptions();
      setOptions(Array.isArray(data) ? data : []);

      const urlPrev = searchParams.get('prev');
      const urlLatest = searchParams.get('latest');

      if (Array.isArray(data) && data.length >= 2) {
        // Auto-select based on URL params or newest two scans
        const prevTarget = urlPrev || data[1].scan_ref;
        const latestTarget = urlLatest || data[0].scan_ref;
        setSelectedPrev(prevTarget);
        setSelectedLatest(latestTarget);
      } else if (data && data.length === 1) {
        setSelectedLatest(data[0].scan_ref);
      }
    } catch (err) {
      console.error('Failed to load comparison options:', err);
      addToast(err.message || 'Failed to load completed scans', 'error');
    } finally {
      setLoadingOptions(false);
    }
  }, [searchParams, addToast]);

  // Fetch historical trends for target or overall
  const fetchTrend = useCallback(async (target) => {
    setLoadingTrend(true);
    try {
      const data = await api.getScanTrend(target);
      setTrendData(data);
    } catch (err) {
      console.error('Failed to load trend data:', err);
    } finally {
      setLoadingTrend(false);
    }
  }, []);

  useEffect(() => {
    fetchOptions();
    fetchTrend();
  }, [fetchOptions, fetchTrend]);

  // Execute Real Comparison
  const handleCompare = async (prevRef, latestRef) => {
    const p = prevRef || selectedPrev;
    const l = latestRef || selectedLatest;

    if (!p || !l) {
      setCompareError('Please select both a Previous Scan and a Latest Scan to compare.');
      return;
    }
    if (p === l) {
      setCompareError('Cannot compare a scan with itself. Please select two distinct completed scans.');
      return;
    }

    setComparing(true);
    setCompareError(null);
    try {
      const result = await api.compareScans(p, l);
      setComparison(result);
      setSearchParams({ prev: p, latest: l });
      addToast(`Compared ${p} vs ${l} successfully`, 'success');
    } catch (err) {
      setCompareError(err.message || 'Comparison failed.');
      setComparison(null);
      addToast(err.message || 'Failed to compare scans', 'error');
    } finally {
      setComparing(false);
    }
  };

  // Trigger comparison when options are loaded and selections ready
  useEffect(() => {
    if (selectedPrev && selectedLatest && selectedPrev !== selectedLatest) {
      handleCompare(selectedPrev, selectedLatest);
    }
  }, [selectedPrev, selectedLatest]);

  const handleDownload = async (format = 'html') => {
    if (!comparison) return;
    const prevRef = comparison.previous_scan.scan_ref;
    const latestRef = comparison.latest_scan.scan_ref;
    addToast(`Generating and downloading ${format.toUpperCase()} comparison report...`, 'info');
    try {
      const url = api.getComparisonDownloadUrl(prevRef, latestRef, format);
      const token = localStorage.getItem('cloudvuln_access_token');
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
      if (!res.ok) throw new Error('Failed to generate report file');
      const blob = await res.blob();
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `CLOUDVULN_Comparison_${prevRef}_vs_${latestRef}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      addToast(`${format.toUpperCase()} comparison report downloaded`, 'success');
    } catch (err) {
      addToast(`Download failed: ${err.message}`, 'error');
    }
  };

  // Helper metadata lookups for dropdown cards
  const prevScanMeta = useMemo(() => options.find(o => o.scan_ref === selectedPrev), [options, selectedPrev]);
  const latestScanMeta = useMemo(() => options.find(o => o.scan_ref === selectedLatest), [options, selectedLatest]);

  if (loadingOptions) {
    return <PageSkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="p-6 rounded-2xl bg-linear-to-r from-slate-900 via-cyan-950/40 to-slate-900 border border-cyan-500/30 shadow-[0_0_30px_rgba(0,243,255,0.08)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
          </div>
          <h2 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center gap-2.5">
            <GitCompare className="w-7 h-7 text-cyan-400" />
            <span>Scan Comparison &amp; Security Trend</span>
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
            Compare two real completed security assessments from your database. Track vulnerabilities fixed, new exposure introduced, OWASP top 10 evolution, security header hardening, and historical security trends.
          </p>
        </div>

        {comparison && (
          <div className="flex flex-wrap items-center gap-2.5">
            <Button
              variant="outline"
              icon={Download}
              onClick={() => handleDownload('csv')}
              className="text-xs"
            >
              Export CSV
            </Button>
            <Button
              variant="primary"
              icon={FileText}
              onClick={() => handleDownload('html')}
              className="text-xs shadow-[0_0_15px_rgba(0,243,255,0.2)]"
            >
              Download HTML Report
            </Button>
          </div>
        )}
      </div>

      {/* Selectors Section */}
      <Card className="border-slate-800 bg-[#0c1220]/90">
        <CardHeader className="pb-3 border-b border-slate-800/80">
          <CardTitle className="text-sm font-bold text-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Select Real Completed Scans to Compare</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {options.length} Completed Scans in DB
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6 space-y-6">
          {options.length < 2 ? (
            <div className="p-6 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-sm">Insufficient completed scans</p>
                <p className="text-xs text-amber-400/80 mt-1">
                  At least two completed scans are required to perform a side-by-side comparison. Run new scans in the Cloud Scanner to begin tracking security changes.
                </p>
                <Button
                  size="sm"
                  variant="primary"
                  className="mt-3"
                  onClick={() => navigate('/scanner')}
                >
                  Go to Cloud Scanner
                </Button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-11 gap-4 items-center">
              {/* Previous Scan Selector */}
              <div className="lg:col-span-5 space-y-3">
                <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  1. Previous / Baseline Scan
                </label>
                <select
                  value={selectedPrev}
                  onChange={(e) => setSelectedPrev(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-xl px-4 py-3 text-xs font-mono focus:border-cyan-400 focus:outline-none"
                >
                  <option value="">-- Select Baseline Scan --</option>
                  {options.map((s) => (
                    <option key={`prev-${s.scan_ref}`} value={s.scan_ref} disabled={s.scan_ref === selectedLatest}>
                      {s.scan_ref} — {s.target} ({formatScanDate(s.created_at)}) [Score: {s.security_score}/100, {s.status.toUpperCase()}]
                    </option>
                  ))}
                </select>

                {prevScanMeta && (
                  <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-2 font-mono">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Target:</span>
                      <span className="text-slate-200 font-bold truncate max-w-50">{prevScanMeta.target}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Executed At:</span>
                      <span className="text-cyan-400">{formatScanDate(prevScanMeta.created_at)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Security Score:</span>
                      <span className="font-bold text-slate-100">{prevScanMeta.security_score}/100</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Total Findings:</span>
                      <span className="text-rose-400 font-bold">{prevScanMeta.total_findings} (Crit: {prevScanMeta.critical_count}, High: {prevScanMeta.high_count})</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Compare Button / Arrow Divider */}
              <div className="lg:col-span-1 flex flex-col items-center justify-center pt-2">
                <div className="hidden lg:flex p-3 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(0,243,255,0.2)]">
                  <ArrowRight className="w-5 h-5" />
                </div>
              </div>

              {/* Latest Scan Selector */}
              <div className="lg:col-span-5 space-y-3">
                <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  2. Latest / Target Scan
                </label>
                <select
                  value={selectedLatest}
                  onChange={(e) => setSelectedLatest(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 text-slate-100 rounded-xl px-4 py-3 text-xs font-mono focus:border-cyan-400 focus:outline-none"
                >
                  <option value="">-- Select Latest Scan --</option>
                  {options.map((s) => (
                    <option key={`latest-${s.scan_ref}`} value={s.scan_ref} disabled={s.scan_ref === selectedPrev}>
                      {s.scan_ref} — {s.target} ({formatScanDate(s.created_at)}) [Score: {s.security_score}/100, {s.status.toUpperCase()}]
                    </option>
                  ))}
                </select>

                {latestScanMeta && (
                  <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-2 font-mono">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Target:</span>
                      <span className="text-slate-200 font-bold truncate max-w-50">{latestScanMeta.target}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Executed At:</span>
                      <span className="text-cyan-400">{formatScanDate(latestScanMeta.created_at)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Security Score:</span>
                      <span className="font-bold text-slate-100">{latestScanMeta.security_score}/100</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Total Findings:</span>
                      <span className="text-rose-400 font-bold">{latestScanMeta.total_findings} (Crit: {latestScanMeta.critical_count}, High: {latestScanMeta.high_count})</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {compareError && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{compareError}</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Comparison Results */}
      {comparing ? (
        <Card className="p-12 text-center border-slate-800">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-sm font-bold text-slate-200">Executing Differential Security Analysis...</p>
          <p className="text-xs text-slate-400 mt-1">Comparing real database records, OWASP matrices, CVEs, and security headers.</p>
        </Card>
      ) : comparison ? (
        <div className="space-y-6">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Score Delta Card */}
            <Card className="border-cyan-500/20 bg-linear-to-br from-slate-900/90 to-cyan-950/20">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
                  <span>Security Score Diff</span>
                  {comparison.summary.score_difference > 0 ? (
                    <TrendingUp className="w-4 h-4 text-emerald-400" />
                  ) : comparison.summary.score_difference < 0 ? (
                    <TrendingDown className="w-4 h-4 text-rose-400" />
                  ) : (
                    <Minus className="w-4 h-4 text-slate-400" />
                  )}
                </div>
                <div className="flex items-baseline gap-2 mt-2">
                  <span className="text-3xl font-black text-slate-100">
                    {comparison.summary.previous_security_score}
                  </span>
                  <span className="text-slate-500 text-lg">&rarr;</span>
                  <span className={`text-3xl font-black ${
                    comparison.summary.score_difference > 0 ? 'text-emerald-400' :
                    comparison.summary.score_difference < 0 ? 'text-rose-400' : 'text-slate-200'
                  }`}>
                    {comparison.summary.latest_security_score}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                  <span className={comparison.summary.score_difference >= 0 ? 'text-emerald-400' : 'text-rose-400'}>
                    {comparison.summary.score_difference > 0 ? `+${comparison.summary.score_difference}` : comparison.summary.score_difference} pts ({comparison.summary.percentage_change}%)
                  </span>
                  <Badge
                    variant={comparison.summary.status_category === 'improved' ? 'success' : comparison.summary.status_category === 'degraded' ? 'critical' : 'neutral'}
                    size="sm"
                  >
                    {comparison.summary.security_status}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Fixed Findings */}
            <Card className="border-emerald-500/20 bg-linear-to-br from-slate-900/90 to-emerald-950/20">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
                  <span>Findings Fixed</span>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-3xl font-black text-emerald-400 mt-2">
                  {comparison.summary.findings_fixed_count}
                </div>
                <p className="text-[11px] text-slate-400 mt-2 pt-2 border-t border-slate-800/80 font-mono">
                  {comparison.summary.cve_improvements} CVEs / {comparison.summary.header_improvements} Headers Resolved
                </p>
              </CardContent>
            </Card>

            {/* New Findings */}
            <Card className="border-rose-500/20 bg-linear-to-br from-slate-900/90 to-rose-950/20">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
                  <span>New Findings</span>
                  <XCircle className="w-4 h-4 text-rose-400" />
                </div>
                <div className="text-3xl font-black text-rose-400 mt-2">
                  {comparison.summary.new_findings_count}
                </div>
                <p className="text-[11px] text-slate-400 mt-2 pt-2 border-t border-slate-800/80 font-mono">
                  Introduced in {comparison.latest_scan.scan_ref}
                </p>
              </CardContent>
            </Card>

            {/* Persistent Findings */}
            <Card className="border-amber-500/20 bg-linear-to-br from-slate-900/90 to-amber-950/20">
              <CardContent className="p-5">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
                  <span>Persistent Findings</span>
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                </div>
                <div className="text-3xl font-black text-amber-400 mt-2">
                  {comparison.summary.persistent_findings_count}
                </div>
                <p className="text-[11px] text-slate-400 mt-2 pt-2 border-t border-slate-800/80 font-mono">
                  Remaining unmitigated across scans
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Severity Matrix & Charts Section */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Severity Matrix Table */}
            <Card className="lg:col-span-5 border-slate-800">
              <CardHeader className="pb-3 border-b border-slate-800">
                <CardTitle className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Severity Findings Matrix</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead className="text-center">Prev</TableHead>
                      <TableHead className="text-center">Latest</TableHead>
                      <TableHead className="text-right">Change</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[
                      { key: 'critical', label: 'Critical', color: 'text-rose-400' },
                      { key: 'high', label: 'High', color: 'text-orange-400' },
                      { key: 'medium', label: 'Medium', color: 'text-amber-400' },
                      { key: 'low', label: 'Low', color: 'text-sky-400' },
                      { key: 'total', label: 'Total Issues', color: 'text-slate-100 font-bold' }
                    ].map(({ key, label, color }) => {
                      const data = comparison.severity_comparison[key] || { previous: 0, latest: 0, change: 0 };
                      return (
                        <TableRow key={key}>
                          <TableCell className={`font-semibold text-xs ${color}`}>
                            {label}
                          </TableCell>
                          <TableCell className="text-center font-mono text-xs text-slate-300">
                            {data.previous}
                          </TableCell>
                          <TableCell className="text-center font-mono text-xs text-slate-300">
                            {data.latest}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs font-bold">
                            {data.change < 0 ? (
                              <span className="text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30">
                                {data.change} (Reduced)
                              </span>
                            ) : data.change > 0 ? (
                              <span className="text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30">
                                +{data.change} (Increased)
                              </span>
                            ) : (
                              <span className="text-slate-500">0 (Unchanged)</span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {/* Historical Real Security Trend Chart */}
            <Card className="lg:col-span-7 border-slate-800">
              <CardHeader className="pb-3 border-b border-slate-800 flex flex-row items-center justify-between">
                <CardTitle className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Real Database Security Trend History</span>
                </CardTitle>
                <span className="text-[11px] font-mono text-cyan-400">
                  {trendData?.total_scans || 0} Scans Audited
                </span>
              </CardHeader>
              <CardContent className="p-4">
                {!trendData || !trendData.has_sufficient_data ? (
                  <div className="h-60 flex flex-col items-center justify-center text-center p-6 text-slate-400 text-xs font-mono">
                    <AlertTriangle className="w-8 h-8 text-amber-400 mb-2" />
                    <p>{trendData?.message || 'At least two completed scans are required to display a security trend.'}</p>
                  </div>
                ) : (
                  <div className="h-60">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trendData.security_trend}>
                        <defs>
                          <linearGradient id="scoreTrendGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#00f3ff" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#00f3ff" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                        <YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} tickLine={false} />
                        <Tooltip contentStyle={ChartTooltipStyle} />
                        <Area
                          type="monotone"
                          dataKey="security_score"
                          stroke="#00f3ff"
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#scoreTrendGradient)"
                          name="Security Score"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Real Historical Severity Breakdown Chart */}
          {trendData && trendData.has_sufficient_data && (
            <Card className="border-slate-800">
              <CardHeader className="pb-3 border-b border-slate-800">
                <CardTitle className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-cyan-400" />
                  <span>Historical Finding Volume by Severity</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData.severity_trend}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                      <Tooltip contentStyle={ChartTooltipStyle} />
                      <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                      <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} name="Critical" dot={{ r: 3 }} />
                      <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} name="High" dot={{ r: 3 }} />
                      <Line type="monotone" dataKey="medium" stroke="#f59e0b" strokeWidth={2} name="Medium" dot={{ r: 3 }} />
                      <Line type="monotone" dataKey="low" stroke="#00f3ff" strokeWidth={2} name="Low" dot={{ r: 3 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Deep Diffs Navigation Tabs */}
          <div className="flex border-b border-slate-800 overflow-x-auto gap-2">
            {[
              { id: 'overview', label: 'Vulnerability Diff', icon: Layers, count: comparison.summary.findings_fixed_count + comparison.summary.new_findings_count + comparison.summary.persistent_findings_count },
              { id: 'owasp', label: 'OWASP Top 10 Diff', icon: ShieldCheck, count: comparison.owasp_comparison.length },
              { id: 'cve', label: 'CVE & NVD Findings', icon: Server, count: comparison.cve_comparison.total_fixed + comparison.cve_comparison.total_new + comparison.cve_comparison.total_persistent },
              { id: 'headers', label: 'HTTP Security Headers', icon: Globe, count: 6 },
              { id: 'ssl', label: 'SSL / TLS Certificate', icon: Lock },
            ].map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className={`flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                    activeTab === t.id
                      ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{t.label}</span>
                  {t.count !== undefined && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
                      {t.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Tab Content: Vulnerabilities Lifecycle */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-slate-400 uppercase">Filter Findings:</span>
                  {['all', 'fixed', 'new', 'persistent'].map((f) => (
                    <button
                      key={f}
                      onClick={() => setVulnFilter(f)}
                      className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                        vulnFilter === f
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
                      }`}
                    >
                      {f.toUpperCase()} ({
                        f === 'all'
                          ? comparison.vulnerability_changes.fixed.length + comparison.vulnerability_changes.new.length + comparison.vulnerability_changes.persistent.length
                          : comparison.vulnerability_changes[f].length
                      })
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Fixed Column */}
                {(vulnFilter === 'all' || vulnFilter === 'fixed') && (
                  <Card className="border-emerald-500/30 bg-slate-950/60">
                    <CardHeader className="pb-3 border-b border-slate-800 flex flex-row items-center justify-between">
                      <CardTitle className="text-xs font-bold text-emerald-400 uppercase flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Fixed in Latest ({comparison.vulnerability_changes.fixed.length})</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-3 space-y-2 max-h-96 overflow-y-auto">
                      {comparison.vulnerability_changes.fixed.length === 0 ? (
                        <p className="text-xs text-slate-500 p-4 text-center">No vulnerabilities fixed.</p>
                      ) : (
                        comparison.vulnerability_changes.fixed.map((v, i) => (
                          <div key={i} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-emerald-400 font-bold">{v.cve_id || v.id}</span>
                              <Badge variant={v.severity.toLowerCase()} size="sm">{v.severity}</Badge>
                            </div>
                            <p className="font-semibold text-slate-200">{v.title}</p>
                            <p className="text-[11px] text-slate-400 truncate">Component: {v.component}</p>
                          </div>
                        ))
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* New Column */}
                {(vulnFilter === 'all' || vulnFilter === 'new') && (
                  <Card className="border-rose-500/30 bg-slate-950/60">
                    <CardHeader className="pb-3 border-b border-slate-800 flex flex-row items-center justify-between">
                      <CardTitle className="text-xs font-bold text-rose-400 uppercase flex items-center gap-1.5">
                        <XCircle className="w-4 h-4" />
                        <span>New Findings ({comparison.vulnerability_changes.new.length})</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-3 space-y-2 max-h-96 overflow-y-auto">
                      {comparison.vulnerability_changes.new.length === 0 ? (
                        <p className="text-xs text-slate-500 p-4 text-center">No new vulnerabilities introduced.</p>
                      ) : (
                        comparison.vulnerability_changes.new.map((v, i) => (
                          <div key={i} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-rose-400 font-bold">{v.cve_id || v.id}</span>
                              <Badge variant={v.severity.toLowerCase()} size="sm">{v.severity}</Badge>
                            </div>
                            <p className="font-semibold text-slate-200">{v.title}</p>
                            <p className="text-[11px] text-slate-400 truncate">Component: {v.component}</p>
                          </div>
                        ))
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* Persistent Column */}
                {(vulnFilter === 'all' || vulnFilter === 'persistent') && (
                  <Card className="border-amber-500/30 bg-slate-950/60">
                    <CardHeader className="pb-3 border-b border-slate-800 flex flex-row items-center justify-between">
                      <CardTitle className="text-xs font-bold text-amber-400 uppercase flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4" />
                        <span>Persistent Findings ({comparison.vulnerability_changes.persistent.length})</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-3 space-y-2 max-h-96 overflow-y-auto">
                      {comparison.vulnerability_changes.persistent.length === 0 ? (
                        <p className="text-xs text-slate-500 p-4 text-center">No persistent findings remaining.</p>
                      ) : (
                        comparison.vulnerability_changes.persistent.map((v, i) => (
                          <div key={i} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-amber-400 font-bold">{v.cve_id || v.id}</span>
                              <Badge variant={v.latest_severity?.toLowerCase() || 'warning'} size="sm">{v.latest_severity || 'Medium'}</Badge>
                            </div>
                            <p className="font-semibold text-slate-200">{v.title}</p>
                            <p className="text-[11px] text-slate-400 truncate">Component: {v.component}</p>
                          </div>
                        ))
                      )}
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          )}

          {/* Tab Content: OWASP Top 10 Matrix */}
          {activeTab === 'owasp' && (
            <Card className="border-slate-800">
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>OWASP ID</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Previous Status</TableHead>
                      <TableHead>Latest Status</TableHead>
                      <TableHead>Posture Evolution</TableHead>
                      <TableHead>Recommendation</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {comparison.owasp_comparison.map((ow) => (
                      <TableRow key={ow.owasp_id}>
                        <TableCell className="font-mono text-xs font-bold text-cyan-400">
                          {ow.owasp_id}
                        </TableCell>
                        <TableCell className="font-semibold text-slate-200 text-xs">
                          {ow.category}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={ow.previous_status === 'Passed' ? 'success' : ow.previous_status === 'Failed' ? 'critical' : 'warning'}
                            size="sm"
                          >
                            {ow.previous_status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={ow.latest_status === 'Passed' ? 'success' : ow.latest_status === 'Failed' ? 'critical' : 'warning'}
                            size="sm"
                          >
                            {ow.latest_status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs font-semibold">
                          {ow.change_type === 'Improvement' ? (
                            <span className="text-emerald-400 flex items-center gap-1 font-bold">
                              <TrendingUp className="w-3.5 h-3.5" /> Improvement
                            </span>
                          ) : ow.change_type === 'New Issue' ? (
                            <span className="text-rose-400 flex items-center gap-1 font-bold">
                              <TrendingDown className="w-3.5 h-3.5" /> New Issue
                            </span>
                          ) : ow.change_type === 'Persistent Issue' ? (
                            <span className="text-amber-400 flex items-center gap-1 font-bold">
                              <AlertTriangle className="w-3.5 h-3.5" /> Persistent Issue
                            </span>
                          ) : (
                            <span className="text-slate-400">{ow.change_type}</span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-slate-400 max-w-xs truncate">
                          {ow.recommendation || 'Maintain current policy enforcement.'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {/* Tab Content: CVE Comparison */}
          {activeTab === 'cve' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="border-slate-800 p-4 bg-slate-900/60">
                  <span className="text-xs font-mono text-slate-400 uppercase">Fixed CVEs</span>
                  <p className="text-2xl font-black text-emerald-400 mt-1">{comparison.cve_comparison.total_fixed}</p>
                </Card>
                <Card className="border-slate-800 p-4 bg-slate-900/60">
                  <span className="text-xs font-mono text-slate-400 uppercase">New CVEs</span>
                  <p className="text-2xl font-black text-rose-400 mt-1">{comparison.cve_comparison.total_new}</p>
                </Card>
                <Card className="border-slate-800 p-4 bg-slate-900/60">
                  <span className="text-xs font-mono text-slate-400 uppercase">Persistent CVEs</span>
                  <p className="text-2xl font-black text-amber-400 mt-1">{comparison.cve_comparison.total_persistent}</p>
                </Card>
              </div>

              <Card className="border-slate-800">
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>CVE ID</TableHead>
                        <TableHead>Severity Status</TableHead>
                        <TableHead>CVSS Score</TableHead>
                        <TableHead>Published Date</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {[
                        ...comparison.cve_comparison.fixed_cves.map(c => ({ ...c, lifecycle: 'Fixed' })),
                        ...comparison.cve_comparison.new_cves.map(c => ({ ...c, lifecycle: 'New' })),
                        ...comparison.cve_comparison.persistent_cves.map(c => ({ ...c, lifecycle: 'Persistent' })),
                      ].length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center py-8 text-slate-500">
                            No distinct CVE discrepancies between selected scans.
                          </TableCell>
                        </TableRow>
                      ) : (
                        [
                          ...comparison.cve_comparison.fixed_cves.map(c => ({ ...c, lifecycle: 'Fixed' })),
                          ...comparison.cve_comparison.new_cves.map(c => ({ ...c, lifecycle: 'New' })),
                          ...comparison.cve_comparison.persistent_cves.map(c => ({ ...c, lifecycle: 'Persistent' })),
                        ].map((cve) => (
                          <TableRow key={cve.cve_id}>
                            <TableCell className="font-mono text-xs font-bold text-cyan-400">
                              {cve.cve_id}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={cve.lifecycle === 'Fixed' ? 'success' : cve.lifecycle === 'New' ? 'critical' : 'warning'}
                                size="sm"
                              >
                                {cve.lifecycle}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs font-bold text-slate-200">
                              {cve.cvss_score || cve.latest_cvss || '—'}
                            </TableCell>
                            <TableCell className="font-mono text-xs text-slate-400">
                              {cve.published_date || 'N/A'}
                            </TableCell>
                            <TableCell className="text-xs text-slate-300 max-w-md truncate">
                              {cve.description}
                            </TableCell>
                            <TableCell className="text-right">
                              {cve.reference_url && (
                                <a
                                  href={cve.reference_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-xs text-cyan-400 hover:underline inline-flex items-center gap-1 font-mono"
                                >
                                  NVD <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Tab Content: HTTP Headers */}
          {activeTab === 'headers' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="p-4 bg-emerald-950/20 border-emerald-500/20">
                  <span className="text-xs font-mono text-emerald-400 uppercase font-semibold">Fixed Headers</span>
                  <p className="text-2xl font-black text-emerald-400 mt-1">{comparison.header_comparison.fixed.length}</p>
                </Card>
                <Card className="p-4 bg-rose-950/20 border-rose-500/20">
                  <span className="text-xs font-mono text-rose-400 uppercase font-semibold">Newly Missing</span>
                  <p className="text-2xl font-black text-rose-400 mt-1">{comparison.header_comparison.newly_missing.length}</p>
                </Card>
                <Card className="p-4 bg-amber-950/20 border-amber-500/20">
                  <span className="text-xs font-mono text-amber-400 uppercase font-semibold">Still Missing</span>
                  <p className="text-2xl font-black text-amber-400 mt-1">{comparison.header_comparison.still_missing.length}</p>
                </Card>
                <Card className="p-4 bg-cyan-950/20 border-cyan-500/20">
                  <span className="text-xs font-mono text-cyan-400 uppercase font-semibold">Remained Secure</span>
                  <p className="text-2xl font-black text-cyan-400 mt-1">{comparison.header_comparison.remained_secure.length}</p>
                </Card>
              </div>

              <Card className="border-slate-800">
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>HTTP Header</TableHead>
                        <TableHead>Previous Value</TableHead>
                        <TableHead>Latest Value</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Recommendation</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {[
                        ...comparison.header_comparison.fixed,
                        ...comparison.header_comparison.newly_missing,
                        ...comparison.header_comparison.still_missing,
                        ...comparison.header_comparison.remained_secure,
                      ].map((hdr) => (
                        <TableRow key={hdr.name}>
                          <TableCell className="font-mono text-xs font-bold text-slate-100">
                            {hdr.name}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-slate-400">
                            {hdr.previous_value}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-slate-200 font-semibold">
                            {hdr.latest_value}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={hdr.status === 'Fixed' || hdr.status === 'Remained Secure' ? 'success' : 'critical'}
                              size="sm"
                            >
                              {hdr.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-slate-400 max-w-sm truncate">
                            {hdr.recommendation}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Tab Content: SSL/TLS Diff */}
          {activeTab === 'ssl' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card className="border-slate-800">
                <CardHeader className="pb-3 border-b border-slate-800">
                  <CardTitle className="text-xs font-mono text-slate-400 uppercase">
                    Baseline Scan SSL/TLS ({comparison.previous_scan.scan_ref})
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-3 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Certificate Status:</span>
                    <Badge variant={comparison.ssl_comparison.previous_is_valid ? 'success' : 'critical'} size="sm">
                      {comparison.ssl_comparison.previous_cert_status}
                    </Badge>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">TLS Protocol:</span>
                    <span className="text-slate-200">{comparison.ssl_comparison.previous_tls_version}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Expiry Date:</span>
                    <span className="text-slate-300">{comparison.ssl_comparison.previous_expiry} ({comparison.ssl_comparison.previous_days_left} days left)</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Issuer Authority:</span>
                    <span className="text-slate-300 truncate max-w-xs">{comparison.ssl_comparison.previous_issuer}</span>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-slate-800">
                <CardHeader className="pb-3 border-b border-slate-800 flex flex-row items-center justify-between">
                  <CardTitle className="text-xs font-mono text-slate-400 uppercase">
                    Latest Scan SSL/TLS ({comparison.latest_scan.scan_ref})
                  </CardTitle>
                  <Badge variant={comparison.ssl_comparison.status === 'Improved' ? 'success' : 'neutral'} size="sm">
                    {comparison.ssl_comparison.status}
                  </Badge>
                </CardHeader>
                <CardContent className="p-4 space-y-3 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Certificate Status:</span>
                    <Badge variant={comparison.ssl_comparison.latest_is_valid ? 'success' : 'critical'} size="sm">
                      {comparison.ssl_comparison.latest_cert_status}
                    </Badge>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">TLS Protocol:</span>
                    <span className="font-bold text-cyan-400">{comparison.ssl_comparison.latest_tls_version}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Expiry Date:</span>
                    <span className="text-slate-300">{comparison.ssl_comparison.latest_expiry} ({comparison.ssl_comparison.latest_days_left} days left)</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Issuer Authority:</span>
                    <span className="text-slate-300 truncate max-w-xs">{comparison.ssl_comparison.latest_issuer}</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
};

export default ScanComparisonPage;
