import React, { useState, useEffect, useCallback, memo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck, ShieldAlert, Radar as RadarIcon, Server, Activity,
  Play, Cloud, Layers, AlertTriangle, RefreshCw,
  Search, ExternalLink, FileText, CheckCircle2
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Badge } from '../components/ui/Badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { PageSkeleton } from '../components/ui/Loader';
import { useToast } from '../components/ui/Toast';
import { useAuth } from '../context/AuthContext';
import api, { formatScanDate } from '../lib/api';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';

// ── Memoized chart tooltip ───────────────────────────────────────────
const ChartTooltipStyle = {
  backgroundColor: '#0d1424',
  borderColor: 'rgba(0,243,255,0.3)',
  borderRadius: '8px',
  fontSize: '11px',
  color: '#e2e8f0',
};

// ── Metric Card ─────────────────────────────────────────────────────
const MetricCard = memo(({ label, value, sub, color, icon: Icon, borderHover }) => (
  <Card className={`hover:${borderHover} transition-colors duration-300`}>
    <CardContent className="p-5 flex items-center justify-between">
      <div className="space-y-1">
        <span className="text-xs font-mono text-slate-400 uppercase tracking-wide">{label}</span>
        <p className={`text-2xl font-extrabold ${color}`}>{value ?? '—'}</p>
        <p className={`text-[11px] font-mono flex items-center gap-1 ${color}`}>{sub}</p>
      </div>
      <div className={`p-3 rounded-xl bg-current/10 border border-current/30 ${color}`} style={{ background: 'rgba(0,0,0,0.3)' }}>
        <Icon className="w-6 h-6" />
      </div>
    </CardContent>
  </Card>
));

// ── Build domain posture from real scan data ─────────────────────────
const buildPostureData = (scans) => {
  if (!scans || scans.length === 0) return null;
  const completedScans = scans.filter(s => s.scan_data);
  if (completedScans.length === 0) return null;
  const avg = (arr) => arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  const parseData = (s) => {
    try { return typeof s.scan_data === 'string' ? JSON.parse(s.scan_data) : s.scan_data; }
    catch { return null; }
  };
  const parsed = completedScans.map(parseData).filter(Boolean);
  return [
    { subject: 'SSL/TLS', score: avg(parsed.map(d => d.ssl_summary?.is_valid ? 90 : 30).filter(v => v > 0)), fullMark: 100 },
    { subject: 'Headers', score: avg(parsed.map(d => d.headers_summary?.score).filter(v => v != null)), fullMark: 100 },
    { subject: 'OWASP:2025', score: avg(parsed.map(d => d.owasp_summary?.overall_score).filter(v => v != null)), fullMark: 100 },
    { subject: 'Security Score', score: avg(parsed.map(d => d.security_score).filter(v => v != null)), fullMark: 100 },
    { subject: 'CVE Risk', score: avg(parsed.map(d => Math.max(0, 100 - (d.critical_count || 0) * 20 - (d.high_count || 0) * 10)).filter(v => v != null)), fullMark: 100 },
    { subject: 'Ports', score: avg(parsed.map(d => d.ports_summary ? Math.max(0, 100 - (d.ports_summary.open_ports_count || 0) * 10) : 85).filter(v => v > 0)), fullMark: 100 },
  ];
};

const EMPTY_SUMMARY = {
  total_scans: 0, monitored_assets: 0,
  critical_vulnerabilities: 0, high_vulnerabilities: 0,
  medium_vulnerabilities: 0, low_vulnerabilities: 0,
  info_vulnerabilities: 0, active_scans: 0,
  compliance_score: 100.0, posture_score: 100,
};

const EMPTY_STATS = {
  severity_breakdown: [
    { name: 'Critical', value: 0, color: '#ef4444' },
    { name: 'High',     value: 0, color: '#f97316' },
    { name: 'Medium',   value: 0, color: '#f59e0b' },
    { name: 'Low',      value: 0, color: '#00f3ff' },
    { name: 'Info',     value: 0, color: '#64748b' },
  ],
  trend_history: [],
};

// ── Main Dashboard Page ─────────────────────────────────────────────
export const DashboardPage = () => {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { user } = useAuth();

  const [loading, setLoading]       = useState(true);
  const [summary, setSummary]       = useState(null);
  const [riskStats, setRiskStats]   = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [activityLogs, setActivityLogs] = useState([]);

  const [cveFeed, setCveFeed]   = useState([]);
  const [cveQuery, setCveQuery] = useState('Cloud');
  const [cveLoading, setCveLoading] = useState(false);

  const fetchDashboardData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [sumData, statsData, scansData, actData] = await Promise.all([
        api.dashboardSummary(),
        api.riskStatistics(),
        api.recentScans(),
        api.activity(),
      ]);
      setSummary(sumData || EMPTY_SUMMARY);
      setRiskStats(statsData || EMPTY_STATS);
      setRecentScans(scansData || []);
      setActivityLogs(actData || []);
    } catch (e) {
      console.error("Dashboard loading error", e);
      setSummary(EMPTY_SUMMARY);
      setRiskStats(EMPTY_STATS);
      setRecentScans([]);
      setActivityLogs([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchCveFeed = useCallback(async (query) => {
    setCveLoading(true);
    try {
      const data = await api.searchCve(query || 'Cloud');
      if (Array.isArray(data) && data.length > 0) setCveFeed(data);
    } catch { /* ignore */ }
    finally { setCveLoading(false); }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    fetchCveFeed('Cloud');
  }, [fetchDashboardData, fetchCveFeed]);

  const totalVulns = riskStats?.severity_breakdown?.reduce((a, c) => a + c.value, 0) || 0;
  const postureData = buildPostureData(recentScans);

  if (loading) return <PageSkeleton />;

  const recentReports = (recentScans || []).slice(0, 5).map(scan => ({
    id: scan.scan_ref,
    target: scan.target,
    date: formatScanDate(scan.created_at),
    risk: scan.risk_score
  }));

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <div className="p-6 rounded-2xl bg-linear-to-r from-slate-900 via-cyan-950/40 to-slate-900 border border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-[0_0_30px_rgba(0,243,255,0.08)]">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-400 font-mono"></span>
          </div>
          <h2 className="text-xl sm:text-2xl font-black text-slate-100">
            Welcome back, <span className="text-cyan-400">{user?.full_name?.split(' ')[0] || 'Operator'}</span>
          </h2>
          <p className="text-xs sm:text-sm text-slate-300">
            Posture Score: <span className="text-emerald-400 font-bold">{summary?.posture_score}/100</span> ·{' '}
            <span className="text-rose-400 font-semibold">{summary?.critical_vulnerabilities} Critical CVEs</span> need action
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline" icon={RefreshCw}
            onClick={() => { addToast('Refreshing dashboard…', 'info'); fetchDashboardData(true); }}
          >
            Refresh
          </Button>
          <Button variant="primary" icon={Play} onClick={() => navigate('/scanner')}>
            Launch Scan
          </Button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Scans" value={summary?.total_scans} icon={Server}
          color="text-cyan-400" borderHover="border-cyan-500/40"
          sub={<><Layers className="w-3 h-3" /> {summary?.monitored_assets} Assets</>}
        />
        <MetricCard
          label="Critical Findings" value={summary?.critical_vulnerabilities} icon={ShieldAlert}
          color="text-rose-400" borderHover="border-rose-500/40"
          sub={<><AlertTriangle className="w-3 h-3" /> Immediate Action</>}
        />
        <MetricCard
          label="High Risk" value={summary?.high_vulnerabilities} icon={ShieldCheck}
          color="text-orange-400" borderHover="border-orange-500/40"
          sub="High CVSS Impact"
        />
        <MetricCard
          label="Compliance Score" value={`${summary?.compliance_score}%`} icon={RadarIcon}
          color="text-emerald-400" borderHover="border-emerald-500/40"
          sub={<><CheckCircle2 className="w-3 h-3" /> CIS Benchmark v2</>}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Donut */}
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={ShieldAlert} subtitle="Vulnerability count by severity">
              Severity Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="h-60 flex items-center justify-center relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskStats?.severity_breakdown || []}
                  cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                  paddingAngle={4} dataKey="value"
                >
                  {riskStats?.severity_breakdown?.map((entry, i) => (
                    <Cell key={i} fill={entry.color} stroke="#090d16" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip contentStyle={ChartTooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none">
              <span className="text-2xl font-extrabold text-slate-100">{totalVulns}</span>
              <span className="text-[10px] font-mono text-slate-400 uppercase">Findings</span>
            </div>
          </CardContent>
          <div className="p-3 bg-slate-950/50 border-t border-slate-800 flex flex-wrap items-center justify-around gap-1 text-xs font-mono">
            {riskStats?.severity_breakdown?.map((s) => (
              <div key={s.name} className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: s.color }} />
                <span className="text-slate-400 text-[10px]">{s.name}:</span>
                <span className="text-slate-100 font-bold text-[10px]">{s.value}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Area Chart */}
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={Activity} subtitle="7-day threat trend">
              Threat Trend History
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64 flex items-center justify-center">
            {(!riskStats?.trend_history || riskStats.trend_history.length === 0) ? (
              <div className="text-center p-6 space-y-2">
                <Activity className="w-8 h-8 text-slate-600 mx-auto" />
                <p className="text-xs text-slate-400">No trend history recorded yet.</p>
                <p className="text-[11px] text-slate-500">Run security scans to track vulnerability trends over time.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskStats.trend_history} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#f97316" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip contentStyle={ChartTooltipStyle} />
                  <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#gCrit)" strokeWidth={2} />
                  <Area type="monotone" dataKey="high"     stroke="#f97316" fill="url(#gHigh)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Radar */}
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={RadarIcon} subtitle="Compliance per security domain">
              Control Domain Posture
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64 flex items-center justify-center">
            {!postureData ? (
              <div className="text-center space-y-2">
                <RadarIcon className="w-8 h-8 text-slate-600 mx-auto" />
                <p className="text-xs text-slate-400">No completed scans available.</p>
                <p className="text-[11px] text-slate-500">Run scans with scan_data to populate the posture radar.</p>
              </div>
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={postureData}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis dataKey="subject" stroke="#94a3b8" fontSize={10} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#334155" fontSize={9} />
                <Radar name="Compliance" dataKey="score" stroke="#00f3ff" fill="#00f3ff" fillOpacity={0.25} />
                <Tooltip contentStyle={ChartTooltipStyle} />
              </RadarChart>
            </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* CVE Feed + Quick Reports */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* CVE Feed */}
        <Card className="lg:col-span-2 border-cyan-500/20">
          <CardHeader action={
            <form
              onSubmit={(e) => { e.preventDefault(); fetchCveFeed(cveQuery); }}
              className="flex items-center gap-2"
            >
              <Input
                placeholder="Search NVD CVEs…"
                icon={Search}
                value={cveQuery}
                onChange={(e) => setCveQuery(e.target.value)}
                className="w-44"
                inputClassName="text-xs"
              />
              <Button type="submit" variant="secondary" size="sm" isLoading={cveLoading}>
                Search
              </Button>
            </form>
          }>
            <CardTitle icon={Layers} subtitle="NVD live stream">
              Latest Vulnerabilities (NVD API v2)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {cveFeed.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No CVE data loaded. Try a search.</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {cveFeed.map((cve) => (
                  <div
                    key={cve.cve_id}
                    className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-2 hover:border-cyan-500/40 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-mono text-xs font-bold text-cyan-400">{cve.cve_id}</span>
                        <Badge variant={cve.severity?.toLowerCase() || 'high'} size="sm">
                          CVSS {cve.cvss_score}
                        </Badge>
                      </div>
                      <p className="text-[11px] text-slate-300 line-clamp-3 leading-relaxed">
                        {cve.description}
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>{cve.published_date}</span>
                      <a
                        href={cve.reference_url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        NVD <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quick Reports */}
        <Card className="border-cyan-500/20">
          <CardHeader>
            <CardTitle icon={FileText} subtitle="Quick report access">
              Recent Reports
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {recentReports.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6 font-mono">No reports available.</p>
            ) : (
              recentReports.map((rep) => (
                <div key={rep.id} className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between text-xs">
                  <div className="space-y-0.5 min-w-0 flex-1">
                    <p className="font-mono font-bold text-slate-200 truncate">{rep.target}</p>
                    <p className="text-[10px] font-mono text-slate-400">{rep.id} · {rep.date}</p>
                  </div>
                  <Button
                    size="sm" variant="outline" icon={FileText}
                    onClick={() => navigate(`/reports/${rep.id}`)}
                  >
                    View
                  </Button>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans + Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader action={
            <Button size="sm" variant="ghost" onClick={() => navigate('/history')}>
              View All
            </Button>
          }>
            <CardTitle icon={Server} subtitle="Latest target assessments">
              Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {recentScans.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-8 font-mono">No completed scans available.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Target</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Execution Date</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentScans.map((scan) => (
                    <TableRow key={scan.scan_ref || scan.id}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-200 max-w-40 truncate">
                        {scan.target}
                      </TableCell>
                      <TableCell className="text-xs text-slate-400 flex items-center gap-1.5">
                        <Cloud className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span className="truncate max-w-25">{scan.provider}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={scan.status === 'passed' ? 'success' : scan.status} size="sm">
                          {scan.status.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono font-bold text-xs text-rose-400">
                        {scan.risk_score}
                      </TableCell>
                      <TableCell className="text-xs text-slate-400 font-mono">
                        {formatScanDate(scan.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm" variant="outline"
                          onClick={() => { addToast(`Re-scanning ${scan.target}`, 'info'); navigate('/scanner'); }}
                        >
                          Rescan
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Activity Stream */}
        <Card>
          <CardHeader>
            <CardTitle icon={Activity} subtitle="Real-time SecOps events">
              Activity Stream
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {activityLogs.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-4">No activity logged yet.</p>
            ) : (
              activityLogs.map((act) => {
                const colors = { warning: 'text-amber-400', error: 'text-rose-400', success: 'text-emerald-400', info: 'text-cyan-400' };
                return (
                  <div key={act.id} className="flex items-start gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 text-xs">
                    <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${colors[act.type] || 'text-slate-400'} bg-current`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-slate-300 leading-relaxed line-clamp-2">{act.text}</p>
                      <span className="text-[10px] font-mono text-slate-500">{act.time_ago}</span>
                    </div>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
