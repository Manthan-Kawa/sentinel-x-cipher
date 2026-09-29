import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  BarChart,
  Bar,
} from 'recharts';
import {
  MailCheck,
  ShieldAlert,
  AlertOctagon,
  Search,
  Target,
  Network,
  ArrowUpRight,
  ArrowDownRight,
  Zap,
  Radio,
  Bot,
  ExternalLink,
  Lock,
  Key,
  ShieldCheck,
  CheckCircle2,
  type LucideIcon,
} from 'lucide-react';
import { type Severity, TOP_VULNERABLE_CIPHERS, RECENT_THREATS, type VulnerableCipherSuite } from '@/data/mockData';
import { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import { useAnalysis } from '@/contexts/AnalysisContext';
import { useCampaigns } from '@/contexts/CampaignContext';
import { useEvidence } from '@/contexts/EvidenceContext';
import { useTheme } from '@/context/ThemeContext';

/* ═══════════════════════════════════════════════════════════
   TYPES
═══════════════════════════════════════════════════════════ */
interface ActivityPoint  { hour: string; threats: number; scanned: number; }
interface SparkPoint     { i: number; v: number; }
interface AttackSlice    { name: string; value: number; color: string; }
interface LiveFeedItem   { id: string; severity: Severity; title: string; source: string; time: string; status: string; }

/* ═══════════════════════════════════════════════════════════
   STATIC LOOKUP TABLES
═══════════════════════════════════════════════════════════ */
const ICON_MAP: Record<string, LucideIcon> = {
  MailCheck, ShieldAlert, AlertOctagon, Search, Target, Network,
};

const ACCENT: Record<string, { glow: string; text: string; hex: string; spark: string }> = {
  blue:  { glow: 'none',  text: 'text-blue-400',  hex: '#3b82f6', spark: '#818cf8' },
  teal:  { glow: 'none',  text: 'text-teal-400',  hex: '#14b8a6', spark: '#2dd4bf' },
  red:   { glow: 'none',  text: 'text-red-400',   hex: '#ef4444', spark: '#f87171' },
  amber: { glow: 'none',  text: 'text-amber-400', hex: '#f59e0b', spark: '#fbbf24' },
  green: { glow: 'none',  text: 'text-green-400', hex: '#22c55e', spark: '#4ade80' },
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#3b82f6',
};

const STATUS_CFG: Record<string, { bg: string; text: string; dot: string }> = {
  open:          { bg: 'bg-red-50 dark:bg-red-500/20',    text: 'text-red-700 dark:text-red-400',    dot: 'bg-red-500' },
  investigating: { bg: 'bg-violet-50 dark:bg-violet-500/20', text: 'text-violet-700 dark:text-violet-300', dot: 'bg-violet-500' },
  contained:     { bg: 'bg-amber-50 dark:bg-amber-500/20',  text: 'text-amber-800 dark:text-amber-400',  dot: 'bg-amber-500' },
  resolved:      { bg: 'bg-emerald-50 dark:bg-green-500/20',  text: 'text-emerald-700 dark:text-green-400',  dot: 'bg-emerald-500' },
};

const STATUS_BADGE: Record<string, { bg: string; text: string }> = {
  INVESTIGATING: { bg: 'bg-violet-50 dark:bg-violet-500/25', text: 'text-violet-700 dark:text-violet-300' },
  QUARANTINED:   { bg: 'bg-amber-50 dark:bg-amber-500/25',  text: 'text-amber-800 dark:text-amber-300' },
  ANALYZED:      { bg: 'bg-blue-50 dark:bg-blue-500/25',   text: 'text-blue-700 dark:text-blue-300' },
};

const SEV_BADGE: Record<Severity, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500',    text: 'text-white' },
  high:     { bg: 'bg-orange-500', text: 'text-white' },
  medium:   { bg: 'bg-amber-500',  text: 'text-white' },
  low:      { bg: 'bg-green-500',  text: 'text-white' },
  info:     { bg: 'bg-blue-500',   text: 'text-white' },
};

function now24h(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/* ═══════════════════════════════════════════════════════════
   UI ATOMS
═══════════════════════════════════════════════════════════ */

/* Slide-in entrance */
function SlideIn({ children, delay = 0, direction = 'up', className = '' }: {
  children: React.ReactNode; delay?: number; direction?: 'up'|'left'|'right'|'down'; className?: string;
}) {
  const [vis, setVis] = useState(false);
  useEffect(() => { const t = setTimeout(() => setVis(true), delay); return () => clearTimeout(t); }, [delay]);
  const from = direction === 'left' ? 'translateX(-36px)' : direction === 'right' ? 'translateX(36px)' : direction === 'down' ? 'translateY(-20px)' : 'translateY(28px)';
  return (
    <div className={className} style={{ opacity: vis ? 1 : 0, transform: vis ? 'none' : from, transition: 'opacity .6s cubic-bezier(.22,1,.36,1), transform .6s cubic-bezier(.22,1,.36,1)' }}>
      {children}
    </div>
  );
}

function TiltCard({ children, className = '', style }: { children: React.ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={className} style={style}>
      {children}
    </div>
  );
}

/* Glowing tooltip */
function GlowTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl px-3 py-2.5 text-xs shadow-2xl border border-white/10" style={{ background: 'rgba(6,8,16,0.97)', backdropFilter: 'blur(16px)' }}>
      <p className="text-gray-400 font-mono mb-1.5">{label}</p>
      {payload.map((p: any) => (
        <p key={p.dataKey} className="font-semibold flex items-center gap-1.5" style={{ color: p.color }}>
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          {p.name}: <span className="text-white font-mono">{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</span>
        </p>
      ))}
    </div>
  );
}

/* Static display — animates count-up ONCE on mount, then stays fixed */
function LiveNumber({ value, fmt }: { value: number; fmt: (n: number) => string }) {
  const [disp, setDisp] = useState(0);
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    const dur = 1000; const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - t0) / dur, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisp(value * ease);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value]);
  return <>{fmt(disp)}</>;
}

/* Thinking dots */
function ThinkingDots() {
  return (
    <div className="flex items-center gap-2 justify-center py-4">
      {[0,1,2,3].map(i => (
        <span key={i} className="w-3 h-3 rounded-full"
          style={{ background: i < 3 ? '#a78bfa' : '#374151', animation: `dot-bounce 1.4s ease-in-out ${i * 0.22}s infinite` }} />
      ))}
    </div>
  );
}

/* Live "LIVE" badge with scanning line */
function LiveBadge() {
  return (
    <span className="flex items-center gap-1.5 text-[10px] font-mono text-green-400 uppercase tracking-widest">
      <span className="relative flex w-2 h-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex rounded-full w-2 h-2 bg-green-500" />
      </span>
      LIVE
    </span>
  );
}

/* Hook: elapsed seconds counter */
function useElapsed() {
  const [sec, setSec] = useState(0);
  useEffect(() => { const id = setInterval(() => setSec(s => s + 1), 1000); return () => clearInterval(id); }, []);
  return sec;
}

/* ═══════════════════════════════════════════════════════════
   MAIN DASHBOARD
═══════════════════════════════════════════════════════════ */
export function DashboardPage({ onNavigate }: { onNavigate?: (route: string) => void }) {
  const { isDark } = useTheme();
  const [activeTab, setActiveTab] = useState<'24H' | '7D'>('24H');
  const { analyzedReports, currentResult } = useAnalysis();
  const { campaigns } = useCampaigns();
  const { evidenceList } = useEvidence();
  const elapsed = useElapsed();

  // Dynamic KPI calculations from user data
  const emailCount = analyzedReports.length;
  const threatCount = analyzedReports.filter(
    (r) =>
      r.threat_score >= 50 ||
      (r.verdict && !r.verdict.toLowerCase().includes('legitimate') && !r.verdict.toLowerCase().includes('benign')) ||
      r.alert_level === 'critical' ||
      r.alert_level === 'high'
  ).length;

  const criticalCount = analyzedReports.filter((r) => r.alert_level === 'critical').length;
  const activeCasesCount = analyzedReports.length;
  const avgAccuracy = emailCount > 0
    ? (analyzedReports.reduce((s, r) => s + (r.confidence || 90), 0) / emailCount)
    : 100;
  const campaignCount = campaigns.length;

  const KPI_DEFS = useMemo(() => [
    { label: 'PCAP Sessions Analyzed',     val: emailCount > 0 ? emailCount : 14892, delta: '+8.2%', icon: 'MailCheck', accent: 'blue', fmt: (n: number) => n.toLocaleString() },
    { label: 'Crypto Weaknesses Found',    val: threatCount > 0 ? threatCount : 1247, delta: '+12.4%', icon: 'ShieldAlert', accent: 'red', fmt: (n: number) => n.toLocaleString() },
    { label: 'Critical Vulnerabilities',   val: criticalCount > 0 ? criticalCount : 38, delta: '+3', icon: 'AlertOctagon', accent: 'red', fmt: (n: number) => String(n) },
    { label: 'Active Investigations',      val: activeCasesCount > 0 ? activeCasesCount : 17, delta: '+2', icon: 'Search', accent: 'amber', fmt: (n: number) => String(n) },
    { label: 'Cryptographic Posture Score', val: emailCount > 0 ? Math.max(10, Math.round(100 - (threatCount / emailCount) * 60)) : 61.2, delta: '-2.1%', icon: 'Target', accent: 'green', fmt: (n: number) => typeof n === 'number' ? (n % 1 === 0 ? `${n}%` : `${n.toFixed(1)}%`) : `${n}%` },
    { label: 'TLS Campaigns Active',       val: campaignCount > 0 ? campaignCount : 4, delta: '+1', icon: 'Network', accent: 'teal', fmt: (n: number) => String(n) },
  ], [emailCount, threatCount, criticalCount, activeCasesCount, campaignCount]);

  // Sparklines
  const sparks = useMemo(() => {
    return KPI_DEFS.map((k) => {
      const v = typeof k.val === 'number' ? k.val : 0;
      if (v === 0) {
        return Array.from({ length: 14 }, (_, i) => ({ i, v: 0 }));
      }
      return Array.from({ length: 14 }, (_, i) => ({
        i,
        v: Math.max(0, Math.round(v * (0.85 + 0.15 * Math.sin(i)))),
      }));
    });
  }, [KPI_DEFS]);

  // Activity Area Chart (24H or 7D)
  const activity = useMemo((): ActivityPoint[] => {
    if (activeTab === '7D') {
      const dayLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const now = new Date();
      const multipliers = [0.4, 0.6, 0.5, 0.75, 0.65, 0.85, 1.0];

      return Array.from({ length: 7 }, (_, i) => {
        const d = new Date(now);
        d.setDate(now.getDate() - (6 - i));
        const label = i === 6 ? 'Today' : dayLabels[d.getDay()];
        if (emailCount === 0) {
          return { hour: label, threats: 0, scanned: 0 };
        }
        const mult = multipliers[i];
        const scanned = i === 6 ? emailCount : Math.max(1, Math.round(emailCount * mult));
        const threats = i === 6 ? threatCount : Math.max(0, Math.round(threatCount * mult));
        return {
          hour: label,
          threats,
          scanned,
        };
      });
    }

    // 24H hourly view
    if (emailCount === 0) {
      return Array.from({ length: 24 }, (_, i) => ({
        hour: `${String(i).padStart(2, '0')}:00`,
        threats: 0,
        scanned: 0,
      }));
    }
    return Array.from({ length: 24 }, (_, i) => {
      const isCurrent = i >= 18;
      const scanned = isCurrent ? Math.max(1, Math.round(emailCount / 3)) : 0;
      const threats = isCurrent ? Math.max(0, Math.round(threatCount / 3)) : 0;
      return {
        hour: `${String(i).padStart(2, '0')}:00`,
        threats,
        scanned,
      };
    });
  }, [activeTab, emailCount, threatCount]);

  // TLS Version Distribution (Pie chart showing 60% TLS 1.3, 30% TLS 1.2, 10% TLS 1.0)
  const attack = useMemo((): AttackSlice[] => {
    return [
      { name: 'TLS 1.3', value: 60, color: '#22c55e' },
      { name: 'TLS 1.2', value: 30, color: '#3b82f6' },
      { name: 'TLS 1.0', value: 10, color: '#ef4444' },
    ];
  }, []);

  const totalThreats = 100;

  // Hourly Volume Bars
  const bars = useMemo(() => {
    return Array.from({ length: 12 }, (_, i) => ({
      hour: `${String(i * 2).padStart(2, '0')}h`,
      scanned: emailCount > 0 ? (i >= 8 ? Math.max(1, Math.round(emailCount / 2)) : 0) : 0,
      threats: emailCount > 0 ? (i >= 8 ? Math.max(0, Math.round(threatCount / 2)) : 0) : 0,
    }));
  }, [emailCount, threatCount]);

  // Live Cryptographic Feed derived from user reports or recent sessions
  const feed: LiveFeedItem[] = useMemo(() => {
    if (analyzedReports.length > 0) {
      return analyzedReports.slice(0, 5).map((r, i) => {
        const fromHdr = r.headers?.find((h) => h.key.toLowerCase() === 'from')?.value || r.threat_intel?.domain || 'SMTP Mail Gateway';
        const ip = r.threat_intel?.sending_ip || r.origin?.sending_ip || '185.220.101.47';
        const sev = (r.alert_level || 'info') as Severity;
        const status = r.alert_level === 'critical' ? 'INVESTIGATING' : r.alert_level === 'high' ? 'DOWNGRADED' : 'ANALYZED';

        return {
          id: r.case_id || String(i + 1),
          severity: sev,
          title: r.verdict || 'Cryptographic Posture Assessment',
          source: `${fromHdr} · Peer: ${ip}`,
          time: i === 0 ? 'Latest scan' : `${i * 4}m ago`,
          status,
        };
      });
    }

    return RECENT_THREATS.slice(0, 5).map((t, i) => ({
      id: t.id,
      severity: t.severity,
      title: `${t.threatType}: ${t.cipherSuite}`,
      source: `${t.protocol} · ${t.sourceIP} → ${t.destIP} (${t.tlsVersion})`,
      time: i === 0 ? 'Just now' : `${i * 6}m ago`,
      status: t.status.toUpperCase(),
    }));
  }, [analyzedReports]);

  // Sentinel AI Card Metrics
  const activeAIResult = currentResult || analyzedReports[0] || null;
  const confidence = activeAIResult ? (activeAIResult.confidence || 94) : 94;
  const aiSummary = activeAIResult
    ? (activeAIResult.summary || `${activeAIResult.verdict} detected with ${activeAIResult.confidence}% confidence. Negotiation forced down to deprecated cipher.`)
    : 'Cryptographic posture evaluated: SMTP transmission accepted deprecated TLS 1.0 handshake and broken cipher TLS_RSA_WITH_RC4_128_SHA with an expired self-signed RSA-1024 certificate.';

  const aiMetrics = useMemo(() => {
    if (!activeAIResult) {
      return [
        { label: 'Negotiated TLS',    value: 'TLS 1.0 (Deprecated)',      color: 'text-red-400' },
        { label: 'Cipher Suite',      value: 'RC4-128 (Broken)',          color: 'text-red-400' },
        { label: 'Forward Secrecy',   value: 'Static RSA (None)',         color: 'text-amber-400' },
        { label: 'Certificate State', value: 'Expired / Self-Signed',     color: 'text-red-400' },
        { label: 'Key Strength',      value: 'RSA-1024 (Insecure)',       color: 'text-amber-400' },
        { label: 'Downgrade Risk',    value: 'Critical (MitM Suspected)', color: 'text-red-400' },
      ];
    }

    const isMalicious = activeAIResult.threat_score >= 70;

    return [
      {
        label: 'Negotiated TLS',
        value: isMalicious ? 'TLS 1.0 (Deprecated)' : 'TLS 1.3 (Modern)',
        color: isMalicious ? 'text-red-400' : 'text-green-400',
      },
      {
        label: 'Cipher Suite',
        value: isMalicious ? 'RC4-128 (Broken)' : 'AES-256-GCM (Strong)',
        color: isMalicious ? 'text-red-400' : 'text-green-400',
      },
      {
        label: 'Forward Secrecy',
        value: isMalicious ? 'Static RSA (None)' : 'ECDHE (Active)',
        color: isMalicious ? 'text-amber-400' : 'text-green-400',
      },
      {
        label: 'Certificate State',
        value: isMalicious ? 'Expired / Self-Signed' : 'Valid CA Chain',
        color: isMalicious ? 'text-red-400' : 'text-green-400',
      },
      {
        label: 'Key Strength',
        value: isMalicious ? 'RSA-1024 (Insecure)' : 'RSA-2048 (Standard)',
        color: isMalicious ? 'text-amber-400' : 'text-green-400',
      },
      {
        label: 'Downgrade Risk',
        value: isMalicious ? 'Critical Risk' : 'Low Risk',
        color: isMalicious ? 'text-red-400' : 'text-green-400',
      },
    ];
  }, [activeAIResult]);

  return (
    <div className="space-y-4" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

      {/* ── global keyframes injected once ── */}
      <style>{`
        @keyframes dot-bounce {
          0%, 80%, 100% { transform: scale(0.7); opacity:.5; }
          40%            { transform: scale(1.1); opacity:1; }
        }
        @keyframes row-flash {
          0%   { background: rgba(139,92,246,0.18); }
          100% { background: transparent; }
        }
        @keyframes scan-line {
          0%   { transform: translateY(0); opacity:.8; }
          50%  { transform: translateY(100%); opacity:.3; }
          100% { transform: translateY(0); opacity:.8; }
        }
        @keyframes fadeInUp {
          from { opacity:0; transform:translateY(12px); }
          to   { opacity:1; transform:translateY(0); }
        }
      `}</style>

      {/* ── Header ── */}
      <SlideIn delay={0} direction="down">
        <div className="relative rounded-2xl overflow-hidden px-4 sm:px-6 py-4 sm:py-5"
          style={{ background: isDark ? 'linear-gradient(135deg,#0a0c14,#0f1520 60%,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 4px 40px rgba(0,0,0,0.6)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: isDark ? 'linear-gradient(rgba(255,255,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.025) 1px,transparent 1px)' : 'none', backgroundSize:'48px 48px' }} />
          <div className="absolute -top-10 right-24 w-44 h-44 rounded-full pointer-events-none" style={{ background:'radial-gradient(circle,rgba(59,130,246,0.07),transparent 70%)' }} />

          <div className="relative z-10 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
            <div>
              <h2 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">Threat Operations Center</h2>
              <p className="text-xs sm:text-sm text-slate-500 dark:text-gray-400 mt-0.5">Real-time visibility into email threats, investigations, campaigns, and forensic activity.</p>
              <div className="flex items-center gap-2 mt-2">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                <span className="text-[11px] text-slate-400 dark:text-gray-500 font-mono">
                  Last updated {elapsed}s ago &nbsp;·&nbsp; {now24h()}
                </span>
              </div>
            </div>
            {/* LIVE MONITORING */}
            <div className="flex items-center gap-3 px-3.5 sm:px-4 py-2 sm:py-2.5 rounded-xl shrink-0 self-start"
              style={{ background: isDark ? 'linear-gradient(135deg,rgba(34,197,94,0.2),rgba(21,128,61,0.1))' : 'rgba(34,197,94,0.1)', border:'1px solid rgba(34,197,94,0.35)' }}>
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse" style={{ boxShadow:'0 0 8px rgba(34,197,94,0.9)' }} />
              <div>
                <p className="text-xs font-bold text-green-600 dark:text-green-400 uppercase tracking-wider leading-none">LIVE MONITORING</p>
                <p className="text-[10px] text-green-700/70 dark:text-green-400/70 mt-0.5">Active</p>
              </div>
            </div>
          </div>
        </div>
      </SlideIn>

      {/* ── KPI Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5 sm:gap-3">
        {KPI_DEFS.map((kpi, i) => {
          const Icon = ICON_MAP[kpi.icon];
          const ac   = ACCENT[kpi.accent] ?? ACCENT.blue;
          const isUp = true;
          return (
            <SlideIn key={kpi.label} delay={100 + i * 65} direction="up">
              <div
                className="relative rounded-2xl overflow-hidden p-3 sm:p-4"
                style={{ background: isDark ? `linear-gradient(145deg,${i%2===0?'#0e1525':'#0c1020'},#070a12)` : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 4px 20px rgba(0,0,0,0.35)' : '0 1px 3px rgba(0,0,0,0.05)', minHeight: 145 }}>
                {/* icon + delta */}
                <div className="flex items-start justify-between mb-2">
                  <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-xl flex items-center justify-center" style={{ background:`${ac.hex}22`, border:`1px solid ${ac.hex}35` }}>
                    {Icon && <Icon className={`w-3.5 h-3.5 sm:w-4 sm:h-4 ${ac.text}`} />}
                  </div>
                  <span className={`flex items-center gap-0.5 text-[10px] sm:text-[11px] font-bold ${isUp ? 'text-green-500 dark:text-green-400' : 'text-red-500 dark:text-red-400'}`}>
                    {isUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                    {kpi.delta}
                  </span>
                </div>

                {/* live value */}
                <p className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight mt-1">
                  <LiveNumber value={typeof kpi.val === 'number' ? kpi.val : 0} fmt={kpi.fmt} />
                </p>
                <p className="text-[10px] sm:text-[11px] text-slate-500 dark:text-gray-400 font-medium mt-0.5 truncate">{kpi.label}</p>

                {/* live sparkline */}
                <div className="mt-2 -mx-1">
                  <ResponsiveContainer width="100%" height={38}>
                    <LineChart data={sparks[i]} margin={{ top:3, right:2, left:2, bottom:0 }}>
                      <Line type="monotoneX" dataKey="v" stroke={ac.spark} strokeWidth={2} dot={false}
                        isAnimationActive animationDuration={1200} animationEasing="ease-in-out" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </SlideIn>
          );
        })}
      </div>

      {/* ── Threat Activity + Attack Surface ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

        {/* Area chart — live sliding window */}
        <SlideIn delay={520} direction="left" className="lg:col-span-3">
          <div className="rounded-2xl p-5 h-full" style={{ background: isDark ? 'linear-gradient(145deg,#090c14,#0c1020)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.5)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-2 mb-0.5">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Cryptographic Traffic Activity</h3>
                  <LiveBadge />
                </div>
                <p className="text-[11px] text-slate-500 dark:text-gray-400">
                  {activeTab === '24H' ? '24-hour TLS session telemetry · protocol posture' : '7-day trend analysis · protocol security posture'}
                </p>
              </div>
              <div className="flex items-center rounded-lg overflow-hidden" style={{ border: isDark ? '1px solid rgba(255,255,255,0.1)' : '1px solid #e2e8f0' }}>
                {(['24H','7D'] as const).map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={`px-3 py-1.5 text-[11px] font-bold transition-all duration-200 ${activeTab===tab ? (isDark ? 'text-white' : 'text-purple-700 bg-purple-50') : (isDark ? 'text-gray-500 hover:text-gray-300' : 'text-slate-500 hover:text-slate-800')}`}
                    style={activeTab===tab && isDark ? { background:'rgba(139,92,246,0.4)' } : {}}>
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            {/* legend */}
            <div className="flex items-center gap-4 text-[11px] mb-3">
              {[{color:'#06b6d4',label:'Sessions Analyzed'},{color:'#8b5cf6',label:'Crypto Weaknesses'}].map(l => (
                <span key={l.label} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background:l.color, boxShadow:`0 0 5px ${l.color}` }} />
                  <span className="text-slate-600 dark:text-gray-400">{l.label}</span>
                </span>
              ))}
            </div>

            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={activity} margin={{ top:8, right:4, left:-22, bottom:0 }}>
                <defs>
                  <linearGradient id="lGradCyan" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="lGradPurple" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.02} />
                  </linearGradient>
                  <filter id="glowCyan">
                    <feGaussianBlur stdDeviation="3" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                  </filter>
                </defs>
                <CartesianGrid strokeDasharray="2 6" stroke={isDark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.05)"} vertical={false} />
                <XAxis dataKey="hour" tick={{ fill: isDark ? '#4b5563' : '#64748b', fontSize:10, fontFamily:"'Inter', sans-serif" }} axisLine={false} tickLine={false} interval={activeTab === '24H' ? 3 : 0} />
                <YAxis tick={{ fill: isDark ? '#4b5563' : '#64748b', fontSize:10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<GlowTooltip />} />
                <Area type="monotone" dataKey="scanned" stroke="#06b6d4" strokeWidth={2.5}
                  fill="url(#lGradCyan)" name="Sessions Analyzed" filter="url(#glowCyan)"
                  isAnimationActive animationDuration={1200} animationEasing="ease-in-out" />
                <Area type="monotone" dataKey="threats" stroke="#8b5cf6" strokeWidth={2.5}
                  fill="url(#lGradPurple)" name="Crypto Weaknesses"
                  isAnimationActive animationDuration={1200} animationEasing="ease-in-out" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </SlideIn>

        {/* TLS Version Distribution donut */}
        <SlideIn delay={600} direction="right" className="lg:col-span-2">
          <div className="rounded-2xl p-5 h-full flex flex-col justify-between" style={{ background: isDark ? 'linear-gradient(145deg,#090c14,#0c1020)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.5)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">TLS Version Distribution</h3>
                <p className="text-[11px] text-slate-500 dark:text-gray-400 mt-0.5">Observed protocol versions across email sessions</p>
              </div>
              <LiveBadge />
            </div>

            <div className="relative flex items-center justify-center my-auto" style={{ height:180 }}>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <defs>
                    <filter id="pieGlow">
                      <feGaussianBlur stdDeviation="3" result="blur"/>
                      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                  </defs>
                  <Pie data={attack} cx="50%" cy="50%" innerRadius={52} outerRadius={82}
                    paddingAngle={3} dataKey="value" startAngle={90} endAngle={-270}
                    isAnimationActive animationDuration={1200} animationEasing="ease-in-out" strokeWidth={0}>
                    {attack.map((entry, i) => (
                      <Cell key={i} fill={entry.color} style={{ filter:`drop-shadow(0 0 5px ${entry.color}80)` }} />
                    ))}
                  </Pie>
                  <Tooltip content={<GlowTooltip />} formatter={(v:any,n:any) => [`${Number(v)}%`, n]} />
                </PieChart>
              </ResponsiveContainer>
              {/* center label */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-xl font-black text-slate-900 dark:text-white">100%</span>
                <span className="text-[8px] text-slate-400 dark:text-gray-500 font-mono uppercase tracking-widest mt-0.5">TLS TRAFFIC</span>
              </div>
            </div>

            {/* legend */}
            <div className="grid grid-cols-3 gap-2 mt-2">
              {attack.map(s => (
                <div key={s.name} className="flex flex-col items-center text-center p-2 rounded-xl bg-slate-50 dark:bg-white/[0.03] border border-slate-200/60 dark:border-white/5">
                  <span className="flex items-center gap-1.5 text-[11px]">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background:s.color, boxShadow:`0 0 4px ${s.color}` }} />
                    <span className="text-slate-700 dark:text-gray-300 font-semibold">{s.name}</span>
                  </span>
                  <span className="text-slate-900 dark:text-white font-mono font-bold text-xs mt-1">{s.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </SlideIn>
      </div>

      {/* ── Volume Bar Chart + Live Feed + Sentinel AI ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

        {/* Volume bars + live feed stacked */}
        <div className="lg:col-span-3 flex flex-col gap-4">

          {/* Hourly Volume Bar Chart — live */}
          <SlideIn delay={680} direction="left">
            <div className="rounded-2xl p-5" style={{ background: isDark ? 'linear-gradient(145deg,#09090f,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.45)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">Hourly Session Volume</h3>
                    <LiveBadge />
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-gray-400 mt-0.5">Total sessions vs. crypto weaknesses</p>
                </div>
                <div className="flex items-center gap-3 text-[11px]">
                  {[{c:'#3b82f680',l:'Sessions'},{c:'#ef444480',l:'Weaknesses'}].map(x => (
                    <span key={x.l} className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded" style={{ background:x.c }} />
                      <span className="text-slate-600 dark:text-gray-400">{x.l}</span>
                    </span>
                  ))}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={110}>
                <BarChart data={bars} margin={{ top:2, right:0, left:-20, bottom:0 }} barGap={2}>
                  <CartesianGrid strokeDasharray="2 6" stroke={isDark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.05)"} vertical={false} />
                  <XAxis dataKey="hour" tick={{ fill: isDark ? '#4b5563' : '#64748b', fontSize:9, fontFamily:"'Inter', sans-serif" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: isDark ? '#4b5563' : '#64748b', fontSize:9 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<GlowTooltip />} />
                  <Bar dataKey="scanned" name="Sessions" fill="#3b82f680" radius={[3,3,0,0]} isAnimationActive animationDuration={1200} animationEasing="ease-in-out" />
                  <Bar dataKey="threats"  name="Weaknesses" fill="#ef444480" radius={[3,3,0,0]} isAnimationActive animationDuration={1200} animationEasing="ease-in-out" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </SlideIn>

          {/* Live Threat Feed */}
          <SlideIn delay={750} direction="left">
            <div className="rounded-2xl p-5 flex-1" style={{ background: isDark ? 'linear-gradient(145deg,#09090f,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.45)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-red-500 dark:text-red-400" style={{ filter:'drop-shadow(0 0 4px rgba(239,68,68,.8))' }} />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Live Cryptographic Posture Feed</h3>
                  <LiveBadge />
                </div>
                <button onClick={() => onNavigate?.('email-analyzer')}
                  className="flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:text-blue-500 transition-colors font-medium">
                  Analyze PCAP <ExternalLink className="w-3 h-3" />
                </button>
              </div>

              <div className="space-y-2">
                {feed.length === 0 ? (
                  <div className="text-center py-6 text-xs text-slate-400 dark:text-gray-500 font-mono">
                    No posture events recorded. Ingest a PCAP in Analyzer to populate live telemetry.
                  </div>
                ) : (
                  feed.map((item) => {
                    const sevBadge  = SEV_BADGE[item.severity] || SEV_BADGE.info;
                    const statBadge = STATUS_BADGE[item.status] ?? STATUS_BADGE.ANALYZED;
                    return (
                      <div key={`${item.id}-${item.time}`}
                        onClick={() => onNavigate?.('header-forensics')}
                        className="flex items-start gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all duration-300 hover:bg-slate-100/80 dark:hover:bg-white/[0.055]"
                        style={{
                          background: isDark ? 'rgba(255,255,255,0.03)' : '#f8fafc',
                          border: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid #e2e8f0',
                          transition: 'background .4s, border-color .4s',
                        }}
                      >
                        {/* dot */}
                        <span className="shrink-0 mt-1 w-2 h-2 rounded-full"
                          style={{ background:SEV_COLOR[item.severity] || '#3b82f6', boxShadow:`0 0 7px ${SEV_COLOR[item.severity] || '#3b82f6'}` }} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${sevBadge.bg} ${sevBadge.text}`}>{item.severity}</span>
                            <span className="text-xs font-semibold text-slate-900 dark:text-white truncate">{item.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-500 dark:text-gray-400 truncate">{item.source}</p>
                        </div>
                        <div className="shrink-0 flex flex-col items-end gap-1.5">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase ${statBadge.bg} ${statBadge.text}`}>{item.status}</span>
                          <span className="text-[10px] text-slate-400 dark:text-gray-600 font-mono">{item.time}</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </SlideIn>
        </div>

        {/* Sentinel AI */}
        <SlideIn delay={820} direction="right" className="lg:col-span-2">
          <div className="rounded-2xl p-5 h-full"
            style={{ background: isDark ? 'linear-gradient(145deg,#09090f,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.5)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
            {/* header */}
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                style={{ background:'rgba(139,92,246,0.2)', border:'1px solid rgba(139,92,246,0.4)' }}>
                <Bot className="w-4 h-4 text-violet-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900 dark:text-white tracking-wide">SENTINEL AI</p>
                <p className="text-[10px] text-slate-500 dark:text-gray-400">Autonomous cryptographic posture assistant</p>
              </div>
            </div>

            <ThinkingDots />

            <div className="rounded-xl px-4 py-3 mb-4 text-xs text-slate-700 dark:text-gray-300 leading-relaxed min-h-[50px]"
              style={{ background: isDark ? 'rgba(255,255,255,0.04)' : '#f8fafc', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0' }}>
              {aiSummary}
            </div>

            {/* live confidence */}
            <div className="mb-3">
              <p className="text-[10px] text-slate-500 dark:text-gray-400 uppercase tracking-widest mb-1 font-mono">POSTURE CONFIDENCE</p>
              <p className="text-3xl font-black transition-all duration-700"
                style={{ background:'linear-gradient(135deg,#a78bfa,#c084fc)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent', filter:'drop-shadow(0 0 10px rgba(167,139,250,.4))' }}>
                {confidence > 0 ? `${confidence.toFixed(1)}%` : '—'}
              </p>
            </div>

            <div className="space-y-1.5 mb-5">
              {aiMetrics.map(m => (
                <div key={m.label} className="flex items-center justify-between text-[11px] py-0.5 border-b border-slate-100 dark:border-white/5 last:border-0">
                  <span className="text-slate-500 dark:text-gray-400">{m.label}</span>
                  <span className={`font-semibold ${m.color}`}>{m.value}</span>
                </div>
              ))}
            </div>

            <button onClick={() => onNavigate?.('email-analyzer')}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold text-white transition-transform duration-150 ease-out active:scale-95 cursor-pointer"
              style={{ background: 'linear-gradient(135deg, #3b82f6, #6366f1)', boxShadow: '0 4px 20px rgba(59, 130, 246, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.1) inset' }}>
              <Zap className="w-4 h-4" />
              Inspect In PCAP Analyzer
            </button>
          </div>
        </SlideIn>
      </div>

      {/* ── Top Vulnerable Cipher Suites ── */}
      <SlideIn delay={880} direction="up">
        <div className="rounded-2xl p-5" style={{ background: isDark ? 'linear-gradient(145deg,#09090f,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.45)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-amber-500/10 border border-amber-500/25 text-amber-500">
                <Lock className="w-3.5 h-3.5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">Top Vulnerable Cipher Suites</h3>
                <p className="text-[11px] text-slate-500 dark:text-gray-400 mt-0.5">Most frequent insecure or deprecated ciphers observed in network captures</p>
              </div>
            </div>
            <button onClick={() => onNavigate?.('threat-intelligence')}
              className="flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:text-blue-500 transition-colors font-medium">
              Certificate Vault <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
            {TOP_VULNERABLE_CIPHERS.map((c) => {
              const isCrit = c.severity === 'critical';
              const isHigh = c.severity === 'high';
              const colorClass = isCrit
                ? 'text-red-500 border-red-500/30 bg-red-500/10'
                : isHigh
                ? 'text-orange-500 border-orange-500/30 bg-orange-500/10'
                : 'text-amber-500 border-amber-500/30 bg-amber-500/10';

              return (
                <div
                  key={c.cipherSuite}
                  className="rounded-xl p-3.5 flex flex-col justify-between transition-all duration-200 hover:scale-[1.01]"
                  style={{
                    background: isDark ? 'rgba(255,255,255,0.025)' : '#f8fafc',
                    border: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid #e2e8f0',
                  }}
                >
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-2">
                      <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-gray-500">#{c.rank}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${colorClass}`}>
                        {c.severity}
                      </span>
                    </div>
                    <p className="text-xs font-mono font-bold text-slate-900 dark:text-white break-all leading-tight mb-1.5" title={c.cipherSuite}>
                      {c.cipherSuite}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-gray-400 line-clamp-2 leading-snug">
                      {c.vulnerability}
                    </p>
                  </div>

                  <div className="mt-3 pt-2 border-t border-slate-200/60 dark:border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-400 dark:text-gray-500">
                    <span className="font-semibold text-slate-600 dark:text-gray-400">{c.rfc}</span>
                    <span className="text-slate-900 dark:text-white font-bold">{c.sessionCount} sessions</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </SlideIn>

      {/* ── Recent Threats Table ── */}
      <SlideIn delay={950} direction="up">
        <div className="rounded-2xl p-5" style={{ background: isDark ? 'linear-gradient(145deg,#09090f,#0c0e18)' : '#ffffff', border: isDark ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e2e8f0', boxShadow: isDark ? '0 8px 32px rgba(0,0,0,0.4)' : '0 1px 3px rgba(0,0,0,0.05)' }}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Recent Cryptographic Posture Detections</h3>
              <p className="text-[11px] text-slate-500 dark:text-gray-400 mt-0.5">Active TLS downgrade attacks, weak ciphers, and certificate validation failures</p>
            </div>
            <button onClick={() => onNavigate?.('email-analyzer')}
              className="flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:text-blue-500 transition-colors font-medium">
              Analyze New PCAP <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full min-w-[540px] md:min-w-0">
              <thead>
                <tr style={{ borderBottom: isDark ? '1px solid rgba(255,255,255,0.06)' : '1px solid #e2e8f0' }}>
                  {['Session ID','Protocol / Peer','Cipher Suite','Threat Type','Severity','Risk Score','Status'].map(h => (
                    <th key={h} className="text-[10px] font-semibold text-slate-400 dark:text-gray-500 uppercase tracking-wider text-left py-3 px-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {analyzedReports.length > 0 ? (
                  analyzedReports.slice(0, 8).map((r, i) => {
                    const fromHdr = r.headers?.find(h => h.key.toLowerCase() === 'from')?.value || r.threat_intel?.domain || 'SMTP Mail Gateway';
                    const sev = (r.alert_level || 'info') as Severity;
                    const status = r.alert_level === 'critical' ? 'investigating' : r.alert_level === 'high' ? 'open' : 'resolved';
                    const st = STATUS_CFG[status] ?? STATUS_CFG.open;

                    return (
                      <tr key={r.case_id || i} onClick={() => onNavigate?.('header-forensics')}
                        className="cursor-pointer transition-colors duration-150"
                        style={{ borderBottom: isDark ? '1px solid rgba(255,255,255,0.04)' : '1px solid #f1f5f9', animation:`fadeInUp .4s ease-out ${i*70}ms both` }}
                        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = isDark ? 'rgba(255,255,255,0.035)' : '#f8fafc'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                        <td className="py-3.5 px-3 text-xs font-mono text-blue-600 dark:text-blue-400 font-bold">{r.case_id}</td>
                        <td className="py-3.5 px-3 text-xs text-slate-800 dark:text-gray-300 max-w-[160px] truncate" title={fromHdr}>{fromHdr}</td>
                        <td className="py-3.5 px-3 text-xs font-mono text-slate-500 dark:text-gray-400 truncate max-w-[180px]">TLS_RSA_WITH_RC4_128_SHA</td>
                        <td className="py-3.5 px-3 text-xs text-slate-500 dark:text-gray-400 hidden md:table-cell">{r.verdict}</td>
                        <td className="py-3.5 px-3 hidden lg:table-cell">
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                            style={{ background:`${SEV_COLOR[sev]}22`, color:SEV_COLOR[sev], border:`1px solid ${SEV_COLOR[sev]}44` }}>
                            <span className="w-1.5 h-1.5 rounded-full" style={{ background:SEV_COLOR[sev] }} />
                            {sev}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 hidden lg:table-cell">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-white/5 overflow-hidden w-16">
                              <div className="h-full rounded-full transition-all duration-1000"
                                style={{ width:`${r.threat_score}%`, background:`linear-gradient(90deg,${r.threat_score>80?'#ef4444':'#f59e0b'},${r.threat_score>80?'#f97316':'#fbbf24'})`, boxShadow:`0 0 6px ${r.threat_score>80?'rgba(239,68,68,.5)':'rgba(245,158,11,.5)'}` }} />
                            </div>
                            <span className="text-xs font-mono text-slate-900 dark:text-white font-bold">{r.threat_score}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-3">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold ${st.bg} ${st.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                            {status}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  RECENT_THREATS.map((t, i) => {
                    const sev = t.severity;
                    const st = STATUS_CFG[t.status] ?? STATUS_CFG.open;
                    return (
                      <tr key={t.id} onClick={() => onNavigate?.('header-forensics')}
                        className="cursor-pointer transition-colors duration-150"
                        style={{ borderBottom: isDark ? '1px solid rgba(255,255,255,0.04)' : '1px solid #f1f5f9', animation:`fadeInUp .4s ease-out ${i*70}ms both` }}
                        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = isDark ? 'rgba(255,255,255,0.035)' : '#f8fafc'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}>
                        <td className="py-3.5 px-3 text-xs font-mono text-blue-600 dark:text-blue-400 font-bold">{t.id}</td>
                        <td className="py-3.5 px-3 text-xs text-slate-800 dark:text-gray-300">
                          <span className="font-semibold text-slate-900 dark:text-white">{t.protocol}</span>
                          <span className="text-slate-400 dark:text-gray-500 font-mono text-[11px] block">{t.sourceIP} → {t.destIP}</span>
                        </td>
                        <td className="py-3.5 px-3 text-xs font-mono text-slate-700 dark:text-gray-300">
                          <span className="font-bold text-slate-900 dark:text-white">{t.tlsVersion}</span>
                          <span className="text-slate-400 dark:text-gray-500 text-[10px] block truncate max-w-[170px]" title={t.cipherSuite}>{t.cipherSuite}</span>
                        </td>
                        <td className="py-3.5 px-3 text-xs text-slate-700 dark:text-gray-300 hidden md:table-cell">
                          <span className="font-medium">{t.threatType}</span>
                        </td>
                        <td className="py-3.5 px-3 hidden lg:table-cell">
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                            style={{ background:`${SEV_COLOR[sev]}22`, color:SEV_COLOR[sev], border:`1px solid ${SEV_COLOR[sev]}44` }}>
                            <span className="w-1.5 h-1.5 rounded-full" style={{ background:SEV_COLOR[sev] }} />
                            {sev}
                          </span>
                        </td>
                        <td className="py-3.5 px-3 hidden lg:table-cell">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-white/5 overflow-hidden w-16">
                              <div className="h-full rounded-full transition-all duration-1000"
                                style={{ width:`${t.riskScore}%`, background:`linear-gradient(90deg,${t.riskScore>80?'#ef4444':'#f59e0b'},${t.riskScore>80?'#f97316':'#fbbf24'})`, boxShadow:`0 0 6px ${t.riskScore>80?'rgba(239,68,68,.5)':'rgba(245,158,11,.5)'}` }} />
                            </div>
                            <span className="text-xs font-mono text-slate-900 dark:text-white font-bold">{t.riskScore}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-3">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold ${st.bg} ${st.text}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                            {t.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </SlideIn>

    </div>
  );
}
