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
} from 'recharts';
import {
  MailCheck,
  ShieldAlert,
  AlertOctagon,
  Target,
  ArrowUpRight,
  ArrowDownRight,
  ExternalLink,
  Lock,
  Activity,
  type LucideIcon,
} from 'lucide-react';
import { type Severity, TOP_VULNERABLE_CIPHERS, RECENT_THREATS } from '@/data/mockData';
import { useRef, useEffect, useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useAnalysis } from '@/contexts/AnalysisContext';
import { useTheme } from '@/context/ThemeContext';

/* ═══════════════════════════════════════════════════════════
   TYPES & LOOKUPS
   ═══════════════════════════════════════════════════════════ */
interface ActivityPoint { hour: string; threats: number; scanned: number; }
interface AttackSlice   { name: string; value: number; color: string; }

const ICON_MAP: Record<string, LucideIcon> = {
  MailCheck,
  ShieldAlert,
  AlertOctagon,
  Target,
};

function now24h(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/* ═══════════════════════════════════════════════════════════
   CLEAN SOLID BADGE COMPONENT (Like Image 5)
   ═══════════════════════════════════════════════════════════ */
function SolidBadge({
  label,
  variant,
}: {
  label: string;
  variant: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'open' | 'investigating' | 'resolved' | 'contained';
}) {
  const textColors: Record<string, string> = {
    critical:      'text-red-600 dark:text-red-400',
    high:          'text-orange-600 dark:text-orange-400',
    medium:        'text-amber-600 dark:text-amber-400',
    low:           'text-emerald-600 dark:text-emerald-400',
    info:          'text-blue-600 dark:text-blue-400',
    open:          'text-red-600 dark:text-red-400',
    investigating: 'text-indigo-600 dark:text-indigo-400',
    resolved:      'text-emerald-600 dark:text-emerald-400',
    contained:     'text-amber-600 dark:text-amber-400',
  };

  const style = textColors[variant.toLowerCase()] || 'text-gray-500 dark:text-gray-400';

  return (
    <span
      className={`inline-flex items-center text-[10px] font-black font-mono uppercase tracking-wider select-none ${style}`}
    >
      {label}
    </span>
  );
}

/* ═══════════════════════════════════════════════════════════
   ANIMATION & ATOMS
   ═══════════════════════════════════════════════════════════ */
function SlideIn({
  children,
  delay = 0,
  direction = 'up',
  className = '',
}: {
  children: React.ReactNode;
  delay?: number;
  direction?: 'up' | 'left' | 'right' | 'down';
  className?: string;
}) {
  const [vis, setVis] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVis(true), delay);
    return () => clearTimeout(t);
  }, [delay]);
  const from =
    direction === 'left'
      ? 'translateX(-24px)'
      : direction === 'right'
      ? 'translateX(24px)'
      : direction === 'down'
      ? 'translateY(-16px)'
      : 'translateY(20px)';
  return (
    <div
      className={className}
      style={{
        opacity: vis ? 1 : 0,
        transform: vis ? 'none' : from,
        transition: 'opacity .5s cubic-bezier(.22,1,.36,1), transform .5s cubic-bezier(.22,1,.36,1)',
      }}
    >
      {children}
    </div>
  );
}

function CleanTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl px-3.5 py-2.5 text-xs shadow-xl bg-zinc-900 text-white border border-zinc-700/70">
      <p className="text-zinc-400 font-mono mb-1.5 font-medium">{label}</p>
      {payload.map((p: any) => (
        <p key={p.dataKey} className="font-semibold flex items-center gap-2" style={{ color: p.color }}>
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          {p.name}: <span className="text-white font-mono">{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</span>
        </p>
      ))}
    </div>
  );
}

function LiveNumber({ value, fmt }: { value: number; fmt: (n: number) => string }) {
  const [disp, setDisp] = useState(0);
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    const dur = 800;
    const t0 = performance.now();
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

function useElapsed() {
  const [sec, setSec] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setSec((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return sec;
}

/* ═══════════════════════════════════════════════════════════
   MAIN DASHBOARD COMPONENT
   ═══════════════════════════════════════════════════════════ */
export function DashboardPage({ onNavigate }: { onNavigate?: (route: string) => void }) {
  const { isDark } = useTheme();
  const [activeTab, setActiveTab] = useState<'24H' | '7D'>('24H');
  const { analyzedReports } = useAnalysis();
  const elapsed = useElapsed();

  // Dynamic KPI calculations from active data
  const emailCount = analyzedReports.length;
  const threatCount = analyzedReports.filter(
    (r) =>
      r.threat_score >= 50 ||
      (r.verdict && !r.verdict.toLowerCase().includes('legitimate') && !r.verdict.toLowerCase().includes('benign')) ||
      r.alert_level === 'critical' ||
      r.alert_level === 'high'
  ).length;

  const criticalCount = analyzedReports.filter((r) => r.alert_level === 'critical').length;

  const KPI_DEFS = useMemo(
    () => [
      {
        label: 'PCAP Sessions Analyzed',
        val: emailCount > 0 ? emailCount : 14892,
        delta: '+8.2%',
        isUp: true,
        icon: 'MailCheck',
        accentColor: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
        fmt: (n: number) => n.toLocaleString(),
      },
      {
        label: 'Crypto Weaknesses Found',
        val: threatCount > 0 ? threatCount : 1247,
        delta: '+12.4%',
        isUp: true,
        icon: 'ShieldAlert',
        accentColor: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
        fmt: (n: number) => n.toLocaleString(),
      },
      {
        label: 'Critical Vulnerabilities',
        val: criticalCount > 0 ? criticalCount : 38,
        delta: '+3',
        isUp: true,
        icon: 'AlertOctagon',
        accentColor: 'text-red-500 bg-red-500/10 border-red-500/20',
        fmt: (n: number) => String(n),
      },
      {
        label: 'Cryptographic Posture Score',
        val: emailCount > 0 ? Math.max(10, Math.round(100 - (threatCount / emailCount) * 60)) : 61.2,
        delta: '-2.1%',
        isUp: false,
        icon: 'Target',
        accentColor: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20',
        fmt: (n: number) => (typeof n === 'number' ? (n % 1 === 0 ? `${n}%` : `${n.toFixed(1)}%`) : `${n}%`),
      },
    ],
    [emailCount, threatCount, criticalCount]
  );

  // Realistic, smooth traffic chart distribution
  const activity = useMemo((): ActivityPoint[] => {
    if (activeTab === '7D') {
      const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      const baseScanned = emailCount > 0 ? emailCount : 240;
      const baseThreats = threatCount > 0 ? threatCount : 48;
      const multipliers = [0.65, 0.82, 0.74, 0.91, 0.88, 0.55, 1.0];

      return days.map((day, idx) => ({
        hour: day,
        scanned: Math.max(1, Math.round(baseScanned * multipliers[idx])),
        threats: Math.max(0, Math.round(baseThreats * multipliers[idx])),
      }));
    }

    // 24H realistic curve
    const hours = ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'];
    const curveScanned = [12, 8, 22, 68, 85, 94, 110, 72];
    const curveThreats = [2, 1, 4, 14, 19, 21, 26, 15];
    const scale = emailCount > 0 ? Math.max(1, Math.round(emailCount / 8)) : 1;
    const threatScale = threatCount > 0 ? Math.max(1, Math.round(threatCount / 8)) : 1;

    return hours.map((h, i) => ({
      hour: h,
      scanned: emailCount > 0 ? Math.round(curveScanned[i] * 0.1 * scale) : curveScanned[i],
      threats: threatCount > 0 ? Math.round(curveThreats[i] * 0.1 * threatScale) : curveThreats[i],
    }));
  }, [activeTab, emailCount, threatCount]);

  // TLS Version Distribution
  const attack = useMemo((): AttackSlice[] => {
    return [
      { name: 'TLS 1.3', value: 60, color: '#3b82f6' },
      { name: 'TLS 1.2', value: 30, color: '#8b5cf6' },
      { name: 'TLS 1.0', value: 10, color: '#f43f5e' },
    ];
  }, []);

  return (
    <div className="space-y-4 max-w-7xl mx-auto pb-10" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
      {/* ── 1. Header Card ── */}
      <SlideIn delay={0} direction="down">
        <div className="rounded-2xl p-5 sm:p-6 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm transition-colors">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl sm:text-2xl font-black text-gray-900 dark:text-zinc-100 tracking-tight">
                  Threat Operations Center
                </h1>
              </div>
              <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400 mt-1">
                Real-time visibility into email threats, investigations, campaigns, and forensic activity.
              </p>
              <div className="flex items-center gap-2 mt-2.5 text-[11px] text-gray-500 dark:text-gray-400 font-mono">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>Last updated {elapsed}s ago · {now24h()}</span>
              </div>
            </div>

            {/* Live Monitoring Badge (Image 4 & 5 solid pill style) */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-600 text-white shadow-sm shrink-0 self-start sm:self-center">
              <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
              <span className="text-xs font-bold font-mono uppercase tracking-wider">LIVE MONITORING</span>
            </div>
          </div>
        </div>
      </SlideIn>

      {/* ── 2. KPI Cards ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {KPI_DEFS.map((kpi, i) => {
          const Icon = ICON_MAP[kpi.icon];

          return (
            <SlideIn key={kpi.label} delay={80 + i * 50} direction="up">
              <div className="rounded-2xl p-4 sm:p-5 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm transition-all duration-200 flex flex-col justify-between h-full">
                <div>
                  <div className="flex items-center justify-between gap-2 mb-3">
                    {/* Squircle icon container (White in dark mode, light blue-white in light mode with blue icon) */}
                    <div className="w-10 h-10 rounded-2xl flex items-center justify-center bg-[#edf5ff] dark:bg-white border border-blue-100 dark:border-white text-blue-600 dark:text-blue-600 shadow-sm transition-colors">
                      {Icon && <Icon className="w-5 h-5 stroke-[2.2]" />}
                    </div>
                    {/* Delta percentage indicator (Only colored text, no background cube/pill) */}
                    <span
                      className={`inline-flex items-center gap-0.5 text-xs font-bold font-mono ${
                        kpi.isUp
                          ? 'text-emerald-600 dark:text-emerald-400'
                          : 'text-red-600 dark:text-red-400'
                      }`}
                    >
                      {kpi.isUp ? <ArrowUpRight className="w-3.5 h-3.5" /> : <ArrowDownRight className="w-3.5 h-3.5" />}
                      {kpi.delta}
                    </span>
                  </div>

                  <p className="text-2xl sm:text-3xl font-black text-gray-900 dark:text-zinc-100 tracking-tight">
                    <LiveNumber value={typeof kpi.val === 'number' ? kpi.val : 0} fmt={kpi.fmt} />
                  </p>
                </div>

                <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mt-2.5">
                  {kpi.label}
                </p>
              </div>
            </SlideIn>
          );
        })}
      </div>

      {/* ── 3. Charts Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Left: Cryptographic Traffic Activity Area Chart */}
        <SlideIn delay={300} direction="left" className="lg:col-span-3">
          <div className="rounded-2xl p-5 sm:p-6 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm flex flex-col justify-between h-full">
            <div>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm sm:text-base font-bold text-gray-900 dark:text-zinc-100">
                      Cryptographic Traffic Activity
                    </h2>
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/40">
                      LIVE
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                    {activeTab === '24H' ? '24-hour TLS session telemetry · protocol posture' : '7-day trend analysis · protocol security posture'}
                  </p>
                </div>

                {/* Range Toggle with smooth sliding animation */}
                <div className="relative flex items-center rounded-xl p-1 bg-gray-100 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700/60 self-start sm:self-auto">
                  {(['24H', '7D'] as const).map((tab) => {
                    const isSelected = activeTab === tab;
                    return (
                      <button
                        key={tab}
                        type="button"
                        onClick={() => setActiveTab(tab)}
                        className={`relative px-3 py-1 rounded-lg text-xs font-bold transition-colors duration-200 cursor-pointer ${
                          isSelected
                            ? 'text-white'
                            : 'text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'
                        }`}
                      >
                        {isSelected && (
                          <motion.div
                            layoutId="activeTrafficRangeTab"
                            className="absolute inset-0 rounded-lg bg-blue-600 shadow-sm"
                            transition={{
                              type: 'spring',
                              stiffness: 450,
                              damping: 32,
                            }}
                          />
                        )}
                        <span className="relative z-10">{tab}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Legend */}
              <div className="flex items-center gap-4 text-xs mb-3 font-medium">
                <span className="flex items-center gap-1.5 text-gray-600 dark:text-gray-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                  Sessions Analyzed
                </span>
                <span className="flex items-center gap-1.5 text-gray-600 dark:text-gray-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-indigo-500" />
                  Crypto Weaknesses
                </span>
              </div>
            </div>

            <div className="w-full h-56 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activity} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradBlue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="gradIndigo" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#27272a' : '#f1f5f9'} vertical={false} />
                  <XAxis
                    dataKey="hour"
                    tick={{ fill: isDark ? '#71717a' : '#94a3b8', fontSize: 11, fontFamily: "'Inter', sans-serif" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: isDark ? '#71717a' : '#94a3b8', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip content={<CleanTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="scanned"
                    stroke="#3b82f6"
                    strokeWidth={2.5}
                    fill="url(#gradBlue)"
                    name="Sessions Analyzed"
                    isAnimationActive
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#6366f1"
                    strokeWidth={2.5}
                    fill="url(#gradIndigo)"
                    name="Crypto Weaknesses"
                    isAnimationActive
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </SlideIn>

        {/* Right: TLS Version Distribution Donut Chart */}
        <SlideIn delay={380} direction="right" className="lg:col-span-2">
          <div className="rounded-2xl p-5 sm:p-6 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm flex flex-col justify-between h-full">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h2 className="text-sm sm:text-base font-bold text-gray-900 dark:text-zinc-100">
                    TLS Version Distribution
                  </h2>
                  <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                    Observed protocol versions across email sessions
                  </p>
                </div>
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/40">
                  LIVE
                </span>
              </div>
            </div>

            {/* Donut Graphic */}
            <div className="relative flex items-center justify-center my-3" style={{ height: 175 }}>
              <ResponsiveContainer width="100%" height={175}>
                <PieChart>
                  {/* Ambient Track Circle */}
                  <Pie
                    data={[{ value: 100 }]}
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={74}
                    fill="currentColor"
                    className="text-gray-100 dark:text-zinc-800/80"
                    isAnimationActive={false}
                    dataKey="value"
                    strokeWidth={0}
                  />
                  <Pie
                    data={attack}
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={74}
                    cornerRadius={5}
                    paddingAngle={4}
                    dataKey="value"
                    startAngle={90}
                    endAngle={-270}
                    strokeWidth={0}
                    isAnimationActive
                  >
                    {attack.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<CleanTooltip />} formatter={(v: any, n: any) => [`${Number(v)}%`, n]} />
                </PieChart>
              </ResponsiveContainer>

              {/* Center label */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-2xl font-black font-mono text-gray-900 dark:text-white tracking-tight">100%</span>
                <span className="text-[9px] text-gray-500 dark:text-gray-400 font-mono font-bold uppercase tracking-widest mt-0.5">
                  TLS SESSIONS
                </span>
              </div>
            </div>

            {/* Legend Cards */}
            <div className="grid grid-cols-3 gap-2 mt-1">
              {attack.map((s) => (
                <div
                  key={s.name}
                  className="flex flex-col items-center justify-center p-2.5 rounded-xl bg-gray-50/80 dark:bg-zinc-800/60 border border-gray-200/80 dark:border-zinc-700/50"
                >
                  <span className="flex items-center gap-1.5 text-[11px] font-semibold text-gray-600 dark:text-zinc-300">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.color }} />
                    {s.name}
                  </span>
                  <span className="text-sm font-mono font-bold text-gray-900 dark:text-white mt-1">
                    {s.value}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </SlideIn>
      </div>

      {/* ── 4. Top Vulnerable Cipher Suites ── */}
      <SlideIn delay={450} direction="up">
        <div className="rounded-2xl p-5 sm:p-6 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              {/* Squircle icon container (Image 4 & 5 style) */}
              <div className="w-10 h-10 rounded-2xl flex items-center justify-center bg-[#edf5ff] dark:bg-white border border-blue-100 dark:border-white text-blue-600 dark:text-blue-600 shadow-sm transition-colors">
                <Lock className="w-5 h-5 stroke-[2.2]" />
              </div>
              <div>
                <h2 className="text-sm sm:text-base font-bold text-gray-900 dark:text-zinc-100">
                  Top Vulnerable Cipher Suites
                </h2>
                <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                  Most frequent insecure or deprecated ciphers observed in network captures
                </p>
              </div>
            </div>
            <button
              onClick={() => onNavigate?.('threat-intelligence')}
              className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline font-semibold"
            >
              Certificate Vault <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
            {TOP_VULNERABLE_CIPHERS.map((c) => (
              <div
                key={c.cipherSuite}
                className="rounded-xl p-4 bg-gray-50 dark:bg-zinc-800/60 border border-gray-200 dark:border-zinc-700/60 flex flex-col justify-between transition-all duration-150 hover:border-gray-300 dark:hover:border-zinc-600"
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-2.5">
                    {/* Solid circular badge */}
                    <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-mono font-bold text-[10px] flex items-center justify-center shadow-sm">
                      {c.rank}
                    </span>
                    <SolidBadge label={c.severity} variant={c.severity as any} />
                  </div>
                  <div className="min-h-[2.5rem] flex items-start mb-2">
                    <p className="text-[11px] font-mono font-bold text-gray-900 dark:text-zinc-100 break-all leading-snug" title={c.cipherSuite}>
                      {c.cipherSuite}
                    </p>
                  </div>
                  <p className="text-[11px] text-gray-500 dark:text-gray-400 line-clamp-2 leading-relaxed min-h-[2rem]">
                    {c.vulnerability}
                  </p>
                </div>

                <div className="mt-4 pt-2.5 border-t border-gray-200 dark:border-zinc-700/60 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-gray-500 dark:text-gray-400 font-medium">{c.rfc}</span>
                  <span className="text-gray-900 dark:text-zinc-200 font-bold">{c.sessionCount} sessions</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </SlideIn>

      {/* ── 5. Recent Detections Table ── */}
      <SlideIn delay={520} direction="up">
        <div className="rounded-2xl p-5 sm:p-6 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm sm:text-base font-bold text-gray-900 dark:text-zinc-100">
                Recent Cryptographic Posture Detections
              </h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                Active TLS downgrade attacks, weak ciphers, and certificate validation failures
              </p>
            </div>
            <button
              onClick={() => onNavigate?.('email-analyzer')}
              className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline font-semibold"
            >
              Analyze New PCAP <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-gray-200 dark:border-zinc-800 text-[10px] font-bold text-gray-400 dark:text-zinc-500 uppercase tracking-wider">
                  <th className="py-3 px-3.5">Session ID</th>
                  <th className="py-3 px-3.5">Protocol / Peer</th>
                  <th className="py-3 px-3.5">Cipher Suite</th>
                  <th className="py-3 px-3.5">Threat Type</th>
                  <th className="py-3 px-3.5">Severity</th>
                  <th className="py-3 px-3.5">Risk Score</th>
                  <th className="py-3 px-3.5 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-zinc-800/60 text-xs">
                {analyzedReports.length > 0 ? (
                  analyzedReports.slice(0, 8).map((r) => {
                    const fromHdr =
                      r.headers?.find((h) => h.key.toLowerCase() === 'from')?.value ||
                      r.threat_intel?.domain ||
                      'SMTP Mail Gateway';
                    const sev = (r.alert_level || 'low') as Severity;
                    const status = r.alert_level === 'critical' ? 'investigating' : r.alert_level === 'high' ? 'open' : 'resolved';

                    return (
                      <tr
                        key={r.case_id}
                        onClick={() => onNavigate?.('header-forensics')}
                        className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/50 cursor-pointer transition-colors duration-150"
                      >
                        <td className="py-3.5 px-3.5 font-mono text-blue-600 dark:text-blue-400 font-bold whitespace-nowrap">
                          {r.case_id}
                        </td>
                        <td className="py-3.5 px-3.5 text-gray-900 dark:text-zinc-200 font-medium max-w-[160px] truncate" title={fromHdr}>
                          {fromHdr}
                        </td>
                        <td className="py-3.5 px-3.5 font-mono text-gray-600 dark:text-zinc-400 max-w-[180px] truncate">
                          TLS_RSA_WITH_RC4_128_SHA
                        </td>
                        <td className="py-3.5 px-3.5 text-gray-600 dark:text-zinc-400 font-medium max-w-[180px] truncate">
                          {r.verdict}
                        </td>
                        <td className="py-3.5 px-3.5 whitespace-nowrap">
                          <SolidBadge label={sev} variant={sev as any} />
                        </td>
                        <td className="py-3.5 px-3.5 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 rounded-full bg-gray-200 dark:bg-zinc-700 overflow-hidden">
                              <div
                                className="h-full rounded-full bg-amber-500 transition-all duration-500"
                                style={{
                                  width: `${r.threat_score}%`,
                                  backgroundColor: r.threat_score >= 70 ? '#ef4444' : r.threat_score >= 40 ? '#f59e0b' : '#10b981',
                                }}
                              />
                            </div>
                            <span className="font-mono font-bold text-gray-900 dark:text-zinc-200">
                              {r.threat_score}
                            </span>
                          </div>
                        </td>
                        <td className="py-3.5 px-3.5 text-right whitespace-nowrap">
                          <SolidBadge label={status} variant={status as any} />
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  RECENT_THREATS.map((t) => {
                    const sev = t.severity;
                    const status = t.status.toLowerCase();

                    return (
                      <tr
                        key={t.id}
                        onClick={() => onNavigate?.('header-forensics')}
                        className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/50 cursor-pointer transition-colors duration-150"
                      >
                        <td className="py-3.5 px-3.5 font-mono text-blue-600 dark:text-blue-400 font-bold whitespace-nowrap">
                          {t.id}
                        </td>
                        <td className="py-3.5 px-3.5 text-gray-900 dark:text-zinc-200">
                          <span className="font-bold text-gray-900 dark:text-zinc-100">{t.protocol}</span>
                          <span className="text-[11px] text-gray-400 dark:text-zinc-500 font-mono block">
                            {t.sourceIP} → {t.destIP}
                          </span>
                        </td>
                        <td className="py-3.5 px-3.5 font-mono text-gray-600 dark:text-zinc-400">
                          <span className="font-bold text-gray-900 dark:text-zinc-200 block">{t.tlsVersion}</span>
                          <span className="text-[11px] text-gray-500 dark:text-zinc-500 block truncate max-w-[170px]" title={t.cipherSuite}>
                            {t.cipherSuite}
                          </span>
                        </td>
                        <td className="py-3.5 px-3.5 text-gray-600 dark:text-zinc-300 font-medium">
                          {t.threatType}
                        </td>
                        <td className="py-3.5 px-3.5 whitespace-nowrap">
                          <SolidBadge label={sev} variant={sev as any} />
                        </td>
                        <td className="py-3.5 px-3.5 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 rounded-full bg-gray-200 dark:bg-zinc-700 overflow-hidden">
                              <div
                                className="h-full rounded-full transition-all duration-500"
                                style={{
                                  width: `${t.riskScore}%`,
                                  backgroundColor: t.riskScore >= 70 ? '#ef4444' : t.riskScore >= 40 ? '#f59e0b' : '#10b981',
                                }}
                              />
                            </div>
                            <span className="font-mono font-bold text-gray-900 dark:text-zinc-200">
                              {t.riskScore}
                            </span>
                          </div>
                        </td>
                        <td className="py-3.5 px-3.5 text-right whitespace-nowrap">
                          <SolidBadge label={status} variant={status as any} />
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

export default DashboardPage;
