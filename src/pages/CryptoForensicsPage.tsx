import { useState, useEffect } from 'react';
import {
 Mail,
 ArrowRight,
 ArrowLeft,
 ShieldX,
 ChevronDown,
 ChevronRight,
 Server,
 Clock,
 Eye,
 Brain,
 AlertTriangle,
 XCircle,
 CheckCircle2,
 Info,
 Network,
 MapPin,
 Sparkles,
 ShieldCheck,
 ShieldAlert,
 Link,
 Archive,
 Check,
 Download,
 Lock,
 Key,
} from 'lucide-react';
import { useAnalysis } from '@/contexts/AnalysisContext';
import { useEvidence } from '@/contexts/EvidenceContext';
import type { EmailAnalysisResult } from '@/services/claudeService';

import {
 DEMO_EMAIL,
 DEMO_PCAP_SESSION,
 TLS_HANDSHAKE_STEPS,
 type TLSHandshakeDetail,
 SMTP_RELAYS,
 EXTENDED_HEADERS,
 HEADER_FACTS,
 HEADER_INFERENCES,
 type ExtendedHeader,
 type HeaderFact,
} from '@/data/mockData';
import { CopyButton } from '@/components/CopyButton';

const AUTH_CARDS = [
 { name: 'TLS Protocol', result: 'FAIL', detail: 'Negotiated TLS 1.0 — deprecated by RFC 8996; requires TLS 1.2 or TLS 1.3' },
 { name: 'Cipher Suite', result: 'FAIL', detail: 'Selected RC4-128 stream cipher — prohibited under RFC 7465; BEAST/POODLE risk' },
 { name: 'Certificate Trust', result: 'FAIL', detail: 'Self-signed certificate from untrusted CA expired 2024-01-01; no chain of trust' },
];

const FACT_ICON: Record<HeaderFact['status'], typeof CheckCircle2> = {
 fail: XCircle,
 warn: AlertTriangle,
 info: Info,
};

const FACT_COLOR: Record<HeaderFact['status'], string> = {
 fail: 'text-red-400',
 warn: 'text-amber-400',
 info: 'text-gray-400',
};

const HEADER_CATEGORY_COLOR: Record<ExtendedHeader['category'], string> = {
 handshake: 'text-cyan-400',
 cipher: 'text-purple-400',
 certificate: 'text-amber-400',
 transport: 'text-blue-400',
 vulnerability: 'text-red-400',
};

/* ─── Slide-in entrance wrapper ─── */
function SlideIn({ children, delay = 0, direction = 'up', className = '' }: {
 children: React.ReactNode; delay?: number; direction?: 'up'|'left'|'right'|'down'; className?: string;
}) {
 const [vis, setVis] = useState(false);
 useEffect(() => { const t = setTimeout(() => setVis(true), delay); return () => clearTimeout(t); }, [delay]);
 const from = direction === 'left' ? 'translateX(-36px)' : direction === 'right' ? 'translateX(36px)' : direction === 'down' ? 'translateY(-20px)' : 'translateY(24px)';
 return (
 <div className={className} style={{ opacity: vis ? 1 : 0, transform: vis ? 'none' : from, transition: 'opacity .5s cubic-bezier(.22,1,.36,1), transform .5s cubic-bezier(.22,1,.36,1)' }}>
 {children}
 </div>
 );
}

const LEVEL_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
 critical: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.35)', text: 'text-red-600 dark:text-red-400', glow: 'none' },
 high: { bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.35)', text: 'text-orange-600 dark:text-orange-400', glow: 'none' },
 medium: { bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.35)', text: 'text-amber-600 dark:text-amber-400', glow: 'none' },
 low: { bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.35)', text: 'text-blue-600 dark:text-blue-400', glow: 'none' },
 info: { bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.35)', text: 'text-gray-600 dark:text-gray-400', glow: 'none' },
};

export function CryptoForensicsPage({ onNavigate }: { onNavigate?: (route: string) => void }) {
 const { currentResult, loadDemoCase } = useAnalysis();
 const { snapshotHeaderForensics } = useEvidence();
 const [vaultSaved, setVaultSaved] = useState(false);
 const [isSavingToVault, setIsSavingToVault] = useState(false);

 const hasLive = Boolean(currentResult && (currentResult.case_id || currentResult.verdict));
 const rawLevel = (currentResult?.alert_level || 'info').toLowerCase();
 const lc = LEVEL_COLORS[rawLevel] || LEVEL_COLORS.info;

 const subjectHeader = Array.isArray(currentResult?.headers)
 ? currentResult?.headers.find((h) => h?.key?.toLowerCase() === 'subject')?.value
 : null;

 const handleSaveHeadersToVault = async () => {
 if (!currentResult) return;
 setIsSavingToVault(true);
 try {
 const raw = currentResult?.headers?.map((h) => `${h.key}: ${h.value}`).join('\n') || '';
 const caseId = currentResult?.case_id || 'CASE-2026-LIVE';
 await snapshotHeaderForensics({
 caseId,
 rawHeaders: raw,
 summary: `RFC-5322 header snapshot for case ${caseId} with SPF/DKIM/DMARC signatures.`,
 });
 setVaultSaved(true);
 setTimeout(() => setVaultSaved(false), 4000);
 } catch {
 // ignore
 } finally {
 setIsSavingToVault(false);
 }
 };

 return (
 <div className="space-y-6" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

 {/* ── Page Header ── */}
 <SlideIn delay={0} direction="down">
 <div className="space-y-3">
 <div className="flex items-start gap-2.5 sm:gap-3">
 {onNavigate && (
 <button
 onClick={() => onNavigate('email-analyzer')}
 className="mt-0.5 w-8 h-8 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl flex items-center justify-center text-blue-400 hover:text-blue-300 transition-all hover:scale-105 active:scale-95 cursor-pointer shrink-0"
 style={{
 background: 'rgba(59, 130, 246, 0.05)',
 border: '1px solid rgba(59, 130, 246, 0.45)',
 boxShadow: '0 0 10px rgba(59, 130, 246, 0.15)',
 }}
 title="Back to Email Analyzer"
 >
 <ArrowLeft className="w-4 h-4" />
 </button>
 )}
 <div className="min-w-0 flex-1">
 <h2 className="text-xl sm:text-2xl font-black text-gray-900 dark:text-white tracking-tight leading-snug">Cryptographic Forensics</h2>
 <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mt-0.5 leading-relaxed">
 Deep inspection of TLS handshakes, cipher suite negotiations, X.509 certificates, and cryptographic posture
 </p>
 </div>
 </div>

 {/* ── Synced Analysis Banner ── */}
 {hasLive && currentResult && (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-3.5 sm:p-4 overflow-hidden max-w-full"
 style={{
 background: lc.bg,
 border: `1px solid ${lc.border}`,
 boxShadow: lc.glow,
 }}
 >
 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 sm:gap-3">
 <div className="flex items-center gap-2 min-w-0 flex-1">
 <div
 className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
 style={{ background: lc.border, opacity: 0.9 }}
 >
 <Link className="w-3.5 h-3.5 text-white" />
 </div>
 <div className="min-w-0 flex-1">
 <p className="text-[10px] font-mono uppercase tracking-widest text-gray-500 dark:text-gray-400 font-bold leading-none mb-0.5">Synced from Session Analysis</p>
 <p className="text-xs font-bold text-gray-900 dark:text-white font-mono truncate block" title={`${currentResult.case_id || 'ANALYSIS-ACTIVE'}${subjectHeader ? ` — ${subjectHeader}` : ''}`}>
 <span>{currentResult.case_id || 'ANALYSIS-ACTIVE'}</span>
 {subjectHeader && <span className="text-gray-600 dark:text-gray-300 font-normal"> — {subjectHeader}</span>}
 </p>
 </div>
 </div>

 <div className="flex items-center gap-1.5 flex-wrap min-w-0">
 <span
 className="px-2.5 py-0.5 rounded text-[10px] sm:text-[11px] font-bold uppercase shrink-0 whitespace-nowrap text-white shadow-sm border border-white/10"
                style={{ background: lc.bg }}
 >
 {currentResult.alert_level || 'INFO'}
 </span>
 {typeof currentResult.threat_score === 'number' && (
 <span className="px-2.5 py-0.5 rounded text-[10px] sm:text-[11px] font-bold text-white shadow-sm border border-white/10 shrink-0 whitespace-nowrap" style={{ background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)' }}>
 Posture Score: {currentResult.threat_score}/100
 </span>
 )}
 {typeof currentResult.confidence === 'number' && (
 <span className="px-2.5 py-0.5 rounded text-[10px] sm:text-[11px] font-bold text-white shadow-sm border border-white/10 shrink-0 whitespace-nowrap" style={{ background: 'linear-gradient(135deg, #22c55e, #16a34a)' }}>
 Confidence: {currentResult.confidence}%
 </span>
 )}
 </div>
 </div>
 </div>
 )}
 </div>
 </SlideIn>

 {!currentResult ? (
 <SlideIn delay={60} direction="up">
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-12 text-center flex flex-col items-center justify-center gap-6 border dark: -transparent dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div
 className="w-16 h-16 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm flex items-center justify-center bg-blue-500/10 border -blue-500/25 text-blue-600 dark:text-blue-400"
 >
 <Mail className="w-8 h-8" />
 </div>

 <div className="max-w-md space-y-2">
 <h3 className="text-lg font-bold text-gray-900 dark:text-white tracking-tight">No PCAP Session Analyzed</h3>
 <p className="text-xs text-gray-600 dark:text-gray-400 leading-relaxed font-mono">
 Upload or analyze network capture in PCAP Analyzer to inspect TLS handshake messages, cipher negotiations, and X.509 certificate chains.
 </p>
 </div>

 <div className="flex flex-wrap items-center justify-center gap-3">
 <button
 onClick={() => onNavigate?.('email-analyzer')}
 className="flex items-center gap-2 px-5 py-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-white transition-all hover:scale-105 shadow-lg font-mono cursor-pointer"
 style={{
 background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
 boxShadow: '0 4px 16px rgba(59,130,246,0.3)',
 }}
 >
 <Mail className="w-4 h-4" />
 Go to PCAP Analyzer
 </button>
 <button
 onClick={loadDemoCase}
 className="flex items-center gap-2 px-5 py-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-gray-700 hover:text-black dark:text-purple-200 dark:hover:text-purple-100 bg-slate-100 hover: dark:bg-purple-900/30 hover:dark:bg-purple-900/50 border dark:border-purple-500/45 hover:dark: -purple-400/60 transition-all font-mono cursor-pointer hover:scale-[1.02] active:scale-[0.98]"
 >
 <Sparkles className="w-4 h-4 text-purple-600 dark:text-purple-400" />
 Load Sample Demo Session
 </button>
 </div>
 </div>
 </SlideIn>
 ) : (
 <>
 <SlideIn delay={80} direction="up">
 <EmailSummary result={currentResult} />
 </SlideIn>

 <SlideIn delay={140} direction="up">
 <TLSHandshakeSequence />
 </SlideIn>


 <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
 <SlideIn delay={400} direction="left">
 <ObservedFactsPanel result={currentResult} />
 </SlideIn>
 <SlideIn delay={440} direction="right">
 <AIInferencePanel result={currentResult} />
 </SlideIn>
 </div>
 </>
 )}
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TLS HANDSHAKE SEQUENCE COMPONENT
═══════════════════════════════════════════════════════════ */
function TLSHandshakeSequence() {
 return (
 <div className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]">
 <div className="flex items-center justify-between mb-4">
 <div>
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Lock className="w-4 h-4 text-purple-500 dark:text-purple-400" />
 TLS Handshake Sequence & Protocol Inspection
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
 Step-by-step cryptographic exchange reconstruction (ClientHello, ServerHello, Certificate Exchange)
 </p>
 </div>
 <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider text-white shadow-sm border border-white/10" style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)' }}>
 Downgrade Intercepted
 </span>
 </div>

 <div className="space-y-2.5">
 {TLS_HANDSHAKE_STEPS.map((step, idx) => {
 const isFail = step.status === 'fail';
 const isWarn = step.status === 'warn';
 const badgeStyle = isFail
 ? { background: 'linear-gradient(135deg, #ef4444, #dc2626)' }
 : isWarn
 ? { background: 'linear-gradient(135deg, #f59e0b, #d97706)' }
 : { background: 'linear-gradient(135deg, #22c55e, #16a34a)' };
 const badgeClass = 'text-white border-white/10 shadow-sm';
 return (
 <div
 key={idx}
 className="p-3.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl dark: /[0.03] border dark: -white/[0.06] flex flex-col md:flex-row md:items-center justify-between gap-3"
 >
 <div className="flex items-start gap-3">
 <div className="w-6 h-6 rounded-lg text-white flex items-center justify-center text-xs font-mono font-bold shrink-0 mt-0.5 shadow-sm border border-white/10" style={{ background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)' }}>
 {idx + 1}
 </div>
 <div>
 <div className="flex items-center gap-2 flex-wrap">
 <span className="text-xs font-bold text-gray-900 dark:text-white font-mono">{step.phase}</span>
 <span className="text-[10px] font-mono text-gray-500 dark:text-gray-400">({step.direction})</span>
 <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${badgeClass}`} style={badgeStyle}>{step.message}</span>
 </div>
 <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{step.detail}</p>
 </div>
 </div>
 </div>
 );
 })}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 SESSION / CRYPTO SUMMARY
═══════════════════════════════════════════════════════════ */
function EmailSummary({ result }: { result: EmailAnalysisResult | null }) {
 const getHeader = (key: string) => {
 if (!result || !Array.isArray(result.headers)) return '';
 return result.headers.find((h) => h?.key?.toLowerCase() === key.toLowerCase())?.value ?? '';
 };

 const domain = result?.threat_intel?.domain || 'mail.attacker-relay.example';
 const sendingIp = result?.threat_intel?.sending_ip || DEMO_PCAP_SESSION.sourceIP;

 const fields = [
 { label: 'Source IP / Port', value: `${sendingIp}:48920`, icon: Server, highlight: true },
 { label: 'Destination Host', value: `${DEMO_PCAP_SESSION.destIP}:25 (acme-mailgw-03)`, icon: ArrowRight, highlight: false },
 { label: 'Protocol Mode', value: 'SMTP STARTTLS (Port 25)', icon: Lock, highlight: false },
 { label: 'Negotiated TLS', value: getHeader('x-tls-version') || DEMO_PCAP_SESSION.tlsVersion, icon: ShieldAlert, highlight: true },
 { label: 'Selected Cipher Suite', value: getHeader('x-cipher-suite') || DEMO_PCAP_SESSION.cipherSuite, icon: Key, highlight: true },
 { label: 'Session Timestamp', value: DEMO_PCAP_SESSION.timestamp, icon: Clock, highlight: false },
 ];

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-4">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Lock className="w-4 h-4 text-purple-500 dark:text-purple-400" />
 Network Session & Cryptographic Summary
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">Core connection attributes, transport protocol, and negotiated security state</p>
 </div>
 <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
 {fields.map((f) => {
 const Icon = f.icon;
 return (
 <div
 key={f.label}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 transition-all duration-200 hover:scale-[1.01] dark: /[0.03] border dark: -white/[0.06]"
 >
 <div className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400 mb-1 font-medium">
 <Icon className="w-3.5 h-3.5 text-purple-500 dark:text-purple-400" />
 {f.label}
 </div>
 <div className="flex items-center justify-between gap-2">
 <span className={`text-xs font-mono break-all font-semibold ${f.highlight ? 'text-orange-500 dark:text-orange-400' : 'text-gray-900 dark:text-white'}`}>
 {f.value}
 </span>
 <CopyButton value={f.value} />
 </div>
 </div>
 );
 })}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 AUTH CARDS (SPF / DKIM / DMARC)
═══════════════════════════════════════════════════════════ */
function AuthCards({ result }: { result: EmailAnalysisResult | null }) {
 const spf = result?.threat_intel?.spf || 'FAIL';
 const dkim = result?.threat_intel?.dkim || 'FAIL';
 const dmarc = result?.threat_intel?.dmarc || 'FAIL';
 const sendingIp = result?.threat_intel?.sending_ip || result?.origin?.sending_ip || '185.220.101.47';

 const authData = result
 ? [
 {
 name: 'SPF',
 result: spf,
 detail: spf === 'PASS'
 ? `Sending IP ${sendingIp} is authorized by the domain SPF record`
 : `Sending IP ${sendingIp} is not designated by domain SPF record`,
 },
 {
 name: 'DKIM',
 result: dkim,
 detail: dkim === 'PASS'
 ? 'DKIM signature present and verification passed'
 : 'Signature present but verification returned permerror or missing',
 },
 {
 name: 'DMARC',
 result: dmarc,
 detail: dmarc === 'PASS'
 ? 'DMARC policy aligned — sender domain is authenticated'
 : 'Neither SPF nor DKIM aligned with the From domain under DMARC policy',
 },
 ]
 : AUTH_CARDS;

 return (
 <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
 {authData.map((auth) => {
 const isPass = auth.result === 'PASS';
 const isNeutral = auth.result === 'NEUTRAL' || auth.result === 'NONE';
 const Icon = isPass ? ShieldCheck : isNeutral ? ShieldAlert : ShieldX;
 const colorClass = isPass ? 'text-green-600 dark:text-green-400' : isNeutral ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400';
 const bgStyle = isPass
 ? { background: 'linear-gradient(135deg, rgba(34,197,94,0.08) 0%, rgba(22,163,74,0.02) 100%)', border: '1px solid rgba(34,197,94,0.3)', boxShadow: '0 0 20px rgba(34,197,94,0.08)' }
 : isNeutral
 ? { background: 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(217,119,6,0.02) 100%)', border: '1px solid rgba(245,158,11,0.3)', boxShadow: '0 0 20px rgba(245,158,11,0.08)' }
 : { background: 'linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(220,38,38,0.02) 100%)', border: '1px solid rgba(239,68,68,0.3)', boxShadow: '0 0 20px rgba(239,68,68,0.08)' };
 const badgeClass = isPass
 ? 'text-green-600 dark:text-green-400 bg-green-500/15 border border-green-500/30'
 : isNeutral
 ? 'text-amber-600 dark:text-amber-400 bg-amber-500/15 border border-amber-500/30'
 : 'text-red-600 dark:text-red-400 bg-red-500/15 border border-red-500/30';
 const StatusIcon = isPass ? CheckCircle2 : isNeutral ? AlertTriangle : XCircle;
 const statusLabel = isPass ? 'Authentication passed' : isNeutral ? 'No result / neutral' : 'Authentication failed';

 return (
 <div key={auth.name} className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 transition-all duration-200 hover:scale-[1.01] dark:bg-transparent dark:shadow-none" style={bgStyle}>
 <div className="flex items-center justify-between mb-3">
 <span className="text-sm font-bold text-gray-900 dark:text-white tracking-wider font-mono">{auth.name}</span>
 <div className="flex items-center gap-1.5">
 <Icon className={`w-4 h-4 ${colorClass}`} />
 <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase ${badgeClass}`}>
 {auth.result}
 </span>
 </div>
 </div>
 <p className="text-xs text-gray-600 dark:text-gray-400 leading-relaxed mb-3">{auth.detail}</p>
 <div className={`flex items-center gap-1.5 text-xs ${colorClass} font-semibold`}>
 <StatusIcon className="w-3.5 h-3.5" />
 {statusLabel}
 </div>
 </div>
 );
 })}
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 SMTP RELAY TIMELINE
═══════════════════════════════════════════════════════════ */
function SmtpRelayTimeline({ result }: { result: EmailAnalysisResult | null }) {
 const hasHops = Array.isArray(result?.origin?.relay_hops) && result!.origin.relay_hops.length > 0;
 const relayList = hasHops
 ? result!.origin.relay_hops.map((hop, idx) => ({
 id: `hop-${idx}`,
 hop: hop?.hop ?? (idx + 1),
 hostname: hop?.hostname || 'relay.node.internal',
 ip: hop?.ip || '0.0.0.0',
 country: hop?.country || result?.origin?.country || 'Global',
 asn: result?.origin?.asn || 'AS-Unknown',
 asnOrg: result?.origin?.hosting || 'Unknown',
 timestamp: '--',
 confidence: 90,
 note: hop?.note || 'Relay node identified in Received headers',
 }))
 : SMTP_RELAYS;

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-3.5 sm:p-5 overflow-hidden border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-4">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Network className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
 SMTP Relay Timeline
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">Reconstructed mail routing path across intermediate relays</p>
 </div>
 <div className="relative pl-0 sm:pl-2">
 <div className="absolute left-[13px] sm:left-[19px] top-3 bottom-3 w-0.5 dark: /10" />
 <div className="space-y-3.5 sm:space-y-4">
 {relayList.map((relay, i) => (
 <div key={relay.id} className="relative flex gap-2.5 sm:gap-4 items-start min-w-0">
 <div
 className="relative z-10 w-7 h-7 sm:w-9 sm:h-9 rounded-lg sm:bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl flex items-center justify-center shrink-0 transition-transform hover:scale-110"
 style={
 i === 0
 ? { background: 'rgba(239,68,68,0.15)', borderColor: '#ef4444', color: '#ef4444', boxShadow: '0 0 12px rgba(239,68,68,0.25)' }
 : i === relayList.length - 1
 ? { background: 'rgba(34,197,94,0.15)', borderColor: '#22c55e', color: '#16a34a', boxShadow: '0 0 12px rgba(34,197,94,0.25)' }
 : { background: 'rgba(100,116,139,0.1)', borderColor: 'rgba(100,116,139,0.3)', color: '#64748b' }
 }
 >
 <span className="text-[10px] sm:text-xs font-bold font-mono">{relay.hop}</span>
 </div>
 <div
 className="flex-1 min-w-0 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3 sm:p-4 overflow-hidden transition-all duration-200 hover:scale-[1.005] dark: /[0.03] border dark: -white/[0.06]"
 >
 <div className="flex flex-wrap items-center justify-between gap-1.5 sm:gap-2 mb-2">
 <div className="flex items-center gap-1.5 sm:gap-2 min-w-0 flex-1">
 <Server className="w-3.5 h-3.5 text-purple-500 dark:text-purple-400 shrink-0" />
 <span className="text-xs font-mono text-gray-900 dark:text-white font-bold truncate block min-w-0 flex-1" title={relay.hostname}>
 {relay.hostname}
 </span>
 <CopyButton value={relay.hostname} />
 </div>
 <span
 className="px-2 py-0.5 rounded text-[10px] font-bold font-mono shrink-0"
 style={{
 background: relay.confidence >= 90 ? 'rgba(34,197,94,0.15)' : 'rgba(245,158,11,0.15)',
 color: relay.confidence >= 90 ? '#16a34a' : '#d97706',
 border: `1px solid ${relay.confidence >= 90 ? 'rgba(34,197,94,0.3)' : 'rgba(245,158,11,0.3)'}`,
 }}
 >
 {relay.confidence}% confidence
 </span>
 </div>

 <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 sm:gap-3 text-xs mt-3 pt-3 border-t dark: -white/5">
 <div className="min-w-0">
 <span className="text-gray-500 dark:text-gray-400 text-[10px] font-mono uppercase">IP Address</span>
 <div className="flex items-center gap-1 mt-0.5 min-w-0">
 <span className="text-gray-900 dark:text-white font-mono font-semibold truncate block">{relay.ip}</span>
 <CopyButton value={relay.ip} />
 </div>
 </div>
 <div className="min-w-0">
 <span className="text-gray-500 dark:text-gray-400 text-[10px] font-mono uppercase">Country</span>
 <div className="flex items-center gap-1 text-gray-700 dark:text-gray-300 mt-0.5 truncate">
 <MapPin className="w-3 h-3 text-cyan-600 dark:text-cyan-400 shrink-0" /> <span className="truncate">{relay.country}</span>
 </div>
 </div>
 <div className="min-w-0">
 <span className="text-gray-500 dark:text-gray-400 text-[10px] font-mono uppercase">ASN</span>
 <div className="text-gray-700 dark:text-gray-300 font-mono mt-0.5 truncate">{relay.asn}</div>
 </div>
 <div className="min-w-0">
 <span className="text-gray-500 dark:text-gray-400 text-[10px] font-mono uppercase">Timestamp</span>
 <div className="text-gray-700 dark:text-gray-300 font-mono text-[11px] mt-0.5 truncate">{relay.timestamp}</div>
 </div>
 </div>

 <div className="mt-2.5 pt-2.5 border-t dark: -white/5 flex flex-wrap items-center justify-between gap-1 text-xs">
 <span className="text-gray-600 dark:text-gray-400 break-words">ASN Org: <span className="text-gray-900 dark:text-white font-medium">{relay.asnOrg}</span></span>
 </div>
 <div className="mt-2 flex items-start gap-1.5">
 <Info className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400 shrink-0 mt-0.5" />
 <span className="text-xs text-gray-600 dark:text-gray-400 break-words">{relay.note}</span>
 </div>
 </div>
 </div>
 ))}
 </div>
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 DETAILED HEADERS (EXPANDABLE)
═══════════════════════════════════════════════════════════ */
function ExpandableHeaders({ result }: { result: EmailAnalysisResult | null }) {
 const [expanded, setExpanded] = useState<Set<string>>(new Set(['From']));
 const [allExpanded, setAllExpanded] = useState(false);

 const liveHeaders = Array.isArray(result?.headers) && result!.headers.length > 0
 ? result!.headers.map((h, idx) => ({
 key: h?.key || `Param-${idx}`,
 value: h?.value || '',
 category: (
 ['tls', 'handshake', 'version', 'client', 'server'].some(k => (h?.key || '').toLowerCase().includes(k)) ? 'handshake'
 : ['cipher', 'encryption', 'hash', 'aes', 'rc4', 'mac', 'key exchange'].some(k => (h?.key || '').toLowerCase().includes(k)) ? 'cipher'
 : ['cert', 'issuer', 'subject', 'public key', 'valid', 'rsa'].some(k => (h?.key || '').toLowerCase().includes(k)) ? 'certificate'
 : ['protocol', 'port', 'ip', 'stream', 'tcp', 'host'].some(k => (h?.key || '').toLowerCase().includes(k)) ? 'transport'
 : 'vulnerability'
 ) as ExtendedHeader['category'],
 id: `live-${idx}`,
 }))
 : EXTENDED_HEADERS;

 const toggle = (key: string) => {
 const next = new Set(expanded);
 if (next.has(key)) next.delete(key);
 else next.add(key);
 setExpanded(next);
 };

 const toggleAll = () => {
 if (allExpanded) {
 setExpanded(new Set());
 setAllExpanded(false);
 } else {
 setExpanded(new Set(liveHeaders.map((h) => h.key)));
 setAllExpanded(true);
 }
 };

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="flex items-center justify-between mb-4">
 <div>
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Server className="w-4 h-4 text-purple-500 dark:text-purple-400" />
 Detailed Headers
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">Full raw header analysis with category tagging and copy features</p>
 </div>
 <button
 onClick={toggleAll}
 className="px-3 py-1.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-semibold text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white transition-colors dark: /5 border dark: -white/10 cursor-pointer"
 >
 {allExpanded ? 'Collapse All' : 'Expand All'}
 </button>
 </div>
 <div className="space-y-1.5">
 {liveHeaders.map((h) => {
 const isOpen = expanded.has(h.key);
 const isLong = (h.value || '').length > 60;
 return (
 <div
 key={h.key}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl overflow-hidden transition-all duration-150 dark: /[0.03] border dark: -white/[0.05]"
 >
 <button
 onClick={() => toggle(h.key)}
 className="w-full flex items-center gap-2 px-3.5 py-2.5 hover: dark:hover: /5 transition-colors text-left cursor-pointer"
 >
 {isOpen ? <ChevronDown className="w-3.5 h-3.5 text-gray-400 dark:text-gray-500 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-gray-400 dark:text-gray-500 shrink-0" />}
 <span className={`text-xs font-mono font-bold ${HEADER_CATEGORY_COLOR[h.category] || 'text-gray-700 dark:text-gray-300'}`}>{h.key}</span>
 {!isLong && !isOpen && (
 <span className="text-xs text-gray-600 dark:text-gray-400 font-mono truncate ml-2">{h.value}</span>
 )}
 <span className="ml-auto text-[10px] font-mono text-gray-500 dark:text-gray-500 uppercase tracking-wider px-2 py-0.5 rounded dark: /5">
 {h.category}
 </span>
 </button>
 {isOpen && (
 <div className="px-3.5 pb-3.5 pt-1">
 <div className="flex items-start gap-2 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3 border dark: -white/5">
 <span className="text-xs font-mono text-gray-800 dark:text-gray-300 break-all flex-1 leading-relaxed">{h.value}</span>
 <CopyButton value={h.value} />
 </div>
 </div>
 )}
 </div>
 );
 })}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 OBSERVED FACTS PANEL
═══════════════════════════════════════════════════════════ */
function ObservedFactsPanel({ result }: { result: EmailAnalysisResult | null }) {
 const hasFacts = Array.isArray(result?.observed_facts) && result!.observed_facts.length > 0;
 const factList = hasFacts
 ? result!.observed_facts.map(f => ({
 id: f?.id || Math.random().toString(),
 fact: f?.field || 'Signal Observed',
 detail: f?.value || '',
 status: (f?.status || 'info') as 'fail' | 'warn' | 'info' | 'pass',
 }))
 : HEADER_FACTS;

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 h-full border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-4">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Eye className="w-4 h-4 text-purple-500 dark:text-purple-400" />
 Observed Facts
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">Verifiable header signals extracted directly from SMTP parameters</p>
 </div>
 <div className="space-y-2">
 {factList.map((fact) => {
 const Icon = FACT_ICON[fact.status as keyof typeof FACT_ICON] || Info;
 const color = FACT_COLOR[fact.status as keyof typeof FACT_COLOR] || 'text-gray-400';
 return (
 <div
 key={fact.id}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 transition-all duration-200 hover:scale-[1.01] dark: /[0.03] border dark: -white/[0.05]"
 >
 <div className="flex items-start gap-2.5 min-w-0">
 <Icon className={`w-4 h-4 shrink-0 mt-0.5 ${color}`} />
 <div className="min-w-0 flex-1">
 <p className="text-xs font-bold text-gray-900 dark:text-white truncate block">{fact.fact}</p>
 <p className="text-[11px] text-gray-600 dark:text-gray-400 mt-1 leading-relaxed break-all">{fact.detail}</p>
 </div>
 </div>
 </div>
 );
 })}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 AI INFERENCE PANEL
═══════════════════════════════════════════════════════════ */
function AIInferencePanel({ result }: { result: EmailAnalysisResult | null }) {
 const hasInferences = Array.isArray(result?.ai_inferences) && result!.ai_inferences.length > 0;
 const infList = hasInferences
 ? result!.ai_inferences
 : HEADER_INFERENCES;

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 h-full border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-4">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <Brain className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
 AI Inference
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">Analytical interpretation based on header anomalies</p>
 </div>

 <div
 className="flex items-start gap-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3 mb-4 bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark: -blue-500/20"
 >
 <Info className="w-4 h-4 text-blue-500 dark:text-blue-400 shrink-0 mt-0.5" />
 <p className="text-xs text-gray-700 dark:text-gray-300">
 Inferences are probabilistic threat assessments — <span className="text-amber-600 dark:text-amber-400 font-semibold">not confirmed findings</span>.
 </p>
 </div>

 <div className="space-y-3">
 {infList.map((inf) => (
 <div
 key={inf.id || inf.inference}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 transition-all duration-200 hover:scale-[1.01] dark: /[0.03] border dark: -white/[0.05]"
 >
 <div className="flex items-start justify-between gap-3 mb-1.5">
 <p className="text-xs font-bold text-gray-900 dark:text-white flex-1">{inf.inference}</p>
 <span className="text-xs font-mono text-gray-900 dark:text-white font-bold shrink-0">{inf.confidence || 0}%</span>
 </div>
 <div className="w-full h-1.5 dark: /10 rounded-full overflow-hidden mb-2">
 <div
 className="h-full rounded-full transition-all duration-500"
 style={{
 width: `${inf.confidence || 0}%`,
 background: (inf.confidence || 0) > 85 ? '#ef4444' : '#f97316',
 boxShadow: `0 0 6px ${(inf.confidence || 0) > 85 ? 'rgba(239,68,68,0.5)' : 'rgba(249,115,22,0.5)'}`,
 }}
 />
 </div>
 <p className="text-xs text-gray-600 dark:text-gray-400 leading-relaxed">
 <span className="text-gray-500 dark:text-gray-500 uppercase text-[10px] font-mono font-bold tracking-wider">Basis: </span>
 {inf.basis || 'Analytical correlation'}
 </p>
 </div>
 ))}
 </div>
 </div>
 );
}
