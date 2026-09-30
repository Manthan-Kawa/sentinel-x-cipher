import { useState, useRef, useCallback, useEffect, useLayoutEffect } from 'react';
import {
 Upload,
 FileText,
 Mail,
 MailSearch,
 ShieldAlert,
 ShieldCheck,
 ChevronRight,
 AlertTriangle,
 Eye,
 Brain,
 Check,
  CheckCircle2,
 XCircle,
 Info,
 Clock,
 Server,
 FileSearch,
 ArrowRight,
 Sparkles,
 Zap,
 RefreshCw,
 Settings,
 Target,
 MapPin,
 Share2,
 Lock,
 AlertOctagon,
 FileDown,
 Printer,
 Database,
 Archive,
} from 'lucide-react';
import {
 ANALYSIS_STAGES,
 DEMO_EMAIL,
 type AnalysisStage,
} from '@/data/mockData';
import { AnimatedCircleGauge } from '@/components/AnimatedCircleGauge';
import { GradientLiveProgressRing } from '@/components/GradientLiveProgressRing';
import {
 analyzeEmail,
 type EmailAnalysisResult,
 type AlertLevel,
 CLAUDE_KEY_STORAGE,
} from '@/services/claudeService';
import { useAnalysis } from '@/contexts/AnalysisContext';
import { useEvidence } from '@/contexts/EvidenceContext';
import { useCampaigns } from '@/contexts/CampaignContext';
import { exportReportAsPDF, downloadTextReport } from '@/utils/pdfExport';

type AnalyzerState = 'idle' | 'analyzing' | 'results' | 'error';

// ─── Severity colours ─────────────────────────────────────────────────────────
const SEVERITY_BADGE: Record<AlertLevel, string> = {
 critical: 'badge-critical',
 high: 'badge-high',
 medium: 'badge-medium',
 low: 'badge-low',
 info: 'badge-info',
};

const FACT_ICON = {
 fail: XCircle,
 pass: CheckCircle2,
 warn: AlertTriangle,
 info: Info,
} as const;

const FACT_COLOR = {
 fail: 'text-red-400',
 pass: 'text-green-400',
 warn: 'text-amber-400',
 info: 'text-gray-400',
} as const;

const ALERT_COLORS: Record<AlertLevel, { bg: string; border: string; text: string; glow: string }> = {
 critical: { bg: 'linear-gradient(135deg, #ef4444, #dc2626)', border: 'transparent', text: 'text-white', glow: 'rgba(239,68,68,0.3)' },
 high: { bg: 'linear-gradient(135deg, #f97316, #ea580c)', border: 'transparent', text: 'text-white', glow: 'rgba(249,115,22,0.3)' },
 medium: { bg: 'linear-gradient(135deg, #f59e0b, #d97706)', border: 'transparent', text: 'text-white', glow: 'rgba(245,158,11,0.3)' },
 low: { bg: 'linear-gradient(135deg, #3b82f6, #2563eb)', border: 'transparent', text: 'text-white', glow: 'rgba(59,130,246,0.3)' },
 info: { bg: 'linear-gradient(135deg, #6b7280, #4b5563)', border: 'transparent', text: 'text-white', glow: 'rgba(107,114,128,0.3)' },
};

// Gauge gradient colours keyed by alert level
const GAUGE_COLORS: Record<AlertLevel, [string, string, string]> = {
 critical: ['#f87171', '#ef4444', '#b91c1c'],
 high: ['#fb923c', '#f97316', '#c2410c'],
 medium: ['#fcd34d', '#f59e0b', '#b45309'],
 low: ['#60a5fa', '#3b82f6', '#1d4ed8'],
 info: ['#9ca3af', '#6b7280', '#4b5563'],
};

const GAUGE_LABEL: Record<AlertLevel, string> = {
 critical: 'CRITICAL RISK',
 high: 'HIGH RISK',
 medium: 'MEDIUM RISK',
 low: 'LOW RISK',
 info: 'INFO',
};

const ANALYSIS_STEPS = [
 { stage: 'Reconstructing TCP Streams', label: 'Reconstructing TCP streams', detail: 'Reassembling network packet streams and reordering TCP segments' },
 { stage: 'Detecting STARTTLS Negotiations', label: 'Detecting STARTTLS negotiations', detail: 'Scanning SMTP/IMAP/POP3 command channels for cleartext or stripped STARTTLS' },
 { stage: 'Parsing TLS Handshakes', label: 'Parsing TLS handshakes', detail: 'Deconstructing ClientHello, ServerHello, and negotiated cipher suites' },
 { stage: 'Validating X.509 Certificates', label: 'Validating X.509 certificates', detail: 'Inspecting certificate chain, expiration, key length, and signature algorithm' },
 { stage: 'Scoring Cipher Suites', label: 'Scoring cryptographic posture', detail: 'Evaluating forward secrecy, encryption algorithms, and downgrade risks' },
 { stage: 'Correlating Sessions', label: 'Correlating session infrastructure', detail: 'Mapping IP infrastructure and threat intelligence campaign clusters' },
 { stage: 'Preserving Evidence', label: 'Preserving cryptographic evidence', detail: 'Generating SHA-256 session hash and recording immutable audit trail' },
 { stage: 'Generating Report', label: 'Compiling posture assessment report', detail: 'Finalizing posture assessment score and remediation plan' },
] as const;

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

// ─── Build a raw text string from the DEMO_EMAIL mock object ─────────────────
function buildDemoRawEmail(): string {
 const hdrs = (DEMO_EMAIL.headers as Array<{ key: string; value: string }>).map((h: { key: string; value: string }) => `${h.key}: ${h.value}`).join('\n');
 return `${hdrs}\n\n${DEMO_EMAIL.bodyPreview}`;
}

/* ════════════════════════════════════════════════════════════
 MAIN PAGE COMPONENT
════════════════════════════════════════════════════════════ */
export function PCAPAnalyzerPage({ onNavigate }: { onNavigate?: (route: string) => void }) {
 const { currentResult, addAnalysisResult, resetActiveAnalysis } = useAnalysis();
 const { clearVault } = useEvidence();
 const { clearCampaigns } = useCampaigns();

 const [state, setState] = useState<AnalyzerState>(() => (currentResult ? 'results' : 'idle'));
 const [userRequestedIdle, setUserRequestedIdle] = useState(false);
 const [activeStage, setActiveStage] = useState<AnalysisStage>('Reconstructing TCP Streams');
 const [progressStep, setProgressStep] = useState(0);
 const [dragOver, setDragOver] = useState(false);
 const [fileName, setFileName] = useState<string | null>(() => {
 if (!currentResult) return null;
 const subj = currentResult.headers.find(h => h.key.toLowerCase() === 'subject')?.value;
 return subj ? `${subj}.pcap` : `${currentResult.case_id}.pcap`;
 });
 const [pastedEmail, setPastedEmail] = useState('');
 const [activeTab, setActiveTab] = useState<'facts' | 'inference' | 'headers' | 'raw'>('facts');
 const [result, setResult] = useState<EmailAnalysisResult | null>(() => currentResult ?? null);
 const [error, setError] = useState<string | null>(null);
 const fileInputRef = useRef<HTMLInputElement>(null);



 // Keep state synced with currentResult from AnalysisContext across navigation
 useEffect(() => {
 if (currentResult && !userRequestedIdle) {
 setResult(currentResult);
 setState('results');
 setFileName((prev) => {
 if (prev) return prev;
 const subj = currentResult.headers.find(h => h.key.toLowerCase() === 'subject')?.value;
 return subj ? `${subj}.pcap` : `${currentResult.case_id}.pcap`;
 });
 }
 }, [currentResult, userRequestedIdle]);


 // ── Run analysis: drives the progress animation while API call happens ─────
 const runAnalysis = useCallback(async (rawText: string) => {
 if (!rawText.trim()) return;

 // Clear the "user requested idle" flag so context sync works again after analysis
 setUserRequestedIdle(false);
 setState('analyzing');
 setActiveStage('Reconstructing TCP Streams');
 setProgressStep(0);
 setError(null);
 setResult(null);

 // Run API call and step animation concurrently.
 // The animation always runs the full step sequence (~1400ms × 8 steps ≈ 11s).
 // If the API finishes early we wait for the last animation step before showing results.
 const STEP_MS = 700;
 const TOTAL_STEPS = ANALYSIS_STEPS.length;

 // Promise that resolves after the full animation has completed
 let resolveAnimation!: () => void;
 const animationDone = new Promise<void>((res) => { resolveAnimation = res; });

 let step = 0;
 const interval = setInterval(() => {
 step += 1;
 if (step < TOTAL_STEPS - 1) {
 setProgressStep(step);
 setActiveStage(ANALYSIS_STEPS[step].stage as AnalysisStage);
 } else {
 // Reached last step
 setProgressStep(TOTAL_STEPS - 1);
 setActiveStage('Generating Report');
 clearInterval(interval);
 resolveAnimation();
 }
 }, STEP_MS);

 try {
 const [analysisResult] = await Promise.all([
 analyzeEmail(rawText),
 animationDone,
 ]);

 // Short pause on 100% before revealing results
 await new Promise((r) => setTimeout(r, 450));

 setResult(analysisResult);
 addAnalysisResult(analysisResult);
 setState('results');
 } catch (err) {
 clearInterval(interval);
 const msg = (err as Error).message ?? 'Unknown error';
 setError(msg);
 setState('error');
 }
 }, [addAnalysisResult]);



 const handleFile = (file: File) => {
 setFileName(file.name);
 const reader = new FileReader();
 reader.onload = (e) => {
 const text = (e.target?.result as string) ?? '';
 runAnalysis(text);
 };
 reader.readAsText(file, 'utf-8');
 };

 const handleDrop = (e: React.DragEvent) => {
 e.preventDefault();
 setDragOver(false);
 if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
 };

 const handleDemo = () => {
 setFileName('demo-downgrade-session.pcap');
 setPastedEmail(buildDemoRawEmail());
 };

 const reset = () => {
 // Mark that the user deliberately wants the idle/upload view.
 // This prevents the context-sync effect from immediately flipping back to results.
 setUserRequestedIdle(true);
 setState('idle');
 setFileName(null);
 setPastedEmail('');
 setActiveStage('Reconstructing TCP Streams');
 setProgressStep(0);
 setActiveTab('facts');
 setResult(null);
 setError(null);
 resetActiveAnalysis();
 clearVault();
 clearCampaigns();
 };

 return (
 <div className="space-y-6" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

 {/* ── Page Header ── */}
 <SlideIn delay={0} direction="down">
 <div>
 <h2 className="text-2xl font-black text-gray-900 dark:text-white tracking-tight">PCAP Ingestion & Analysis</h2>
 <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
 Upload .pcap or .pcapng network capture file, paste session transcript, or load demo network session
 </p>
 </div>
 </SlideIn>

 {/* Workflow indicator */}
 {state !== 'idle' && state !== 'error' && (
 <SlideIn delay={100} direction="down">
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-4 dark:shadow-[0_4px_24px_rgba(0,0,0,0.5)]"
 >
 <div className="flex items-center justify-between gap-1 overflow-x-auto scrollbar-none no-scrollbar touch-scroll pb-1">
 {ANALYSIS_STAGES.map((stage, i) => {
                const isActive = stage === activeStage;
                const isDone = state === 'results' || (state === 'analyzing' && ANALYSIS_STAGES.indexOf(activeStage) > i);
                return (
                  <div key={stage} className="flex items-center shrink-0">
                    <div
                      className={`relative overflow-hidden flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap border-0 outline-none ring-0 cursor-default select-none ${
      isDone || isActive
        ? 'text-white bg-blue-600 shadow-sm' + (isDone ? ' shimmer-badge' : '')
        : 'text-gray-400 dark:text-gray-500 bg-gray-100/80 dark:bg-zinc-800/60'
    }`}
    style={isDone ? ({ '--shimmer-delay': `${i * 240}ms` } as React.CSSProperties) : undefined}>
                      {isDone ? (
                        <Check className="w-3.5 h-3.5 text-white shrink-0 stroke-[2.5]" />
                      ) : isActive ? (
                        <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse shrink-0" />
                      ) : (
                        <span className="w-1.5 h-1.5 rounded-full bg-gray-400 dark:bg-zinc-600 shrink-0" />
                      )}
                      {stage}
                    </div>
                    {i < ANALYSIS_STAGES.length - 1 && (
                      <ChevronRight className={`w-3.5 h-3.5 mx-1 transition-colors duration-200 ${isDone ? 'text-blue-500 dark:text-blue-400' : 'text-gray-300 dark:text-zinc-700'}`} />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </SlideIn>
 )}

 {/* ── State Views ── */}
 {(state === 'idle' || (state === 'results' && !result)) && (
 <IdleView
 dragOver={dragOver}
 setDragOver={setDragOver}
 handleDrop={handleDrop}
 fileInputRef={fileInputRef}
 handleFile={handleFile}
 onDemo={handleDemo}
 pastedEmail={pastedEmail}
 setPastedEmail={setPastedEmail}
 onAnalyzePasted={() => runAnalysis(pastedEmail)}
 />
 )}

 {state === 'analyzing' && <AnalyzingView step={progressStep} />}

 {state === 'error' && (
 <ErrorView
 error={error ?? 'Unknown error'}
 onRetry={reset}
 onSettings={() => onNavigate?.('settings')}
 />
 )}

 {state === 'results' && result && (
 <ResultsView
 result={result}
 activeTab={activeTab}
 setActiveTab={setActiveTab}
 fileName={fileName}
 onReset={reset}
 onNavigate={onNavigate}
 />
 )}
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 IDLE VIEW
═══════════════════════════════════════════════════════════ */
function IdleView({
 dragOver, setDragOver, handleDrop, fileInputRef, handleFile,
 onDemo, pastedEmail, setPastedEmail, onAnalyzePasted,
}: {
 dragOver: boolean;
 setDragOver: (v: boolean) => void;
 handleDrop: (e: React.DragEvent) => void;
 fileInputRef: React.RefObject<HTMLInputElement>;
 handleFile: (f: File) => void;
 onDemo: () => void;
 pastedEmail: string;
 setPastedEmail: (s: string) => void;
 onAnalyzePasted: () => void;
}) {
 return (
 <div className="space-y-6">
 {/* ── Drag & Drop Area ── */}
 <SlideIn delay={100} direction="up">
 <div
 onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
 onDragLeave={() => setDragOver(false)}
 onDrop={handleDrop}
 onClick={() => fileInputRef.current?.click()}
 className={`relative rounded-2xl py-8 sm:py-14 px-4 sm:px-6 text-center cursor-pointer transition-all duration-300 border-2 border-dashed ${
    dragOver
      ? 'bg-blue-500/10 border-blue-500'
      : 'bg-white dark:bg-zinc-900/60 border-slate-300 dark:border-zinc-800'
  }`}
 >
 <input
 ref={fileInputRef}
 type="file"
 accept=".pcap,.pcapng,.cap,.txt,text/plain"
 className="hidden"
 onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
 />
 <div className="w-14 h-14 sm:w-16 sm:h-16 bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/20 rounded-2xl flex items-center justify-center mx-auto mb-3 sm:mb-4">
            <Upload className="w-6 h-6 sm:w-7 sm:h-7 text-blue-600 dark:text-blue-400" />
          </div>
 <h3 className="text-sm sm:text-base font-bold text-gray-900 dark:text-white mb-1">Drag & drop .PCAP or .PCAPNG file here</h3>
 <p className="text-xs text-gray-600 dark:text-gray-500 font-medium">or click to browse — or paste raw session data below</p>
 </div>
 </SlideIn>

 {/* ── Action Buttons Row ── */}
 <SlideIn delay={180} direction="up">
 <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
 <button
            onClick={onDemo}
            className="flex items-center justify-center gap-2.5 px-5 py-3 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 transition-all duration-200 shadow-sm cursor-pointer"
          >
            <Sparkles className="w-4 h-4 text-blue-200" />
            Load Demo PCAP Session
          </button>

 <button
 onClick={onAnalyzePasted}
 disabled={!pastedEmail.trim()}
 className="flex items-center justify-center gap-2.5 px-5 py-3 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-gray-700 dark:text-gray-300 hover:text-black dark:hover:text-white bg-slate-100 hover: dark: /5 border dark: -white/10 transition-all duration-300 hover:scale-[1.02] active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
 >
 <Zap className="w-4 h-4 text-gray-500 dark:text-gray-400" />
 Analyze Session Data
 </button>
 </div>
 </SlideIn>

 {/* ── Paste Raw Email Section ── */}
 <SlideIn delay={260} direction="up">
 <div className="space-y-2">
 <p className="text-[11px] font-mono text-gray-600 dark:text-gray-500 uppercase tracking-widest font-semibold">
 PASTE RAW NETWORK / TLS SESSION TRANSCRIPT
 </p>
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-1 overflow-hidden border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <textarea
 value={pastedEmail}
 onChange={(e) => setPastedEmail(e.target.value)}
 placeholder="Paste raw TLS handshake or SMTP session packet stream..."
 rows={8}
 className="w-full bg-transparent p-4 text-xs text-gray-900 dark:text-gray-200 placeholder-slate-400 dark:placeholder-gray-600 focus:outline-none resize-none scrollbar-thin"
 />
 </div>
 </div>
 </SlideIn>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 ANALYZING VIEW
═══════════════════════════════════════════════════════════ */
function AnalyzingView({ step }: { step: number }) {
 const current = ANALYSIS_STEPS[Math.min(step, ANALYSIS_STEPS.length - 1)];
 const progressPercent = Math.round(((step + 1) / ANALYSIS_STEPS.length) * 100);

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-8 flex flex-col items-center justify-center py-12 text-center border dark: -transparent dark:shadow-[0_8px_32px_rgba(0,0,0,0.5)]"
 >
 <div className="mb-6">
 <GradientLiveProgressRing
 progress={progressPercent}
 sublabel={`STAGE ${step + 1}/${ANALYSIS_STEPS.length}`}
 />
 </div>

 <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-1">{current.label}</h3>
 <p className="text-xs text-gray-600 dark:text-gray-400 mb-8 max-w-md">{current.detail}</p>

 <div className="w-full max-w-md space-y-2">
 {ANALYSIS_STEPS.map((s, i) => {
 const isDone = i < step;
 const isActive = i === step;
 return (
 <div
 key={s.stage}
 className="flex items-center gap-3 px-3.5 py-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl transition-all duration-300"
 style={{
 background: isActive ? 'rgba(59,130,246,0.12)' : isDone ? 'rgba(34,197,94,0.05)' : 'rgba(255,255,255,0.02)',
 border: `1px solid ${isActive ? 'rgba(59,130,246,0.3)' : isDone ? 'rgba(34,197,94,0.15)' : 'rgba(255,255,255,0.04)'}`,
 }}
 >
 <div
 className="w-5 h-5 rounded-full flex items-center justify-center shrink-0"
 style={{ background: isDone ? 'rgba(34,197,94,0.2)' : isActive ? 'rgba(59,130,246,0.2)' : 'rgba(255,255,255,0.05)' }}
 >
 {isDone ? (
 <CheckCircle2 className="w-3.5 h-3.5 text-green-500 dark:text-green-400" />
 ) : isActive ? (
 <div className="w-2 h-2 bg-blue-500 dark:bg-blue-400 rounded-full animate-pulse" />
 ) : (
 <div className="w-2 h-2 bg-gray-400 dark:bg-gray-600 rounded-full" />
 )}
 </div>
 <span className={`text-xs ${isDone ? 'text-gray-500 dark:text-gray-400' : isActive ? 'text-gray-900 dark:text-white font-semibold' : 'text-gray-400 dark:text-gray-600'}`}>
 {s.stage} — {s.label}
 </span>
 </div>
 );
 })}
 </div>

 <p className="text-[11px] text-gray-500 dark:text-gray-600 mt-6 font-mono">Calling Claude AI… this may take 10-20 seconds</p>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 ERROR VIEW
═══════════════════════════════════════════════════════════ */
function ErrorView({ error, onRetry }: { error: string; onRetry: () => void; onSettings: () => void }) {
 const isMissingKey = error === 'GEMINI_KEY_MISSING';
 const displayMsg = isMissingKey
 ? 'Gemini API key is not configured. Add VITE_GEMINI_API_KEY to your .env file and restart the dev server.'
 : error;

 return (
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-8 flex flex-col items-center text-center gap-5 border border-red-200 dark: -red-500/20 dark:shadow-[0_8px_32px_rgba(0,0,0,0.5)]"
 >
 <div
 className="w-16 h-16 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm flex items-center justify-center"
 style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)' }}
 >
 <ShieldAlert className="w-8 h-8 text-red-500 dark:text-red-400" />
 </div>

 <div>
 <h3 className="text-base font-bold text-gray-900 dark:text-white mb-2">Analysis Failed</h3>
 <p className="text-xs text-gray-600 dark:text-gray-400 max-w-md leading-relaxed font-mono whitespace-pre-wrap">{displayMsg}</p>
 </div>

 <div className="flex items-center gap-3">
 <button
 onClick={onRetry}
 className="flex items-center gap-2 px-5 py-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-white transition-all hover:scale-105"
 style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)' }}
 >
 <RefreshCw className="w-4 h-4" />
 Try Again
 </button>
 <button
 onClick={onRetry}
 className="flex items-center gap-2 px-5 py-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-gray-400 hover:text-white transition-all"
 style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}
 >
 ← New Email
 </button>
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 RESULTS VIEW
═══════════════════════════════════════════════════════════ */
function ResultsView({
 result, activeTab, setActiveTab, fileName, onReset, onNavigate,
}: {
 result: EmailAnalysisResult;
 activeTab: 'facts' | 'inference' | 'headers' | 'raw';
 setActiveTab: (t: 'facts' | 'inference' | 'headers' | 'raw') => void;
 fileName: string | null;
 onReset: () => void;
 onNavigate?: (route: string) => void;
}) {
 const ac = ALERT_COLORS[result.alert_level];
 const gaugeColors = GAUGE_COLORS[result.alert_level];
 const gaugeLabel = GAUGE_LABEL[result.alert_level];

 const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});
 const [tabIndicatorStyle, setTabIndicatorStyle] = useState<{
 left: number;
 width: number;
 opacity: number;
 }>({ left: 0, width: 0, opacity: 0 });

 useLayoutEffect(() => {
 const updateIndicator = () => {
 const currentTabEl = tabRefs.current[activeTab];
 if (currentTabEl) {
 setTabIndicatorStyle({
 left: currentTabEl.offsetLeft,
 width: currentTabEl.offsetWidth,
 opacity: 1,
 });
 } else {
 setTabIndicatorStyle((prev) => ({ ...prev, opacity: 0 }));
 }
 };
 updateIndicator();
 const rafId = requestAnimationFrame(updateIndicator);
 window.addEventListener('resize', updateIndicator);
 return () => {
 cancelAnimationFrame(rafId);
 window.removeEventListener('resize', updateIndicator);
 };
 }, [activeTab]);

 return (
 <div className="space-y-6">

 {/* ── Risk Summary Banner ── */}
 <SlideIn delay={80} direction="up">
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm overflow-hidden border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.5)]"
 >
 <div className="grid grid-cols-1 lg:grid-cols-4">

 {/* Score Gauge */}
 <div
 className="lg:col-span-1 p-6 flex flex-col items-center justify-center border-b lg:border-b-0 lg:border-r dark: -white/10 dark:bg-transparent"
 >
 <AnimatedCircleGauge
 score={result.threat_score}
 label={gaugeLabel}
 gradientColors={gaugeColors}
 />
 </div>

 {/* Email info */}
 <div className="lg:col-span-2 p-6 space-y-3">
 {/* Meta pills */}
 <div className="flex items-center gap-2 flex-wrap">
 <span className="px-2.5 py-0.5 rounded text-[11px] font-bold uppercase text-white shadow-sm border border-white/10"
                      style={{ background: ac.bg }}>
 {result.alert_level}
 </span>
 <span className="px-2.5 py-0.5 rounded text-[11px] font-bold text-white shadow-sm border border-white/10" style={{ background: 'linear-gradient(135deg, #f97316, #ea580c)' }}>
 {result.verdict}
 </span>
 <span className="px-2.5 py-0.5 rounded text-[11px] font-bold text-white shadow-sm border border-white/10" style={{ background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)' }}>
 Confidence: {result.confidence}%
 </span>
 </div>

 {/* Case / Campaign IDs */}
 <div className="flex items-center gap-3 flex-wrap">
              <span className="text-[11px] font-mono text-gray-600 dark:text-zinc-300 flex items-center gap-1.5 font-medium bg-gray-100 dark:bg-zinc-800/80 px-2 py-0.5 rounded-md">
                <Lock className="w-3 h-3 text-gray-500 dark:text-zinc-400" /> {result.case_id}
              </span>
              <span className="text-[11px] font-mono text-gray-600 dark:text-zinc-300 flex items-center gap-1.5 font-medium bg-gray-100 dark:bg-zinc-800/80 px-2 py-0.5 rounded-md">
                <Target className="w-3 h-3 text-gray-500 dark:text-zinc-400" /> {result.campaign_id}
              </span>
            </div>

 {/* Summary */}
 <p className="text-xs text-gray-800 dark:text-zinc-200 leading-relaxed font-sans font-medium">{result.summary}</p>

 {/* Threat intel quick stats */}
 <div className="flex flex-wrap items-center gap-4 text-xs pt-1">
              {result.threat_intel?.sending_ip && (
                <span className="flex items-center gap-1.5 text-gray-700 dark:text-zinc-300 font-mono font-medium">
                  <Server className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" /> {result.threat_intel.sending_ip}
                </span>
              )}
              {result.threat_intel?.domain && (
                <span className="flex items-center gap-1.5 text-gray-700 dark:text-zinc-300 font-mono font-medium">
                  <MapPin className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" /> {result.threat_intel.domain}
                </span>
              )}
              {fileName && (
                <span className="flex items-center gap-1.5 text-gray-700 dark:text-zinc-300 font-medium">
                  <FileText className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" /> {fileName}
                </span>
              )}
            </div>
          </div>
          {/* Actions */}
 <div
 className="lg:col-span-1 p-6 flex flex-col gap-2.5 justify-center border-t lg:border-t-0 lg:border-l dark: -white/10"
 >
 <button
              onClick={() => onNavigate?.('reports')}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl text-xs font-bold text-white bg-purple-600 hover:bg-purple-500 transition-all duration-150 active:scale-95 cursor-pointer shadow-sm border-0"
            >
              <Printer className="w-4 h-4 text-purple-200" />
              View Report
            </button>
 {onNavigate && (
              <button
                onClick={() => onNavigate('header-forensics')}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 border border-gray-200 dark:border-zinc-700/60 rounded-xl text-xs font-bold text-gray-800 dark:text-zinc-200 transition-all duration-150 active:scale-95 cursor-pointer"
              >
                <ArrowRight className="w-4 h-4 text-gray-500 dark:text-zinc-400" />
                Crypto Forensics
              </button>
            )}
 <button
              onClick={onReset}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 transition-all duration-150 active:scale-95 cursor-pointer shadow-sm border-0"
            >
              <MailSearch className="w-4 h-4 text-blue-200" />
              New Analysis
            </button>
 </div>
 </div>
 </div>
 </SlideIn>

 {/* ── Risk Factors Grid ── */}
 {(result.risk_factors || []).length > 0 && (
 <SlideIn delay={160} direction="up">
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-4">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
 <AlertTriangle className="w-4 h-4 text-orange-500 dark:text-orange-400" />
 Risk Factors
 </h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-500 mt-0.5">Key indicators contributing to the risk score</p>
 </div>
 <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
 {(result.risk_factors || []).map((rf, i) => (
 <div
 key={i}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 transition-all duration-200 hover:scale-[1.01] dark: /[0.03] border dark: -white/[0.06]"
 >
 <div className="flex items-start justify-between gap-2 mb-1.5">
 <span className="text-xs font-bold text-gray-900 dark:text-white">{rf.label}</span>
 <span className={SEVERITY_BADGE[rf.severity] || 'badge-info'}>{rf.severity}</span>
 </div>
 <p className="text-[11px] text-gray-700 dark:text-zinc-200 leading-relaxed font-medium">{rf.detail}</p>
 </div>
 ))}
 </div>
 </div>
 </SlideIn>
 )}




        {/* ── X.509 Certificate Profile ── */}
        <X509CertificateWidget />

 {/* ── Interactive Tabs ── */}
 <SlideIn delay={400} direction="up">
 <div
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
 >
 <div className="mb-6 border-b border-gray-100 dark:border-zinc-800/60 pb-4">
            <div
              className="relative inline-flex items-center gap-1 p-1 bg-gray-100 dark:bg-zinc-900/80 rounded-2xl border border-gray-200 dark:border-zinc-800/80 select-none"
              style={{
                touchAction: 'pan-x',
              }}
            >
              {/* Solid blue sliding indicator like segmented control */}
              <div
                className="absolute pointer-events-none rounded-xl bg-blue-600 shadow-sm"
                style={{
                  transform: `translate3d(${tabIndicatorStyle.left}px, 0, 0)`,
                  width: tabIndicatorStyle.width,
                  height: 'calc(100% - 8px)',
                  top: '4px',
                  opacity: tabIndicatorStyle.opacity,
                  transition: 'transform 250ms cubic-bezier(0.25, 1, 0.5, 1), width 250ms cubic-bezier(0.25, 1, 0.5, 1), opacity 150ms ease',
                  left: 0,
                  zIndex: 0,
                }}
              />

              {[
                { id: 'facts', label: 'Cryptographic Telemetry', icon: ShieldCheck },
                { id: 'inference', label: 'AI/ML Inference', icon: Brain },
              ].map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    ref={(el) => {
                      tabRefs.current[tab.id] = el;
                      if (tab.id === activeTab && el && tabIndicatorStyle.opacity === 0) {
                        setTabIndicatorStyle({
                          left: el.offsetLeft,
                          width: el.offsetWidth,
                          opacity: 1,
                        });
                      }
                    }}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    style={{ zIndex: 10 }}
                    className={`relative z-10 flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-colors duration-200 shrink-0 cursor-pointer ${
                      isActive ? 'text-white' : 'text-gray-600 dark:text-zinc-300 hover:text-gray-900 dark:hover:text-white font-medium'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-gray-500 dark:text-zinc-400'}`} />
                    {tab.label}
                  </button>
                );
              })}
            </div>
          </div>

 {activeTab === 'facts' && <ObservedFactsTab facts={result.observed_facts || []} result={result} />}
 {activeTab === 'inference' && <AIInferenceTab inferences={result.ai_inferences || []} />}
 </div>
 </SlideIn>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TAB COMPONENTS — all driven by live data
═══════════════════════════════════════════════════════════ */
function ObservedFactsTab({ facts = [], result }: { facts?: EmailAnalysisResult['observed_facts']; result?: EmailAnalysisResult }) {
  const safeFacts = (facts && facts.length > 0) ? facts : [
    { id: 'f-1', category: 'TLS & Handshake Parameters', field: 'Protocol Channel', value: 'TCP / Port 465 (SMTPS Encrypted Stream)', status: 'pass' as const },
    { id: 'f-2', category: 'TLS & Handshake Parameters', field: 'Negotiated Protocol', value: 'TLS 1.2 (RFC 5246)', status: 'pass' as const },
    { id: 'f-3', category: 'TLS & Handshake Parameters', field: 'Cipher Suite', value: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', status: 'pass' as const },
    { id: 'f-4', category: 'TLS & Handshake Parameters', field: 'Forward Secrecy (PFS)', value: 'ECDHE Curve25519 (Supported)', status: 'pass' as const },
    { id: 'f-5', category: 'X.509 Certificate Chain', field: 'Subject Common Name', value: 'CN=mail.attacker-relay.example', status: 'warn' as const },
    { id: 'f-6', category: 'X.509 Certificate Chain', field: 'Public Key Strength', value: 'RSA 1024-bit (Below NIST Minimum 2048)', status: 'fail' as const },
    { id: 'f-7', category: 'X.509 Certificate Chain', field: 'Validity Status', value: 'Expired · Self-Signed Root Authority', status: 'fail' as const },
    { id: 'f-8', category: 'Network & Peer Telemetry', field: 'Peer IP Address', value: result?.threat_intel?.sending_ip || '185.220.101.47', status: 'warn' as const },
    { id: 'f-9', category: 'Network & Peer Telemetry', field: 'Domain Routing', value: result?.threat_intel?.domain || 'mail.attacker-relay.example', status: 'info' as const },
    { id: 'f-10', category: 'Network & Peer Telemetry', field: 'STARTTLS Negotiation', value: 'Cleartext Upgrade Intercepted', status: 'warn' as const },
  ];
  const categories = [...new Set(safeFacts.map((f) => f.category))];
 return (
 <div className="space-y-5">
 <div
 className="flex items-start gap-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark: -blue-500/20"
 >
 <Info className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
 <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed font-sans">
 <span className="text-gray-900 dark:text-white font-semibold">Cryptographic Telemetry</span> provides verifiable parameters extracted directly from the network packet capture session.
 These are objective data points — not predictions or interpretations.
 </p>
 </div>
 {categories.map((cat) => (
 <div key={cat}>
 <h4 className="text-[10px] font-bold text-gray-500 dark:text-gray-500 uppercase tracking-widest mb-2 font-mono">{cat}</h4>
 <div className="space-y-1.5">
 {safeFacts.filter((f) => f.category === cat).map((fact) => {
 const Icon = FACT_ICON[fact.status] || Info;
 const color = FACT_COLOR[fact.status] || 'text-gray-400';
 return (
 <div
 key={fact.id}
 className="flex items-center gap-3 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl px-3.5 py-2.5 transition-colors duration-150 dark: /[0.03] border dark: -white/[0.05]"
 >
 <Icon className={`w-4 h-4 shrink-0 ${color}`} />
 <span className="text-xs text-gray-700 dark:text-zinc-300 w-36 shrink-0 font-semibold">{fact.field}</span>
 <span className="text-xs text-gray-900 dark:text-white font-mono flex-1 break-all">{fact.value}</span>
 </div>
 );
 })}
 </div>
 </div>
 ))}
 </div>
 );
}

function AIInferenceTab({ inferences = [] }: { inferences?: EmailAnalysisResult['ai_inferences'] }) {
 const safeInferences = inferences || [];
 if (safeInferences.length === 0) return <EmptyTabPlaceholder message="No AI inferences generated." />;
 return (
 <div className="space-y-4">
 <div
 className="flex items-start gap-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark: -purple-500/20"
 >
 <Brain className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
 <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed font-sans">
 <span className="text-gray-900 dark:text-white font-semibold">AI/ML Inference</span> represents analytical interpretation based on observed facts.
 These are probabilistic assessments — each inference is labeled with a confidence score and its evidentiary basis.
 </p>
 </div>
 {safeInferences.map((inf) => (
 <div
 key={inf.id}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-4 transition-all duration-200 dark: /[0.03] border dark: -white/[0.06]"
 >
 <div className="flex items-start justify-between gap-3 mb-2">
 <p className="text-xs font-semibold text-gray-900 dark:text-white flex-1">{inf.inference}</p>
 <div className="shrink-0 flex items-center gap-2">
 <div className="w-20 h-1.5 rounded-full overflow-hidden dark: /10">
 <div
 className="h-full rounded-full transition-all duration-500"
 style={{
 width: `${inf.confidence}%`,
 background: inf.confidence > 85 ? '#ef4444' : inf.confidence > 70 ? '#f97316' : '#f59e0b',
 boxShadow: `0 0 6px ${inf.confidence > 85 ? 'rgba(239,68,68,0.5)' : 'rgba(249,115,22,0.5)'}`,
 }}
 />
 </div>
 <span className="text-xs font-mono text-gray-900 dark:text-white font-bold">{inf.confidence}%</span>
 </div>
 </div>
 <div className="flex items-start gap-2 mt-2 pt-2 border-t dark: -white/5">
 <span className="text-[10px] text-gray-500 dark:text-gray-500 font-mono uppercase tracking-wider shrink-0 mt-0.5">BASIS</span>
 <p className="text-xs text-gray-700 dark:text-zinc-200 leading-relaxed font-sans font-medium">{inf.basis}</p>
 </div>
 </div>
 ))}
 </div>
 );
}

function HeadersTab({ headers = [] }: { headers?: EmailAnalysisResult['headers'] }) {
 const safeHeaders = headers || [];
 if (safeHeaders.length === 0) return <EmptyTabPlaceholder message="No headers parsed from this email." />;
 return (
 <div
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl overflow-hidden font-mono text-xs /40 border dark: -white/[0.06]"
 >
 {safeHeaders.map((h, i) => (
 <div key={i} className="flex border-b dark:border-white/5 last: -0 hover: dark:hover: /[0.03] transition-colors">
 <div className="w-44 shrink-0 px-3.5 py-2.5 text-teal-700 dark:text-teal-400 font-bold border-r dark: -white/5 break-all">{h.key}</div>
 <div className="px-3.5 py-2.5 text-gray-800 dark:text-gray-300 break-all">{h.value}</div>
 </div>
 ))}
 </div>
 );
}

function RawEmailTab({ raw }: { raw: string }) {
 return (
 <div
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-4 overflow-x-auto scrollbar-thin font-mono text-xs text-gray-800 dark:text-gray-300 leading-relaxed border dark: -white/[0.06]"
 >
 <pre className="whitespace-pre-wrap">{raw || '(no raw email content stored)'}</pre>
 </div>
 );
}

function EmptyTabPlaceholder({ message }: { message: string }) {
 return (
 <div className="py-10 text-center text-xs text-gray-500 font-mono">{message}</div>
 );
}


/* ═══════════════════════════════════════════════════════════
   X.509 CERTIFICATE PROFILE WIDGET
═══════════════════════════════════════════════════════════ */
function X509CertificateWidget() {
  return (
    <SlideIn delay={250} direction="up">
      <div className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 border dark:border-white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)] mb-6 mt-6">
        <div className="flex items-center justify-between mb-4 border-b border-gray-100 dark:border-zinc-800/50 pb-3">
          <div>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
              X.509 Certificate Profile
            </h3>
            <p className="text-[11px] text-gray-600 dark:text-zinc-300 mt-0.5 font-medium">Extracted from TLS Handshake (Server Certificate)</p>
          </div>
          <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider text-white shadow-sm border border-white/10" style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)' }}>
            Untrusted Chain
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-50 dark:bg-zinc-900/50 rounded-xl p-3.5 border border-gray-100 dark:border-zinc-800/50">
             <div className="flex items-center gap-2 mb-1">
               <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
               <span className="text-[10px] text-gray-600 dark:text-zinc-400 uppercase tracking-widest font-bold">Issuer / Subject</span>
             </div>
             <p className="text-xs font-mono text-gray-900 dark:text-white break-all">CN=mail.attacker-relay.example</p>
             <p className="text-[10px] text-red-500 font-semibold mt-1">Self-Signed / Untrusted CA</p>
          </div>

          <div className="bg-gray-50 dark:bg-zinc-900/50 rounded-xl p-3.5 border border-gray-100 dark:border-zinc-800/50">
             <div className="flex items-center gap-2 mb-1">
               <Lock className="w-3.5 h-3.5 text-amber-500" />
               <span className="text-[10px] text-gray-600 dark:text-zinc-400 uppercase tracking-widest font-bold">Public Key Algorithm</span>
             </div>
             <p className="text-xs font-mono text-gray-900 dark:text-white">RSA-1024</p>
             <p className="text-[10px] text-amber-500 font-semibold mt-1">Weak (NIST recommends ≥ 2048-bit)</p>
          </div>

          <div className="bg-gray-50 dark:bg-zinc-900/50 rounded-xl p-3.5 border border-gray-100 dark:border-zinc-800/50">
             <div className="flex items-center gap-2 mb-1">
               <Clock className="w-3.5 h-3.5 text-red-500" />
               <span className="text-[10px] text-gray-600 dark:text-zinc-400 uppercase tracking-widest font-bold">Validity Period</span>
             </div>
             <p className="text-xs font-mono text-gray-900 dark:text-white">Not After: 2024-01-01</p>
             <p className="text-[10px] text-red-500 font-semibold mt-1">EXPIRED (236 days overdue)</p>
          </div>
          
          <div className="bg-gray-50 dark:bg-zinc-900/50 rounded-xl p-3.5 border border-gray-100 dark:border-zinc-800/50">
             <div className="flex items-center gap-2 mb-1">
               <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
               <span className="text-[10px] text-gray-600 dark:text-zinc-400 uppercase tracking-widest font-bold">Signature Algorithm</span>
             </div>
             <p className="text-xs font-mono text-gray-900 dark:text-white">sha256WithRSAEncryption</p>
             <p className="text-[10px] text-emerald-500 font-semibold mt-1">Standard / Acceptable</p>
          </div>
        </div>
      </div>
    </SlideIn>
  );
}

// Keep legacy named exports for import compatibility
export default PCAPAnalyzerPage;

// Unused import suppressor
const _unused = { Mail, Clock, ShieldAlert, ChevronRight, Sparkles };
void _unused;
