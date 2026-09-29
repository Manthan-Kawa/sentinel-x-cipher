import { useState, useMemo } from 'react';
import {
  Lock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Upload,
  ClipboardList,
  RefreshCw,
  Eye,
  Server,
  Globe,
  Activity,
  CheckCircle2,
  XCircle,
  X,
  Radio,
  Sparkles,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  Key,
  Cpu,
  FileCode,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useTickets } from '@/contexts/TicketContext';
import { SlideIn } from '@/components/SlideIn';

interface EmailsPageProps {
  onNavigate: (route: string, opts?: { role?: 'analyst' | 'user' }) => void;
}

export type SessionPosture = 'secure' | 'warning' | 'critical';
export type TlsVersion = 'TLS 1.3' | 'TLS 1.2' | 'TLS 1.0' | 'SSL 3.0';

export interface NetworkSession {
  id: string;
  timestamp: string;
  clientIp: string;
  serverHost: string;
  serverIp: string;
  serverPort: number;
  sni: string;
  protocol: string;
  tlsVersion: TlsVersion;
  cipherSuite: string;
  keyExchange: string;
  posture: SessionPosture;
  threatScore: number;
  alpn: string;
  certificate: {
    subject: string;
    issuer: string;
    validity: string;
    isExpired: boolean;
    keyType: string;
    sigAlg: string;
    status: 'valid' | 'expired' | 'self-signed' | 'weak-key';
  };
  vulnerabilities: string[];
  recommendation: string;
  bytesTransferred: string;
  durationMs: number;
}

const MOCK_SESSIONS: NetworkSession[] = [
  {
    id: 'SESS-9821-TLS',
    timestamp: 'Just now',
    clientIp: '192.168.1.104:54320',
    serverHost: 'api.payment-auth.net',
    serverIp: '104.21.54.12',
    serverPort: 443,
    sni: 'api.payment-auth.net',
    protocol: 'HTTPS / 443',
    tlsVersion: 'TLS 1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    keyExchange: 'ECDH (x25519) - 253 bits',
    posture: 'secure',
    threatScore: 4,
    alpn: 'h2',
    certificate: {
      subject: 'CN=api.payment-auth.net, O=Cloud Payments Inc, C=US',
      issuer: 'Let\'s Encrypt Authority R3',
      validity: 'Valid (Expires in 64 days)',
      isExpired: false,
      keyType: 'ECC P-256',
      sigAlg: 'SHA256withECDSA',
      status: 'valid',
    },
    vulnerabilities: [],
    recommendation: 'Session complies with strict cryptographic posture standards. Modern forward secrecy enabled.',
    bytesTransferred: '142.8 KB',
    durationMs: 82,
  },
  {
    id: 'SESS-9784-SMTP',
    timestamp: '3m ago',
    clientIp: '192.168.1.104:49812',
    serverHost: 'mail-legacy.telecom-partner.org',
    serverIp: '185.220.101.47',
    serverPort: 465,
    sni: 'mail-legacy.telecom-partner.org',
    protocol: 'SMTPS / 465',
    tlsVersion: 'TLS 1.0',
    cipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    keyExchange: 'Static RSA (No Forward Secrecy)',
    posture: 'critical',
    threatScore: 94,
    alpn: 'none',
    certificate: {
      subject: 'CN=mail-legacy.telecom-partner.org, OU=IT Dept',
      issuer: 'Untrusted Enterprise Self-Signed Root CA',
      validity: 'Expired (Expired 28 days ago)',
      isExpired: true,
      keyType: 'RSA 1024-bit',
      sigAlg: 'SHA1withRSA',
      status: 'expired',
    },
    vulnerabilities: [
      'SWEET32 64-bit block cipher attack (CVE-2016-2183)',
      'Deprecated TLS 1.0 protocol (RFC 8996 violation)',
      'Static RSA key exchange (Lacks Perfect Forward Secrecy)',
      'Expired X.509 certificate with weak 1024-bit RSA key',
    ],
    recommendation: 'Immediate action: Terminate connection. Enforce TLS 1.3/1.2 minimum and upgrade server certificate to 2048-bit RSA or ECC P-256.',
    bytesTransferred: '2.4 MB',
    durationMs: 420,
  },
  {
    id: 'SESS-9650-IMAP',
    timestamp: '9m ago',
    clientIp: '192.168.1.104:51204',
    serverHost: 'imap.corporate-mail.internal',
    serverIp: '172.16.4.22',
    serverPort: 993,
    sni: 'imap.corporate-mail.internal',
    protocol: 'IMAPS / 993',
    tlsVersion: 'TLS 1.2',
    cipherSuite: 'ECDHE-RSA-AES128-GCM-SHA256',
    keyExchange: 'ECDH (secp256r1) - 256 bits',
    posture: 'secure',
    threatScore: 12,
    alpn: 'imap',
    certificate: {
      subject: 'CN=imap.corporate-mail.internal, O=Internal Mail Infrastructure',
      issuer: 'Corporate Internal PKI Sub-CA 1',
      validity: 'Valid (Expires in 280 days)',
      isExpired: false,
      keyType: 'RSA 2048-bit',
      sigAlg: 'SHA256withRSA',
      status: 'valid',
    },
    vulnerabilities: [],
    recommendation: 'Cryptographic configuration is solid. Recommend scheduling TLS 1.3 enablement during next maintenance window.',
    bytesTransferred: '680.5 KB',
    durationMs: 145,
  },
  {
    id: 'SESS-9512-VPN',
    timestamp: '18m ago',
    clientIp: '192.168.1.104:48122',
    serverHost: 'gateway-us-east.remote-vpn.net',
    serverIp: '198.51.100.88',
    serverPort: 443,
    sni: 'gateway-us-east.remote-vpn.net',
    protocol: 'HTTPS / 443',
    tlsVersion: 'TLS 1.2',
    cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
    keyExchange: 'Static RSA (No Forward Secrecy)',
    posture: 'critical',
    threatScore: 91,
    alpn: 'http/1.1',
    certificate: {
      subject: 'CN=gateway-us-east.remote-vpn.net, O=VPN Services Ltd',
      issuer: 'Sectigo RSA Domain Validation CA',
      validity: 'Valid (Expires in 110 days)',
      isExpired: false,
      keyType: 'RSA 2048-bit',
      sigAlg: 'SHA256withRSA',
      status: 'valid',
    },
    vulnerabilities: [
      'RC4 broken stream cipher (RFC 7465 prohibited)',
      'Static RSA key exchange vulnerable to passive decryption',
      'Potential Man-in-the-Middle cipher downgrade detected',
    ],
    recommendation: 'Remove RC4 from server cipher suites. Enforce modern AEAD suites (AES-GCM or CHACHA20-POLY1305).',
    bytesTransferred: '5.1 MB',
    durationMs: 890,
  },
  {
    id: 'SESS-9440-WEB',
    timestamp: '25m ago',
    clientIp: '192.168.1.104:53991',
    serverHost: 'cdn.static-assets.cloud',
    serverIp: '151.101.65.140',
    serverPort: 443,
    sni: 'cdn.static-assets.cloud',
    protocol: 'HTTPS / 443',
    tlsVersion: 'TLS 1.3',
    cipherSuite: 'TLS_CHACHA20_POLY1305_SHA256',
    keyExchange: 'ECDH (x25519) - 253 bits',
    posture: 'secure',
    threatScore: 2,
    alpn: 'h2',
    certificate: {
      subject: 'CN=*.static-assets.cloud, O=Global CDN Corp',
      issuer: 'DigiCert Global Root G2',
      validity: 'Valid (Expires in 312 days)',
      isExpired: false,
      keyType: 'ECC P-384',
      sigAlg: 'SHA384withECDSA',
      status: 'valid',
    },
    vulnerabilities: [],
    recommendation: 'Optimal cryptographic setup with quantum-resistant forward secrecy and high-speed AEAD encryption.',
    bytesTransferred: '1.8 MB',
    durationMs: 64,
  },
  {
    id: 'SESS-9302-API',
    timestamp: '42m ago',
    clientIp: '192.168.1.104:56102',
    serverHost: 'legacy-billing.vendor-connect.io',
    serverIp: '203.0.113.45',
    serverPort: 443,
    sni: 'legacy-billing.vendor-connect.io',
    protocol: 'HTTPS / 443',
    tlsVersion: 'TLS 1.2',
    cipherSuite: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    keyExchange: 'Static RSA (No Forward Secrecy)',
    posture: 'warning',
    threatScore: 68,
    alpn: 'http/1.1',
    certificate: {
      subject: 'CN=legacy-billing.vendor-connect.io, O=Vendor Connect',
      issuer: 'GoDaddy Secure Certificate Authority - G2',
      validity: 'Valid (Expires in 45 days)',
      isExpired: false,
      keyType: 'RSA 2048-bit',
      sigAlg: 'SHA256withRSA',
      status: 'valid',
    },
    vulnerabilities: [
      'CBC mode padding oracle vulnerability risk (Lucky13 / POODLE-TLS)',
      'Static RSA key exchange lacks forward secrecy',
      'SHA-1 MAC used for message integrity',
    ],
    recommendation: 'Transition cipher suite to ECDHE-ECDSA-AES256-GCM-SHA384 or upgrade server endpoint to TLS 1.3.',
    bytesTransferred: '312.4 KB',
    durationMs: 198,
  },
  {
    id: 'SESS-9150-DOH',
    timestamp: '1h ago',
    clientIp: '192.168.1.104:58210',
    serverHost: 'dns.quad9.net',
    serverIp: '9.9.9.9',
    serverPort: 853,
    sni: 'dns.quad9.net',
    protocol: 'DoT / 853',
    tlsVersion: 'TLS 1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    keyExchange: 'ECDH (x25519) - 253 bits',
    posture: 'secure',
    threatScore: 0,
    alpn: 'dot',
    certificate: {
      subject: 'CN=dns.quad9.net, O=Quad9 Foundation',
      issuer: 'DigiCert TLS RSA SHA256 2020 CA1',
      validity: 'Valid (Expires in 184 days)',
      isExpired: false,
      keyType: 'RSA 2048-bit',
      sigAlg: 'SHA256withRSA',
      status: 'valid',
    },
    vulnerabilities: [],
    recommendation: 'DNS-over-TLS query channel verified secure with pristine certificate verification.',
    bytesTransferred: '48.2 KB',
    durationMs: 32,
  },
  {
    id: 'SESS-8920-C2',
    timestamp: '1h 30m ago',
    clientIp: '192.168.1.104:47102',
    serverHost: 'update-svc-auth.dark-route.xyz',
    serverIp: '185.220.101.99',
    serverPort: 443,
    sni: 'update-svc-auth.dark-route.xyz',
    protocol: 'HTTPS / 443',
    tlsVersion: 'SSL 3.0',
    cipherSuite: 'TLS_RSA_WITH_DES_CBC_SHA',
    keyExchange: 'Static RSA (No Forward Secrecy)',
    posture: 'critical',
    threatScore: 98,
    alpn: 'none',
    certificate: {
      subject: 'CN=update-svc-auth.dark-route.xyz',
      issuer: 'Untrusted Self-Signed Test CA',
      validity: 'Self-Signed (Untrusted Root CA)',
      isExpired: false,
      keyType: 'RSA 512-bit (Extremely Weak)',
      sigAlg: 'MD5withRSA',
      status: 'self-signed',
    },
    vulnerabilities: [
      'Critical: SSL 3.0 protocol used (POODLE vulnerable, RFC 7568 deprecated)',
      'DES 56-bit encryption key — easily crackable within hours',
      'MD5 signature algorithm is broken and susceptible to collision attacks',
      'Untrusted self-signed certificate signature',
    ],
    recommendation: 'Isolate host endpoint immediately. Signature matches known Command & Control (C2) cryptographic profile.',
    bytesTransferred: '18.4 KB',
    durationMs: 512,
  },
];

export function EmailsPage({ onNavigate }: EmailsPageProps) {
  const { currentUser } = useAuth();
  const { submitTicket } = useTickets();

  const [sessions, setSessions] = useState<NetworkSession[]>(MOCK_SESSIONS);
  const [filterPosture, setFilterPosture] = useState<'all' | 'critical' | 'secure' | 'tls13' | 'tls12'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSession, setSelectedSession] = useState<NetworkSession | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [escalatedMap, setEscalatedMap] = useState<Record<string, boolean>>({});
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 6;

  // Filtered sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      // Filter tab
      if (filterPosture === 'critical') {
        if (s.posture !== 'critical' && s.posture !== 'warning') return false;
      } else if (filterPosture === 'secure') {
        if (s.posture !== 'secure') return false;
      } else if (filterPosture === 'tls13') {
        if (s.tlsVersion !== 'TLS 1.3') return false;
      } else if (filterPosture === 'tls12') {
        if (s.tlsVersion !== 'TLS 1.2') return false;
      }

      // Search query
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const matchHost = s.serverHost.toLowerCase().includes(q);
        const matchIp = s.serverIp.toLowerCase().includes(q) || s.clientIp.toLowerCase().includes(q);
        const matchCipher = s.cipherSuite.toLowerCase().includes(q);
        const matchTls = s.tlsVersion.toLowerCase().includes(q);
        const matchSni = s.sni.toLowerCase().includes(q);
        if (!matchHost && !matchIp && !matchCipher && !matchTls && !matchSni) {
          return false;
        }
      }
      return true;
    });
  }, [sessions, filterPosture, searchQuery]);

  const totalPages = Math.ceil(filteredSessions.length / itemsPerPage) || 1;
  const paginatedSessions = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredSessions.slice(start, start + itemsPerPage);
  }, [filteredSessions, currentPage, itemsPerPage]);

  const stats = useMemo(() => {
    const total = sessions.length;
    const tls13Count = sessions.filter((s) => s.tlsVersion === 'TLS 1.3').length;
    const weakCiphers = sessions.filter((s) => s.posture === 'warning' || s.posture === 'critical').length;
    const criticalThreats = sessions.filter((s) => s.posture === 'critical').length;
    return { total, tls13Count, weakCiphers, criticalThreats };
  }, [sessions]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setStatusMessage('Refreshing network packet telemetry streams...');
    setTimeout(() => {
      setIsRefreshing(false);
      setStatusMessage('Telemetry updated: 8 live TLS sessions synchronized.');
      setTimeout(() => setStatusMessage(null), 4000);
    }, 900);
  };

  const handleEscalateToSoc = async (session: NetworkSession) => {
    try {
      await submitTicket({
        userEmail: currentUser?.email || 'user@company.com',
        userComment: `Cryptographic Vulnerability Alert: ${session.serverHost} (${session.cipherSuite})\nHost: ${session.serverHost} (${session.serverIp})\nProtocol: ${session.protocol} | ${session.tlsVersion}\nCipher: ${session.cipherSuite}\nIdentified Flaws: ${session.vulnerabilities.join('; ')}\nRecommendation: ${session.recommendation}`,
        emlFile: null,
        emailId: session.id,
        priority: session.posture === 'critical' ? 'critical' : 'high',
        threatCategory: 'Weak Cipher / Downgrade Attack',
      });

      setEscalatedMap((prev) => ({ ...prev, [session.id]: true }));
      setStatusMessage(`Session ${session.id} successfully escalated to SOC Analysts for PCAP review!`);
      setTimeout(() => setStatusMessage(null), 5000);
    } catch (e) {
      console.error(e);
      setStatusMessage('Failed to escalate session.');
    }
  };

  const renderPostureBadge = (posture: SessionPosture, score: number) => {
    if (posture === 'critical') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
          <span>Critical Risk ({score})</span>
        </span>
      );
    }
    if (posture === 'warning') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>Vulnerable ({score})</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
        <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
        <span>Secure ({score})</span>
      </span>
    );
  };

  const renderTlsBadge = (tls: TlsVersion) => {
    switch (tls) {
      case 'TLS 1.3':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wide uppercase bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
            TLS 1.3 (Modern)
          </span>
        );
      case 'TLS 1.2':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wide uppercase bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-500/30">
            TLS 1.2 (Standard)
          </span>
        );
      case 'TLS 1.0':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wide uppercase bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30">
            TLS 1.0 (Deprecated)
          </span>
        );
      case 'SSL 3.0':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold tracking-wide uppercase bg-red-500/25 text-red-600 dark:text-red-400 border border-red-500/40">
            SSL 3.0 (Broken)
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 text-slate-900 dark:text-white pb-16">
      {/* ── Top Header Banner ── */}
      <SlideIn delay={0} direction="down">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 lg:p-6 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm dark:shadow-2xl relative overflow-hidden">
          <div className="flex items-start sm:items-center gap-4 min-w-0">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-violet-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center shrink-0 shadow-inner">
              <Lock className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-black tracking-tight text-slate-900 dark:text-white">
                  Cryptographic Network Sessions
                </h1>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  Live DPI Engine (eth0)
                </span>
                <span className="hidden sm:inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                  <Sparkles className="w-3 h-3" />
                  Zero Plaintext Enforced
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
                Continuous TLS handshake telemetry, cipher suite strength auditing & encrypted stream classification.
              </p>
            </div>
          </div>

          {/* Action buttons: Equal 3-column grid on mobile, inline-flex on larger screens */}
          <div className="grid grid-cols-3 gap-2 w-full lg:w-auto lg:flex lg:items-center lg:gap-2.5 shrink-0 pt-2 lg:pt-0">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="w-full lg:w-auto h-10 flex items-center justify-center gap-1.5 sm:gap-2 px-2 sm:px-3.5 rounded-xl font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-white/5 hover:bg-slate-200 dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 transition-all cursor-pointer active:scale-95 disabled:opacity-50"
              title="Refresh session telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 shrink-0 ${isRefreshing ? 'animate-spin text-cyan-500' : ''}`} />
              <span className="whitespace-nowrap text-[11px] sm:text-xs">Refresh</span>
            </button>

            <button
              onClick={() => onNavigate('check-status')}
              className="w-full lg:w-auto h-10 flex items-center justify-center gap-1.5 sm:gap-2 px-2 sm:px-3.5 rounded-xl font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-white/5 hover:bg-slate-200 dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 transition-all cursor-pointer active:scale-95"
            >
              <ClipboardList className="w-3.5 h-3.5 text-violet-500 shrink-0" />
              <span className="whitespace-nowrap text-[11px] sm:text-xs">Check Status</span>
            </button>

            <button
              onClick={() => onNavigate('submit-report')}
              className="w-full lg:w-auto h-10 flex items-center justify-center gap-1.5 sm:gap-2 px-2 sm:px-4 rounded-xl font-bold text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 shadow-md shadow-cyan-500/20 transition-all cursor-pointer active:scale-95"
            >
              <Upload className="w-3.5 h-3.5 shrink-0" />
              <span className="whitespace-nowrap text-[11px] sm:text-xs">Submit PCAP</span>
            </button>
          </div>
        </div>
      </SlideIn>

      {/* Notification Toast */}
      {statusMessage && (
        <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-700 dark:text-cyan-300 text-xs font-medium flex items-center justify-between gap-3 animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-500 animate-pulse shrink-0" />
            <span>{statusMessage}</span>
          </div>
          <button onClick={() => setStatusMessage(null)} className="p-1 hover:bg-cyan-500/20 rounded-md">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* ── KPI Metrics Grid ── */}
      <SlideIn delay={100} direction="up">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4">
          {/* Card 1 */}
          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Monitored Sessions
              </span>
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Activity className="w-4 h-4 text-blue-500" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white">
              {stats.total.toLocaleString()}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Active TCP / TLS streams
            </p>
          </div>

          {/* Card 2 */}
          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                TLS 1.3 Active
              </span>
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-emerald-600 dark:text-emerald-400">
              {stats.tls13Count}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Modern Forward Secrecy (PFS)
            </p>
          </div>

          {/* Card 3 */}
          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Weak / Legacy Ciphers
              </span>
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-amber-600 dark:text-amber-400">
              {stats.weakCiphers}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              CBC, 3DES, or static RSA detected
            </p>
          </div>

          {/* Card 4 */}
          <div className="p-4 sm:p-5 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Critical Threats
              </span>
              <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 text-red-500" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-red-600 dark:text-red-400">
              {stats.criticalThreats}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Expired certs & downgrade attacks
            </p>
          </div>
        </div>
      </SlideIn>

      {/* ── Search & Filter Bar ── */}
      <SlideIn delay={150} direction="up">
        <div className="p-4 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 shadow-sm flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search by Hostname, IP, SNI, Cipher Suite, or TLS version..."
              className="w-full pl-10 pr-4 py-2 rounded-xl text-xs bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 text-slate-900 dark:text-white placeholder-slate-400 transition-all"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0 scrollbar-none">
            <button
              onClick={() => {
                setFilterPosture('all');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                filterPosture === 'all'
                  ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-950 shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-white/5'
              }`}
            >
              All ({sessions.length})
            </button>
            <button
              onClick={() => {
                setFilterPosture('critical');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer flex items-center gap-1.5 ${
                filterPosture === 'critical'
                  ? 'bg-red-500 text-white shadow-sm shadow-red-500/20'
                  : 'text-red-600 dark:text-red-400 hover:bg-red-500/10'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Vulnerable ({stats.weakCiphers})
            </button>
            <button
              onClick={() => {
                setFilterPosture('tls13');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer flex items-center gap-1.5 ${
                filterPosture === 'tls13'
                  ? 'bg-emerald-600 text-white shadow-sm shadow-emerald-500/20'
                  : 'text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/10'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              TLS 1.3 Modern ({stats.tls13Count})
            </button>
            <button
              onClick={() => {
                setFilterPosture('tls12');
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                filterPosture === 'tls12'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-blue-600 dark:text-blue-400 hover:bg-blue-500/10'
              }`}
            >
              TLS 1.2
            </button>
          </div>
        </div>
      </SlideIn>

      {/* ── Sessions List ── */}
      <SlideIn delay={200} direction="up">
        <div className="space-y-3">
          {paginatedSessions.length === 0 ? (
            <div className="p-12 text-center rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10">
              <Server className="w-12 h-12 mx-auto text-slate-400 mb-3 opacity-50" />
              <h3 className="text-base font-bold text-slate-800 dark:text-slate-200">No cryptographic sessions found</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm mx-auto">
                No active encrypted traffic streams match your current search and posture filters.
              </p>
              <button
                onClick={() => {
                  setSearchQuery('');
                  setFilterPosture('all');
                }}
                className="mt-4 px-4 py-2 rounded-xl text-xs font-semibold bg-slate-100 dark:bg-white/10 hover:bg-slate-200 dark:hover:bg-white/15 transition-all"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            paginatedSessions.map((session) => (
              <div
                key={session.id}
                className="group p-4 sm:p-5 rounded-2xl bg-white dark:bg-[#090b12] border border-slate-200 dark:border-white/10 hover:border-cyan-500/40 dark:hover:border-cyan-500/40 shadow-sm transition-all duration-200 relative overflow-hidden"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left: Icon + Host info + Cipher Suite */}
                  <div className="flex items-start gap-3.5 min-w-0 flex-1">
                    <div
                      className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 border ${
                        session.posture === 'critical'
                          ? 'bg-red-500/10 border-red-500/30 text-red-500'
                          : session.posture === 'warning'
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-500'
                          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500'
                      }`}
                    >
                      {session.posture === 'critical' ? (
                        <ShieldAlert className="w-5 h-5" />
                      ) : session.posture === 'warning' ? (
                        <AlertTriangle className="w-5 h-5" />
                      ) : (
                        <Lock className="w-5 h-5" />
                      )}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="font-mono text-xs font-bold text-cyan-600 dark:text-cyan-400">
                          {session.id}
                        </span>
                        {renderTlsBadge(session.tlsVersion)}
                        {renderPostureBadge(session.posture, session.threatScore)}
                        <span className="text-[11px] text-slate-600 dark:text-slate-400 font-medium">
                          {session.timestamp}
                        </span>
                      </div>

                      <div className="flex flex-wrap items-baseline gap-2">
                        <h3 className="text-base font-bold text-slate-900 dark:text-white truncate">
                          {session.serverHost}
                        </h3>
                        <span className="text-xs text-slate-600 dark:text-slate-400 font-mono">
                          {session.serverIp}:{session.serverPort}
                        </span>
                      </div>

                      {/* Cipher details line */}
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-xs text-slate-600 dark:text-slate-400">
                        <div className="flex items-center gap-1.5">
                          <Key className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span className="font-mono font-medium text-slate-800 dark:text-slate-200 truncate max-w-xs sm:max-w-md">
                            {session.cipherSuite}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <Globe className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span>ALPN: <strong className="font-mono text-slate-700 dark:text-slate-300">{session.alpn}</strong></span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span>{session.bytesTransferred}</span>
                        </div>
                      </div>

                      {/* Vulnerability tags if any */}
                      {session.vulnerabilities.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-2.5">
                          {session.vulnerabilities.map((v, i) => (
                            <span
                              key={i}
                              className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20"
                            >
                              {v}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Actions */}
                  <div className="flex items-center gap-2 self-end lg:self-center shrink-0">
                    {/* Escalate button for vulnerable sessions */}
                    {(session.posture === 'critical' || session.posture === 'warning') && (
                      <button
                        onClick={() => handleEscalateToSoc(session)}
                        disabled={escalatedMap[session.id]}
                        className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer active:scale-95 ${
                          escalatedMap[session.id]
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30 cursor-default'
                            : 'bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-500/20 border border-red-500/30'
                        }`}
                      >
                        {escalatedMap[session.id] ? '✓ Escalated' : 'Escalate to SOC'}
                      </button>
                    )}

                    {/* Inspect Handshake Modal button */}
                    <button
                      onClick={() => setSelectedSession(session)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold text-slate-800 dark:text-slate-200 bg-slate-100 dark:bg-white/10 hover:bg-cyan-500/15 hover:text-cyan-600 dark:hover:text-cyan-400 border border-slate-200 dark:border-white/10 transition-all cursor-pointer active:scale-95"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Inspect Handshake</span>
                    </button>

                    {/* Deep Forensics Route */}
                    <button
                      onClick={() => onNavigate(`emails/${encodeURIComponent(session.id)}/forensics`)}
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-bold text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10 transition-all cursor-pointer"
                      title="Launch full deep forensics workspace"
                    >
                      <span>Deep Forensics</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </SlideIn>

      {/* ── Pagination ── */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, filteredSessions.length)} of {filteredSessions.length} sessions
          </p>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-100 dark:hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-xs font-semibold px-2">
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-100 dark:hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Interactive Handshake Inspector Modal ── */}
      {selectedSession && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/70 backdrop-blur-md animate-in fade-in duration-200">
          <div
            className="w-full max-w-3xl max-h-[90vh] flex flex-col rounded-3xl bg-white dark:bg-[#0c0f19] border border-slate-200 dark:border-white/15 shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-5 sm:p-6 border-b border-slate-200 dark:border-white/10 flex items-center justify-between bg-slate-50 dark:bg-white/5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                  <Lock className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-black text-slate-900 dark:text-white">
                      TLS Handshake Inspection
                    </h2>
                    {renderTlsBadge(selectedSession.tlsVersion)}
                  </div>
                  <p className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    Session ID: {selectedSession.id} • {selectedSession.serverHost}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedSession(null)}
                className="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-white/10 transition-all cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 sm:p-6 overflow-y-auto space-y-5 text-xs">
              {/* Endpoint Overview */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-2xl bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/10 font-mono">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400">Client Endpoint</span>
                  <div className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                    {selectedSession.clientIp}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400">Server Endpoint (SNI)</span>
                  <div className="text-sm font-bold text-cyan-600 dark:text-cyan-400 mt-0.5 truncate">
                    {selectedSession.sni} ({selectedSession.serverIp}:{selectedSession.serverPort})
                  </div>
                </div>
              </div>

              {/* Handshake Details */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-cyan-500" />
                  Handshake Parameters
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 space-y-1.5">
                    <span className="text-[11px] text-slate-500">Negotiated Cipher Suite</span>
                    <div className="font-mono font-bold text-slate-900 dark:text-white break-all">
                      {selectedSession.cipherSuite}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 space-y-1.5">
                    <span className="text-[11px] text-slate-500">Key Exchange / Curve</span>
                    <div className="font-mono font-bold text-slate-900 dark:text-white break-all">
                      {selectedSession.keyExchange}
                    </div>
                  </div>
                </div>
              </div>

              {/* Certificate Chain Analysis */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-violet-500" />
                  X.509 Certificate Chain
                </h4>
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 space-y-2 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-400">Subject: </span>
                    <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedSession.certificate.subject}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Issuer CA: </span>
                    <span className="text-slate-800 dark:text-slate-200">{selectedSession.certificate.issuer}</span>
                  </div>
                  <div className="flex flex-wrap gap-4 pt-1 text-slate-600 dark:text-slate-400">
                    <span>Key Type: <strong className="text-slate-900 dark:text-white">{selectedSession.certificate.keyType}</strong></span>
                    <span>Signature: <strong className="text-slate-900 dark:text-white">{selectedSession.certificate.sigAlg}</strong></span>
                    <span>Status: <strong className={selectedSession.certificate.isExpired ? 'text-red-500' : 'text-emerald-500'}>{selectedSession.certificate.validity}</strong></span>
                  </div>
                </div>
              </div>

              {/* Cryptographic Posture & Vulnerabilities */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                  Posture Assessment & Vulnerability Findings
                </h4>
                <div
                  className={`p-4 rounded-xl border ${
                    selectedSession.posture === 'critical'
                      ? 'bg-red-500/10 border-red-500/30'
                      : selectedSession.posture === 'warning'
                      ? 'bg-amber-500/10 border-amber-500/30'
                      : 'bg-emerald-500/10 border-emerald-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
                      Posture Status: {selectedSession.posture}
                    </span>
                    <span className="font-mono text-xs font-bold">
                      Risk Score: {selectedSession.threatScore} / 100
                    </span>
                  </div>

                  {selectedSession.vulnerabilities.length > 0 ? (
                    <ul className="list-disc list-inside space-y-1 text-slate-800 dark:text-slate-200 mb-3">
                      {selectedSession.vulnerabilities.map((v, i) => (
                        <li key={i}>{v}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-emerald-700 dark:text-emerald-300 mb-3">
                      No cryptographic vulnerabilities detected. Forward secrecy is active and certificate chain is authenticated.
                    </p>
                  )}

                  <div className="pt-2 border-t border-slate-200/50 dark:border-white/10">
                    <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400">
                      Remediation Plan:
                    </span>
                    <p className="text-xs font-medium text-slate-900 dark:text-white mt-0.5">
                      {selectedSession.recommendation}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 sm:p-5 border-t border-slate-200 dark:border-white/10 flex flex-wrap items-center justify-between gap-3 bg-slate-50 dark:bg-white/5">
              <button
                onClick={() => setSelectedSession(null)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/10 transition-all cursor-pointer"
              >
                Close
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const sid = selectedSession.id;
                    setSelectedSession(null);
                    onNavigate(`emails/${encodeURIComponent(sid)}/forensics`);
                  }}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold text-white bg-slate-900 dark:bg-white/15 hover:bg-slate-800 dark:hover:bg-white/25 transition-all cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open Deep Forensics</span>
                </button>

                <button
                  onClick={() => {
                    setSelectedSession(null);
                    onNavigate('submit-report');
                  }}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 shadow-md transition-all cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Submit PCAP Capture</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
