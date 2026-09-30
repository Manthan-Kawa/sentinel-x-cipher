import { useState, useRef, useLayoutEffect, useMemo } from 'react';
import {
 Server,
 Globe,
 Network,
 Search,
 ShieldAlert,
 ShieldCheck,
 AlertTriangle,
 XCircle,
 ArrowLeft,
 Key,
 Lock,
 Copy,
 Check,
 ExternalLink,
 Calendar,
 FileCode,
 X,
 Filter,
 type LucideIcon,
} from 'lucide-react';
import {
 type Severity,
} from '@/data/mockData';
import { CopyButton } from '@/components/CopyButton';
import { useAnalysis } from '@/contexts/AnalysisContext';

export interface X509CertRecord {
 id: string;
 subject: string;
 sanList: string[];
 issuer: string;
 serialNumber: string;
 validFrom: string;
 expiry: string;
 isExpired: boolean;
 daysExpired?: number;
 keyLength: number;
 keyAlgo: string;
 isWeakKey: boolean;
 selfSigned: boolean;
 sigAlgo: string;
 ocspStatus: 'Good' | 'Missing' | 'Revoked';
 fingerprintSha256: string;
 severity: Severity;
 protocolSession: string;
 cipherSuite: string;
 keyUsage: string[];
 rawAsn1: string;
 rawPem: string;
}

export const CERTIFICATES_VAULT: X509CertRecord[] = [
 {
 id: 'CERT-2026-001',
 subject: 'mail.attacker.example',
 sanList: ['mail.attacker.example', 'smtp.attacker.example', '185.220.101.47'],
 issuer: 'Self-Signed (Untrusted Root CA)',
 serialNumber: '4A:2F:8C:91:00:23:D4:E8:11:AB',
 validFrom: '2023-01-01',
 expiry: '2024-01-01',
 isExpired: true,
 daysExpired: 972,
 keyLength: 1024,
 keyAlgo: 'RSA',
 isWeakKey: true,
 selfSigned: true,
 sigAlgo: 'sha1WithRSAEncryption (RFC 3279 Deprecated)',
 ocspStatus: 'Missing',
 fingerprintSha256: '9F:88:21:4B:33:DE:71:0A:88:C4:29:10:4E:5F:AA:32:11:80:CC:2B:99:41:82:10:65:4F:33:12:00:99:AA:BB',
 severity: 'critical',
 protocolSession: 'SMTP · TLS 1.0 (Downgraded)',
 cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 4a:2f:8c:91:00:23:d4:e8:11:ab
 Signature Algorithm: sha1WithRSAEncryption
 Issuer: C=US, ST=Attacker State, O=Rogue Relay, CN=mail.attacker.example
 Validity
 Not Before: Jan 1 00:00:00 2023 GMT
 Not After : Jan 1 00:00:00 2024 GMT [EXPIRED: 900+ days ago]
 Subject: C=US, ST=Attacker State, O=Rogue Relay, CN=mail.attacker.example
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public-Key: (1024 bit) [INSECURE: Below NIST 2048-bit minimum]
 Modulus:
 00:b4:9f:3a:11:cc:98:ef:22:31:0a:74:e2:39:18:
 67:90:ab:44:de:12:35:89:ef:71:22:90:cb:af:44:
 ee:89:12:44:aa:bb:cc:dd:ee:ff:00:11:22:33:44
 Exponent: 65537 (0x10001)
 X509v3 extensions:
 X509v3 Basic Constraints: critical
 CA:FALSE
 X509v3 Key Usage: critical
 Digital Signature, Key Encipherment
 X509v3 Subject Alternative Name:
 DNS:mail.attacker.example, DNS:smtp.attacker.example, IP Address:185.220.101.47
 X509v3 Authority Key Identifier:
 keyid:4A:2F:8C:91:00:23:D4:E8:11:AB
 Signature Algorithm: sha1WithRSAEncryption
 22:99:41:88:ef:31:00:bb:49:12:00:cc:77:88:99:aa:bb:cc:dd:ee`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIClTCCAf6gAwIBAgILSi+MkQAj1OgRqzANBgkqhkiG9w0BAQUFADBFMRcwFQYD
VQQDEw5hdHRhY2tlci5sb2NhbDEUMBIGA1UEChMLUm9ndWUgUmVsYXkxDzANBgNV
BAgTBk5ldHd0czELMAkGA1UEBhMCVVMwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAx
MDAwMDAwWjBFMRcwFQYDVQQDEw5hdHRhY2tlci5sb2NhbDEUMBIGA1UEChMLUm9n
dWUgUmVsYXkxDzANBgNVBAgTBk5ldHd0czELMAkGA1UEBhMCVVMwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBALSfOhHMyO8iMQp04jkYZ5CrRN4SNYnvcSKQy69E
7okSRKq7zN3u/wARIjNEAgMBAAGjgZgwgZUwDAYDVR0TAQH/BAIwADAPBgNVHQ8B
Af8EBQMDB4AAMDcGA1UdEQQwMC6CEmF0dGFja2VyLW1haWwubG9jYWyCE3NtdHAu
YXR0YWNrZXItbWFpbIYH5d5lIT8wHQYDVR0OBBYEFIovjJEAI9ToEavAMBkGCSqG
SIb3DQEBBQUAA4GBACI5QYjvwzEAu0kSAADsd4iZqrvc3u8=
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-002',
 subject: 'mail.acme-relay.example',
 sanList: ['mail.acme-relay.example'],
 issuer: 'Unknown CA (Self-Generated Root)',
 serialNumber: '7E:33:10:A9:B2:44:88:C1:20:91',
 validFrom: '2022-01-01',
 expiry: '2023-12-31',
 isExpired: true,
 daysExpired: 973,
 keyLength: 512,
 keyAlgo: 'RSA',
 isWeakKey: true,
 selfSigned: true,
 sigAlgo: 'md5WithRSAEncryption (Cryptographically Broken)',
 ocspStatus: 'Revoked',
 fingerprintSha256: 'AA:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE',
 severity: 'critical',
 protocolSession: 'SMTP · SSLv3 (Obsolete Protocol)',
 cipherSuite: 'TLS_RSA_WITH_DES_CBC_SHA',
 keyUsage: ['Digital Signature'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 7e:33:10:a9:b2:44:88:c1:20:91
 Signature Algorithm: md5WithRSAEncryption
 Issuer: C=US, O=Unknown Rogue CA, CN=Internal Fake Root
 Validity
 Not Before: Jan 1 00:00:00 2022 GMT
 Not After : Dec 31 23:59:59 2023 GMT [EXPIRED]
 Subject: CN=mail.acme-relay.example
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public-Key: (512 bit) [CRITICAL: Trivial factorization risk]
 X509v3 extensions:
 X509v3 Basic Constraints: CA:FALSE`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIBtjCCAR8CAf4wDQYJKoZIhvcNAQEEBQAwMzELMAkGA1UEBhMCVVMxGDAWBgNV
BAoTD1Vua25vd24gUm9ndWUgQ0ExETAPBgNVBAMTCGZha2UtY2EwHhcNMjIwMTAx
MDAwMDAwWhcNMjMxMjMxMjM1OTU5WjAiMSAwHgYDVQQDExdtYWlsLmFjbWUtcmVs
YXkuZXhhbXBsZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDEzE/GAA78b7Qv1809
AQMBAAEwDQYJKoZIhvcNAQEEBQADQQBHh90=
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-003',
 subject: 'imap.acme-payroll.example',
 sanList: ['imap.acme-payroll.example'],
 issuer: 'Self-Signed Authority',
 serialNumber: '1B:44:90:3A:C2:77:51:EE:89:12',
 validFrom: '2024-01-15',
 expiry: '2026-01-15',
 isExpired: false,
 keyLength: 1024,
 keyAlgo: 'RSA',
 isWeakKey: true,
 selfSigned: true,
 sigAlgo: 'sha256WithRSAEncryption',
 ocspStatus: 'Missing',
 fingerprintSha256: 'CC:44:88:12:90:EE:11:AB:55:78:22:91:00:44:33:DE:71:0A:88:C4:29:10:4E:5F:AA:32:11:80:CC:2B:99:41',
 severity: 'high',
 protocolSession: 'IMAPS · TLS 1.3',
 cipherSuite: 'TLS_AES_128_GCM_SHA256',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 1b:44:90:3a:c2:77:51:ee:89:12
 Issuer: CN=imap.acme-payroll.example
 Validity
 Not Before: Jan 15 00:00:00 2024 GMT
 Not After : Jan 15 00:00:00 2026 GMT
 Subject: CN=imap.acme-payroll.example
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public-Key: (1024 bit) [WEAK KEY: Violates NIST 2048-bit mandate]`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIClTCCAf6gAwIBAgIQG0SQOsJ3Ue6JElFBAjANBgkqhkiG9w0BAQsFADAkMSIw
IAYDVQQDExlpbWFwLmFjbWUtcGF5cm9sbC5leGFtcGxlMB4XDTI0MDExNTAwMDAw
MFoXDTI2MDExNTAwMDAwMFowJDEiMCAGA1UEAxMZaW1hcC5hY21lLXBheXJvbGwu
ZXhhbXBsZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA02c...
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-004',
 subject: 'mail.paypa1-secure.example',
 sanList: ['mail.paypa1-secure.example', 'smtp.paypa1-secure.example'],
 issuer: "Let's Encrypt Authority X3",
 serialNumber: '03:F1:8A:29:C4:55:10:9B:67:E2',
 validFrom: '2024-12-15',
 expiry: '2025-03-15',
 isExpired: false,
 keyLength: 2048,
 keyAlgo: 'RSA',
 isWeakKey: false,
 selfSigned: false,
 sigAlgo: 'sha256WithRSAEncryption',
 ocspStatus: 'Good',
 fingerprintSha256: '44:99:11:88:22:EE:FF:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22',
 severity: 'high',
 protocolSession: 'IMAP · TLS 1.1 (Deprecated)',
 cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 03:f1:8a:29:c4:55:10:9b:67:e2
 Issuer: C=US, O=Let's Encrypt, CN=R3
 Validity
 Not Before: Dec 15 00:00:00 2024 GMT
 Not After : Mar 15 00:00:00 2025 GMT
 Subject: CN=mail.paypa1-secure.example [LOOKALIKE / HOMOGLYPH TARGET]
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public-Key: (2048 bit) [STANDARD]`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgISAvGKKcRVEJtn4hANBgkqhkiG9w0BAQsFADAWMRQwEgYD
VQQDEwtMZXQncyBFbmNyeXB0MB4XDTI0MTIxNTAwMDAwMFoXDTI1MDMxNTAwMDAw
MFowJDEiMCAGA1UEAxMZbWFpbC5wYXlwYTEtc2VjdXJlLmV4YW1wbGUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7...
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-005',
 subject: 'mail.micros0ft-365.example',
 sanList: ['mail.micros0ft-365.example', 'smtp.micros0ft-365.example'],
 issuer: 'Unknown CA (Rogue Relay Proxy)',
 serialNumber: '29:10:5B:C4:DE:88:31:02:77:4A',
 validFrom: '2024-08-01',
 expiry: '2025-08-01',
 isExpired: false,
 keyLength: 2048,
 keyAlgo: 'RSA',
 isWeakKey: false,
 selfSigned: false,
 sigAlgo: 'sha256WithRSAEncryption',
 ocspStatus: 'Missing',
 fingerprintSha256: '88:44:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55',
 severity: 'high',
 protocolSession: 'SMTP · TLS 1.1',
 cipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 29:10:5b:c4:de:88:31:02:77:4a
 Issuer: CN=Unknown Relay Proxy Intermediate CA
 Validity
 Not Before: Aug 1 00:00:00 2024 GMT
 Not After : Aug 1 00:00:00 2025 GMT
 Subject: CN=mail.micros0ft-365.example`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgIQKRBbxN6IMQJ3SgANBgkqhkiG9w0BAQsFADAoMSYwJAYD
VQQDEx1Vbmtub3duIFJlbGF5IFByb3h5IEludGVybWVkaWF0ZTAeFw0yNDA4MDEw
MDAwMDBaFw0yNTA4MDEwMDAwMDBaMSQwIgYDVQQDExttYWlsLm1pY3JvczBmdC0z
NjUuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL...
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-006',
 subject: 'mail.vendor-portal.example',
 sanList: ['mail.vendor-portal.example', 'portal.vendor-portal.example'],
 issuer: 'DigiCert TLS RSA4096 Root G5',
 serialNumber: '55:AA:71:03:99:BC:2E:14:80:FF',
 validFrom: '2024-06-01',
 expiry: '2027-06-01',
 isExpired: false,
 keyLength: 4096,
 keyAlgo: 'RSA',
 isWeakKey: false,
 selfSigned: false,
 sigAlgo: 'sha384WithRSAEncryption',
 ocspStatus: 'Good',
 fingerprintSha256: '12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF',
 severity: 'info',
 protocolSession: 'SMTP · TLS 1.2 (MitM Monitored)',
 cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 55:aa:71:03:99:bc:2e:14:80:ff
 Issuer: C=US, O=DigiCert Inc, CN=DigiCert Global Root G5
 Validity
 Not Before: Jun 1 00:00:00 2024 GMT
 Not After : Jun 1 00:00:00 2027 GMT
 Subject: CN=mail.vendor-portal.example
 Subject Public Key Info:
 Public Key Algorithm: rsaEncryption
 RSA Public-Key: (4096 bit) [STRONG / HIGH CONFIDENCE]`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIF8jCCBNqgAwIBAgIQVapxA5m8LhSAD/ANBgkqhkiG9w0BAQwFADBHMQswCQYD
VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSAwHgYDVQQDExdEaWdpQ2Vy
dCBHbG9iYWwgUm9vdCBHNTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AOWx62e8G...
-----END CERTIFICATE-----`,
 },
 {
 id: 'CERT-2026-007',
 subject: 'pop3.dhl-express-notify.example',
 sanList: ['pop3.dhl-express-notify.example'],
 issuer: 'Sectigo RSA Domain Validation CA',
 serialNumber: '88:CC:11:00:23:45:9B:EE:71:22',
 validFrom: '2024-11-30',
 expiry: '2026-11-30',
 isExpired: false,
 keyLength: 2048,
 keyAlgo: 'RSA',
 isWeakKey: false,
 selfSigned: false,
 sigAlgo: 'sha256WithRSAEncryption',
 ocspStatus: 'Good',
 fingerprintSha256: 'EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
 severity: 'medium',
 protocolSession: 'POP3 · TLS 1.2',
 cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
 keyUsage: ['Digital Signature', 'Key Encipherment'],
 rawAsn1: `Certificate:
 Data:
 Version: 3 (0x2)
 Serial Number: 88:cc:11:00:23:45:9b:ee:71:22
 Issuer: C=GB, O=Sectigo Limited, CN=Sectigo RSA Domain Validation CA
 Validity
 Not Before: Nov 30 00:00:00 2024 GMT
 Not After : Nov 30 00:00:00 2026 GMT
 Subject: CN=pop3.dhl-express-notify.example`,
 rawPem: `-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgIQiMwRADNFm+5xIgANBgkqhkiG9w0BAQsFADBDMQswCQYD
VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQDExtTZWN0
aWdvIFJTQSBETyBDQTAeFw0yNDExMzAwMDAwMDBaFw0yNjExMzAwMDAwMDBaMCgx
JjAkBgNVBAMTHXBvcDMuZGhsLWV4cHJlc3Mtbm90aWZ5LmV4YW1wbGUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9...
-----END CERTIFICATE-----`,
 },
];

type TabId = 'certificates' | 'rootca' | 'indicators' | 'endpoint';

const TABS: { id: TabId; label: string; icon: LucideIcon }[] = [
 { id: 'certificates', label: 'X.509 Certificates', icon: ShieldCheck },
 { id: 'rootca', label: 'Root CAs & Trust Chains', icon: Key },
 { id: 'indicators', label: 'Cryptographic Telemetry', icon: Network },
 { id: 'endpoint', label: 'Host & Origin Records', icon: Server },
];

function SlideIn({ children, delay = 0, direction = 'up', className = '' }: {
 children: React.ReactNode; delay?: number; direction?: 'up'|'left'|'right'|'down'; className?: string;
}) {
 const [vis, setVis] = useState(false);
 useLayoutEffect(() => { const t = setTimeout(() => setVis(true), delay); return () => clearTimeout(t); }, [delay]);
 const from = direction === 'left' ? 'translateX(-36px)' : direction === 'right' ? 'translateX(36px)' : direction === 'down' ? 'translateY(-20px)' : 'translateY(24px)';
 return (
 <div className={className} style={{ opacity: vis ? 1 : 0, transform: vis ? 'none' : from, transition: 'opacity .5s cubic-bezier(.22,1,.36,1), transform .5s cubic-bezier(.22,1,.36,1)' }}>
 {children}
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 CERTIFICATE VAULT PAGE
═══════════════════════════════════════════════════════════ */
export function CertificateVaultPage({ onNavigate }: { onNavigate?: (route: string) => void }) {
 const [tab, setTab] = useState<TabId>('certificates');
 const { currentResult } = useAnalysis();
 const [selectedCert, setSelectedCert] = useState<X509CertRecord | null>(null);

 const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});
 const [indicatorStyle, setIndicatorStyle] = useState<{
 left: number;
 top: number;
 width: number;
 height: number;
 opacity: number;
 }>({ left: 0, top: 0, width: 0, height: 0, opacity: 0 });

 useLayoutEffect(() => {
 const updateIndicator = () => {
 const currentTabEl = tabRefs.current[tab];
 if (currentTabEl) {
 setIndicatorStyle({
 left: currentTabEl.offsetLeft,
 top: currentTabEl.offsetTop,
 width: currentTabEl.offsetWidth,
 height: currentTabEl.offsetHeight,
 opacity: 1,
 });
 }
 };
 updateIndicator();
 const rafId = requestAnimationFrame(updateIndicator);
 window.addEventListener('resize', updateIndicator);
 return () => {
 cancelAnimationFrame(rafId);
 window.removeEventListener('resize', updateIndicator);
 };
 }, [tab]);

 // Aggregate stats
 const totalCerts = CERTIFICATES_VAULT.length;
 const expiredCount = CERTIFICATES_VAULT.filter((c) => c.isExpired).length;
 const weakKeysCount = CERTIFICATES_VAULT.filter((c) => c.isWeakKey).length;
 const selfSignedCount = CERTIFICATES_VAULT.filter((c) => c.selfSigned).length;

 return (
 <div className="space-y-6" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

 {/* ── Page Header ── */}
 <SlideIn delay={0} direction="down">
 <div className="space-y-4">
 <div className="flex items-start gap-2.5 sm:gap-3">
 {onNavigate && (
 <button
 onClick={() => onNavigate('header-forensics')}
 className="mt-0.5 w-8 h-8 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl flex items-center justify-center text-blue-400 hover:text-blue-300 transition-all hover:scale-105 active:scale-95 cursor-pointer shrink-0"
 style={{
 background: 'rgba(59, 130, 246, 0.05)',
 border: '1px solid rgba(59, 130, 246, 0.45)',
 boxShadow: '0 0 10px rgba(59, 130, 246, 0.15)',
 }}
 title="Back to Cryptographic Forensics"
 >
 <ArrowLeft className="w-4 h-4" />
 </button>
 )}
 <div className="min-w-0 flex-1">
 <div className="flex items-center gap-2">
 <h2 className="text-xl sm:text-2xl font-black text-gray-900 dark:text-white tracking-tight leading-snug">
 Certificate Vault
 </h2>
 <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-violet-500/10 text-violet-400 border -violet-500/30">
 X.509 Intelligence
 </span>
 </div>
 <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 mt-0.5 leading-relaxed">
 Extracted X.509 digital certificates, root CA trust chains, validity monitoring &amp; public key strength evaluation
 </p>
 </div>
 </div>

 {/* ── Summary KPI Row ── */}
 <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
 <div className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 dark: /[0.03] border dark: -white/[0.06] flex items-center justify-between">
 <div>
 <p className="text-[10px] font-mono uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold">Tracked Certs</p>
 <p className="text-2xl font-black text-gray-900 dark:text-white font-mono mt-0.5">{totalCerts}</p>
 </div>
 <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-blue-500/10 border -blue-500/25 text-blue-500">
 <ShieldCheck className="w-4 h-4" />
 </div>
 </div>

 <div className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 bg-red-500/[0.04] border -red-500/20 flex items-center justify-between shadow-[0_0_12px_rgba(239,68,68,0.1)]">
 <div>
 <p className="text-[10px] font-mono uppercase tracking-wider text-red-600 dark:text-red-400 font-bold">Expired Certs</p>
 <p className="text-2xl font-black text-red-600 dark:text-red-400 font-mono mt-0.5">{expiredCount}</p>
 </div>
 <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-red-500/15 border -red-500/35 text-red-500 animate-pulse">
 <AlertTriangle className="w-4 h-4" />
 </div>
 </div>

 <div className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 bg-amber-500/[0.04] border -amber-500/20 flex items-center justify-between">
 <div>
 <p className="text-[10px] font-mono uppercase tracking-wider text-amber-600 dark:text-amber-400 font-bold">Weak Keys (&lt;2048b)</p>
 <p className="text-2xl font-black text-amber-600 dark:text-amber-400 font-mono mt-0.5">{weakKeysCount}</p>
 </div>
 <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-amber-500/15 border -amber-500/35 text-amber-500">
 <Key className="w-4 h-4" />
 </div>
 </div>

 <div className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3.5 bg-orange-500/[0.04] border -orange-500/20 flex items-center justify-between">
 <div>
 <p className="text-[10px] font-mono uppercase tracking-wider text-orange-600 dark:text-orange-400 font-bold">Self-Signed / Untrusted</p>
 <p className="text-2xl font-black text-orange-600 dark:text-orange-400 font-mono mt-0.5">{selfSignedCount}</p>
 </div>
 <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-orange-500/15 border -orange-500/35 text-orange-500">
 <Lock className="w-4 h-4" />
 </div>
 </div>
 </div>

 {/* Active PCAP Session sync banner if result is present */}
 {currentResult && (
 <div className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-3 bg-gradient-to-r from-red-500/10 via-amber-500/5 to-transparent border -red-500/30 flex items-center justify-between gap-3">
 <div className="flex items-center gap-2.5 min-w-0">
 <div className="w-7 h-7 rounded-lg bg-red-500/20 text-red-400 flex items-center justify-center shrink-0">
 <ShieldAlert className="w-4 h-4" />
 </div>
 <div className="min-w-0">
 <p className="text-[10px] font-mono uppercase text-red-500 dark:text-red-400 font-bold">Active PCAP Session Certificate Detected</p>
 <p className="text-xs font-bold text-gray-900 dark:text-white truncate font-mono">
 mail.attacker.example · Self-Signed RSA-1024 (Expired Jan 01, 2024)
 </p>
 </div>
 </div>
 <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-400 border -red-500/40 shrink-0">
 CRITICAL VIOLATION
 </span>
 </div>
 )}
 </div>
 </SlideIn>

 {/* ── Interactive Tabbed Container ── */}
 <SlideIn delay={100} direction="up">
 <div className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm overflow-hidden border dark: -white/10 dark:shadow-[0_8px_32px_rgba(0,0,0,0.4)]">
 {/* Tabs header with smooth sliding indicator pill */}
 <div className="relative isolate flex items-center gap-1 border-b dark: -white/10 p-1.5 sm:p-2 overflow-x-auto scrollbar-none touch-scroll">
 <div
 className="absolute z-0 pointer-events-none bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl bg-purple-500/15 dark:bg-purple-500/20 border border-purple-400/50 dark: -purple-500/40 "
 style={{
 transform: `translate3d(${indicatorStyle.left}px, ${indicatorStyle.top}px, 0)`,
 width: indicatorStyle.width,
 height: indicatorStyle.height,
 opacity: indicatorStyle.opacity,
 transition: 'transform 300ms cubic-bezier(0.25, 1, 0.5, 1), width 300ms cubic-bezier(0.25, 1, 0.5, 1), height 300ms cubic-bezier(0.25, 1, 0.5, 1), opacity 150ms ease',
 left: 0,
 top: 0,
 zIndex: 0,
 }}
 />

 {TABS.map((t) => {
 const Icon = t.icon;
 const isActive = tab === t.id;
 return (
 <button
 key={t.id}
 ref={(el) => { tabRefs.current[t.id] = el; }}
 onClick={() => setTab(t.id)}
 style={{ zIndex: 10 }}
 className={`relative z-10 shrink-0 flex items-center gap-1.5 sm:gap-2 px-3 sm:px-4 py-2 sm:py-2.5 rounded-xl text-xs font-bold transition-colors duration-200 whitespace-nowrap cursor-pointer ${
 isActive
 ? 'text-purple-700 dark:text-purple-300'
 : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
 }`}
 >
 <Icon className={`w-4 h-4 transition-colors duration-200 ${isActive ? 'text-purple-600 dark:text-purple-400' : 'text-gray-400 dark:text-gray-500'}`} />
 {t.label}
 </button>
 );
 })}
 </div>

 {/* Content area */}
 <div className="p-3.5 sm:p-6 overflow-hidden transition-all duration-300">
 {tab === 'certificates' && (
 <CertificatesTab
 onSelectCert={(c) => setSelectedCert(c)}
 onInspectHandshake={() => onNavigate?.('header-forensics')}
 />
 )}
 {tab === 'rootca' && <RootCATab />}
 {tab === 'indicators' && <CryptoIndicatorsTab />}
 {tab === 'endpoint' && <EndpointTab />}
 </div>
 </div>
 </SlideIn>

 {/* ── Modal for Raw Decoded X.509 Certificate ── */}
 {selectedCert && (
 <RawCertModal cert={selectedCert} onClose={() => setSelectedCert(null)} />
 )}
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TAB 1: X.509 CERTIFICATES VAULT
═══════════════════════════════════════════════════════════ */
function CertificatesTab({
 onSelectCert,
 onInspectHandshake,
}: {
 onSelectCert: (cert: X509CertRecord) => void;
 onInspectHandshake: () => void;
}) {
 const [search, setSearch] = useState('');
 const [filter, setFilter] = useState<'all' | 'expired' | 'weak' | 'self' | 'valid'>('all');

 const filteredCerts = useMemo(() => {
 return CERTIFICATES_VAULT.filter((c) => {
 const q = search.toLowerCase();
 const matchSearch =
 c.subject.toLowerCase().includes(q) ||
 c.issuer.toLowerCase().includes(q) ||
 c.fingerprintSha256.toLowerCase().includes(q) ||
 c.cipherSuite.toLowerCase().includes(q);

 if (!matchSearch) return false;
 if (filter === 'expired') return c.isExpired;
 if (filter === 'weak') return c.isWeakKey;
 if (filter === 'self') return c.selfSigned;
 if (filter === 'valid') return !c.isExpired && !c.isWeakKey && !c.selfSigned;
 return true;
 });
 }, [search, filter]);

 return (
 <div className="space-y-5">
 {/* Search and Filters */}
 <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
 <div className="flex items-center gap-2 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl px-3 py-2 flex-1 dark: /[0.04] border dark: -white/[0.08]">
 <Search className="w-4 h-4 text-gray-400 dark:text-gray-500" />
 <input
 type="text"
 placeholder="Search certificate by Common Name, SAN, Issuer, or Fingerprint..."
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 className="bg-transparent text-xs text-gray-900 dark:text-white placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none w-full font-mono"
 />
 </div>

 <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-thin">
 <Filter className="w-3.5 h-3.5 text-gray-400 dark:text-gray-500 ml-1 mr-0.5 shrink-0" />
 {(
 [
 { id: 'all', label: 'All Certs (7)' },
 { id: 'expired', label: 'Expired (2)' },
 { id: 'weak', label: 'Weak Key: <2048b (3)' },
 { id: 'self', label: 'Self-Signed (3)' },
 { id: 'valid', label: 'Valid / Compliant (2)' },
 ] as const
 ).map((f) => (
 <button
 key={f.id}
 onClick={() => setFilter(f.id)}
 className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all duration-200 shrink-0 cursor-pointer ${
 filter === f.id
 ? 'text-purple-700 dark:text-purple-300'
 : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
 }`}
 style={
 filter === f.id
 ? { background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.35)' }
 : { background: 'rgba(0,0,0,0.03)', border: '1px solid rgba(0,0,0,0.08)' }
 }
 >
 {f.label}
 </button>
 ))}
 </div>
 </div>

 {/* Certificate Cards Grid */}
 <div className="space-y-4">
 {filteredCerts.map((cert) => {
 const isCrit = cert.severity === 'critical';
 const isHigh = cert.severity === 'high';

 return (
 <div
 key={cert.id}
 className="bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-4 sm:p-5 transition-all duration-200 hover:shadow-lg relative overflow-hidden"
 style={{
 background: cert.isExpired
 ? 'linear-gradient(145deg, rgba(239,68,68,0.04), rgba(15,18,28,0.98))'
 : 'linear-gradient(145deg, rgba(255,255,255,0.02), rgba(15,18,28,0.98))',
 border: cert.isExpired
 ? '1px solid rgba(239,68,68,0.4)'
 : cert.isWeakKey
 ? '1px solid rgba(245,158,11,0.35)'
 : '1px solid rgba(255,255,255,0.08)',
 boxShadow: cert.isExpired ? '0 0 16px rgba(239,68,68,0.15)' : 'none',
 }}
 >
 {/* Top Row: Subject CN + Badges */}
 <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5 pb-3 border-b dark: -white/5">
 <div className="flex items-center gap-3">
 <div
 className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
 cert.isExpired
 ? 'bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse'
 : cert.isWeakKey
 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
 : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
 }`}
 >
 {cert.isExpired ? (
 <AlertTriangle className="w-4 h-4" />
 ) : cert.isWeakKey ? (
 <Key className="w-4 h-4" />
 ) : (
 <ShieldCheck className="w-4 h-4" />
 )}
 </div>
 <div>
 <div className="flex items-center gap-2">
 <h4 className="text-sm font-bold text-gray-900 dark:text-white font-mono break-all">
 {cert.subject}
 </h4>
 <span className="text-[10px] text-gray-400 dark:text-gray-500 font-mono">
 {cert.id}
 </span>
 </div>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 font-mono mt-0.5">
 Session: {cert.protocolSession}
 </p>
 </div>
 </div>

 {/* Status Badges */}
 <div className="flex items-center gap-1.5 flex-wrap">
 {cert.isExpired && (
 <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-500/20 text-red-400 border -red-500/40 flex items-center gap-1 ">
 <AlertTriangle className="w-3 h-3" />
 EXPIRED ({cert.expiry})
 </span>
 )}
 {cert.isWeakKey && (
 <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/20 text-amber-400 border -amber-500/40 flex items-center gap-1">
 <Key className="w-3 h-3" />
 WEAK KEY: {cert.keyAlgo}-{cert.keyLength}
 </span>
 )}
 {cert.selfSigned && (
 <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-orange-500/20 text-orange-400 border -orange-500/40">
 SELF-SIGNED
 </span>
 )}
 {!cert.isExpired && !cert.isWeakKey && !cert.selfSigned && (
 <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-400 border -emerald-500/40">
 COMPLIANT ({cert.keyLength}b)
 </span>
 )}
 </div>
 </div>

 {/* Expired Warning Callout Banner if Expired */}
 {cert.isExpired && (
 <div className="mt-3 p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl bg-red-500/10 border -red-500/30 flex items-center gap-2.5 text-xs text-red-600 dark:text-red-400">
 <XCircle className="w-4 h-4 shrink-0" />
 <div>
 <span className="font-bold">CRITICAL CERTIFICATE EXPIRATION:</span> Expired on{' '}
 <span className="font-mono font-bold">{cert.expiry}</span> ({cert.daysExpired} days overdue). Remote peer accepted invalid, untrusted certificate during TLS handshake.
 </div>
 </div>
 )}

 {/* Weak Key Callout Banner if Weak */}
 {cert.isWeakKey && (
 <div className="mt-2.5 p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl bg-amber-500/10 border -amber-500/30 flex items-center gap-2.5 text-xs text-amber-600 dark:text-amber-400">
 <AlertTriangle className="w-4 h-4 shrink-0" />
 <div>
 <span className="font-bold">INSECURE KEY LENGTH VIOLATION:</span> Public key length is only{' '}
 <span className="font-mono font-bold">{cert.keyLength} bits</span>. Violates NIST SP 800-131A requiring at least 2048-bit RSA for cryptographic confidentiality.
 </div>
 </div>
 )}

 {/* Middle Row: Certificate Attributes Grid */}
 <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-3 text-xs">
 <div className="p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl dark: /[0.02] border dark: -white/5">
 <span className="text-[10px] font-mono uppercase text-gray-500 dark:text-gray-400 font-bold block mb-1">
 Issuer / CA
 </span>
 <span className="font-semibold text-gray-900 dark:text-white break-all">
 {cert.issuer}
 </span>
 </div>

 <div className="p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl dark: /[0.02] border dark: -white/5">
 <span className="text-[10px] font-mono uppercase text-gray-500 dark:text-gray-400 font-bold block mb-1">
 Public Key &amp; Algorithm
 </span>
 <span className="font-mono font-semibold text-gray-900 dark:text-white">
 {cert.keyAlgo} {cert.keyLength}-bit ({cert.isWeakKey ? 'Insecure' : 'Adequate'})
 </span>
 </div>

 <div className="p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl dark: /[0.02] border dark: -white/5">
 <span className="text-[10px] font-mono uppercase text-gray-500 dark:text-gray-400 font-bold block mb-1">
 Signature Algorithm
 </span>
 <span className="font-mono text-gray-800 dark:text-gray-300 break-all text-[11px]">
 {cert.sigAlgo}
 </span>
 </div>

 <div className="p-2.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl dark: /[0.02] border dark: -white/5">
 <span className="text-[10px] font-mono uppercase text-gray-500 dark:text-gray-400 font-bold block mb-1">
 Validity Window
 </span>
 <span className="font-mono text-gray-900 dark:text-white text-[11px] block">
 {cert.validFrom} → {cert.expiry}
 </span>
 </div>
 </div>

 {/* Bottom Row: Fingerprint + Actions */}
 <div className="mt-3 pt-3 border-t dark: -white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
 <div className="flex items-center gap-2 min-w-0 flex-1">
 <span className="text-[10px] font-mono uppercase text-gray-400 dark:text-gray-500 shrink-0">SHA-256:</span>
 <span className="text-[11px] font-mono text-gray-600 dark:text-gray-400 truncate max-w-[280px] sm:max-w-md" title={cert.fingerprintSha256}>
 {cert.fingerprintSha256}
 </span>
 <CopyButton value={cert.fingerprintSha256} />
 </div>

 <div className="flex items-center gap-2 shrink-0">
 <button
 onClick={() => onSelectCert(cert)}
 className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-gray-700 hover:text-black dark:text-gray-300 dark:hover:text-white bg-slate-100 hover: dark:bg-white/5 hover:dark: /10 border dark: -white/10 transition-all font-mono cursor-pointer"
 >
 <FileCode className="w-3.5 h-3.5 text-blue-400" />
 Inspect X.509 ASN.1
 </button>
 <button
 onClick={onInspectHandshake}
 className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 transition-all font-mono cursor-pointer "
 >
 <ExternalLink className="w-3.5 h-3.5" />
 View Handshake
 </button>
 </div>
 </div>
 </div>
 );
 })}

 {filteredCerts.length === 0 && (
 <div className="text-center py-12 text-xs text-gray-400 dark:text-gray-500 font-mono">
 No certificates match the selected filter query.
 </div>
 )}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TAB 2: ROOT CA & TRUST CHAINS
═══════════════════════════════════════════════════════════ */
function RootCATab() {
 const rootAuthorities = [
 {
 name: 'DigiCert Global Root G5',
 trustStatus: 'TRUSTED ROOT',
 statusColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
 keyType: 'RSA 4096-bit',
 crl: 'http://crl3.digicert.com/DigiCertGlobalRootG5.crl',
 ocsp: 'http://ocsp.digicert.com',
 expiry: '2038-01-15',
 trustedInMozilla: true,
 trustedInMicrosoft: true,
 },
 {
 name: 'ISRG Root X1 (Let\'s Encrypt)',
 trustStatus: 'TRUSTED ROOT',
 statusColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
 keyType: 'RSA 4096-bit',
 crl: 'http://crl.isrg.org/isrgrootx1.crl',
 ocsp: 'http://ocsp.int-x3.letsencrypt.org',
 expiry: '2035-06-04',
 trustedInMozilla: true,
 trustedInMicrosoft: true,
 },
 {
 name: 'Sectigo Public CA Root',
 trustStatus: 'TRUSTED ROOT',
 statusColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
 keyType: 'RSA 4096-bit',
 crl: 'http://crl.sectigo.com/SectigoRoot.crl',
 ocsp: 'http://ocsp.sectigo.com',
 expiry: '2036-12-31',
 trustedInMozilla: true,
 trustedInMicrosoft: true,
 },
 {
 name: 'Self-Signed Untrusted Root CA (185.220.101.47)',
 trustStatus: 'UNTRUSTED ROOT',
 statusColor: 'text-red-400 bg-red-500/15 border-red-500/35',
 keyType: 'RSA 1024-bit (Insecure)',
 crl: 'None / Missing',
 ocsp: 'None / Missing',
 expiry: '2024-01-01 (Expired)',
 trustedInMozilla: false,
 trustedInMicrosoft: false,
 },
 {
 name: 'Unknown CA (Fake Corporate Relay Intermediate)',
 trustStatus: 'ROGUE ANCHOR',
 statusColor: 'text-red-400 bg-red-500/15 border-red-500/35',
 keyType: 'RSA 512-bit (Broken)',
 crl: 'None / Missing',
 ocsp: 'None / Missing',
 expiry: '2023-12-31 (Expired)',
 trustedInMozilla: false,
 trustedInMicrosoft: false,
 },
 ];

 return (
 <div className="space-y-4">
 <div className="mb-2">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white">Root Certificate Authorities &amp; Trust Store</h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
 Validation status against standard OS/Browser trust stores (Mozilla NSS, Microsoft CTP)
 </p>
 </div>

 <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
 {rootAuthorities.map((ra) => (
 <div
 key={ra.name}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-4 dark: /[0.025] border dark: -white/[0.06] flex flex-col justify-between"
 >
 <div>
 <div className="flex items-center justify-between gap-2 mb-2">
 <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${ra.statusColor}`}>
 {ra.trustStatus}
 </span>
 <span className="text-[11px] font-mono text-gray-400 dark:text-gray-500">Expires: {ra.expiry}</span>
 </div>
 <h4 className="text-sm font-bold text-gray-900 dark:text-white font-mono break-all">{ra.name}</h4>
 <p className="text-xs text-gray-500 dark:text-gray-400 font-mono mt-1">Key: {ra.keyType}</p>
 </div>

 <div className="mt-4 pt-3 border-t dark: -white/5 space-y-1.5 text-[11px] font-mono">
 <div className="flex items-center justify-between text-gray-500 dark:text-gray-400">
 <span>CRL Endpoint:</span>
 <span className="text-gray-800 dark:text-gray-300 truncate max-w-[200px]" title={ra.crl}>{ra.crl}</span>
 </div>
 <div className="flex items-center justify-between text-gray-500 dark:text-gray-400">
 <span>OCSP Responder:</span>
 <span className="text-gray-800 dark:text-gray-300 truncate max-w-[200px]" title={ra.ocsp}>{ra.ocsp}</span>
 </div>
 <div className="flex items-center justify-between pt-1">
 <span>NSS / MS Trust:</span>
 <span className={ra.trustedInMozilla ? 'text-emerald-500 font-bold' : 'text-red-500 font-bold'}>
 {ra.trustedInMozilla ? 'VERIFIED' : 'REJECTED / UNTRUSTED'}
 </span>
 </div>
 </div>
 </div>
 ))}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TAB 3: CRYPTOGRAPHIC INDICATORS
═══════════════════════════════════════════════════════════ */
function CryptoIndicatorsTab() {
 const indicators = [
 { type: 'Prohibited Cipher', value: 'TLS_RSA_WITH_RC4_128_SHA', rfc: 'RFC 7465 Violation', severity: 'critical', desc: 'RC4 stream cipher keystream biases allow plaintext recovery.' },
 { type: 'Deprecated Protocol', value: 'TLS 1.0 (0x0301)', rfc: 'RFC 8996 Prohibition', severity: 'critical', desc: 'TLS 1.0 formally deprecated; CBC padding attacks and weak MACs.' },
 { type: 'Weak RSA Key', value: 'RSA 1024-bit Modulus', rfc: 'NIST SP 800-131A', severity: 'high', desc: '1024-bit RSA key provides under 80 bits of security.' },
 { type: 'Obsolete Hash', value: 'sha1WithRSAEncryption', rfc: 'RFC 6194 Deprecation', severity: 'high', desc: 'SHA-1 collision resistance compromised by SHAttered & Chosen-Prefix attacks.' },
 { type: 'Missing PFS', value: 'Static RSA Key Exchange', rfc: 'RFC 9325 Recommendation', severity: 'high', desc: 'No ephemeral Diffie-Hellman (DHE/ECDHE); past sessions decryptable if key leaks.' },
 { type: 'JA3S TLS Fingerprint', value: 'e35df3e00ca4ef31d42b87e9c7a9b0f2', rfc: 'Malicious Server Hello Hash', severity: 'critical', desc: 'Matched known TLS downgrade interception proxy signature.' },
 ];

 return (
 <div className="space-y-4">
 <div className="mb-2">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white">Correlated Cryptographic Threat Indicators</h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
 Prohibited ciphers, obsolete protocol versions, and signature collisions identified across network captures
 </p>
 </div>

 <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
 {indicators.map((ind) => (
 <div
 key={ind.value}
 className="bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-4 dark: /[0.025] border dark: -white/[0.06] flex flex-col justify-between"
 >
 <div>
 <div className="flex items-center justify-between gap-1 mb-2">
 <span className="text-[10px] font-mono uppercase text-gray-400 dark:text-gray-500 font-bold">{ind.type}</span>
 <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
 ind.severity === 'critical' ? 'text-red-400 bg-red-500/15 border border-red-500/30' : 'text-amber-400 bg-amber-500/15 border border-amber-500/30'
 }`}>
 {ind.severity}
 </span>
 </div>
 <p className="text-xs font-mono font-bold text-gray-900 dark:text-white break-all">{ind.value}</p>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 leading-relaxed">{ind.desc}</p>
 </div>
 <div className="mt-3 pt-2 border-t dark: -white/5 flex items-center justify-between text-[10px] font-mono text-gray-400 dark:text-gray-500">
 <span>{ind.rfc}</span>
 <CopyButton value={ind.value} />
 </div>
 </div>
 ))}
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 TAB 4: HOST & ORIGIN RECORDS
═══════════════════════════════════════════════════════════ */
function EndpointTab() {
 const hosts = [
 { ip: '185.220.101.47', asn: 'AS208294 (Tor Relay / Bulletproof)', country: 'Germany', port: 25, protocol: 'SMTP', alert: 'Active TLS Downgrade Server' },
 { ip: '45.137.21.88', asn: 'AS59487 (Hosting Solutions)', country: 'Netherlands', port: 143, protocol: 'IMAP', alert: 'Weak CBC Ciphers Accepted' },
 { ip: '91.243.59.12', asn: 'AS44034 (HiChina Web)', country: 'China', port: 25, protocol: 'SMTP', alert: 'Suspected MitM Proxy' },
 { ip: '190.34.176.22', asn: 'AS28006 (Cable & Wireless)', country: 'Panama', port: 25, protocol: 'SMTP', alert: 'SSLv3 Negotiation Accepted' },
 ];

 return (
 <div className="space-y-4">
 <div className="mb-2">
 <h3 className="text-sm font-bold text-gray-900 dark:text-white">Peer Mail Servers &amp; Network Gateways</h3>
 <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
 Autonomous systems and network origin nodes participating in degraded TLS sessions
 </p>
 </div>

 <div className="overflow-x-auto scrollbar-thin">
 <table className="w-full">
 <thead>
 <tr className="border-b dark: -white/10 text-[10px] font-mono uppercase text-gray-400 dark:text-gray-500 text-left">
 <th className="py-2.5 px-3">IP Address</th>
 <th className="py-2.5 px-3">Port / Protocol</th>
 <th className="py-2.5 px-3">Autonomous System (ASN)</th>
 <th className="py-2.5 px-3">Country</th>
 <th className="py-2.5 px-3">Posture Assessment</th>
 </tr>
 </thead>
 <tbody>
 {hosts.map((h) => (
 <tr key={h.ip} className="border-b dark: -white/5 text-xs">
 <td className="py-3 px-3 font-mono font-bold text-gray-900 dark:text-white">{h.ip}</td>
 <td className="py-3 px-3 font-mono text-gray-600 dark:text-gray-400">{h.port} / {h.protocol}</td>
 <td className="py-3 px-3 text-gray-700 dark:text-gray-300">{h.asn}</td>
 <td className="py-3 px-3 text-gray-600 dark:text-gray-400">{h.country}</td>
 <td className="py-3 px-3">
 <span className="px-2 py-0.5 rounded text-[10px] font-bold text-red-600 dark:text-red-400 bg-red-500/10 border -red-500/25">
 {h.alert}
 </span>
 </td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 </div>
 );
}

/* ═══════════════════════════════════════════════════════════
 MODAL: RAW DECODED X.509 CERTIFICATE
═══════════════════════════════════════════════════════════ */
function RawCertModal({ cert, onClose }: { cert: X509CertRecord; onClose: () => void }) {
 const [viewMode, setViewMode] = useState<'asn1' | 'pem'>('asn1');

 return (
 <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in">
 <div
 className="w-full max-w-3xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-800/50 rounded-2xl shadow-sm p-5 sm:p-6 bg-[#0c101c] border -white/10 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden"
 >
 <div className="flex items-center justify-between pb-3 border-b -white/10">
 <div>
 <div className="flex items-center gap-2">
 <h3 className="text-base font-bold text-white font-mono">{cert.subject}</h3>
 <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-blue-500/15 text-blue-400 border -blue-500/30">
 X.509 RFC 5280
 </span>
 </div>
 <p className="text-[11px] text-gray-400 font-mono mt-0.5">Serial: {cert.serialNumber}</p>
 </div>
 <button
 onClick={onClose}
 className="w-8 h-8 rounded-lg flex items-center justify-center text-gray-400 hover:text-white bg-white/5 hover: /10 transition-colors cursor-pointer"
 >
 <X className="w-4 h-4" />
 </button>
 </div>

 {/* View toggle */}
 <div className="flex items-center justify-between py-3">
 <div className="flex items-center gap-2">
 <button
 onClick={() => setViewMode('asn1')}
 className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-colors cursor-pointer ${
 viewMode === 'asn1' ? 'bg-purple-600 text-white' : 'bg-white/5 text-gray-400 hover:text-white'
 }`}
 >
 Decoded ASN.1 Tree
 </button>
 <button
 onClick={() => setViewMode('pem')}
 className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-colors cursor-pointer ${
 viewMode === 'pem' ? 'bg-purple-600 text-white' : 'bg-white/5 text-gray-400 hover:text-white'
 }`}
 >
 Raw PEM Format
 </button>
 </div>

 <div className="flex items-center gap-1.5">
 <span className="text-xs font-mono text-gray-400">Copy</span>
 <CopyButton value={viewMode === 'asn1' ? cert.rawAsn1 : cert.rawPem} />
 </div>
 </div>

 {/* Code Content */}
 <div className="flex-1 overflow-auto bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl p-4 bg-black/60 border -white/5 font-mono text-xs text-gray-300 leading-relaxed scrollbar-thin">
 <pre className="whitespace-pre-wrap">
 {viewMode === 'asn1' ? cert.rawAsn1 : cert.rawPem}
 </pre>
 </div>

 {/* Modal Footer */}
 <div className="mt-4 pt-3 border-t -white/10 flex items-center justify-between text-xs text-gray-400">
 <span className="font-mono">Fingerprint: {cert.fingerprintSha256.slice(0, 32)}...</span>
 <button
 onClick={onClose}
 className="px-4 py-2 bg-gray-50 dark:bg-zinc-900/50 border border-gray-200 dark:border-zinc-800/50 rounded-xl text-xs font-bold text-white bg-white/10 hover: /15 transition-colors cursor-pointer"
 >
 Close
 </button>
 </div>
 </div>
 </div>
 );
}
