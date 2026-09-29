export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ThreatType = 'BEC' | 'Phishing' | 'Malware' | 'Credential Harvesting' | 'Spoofing' | 'Ransomware' | 'C2' | 'Spam';
export type CryptoThreatType = 'Downgrade Attack' | 'Weak Cipher' | 'Man-in-the-Middle (MitM)' | 'Expired Certificate' | 'Weak Key' | 'Self-Signed Certificate' | 'Protocol Violation' | 'Unknown';

export interface KPIData {
  label: string;
  value: string | number;
  delta?: string;
  trend?: 'up' | 'down' | 'flat';
  icon: string;
  accent: 'blue' | 'teal' | 'red' | 'amber' | 'green';
}

export interface ThreatRecord {
  id: string;
  timestamp: string;
  sender: string;
  subject: string;
  type: ThreatType;
  severity: Severity;
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  riskScore: number;
  destination: string;
}

export interface ActivityPoint {
  hour: string;
  threats: number;
  scanned: number;
}

export interface ThreatDistribution {
  name: string;
  value: number;
  color: string;
}

export interface GeoThreat {
  id: string;
  city: string;
  country: string;
  lat: number;
  lng: number;
  count: number;
  severity: Severity;
}

export interface RiskFactor {
  label: string;
  severity: Severity;
  detail: string;
}

export interface ObservedFact {
  id: string;
  category: string;
  field: string;
  value: string;
  status: 'fail' | 'pass' | 'warn' | 'info';
}

export interface AIInference {
  id: string;
  inference: string;
  confidence: number;
  basis: string;
}

export interface DemoEmail {
  from: string;
  replyTo: string;
  to: string;
  subject: string;
  date: string;
  receivedVia: string;
  bodyPreview: string;
  headers: { key: string; value: string }[];
}

export const KPIS: KPIData[] = [
  { label: 'PCAP Sessions Analyzed', value: '14,892', delta: '+8.2%', trend: 'up', icon: 'MailCheck', accent: 'blue' },
  { label: 'Crypto Weaknesses Found', value: '1,247', delta: '+12.4%', trend: 'up', icon: 'ShieldAlert', accent: 'red' },
  { label: 'Critical Vulnerabilities', value: '38', delta: '+3', trend: 'up', icon: 'AlertOctagon', accent: 'red' },
  { label: 'Active Investigations', value: '17', delta: '+2', trend: 'up', icon: 'Search', accent: 'amber' },
  { label: 'Posture Score', value: '61.2%', delta: '-2.1%', trend: 'down', icon: 'Target', accent: 'green' },
  { label: 'TLS Campaigns', value: '6', delta: '+1', trend: 'up', icon: 'Network', accent: 'teal' },
];

export const THREAT_DISTRIBUTION: ThreatDistribution[] = [
  { name: 'TLS 1.3', value: 48, color: '#22c55e' },
  { name: 'TLS 1.2', value: 31, color: '#3b82f6' },
  { name: 'TLS 1.1', value: 12, color: '#f59e0b' },
  { name: 'TLS 1.0', value: 6, color: '#f97316' },
  { name: 'SSLv3', value: 2, color: '#ef4444' },
  { name: 'Unknown', value: 1, color: '#6b7280' },
];

export const HOURLY_ACTIVITY: ActivityPoint[] = [
  { hour: '00:00', threats: 4, scanned: 142 },
  { hour: '02:00', threats: 2, scanned: 98 },
  { hour: '04:00', threats: 1, scanned: 76 },
  { hour: '06:00', threats: 3, scanned: 110 },
  { hour: '08:00', threats: 12, scanned: 287 },
  { hour: '10:00', threats: 19, scanned: 341 },
  { hour: '12:00', threats: 24, scanned: 398 },
  { hour: '14:00', threats: 31, scanned: 452 },
  { hour: '16:00', threats: 27, scanned: 421 },
  { hour: '18:00', threats: 18, scanned: 312 },
  { hour: '20:00', threats: 9, scanned: 198 },
  { hour: '22:00', threats: 5, scanned: 154 },
];

// ─── Network Session Data Model ─────────────────────────────────────────────

export interface NetworkSession {
  id: string;
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'SMTPS' | 'IMAPS';
  tlsVersion: 'TLS 1.3' | 'TLS 1.2' | 'TLS 1.1' | 'TLS 1.0' | 'SSLv3' | 'None';
  cipherSuite: string;
  certificate: {
    issuer: string;
    subject: string;
    expiry: string;
    keyLength: number;
    keyAlgo: string;
    selfSigned: boolean;
    expired: boolean;
  };
  threatType: CryptoThreatType;
  severity: Severity;
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  riskScore: number;
}

export const RECENT_THREATS: NetworkSession[] = [
  {
    id: 'NS-2026-0892',
    timestamp: '2026-08-25 14:32:11',
    sourceIP: '185.220.101.47',
    destIP: '10.14.22.5',
    protocol: 'SMTP',
    tlsVersion: 'TLS 1.0',
    cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
    certificate: { issuer: 'Self-Signed', subject: 'mail.attacker.example', expiry: '2024-01-01', keyLength: 1024, keyAlgo: 'RSA', selfSigned: true, expired: true },
    threatType: 'Downgrade Attack',
    severity: 'critical',
    status: 'investigating',
    riskScore: 96,
  },
  {
    id: 'NS-2026-0891',
    timestamp: '2026-08-25 13:18:44',
    sourceIP: '45.137.21.88',
    destIP: '10.14.22.6',
    protocol: 'IMAP',
    tlsVersion: 'TLS 1.1',
    cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    certificate: { issuer: 'Let\'s Encrypt', subject: 'mail.paypa1-secure.example', expiry: '2025-03-15', keyLength: 2048, keyAlgo: 'RSA', selfSigned: false, expired: false },
    threatType: 'Weak Cipher',
    severity: 'high',
    status: 'open',
    riskScore: 87,
  },
  {
    id: 'NS-2026-0890',
    timestamp: '2026-08-25 12:05:22',
    sourceIP: '91.243.59.12',
    destIP: '10.14.22.7',
    protocol: 'SMTP',
    tlsVersion: 'TLS 1.2',
    cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    certificate: { issuer: 'DigiCert', subject: 'mail.vendor-portal.example', expiry: '2027-06-01', keyLength: 4096, keyAlgo: 'RSA', selfSigned: false, expired: false },
    threatType: 'Man-in-the-Middle (MitM)',
    severity: 'high',
    status: 'contained',
    riskScore: 82,
  },
  {
    id: 'NS-2026-0889',
    timestamp: '2026-08-25 11:47:09',
    sourceIP: '190.34.176.22',
    destIP: '10.14.22.5',
    protocol: 'SMTP',
    tlsVersion: 'SSLv3',
    cipherSuite: 'TLS_RSA_WITH_DES_CBC_SHA',
    certificate: { issuer: 'Unknown CA', subject: 'mail.acme-relay.example', expiry: '2023-12-31', keyLength: 512, keyAlgo: 'RSA', selfSigned: true, expired: true },
    threatType: 'Downgrade Attack',
    severity: 'critical',
    status: 'investigating',
    riskScore: 94,
  },
  {
    id: 'NS-2026-0888',
    timestamp: '2026-08-25 10:33:51',
    sourceIP: '198.51.100.77',
    destIP: '10.14.22.8',
    protocol: 'POP3',
    tlsVersion: 'TLS 1.2',
    cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    certificate: { issuer: 'Comodo', subject: 'pop3.dhl-express-notify.example', expiry: '2026-11-30', keyLength: 2048, keyAlgo: 'RSA', selfSigned: false, expired: false },
    threatType: 'Weak Cipher',
    severity: 'medium',
    status: 'resolved',
    riskScore: 61,
  },
  {
    id: 'NS-2026-0887',
    timestamp: '2026-08-25 09:22:17',
    sourceIP: '203.0.113.91',
    destIP: '10.14.22.9',
    protocol: 'IMAPS',
    tlsVersion: 'TLS 1.3',
    cipherSuite: 'TLS_AES_128_GCM_SHA256',
    certificate: { issuer: 'Self-Signed', subject: 'imap.acme-payroll.example', expiry: '2025-01-15', keyLength: 1024, keyAlgo: 'RSA', selfSigned: true, expired: false },
    threatType: 'Weak Key',
    severity: 'high',
    status: 'contained',
    riskScore: 79,
  },
  {
    id: 'NS-2026-0886',
    timestamp: '2026-08-25 08:14:03',
    sourceIP: '203.0.113.55',
    destIP: '10.14.22.5',
    protocol: 'SMTP',
    tlsVersion: 'TLS 1.1',
    cipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    certificate: { issuer: 'Unknown CA', subject: 'mail.micros0ft-365.example', expiry: '2025-08-01', keyLength: 2048, keyAlgo: 'RSA', selfSigned: false, expired: false },
    threatType: 'Weak Cipher',
    severity: 'high',
    status: 'open',
    riskScore: 85,
  },
];

export const GEO_THREATS: GeoThreat[] = [
  { id: 'G1', city: 'Lagos', country: 'Nigeria', lat: 6.52, lng: 3.37, count: 47, severity: 'critical' },
  { id: 'G2', city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.61, count: 38, severity: 'critical' },
  { id: 'G3', city: 'Saint Petersburg', country: 'Russia', lat: 59.93, lng: 30.34, count: 22, severity: 'high' },
  { id: 'G4', city: 'Kyiv', country: 'Ukraine', lat: 50.45, lng: 30.52, count: 18, severity: 'high' },
  { id: 'G5', city: 'Beijing', country: 'China', lat: 39.90, lng: 116.40, count: 31, severity: 'critical' },
  { id: 'G6', city: 'Shanghai', country: 'China', lat: 31.23, lng: 121.47, count: 19, severity: 'high' },
  { id: 'G7', city: 'Mumbai', country: 'India', lat: 19.07, lng: 72.87, count: 14, severity: 'medium' },
  { id: 'G8', city: 'São Paulo', country: 'Brazil', lat: -23.55, lng: -46.63, count: 16, severity: 'high' },
  { id: 'G9', city: 'Mexico City', country: 'Mexico', lat: 19.43, lng: -99.13, count: 12, severity: 'medium' },
  { id: 'G10', city: 'Istanbul', country: 'Turkey', lat: 41.01, lng: 28.97, count: 9, severity: 'medium' },
  { id: 'G11', city: 'Johannesburg', country: 'South Africa', lat: -26.20, lng: 28.04, count: 8, severity: 'low' },
  { id: 'G12', city: 'Hanoi', country: 'Vietnam', lat: 21.03, lng: 105.85, count: 11, severity: 'medium' },
];

// ─── Demo PCAP Session (replaces DEMO_EMAIL) ─────────────────────────────

export interface TLSHandshakeDetail {
  phase: string;
  direction: 'Client → Server' | 'Server → Client' | 'Bidirectional';
  message: string;
  detail: string;
  status: 'ok' | 'warn' | 'fail';
}

export const DEMO_PCAP_SESSION: NetworkSession = {
  id: 'NS-2026-DEMO',
  timestamp: '2026-08-25 14:31:48 UTC',
  sourceIP: '185.220.101.47',
  destIP: '10.14.22.5',
  protocol: 'SMTP',
  tlsVersion: 'TLS 1.0',
  cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
  certificate: {
    issuer: 'Self-Signed (Unknown CA)',
    subject: 'mail.attacker-relay.example',
    expiry: '2024-01-01',
    keyLength: 1024,
    keyAlgo: 'RSA',
    selfSigned: true,
    expired: true,
  },
  threatType: 'Downgrade Attack',
  severity: 'critical',
  status: 'investigating',
  riskScore: 96,
};

export const DEMO_EMAIL = {
  id: 'DEMO-PCAP-001',
  subject: '[SMTP Posture Alert] TLS Downgrade & Expired Certificate Intercepted',
  from: '185.220.101.47:48920 (FlokiNET Bulletproof)',
  replyTo: '10.14.22.5:25 (acme-mailgw-03.acme-corp.example)',
  date: '2026-08-25 14:31:48 UTC',
  headers: [
    { key: 'X-Session-ID', value: 'NS-2026-DEMO-0471' },
    { key: 'X-Protocol', value: 'SMTP (Port 25 STARTTLS)' },
    { key: 'X-TLS-Version', value: 'TLS 1.0 (Deprecated RFC 8996)' },
    { key: 'X-Cipher-Suite', value: 'TLS_RSA_WITH_RC4_128_SHA (RFC 7465 Violation)' },
    { key: 'X-Certificate-Issuer', value: 'CN=mail.attacker-relay.example (Self-Signed / Untrusted)' },
    { key: 'X-Certificate-Status', value: 'EXPIRED (2024-01-01) — 236 days overdue' },
    { key: 'X-Public-Key', value: 'RSA-1024 (Insecure < 2048-bit NIST threshold)' },
    { key: 'X-Forward-Secrecy', value: 'NO (Static RSA Key Exchange)' },
  ],
  bodyPreview: 'CRITICAL SECURITY POSTURE ALERT: Live network capture revealed an active TLS Downgrade Attack on incoming SMTP transmission. The client and mail gateway negotiated deprecated TLS 1.0 with cryptographically prohibited cipher suite TLS_RSA_WITH_RC4_128_SHA. Untrusted self-signed RSA-1024 digital certificate presented by remote host.',
  riskScore: 96,
  severity: 'critical' as Severity,
};

export const TLS_HANDSHAKE_STEPS: TLSHandshakeDetail[] = [
  { phase: 'Client Hello', direction: 'Client → Server', message: 'ClientHello', detail: 'Proposed cipher suites include RC4, DES, and TLS 1.0 — all deprecated', status: 'fail' },
  { phase: 'Server Hello', direction: 'Server → Client', message: 'ServerHello', detail: 'Server selected TLS 1.0 / TLS_RSA_WITH_RC4_128_SHA — weak negotiation accepted', status: 'fail' },
  { phase: 'Certificate', direction: 'Server → Client', message: 'Certificate Exchange', detail: 'Self-signed certificate (RSA-1024) presented — issuer unverified, expired 2024-01-01', status: 'fail' },
  { phase: 'ServerKeyExchange', direction: 'Server → Client', message: 'ServerKeyExchange', detail: 'RSA key exchange without forward secrecy — session keys not ephemeral', status: 'warn' },
  { phase: 'ChangeCipherSpec', direction: 'Bidirectional', message: 'ChangeCipherSpec', detail: 'Cipher downgrade to RC4 confirmed — stream cipher known to be broken', status: 'fail' },
  { phase: 'Application Data', direction: 'Bidirectional', message: 'Encrypted Application Data', detail: 'SMTP data transfer under RC4 — susceptible to BEAST/POODLE attacks', status: 'warn' },
];


export const RISK_FACTORS: RiskFactor[] = [
  {
    label: 'Deprecated TLS 1.0 protocol negotiated',
    severity: 'critical',
    detail: 'Server accepted TLS 1.0 handshake — vulnerable to BEAST and POODLE attacks; deprecated since RFC 8996 (2021)',
  },
  {
    label: 'Broken RC4 stream cipher active',
    severity: 'critical',
    detail: 'TLS_RSA_WITH_RC4_128_SHA selected — RC4 is cryptographically broken and banned in RFC 7465',
  },
  {
    label: 'Expired self-signed certificate',
    severity: 'critical',
    detail: 'Server certificate expired 2024-01-01, issued by unknown CA — no chain of trust, MITM trivially possible',
  },
  {
    label: 'RSA-1024 weak public key',
    severity: 'high',
    detail: 'Certificate uses 1024-bit RSA key — below NIST minimum of 2048 bits; factorable with modern compute',
  },
  {
    label: 'No forward secrecy (non-ephemeral RSA)',
    severity: 'high',
    detail: 'RSA key exchange without ephemeral variant — past sessions can be decrypted if private key is ever compromised',
  },
];

export const OBSERVED_FACTS: ObservedFact[] = [
  {
    id: 'F1',
    category: 'TLS Protocol',
    field: 'Negotiated Version',
    value: 'TLS 1.0 (Deprecated)',
    status: 'fail',
  },
  {
    id: 'F2',
    category: 'TLS Protocol',
    field: 'STARTTLS Observed',
    value: 'Yes — SMTP STARTTLS negotiation detected on port 25',
    status: 'info',
  },
  {
    id: 'F3',
    category: 'Cipher Suite',
    field: 'Negotiated Cipher',
    value: 'TLS_RSA_WITH_RC4_128_SHA (Broken)',
    status: 'fail',
  },
  {
    id: 'F4',
    category: 'Cipher Suite',
    field: 'Key Exchange',
    value: 'RSA (No Forward Secrecy)',
    status: 'fail',
  },
  {
    id: 'F5',
    category: 'Cipher Suite',
    field: 'Encryption',
    value: 'RC4-128 (Broken stream cipher)',
    status: 'fail',
  },
  {
    id: 'F6',
    category: 'Cipher Suite',
    field: 'MAC',
    value: 'SHA-1 (Weak HMAC)',
    status: 'warn',
  },
  {
    id: 'F7',
    category: 'Certificate',
    field: 'Issuer',
    value: 'Self-Signed (Unknown CA)',
    status: 'fail',
  },
  {
    id: 'F8',
    category: 'Certificate',
    field: 'Expiry',
    value: '2024-01-01 (Expired 236 days ago)',
    status: 'fail',
  },
  {
    id: 'F9',
    category: 'Certificate',
    field: 'Public Key',
    value: 'RSA-1024 (Below NIST minimum 2048)',
    status: 'fail',
  },
  {
    id: 'F10',
    category: 'Certificate',
    field: 'Subject',
    value: 'mail.attacker-relay.example (Suspicious hostname)',
    status: 'warn',
  },
  {
    id: 'F11',
    category: 'Infrastructure',
    field: 'Source IP',
    value: '185.220.101.47 (Bulletproof hosting)',
    status: 'fail',
  },
  {
    id: 'F12',
    category: 'Infrastructure',
    field: 'Destination IP',
    value: '10.14.22.5 (acme-mailgw-03.acme-corp.example)',
    status: 'info',
  },
  {
    id: 'F13',
    category: 'Infrastructure',
    field: 'Protocol',
    value: 'SMTP (port 25) — Plaintext channel susceptible to MITM',
    status: 'warn',
  },
  {
    id: 'F14',
    category: 'Attack Vectors',
    field: 'POODLE Vulnerability',
    value: 'Confirmed — SSLv3/TLS 1.0 + CBC padding oracle possible',
    status: 'fail',
  },
  {
    id: 'F15',
    category: 'Attack Vectors',
    field: 'BEAST Vulnerability',
    value: 'Confirmed — TLS 1.0 + CBC mode IV predictability',
    status: 'fail',
  },
];

export const AI_INFERENCES: AIInference[] = [
  {
    id: 'I1',
    inference: 'Active TLS downgrade attack — adversary forced negotiation to deprecated TLS 1.0',
    confidence: 94.7,
    basis: 'ClientHello offered modern suites but server selected TLS 1.0/RC4; indicative of active MITM interception',
  },
  {
    id: 'I2',
    inference: 'SMTP session at high risk of POODLE/BEAST exploitation due to CBC mode under TLS 1.0',
    confidence: 88.2,
    basis: 'TLS 1.0 + CBC cipher combo; known CBC padding oracle attack surface confirmed',
  },
  {
    id: 'I3',
    inference: 'Certificate chain unverifiable — self-signed RSA-1024 from unknown issuer enables trivial MITM',
    confidence: 91.3,
    basis: 'Expired self-signed cert, 1024-bit RSA, no OCSP/CRL stapling, no chain of trust presented',
  },
  {
    id: 'I4',
    inference: 'Infrastructure consistent with known MitM proxy cluster used in STARTTLS stripping campaigns',
    confidence: 72.5,
    basis: 'Source IP 185.220.101.47 on bulletproof hosting; TLS downgrade pattern matches cluster TLSDOWN-019',
  },
];

export const ANALYSIS_STAGES = [
  'Reconstructing TCP Streams',
  'Detecting STARTTLS Negotiations',
  'Parsing TLS Handshakes',
  'Validating X.509 Certificates',
  'Scoring Cipher Suites',
  'Correlating Sessions',
  'Preserving Evidence',
  'Generating Report',
] as const;

export type AnalysisStage = (typeof ANALYSIS_STAGES)[number];

// ─── Phase 2: Crypto Forensics (TLS Relay Hops / Session Hops) ──────────────

export interface SmtpRelayHop {
  id: string;
  hop: number;
  ip: string;
  hostname: string;
  timestamp: string;
  country: string;
  countryCode: string;
  asn: string;
  asnOrg: string;
  confidence: number;
  note: string;
  tlsVersion?: string;
  cipherSuite?: string;
}

export const SMTP_RELAYS: SmtpRelayHop[] = [
  {
    id: 'R1', hop: 1, ip: '185.220.101.47', hostname: 'mail-attacker-relay.example',
    timestamp: '2026-08-25 14:31:48 UTC', country: 'Romania', countryCode: 'RO',
    asn: 'AS200651', asnOrg: 'FlokiNET Ltd (synthetic)', confidence: 82,
    note: 'Session origin — TLS 1.0/RC4 downgrade initiated here; bulletproof hosting',
    tlsVersion: 'TLS 1.0', cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
  },
  {
    id: 'R2', hop: 2, ip: '45.137.21.88', hostname: 'mitm-proxy-01.flokinet-redirect.example',
    timestamp: '2026-08-25 14:31:50 UTC', country: 'Iceland', countryCode: 'IS',
    asn: 'AS20495', asnOrg: 'ThorDatacenter (synthetic)', confidence: 71,
    note: 'MitM proxy node — STARTTLS stripping observed; re-encrypted with weak cipher',
    tlsVersion: 'TLS 1.0', cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
  },
  {
    id: 'R3', hop: 3, ip: '91.243.59.12', hostname: 'gw-acme-edge-02.acme-corp.example',
    timestamp: '2026-08-25 14:31:52 UTC', country: 'United States', countryCode: 'US',
    asn: 'AS40023', asnOrg: 'Acme Corp Networks (synthetic)', confidence: 99,
    note: 'Recipient corporate edge gateway — accepted TLS 1.0 session without policy enforcement',
    tlsVersion: 'TLS 1.0', cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
  },
  {
    id: 'R4', hop: 4, ip: '10.14.22.5', hostname: 'acme-mailgw-03.acme-corp.example',
    timestamp: '2026-08-25 14:31:53 UTC', country: 'United States', countryCode: 'US',
    asn: 'Internal', asnOrg: 'Acme Corp Internal (synthetic)', confidence: 100,
    note: 'Internal mail gateway — final SMTP delivery endpoint; no TLS version upgrade enforced',
    tlsVersion: 'TLS 1.0', cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA',
  },
];


// TLS extended parameters (replaces EXTENDED_HEADERS for Crypto Forensics page)
export interface ExtendedHeader {
  key: string;
  value: string;
  category: 'handshake' | 'cipher' | 'certificate' | 'transport' | 'vulnerability';
}

export const EXTENDED_HEADERS: ExtendedHeader[] = [
  { key: 'TLS Version Negotiated', value: 'TLS 1.0 (deprecated — RFC 8996)', category: 'handshake' },
  { key: 'ClientHello Supported Versions', value: 'TLS 1.0, TLS 1.1, TLS 1.2 (TLS 1.3 not proposed)', category: 'handshake' },
  { key: 'ServerHello Selected Cipher', value: 'TLS_RSA_WITH_RC4_128_SHA', category: 'cipher' },
  { key: 'Key Exchange Algorithm', value: 'RSA (Static — no forward secrecy)', category: 'cipher' },
  { key: 'Encryption Algorithm', value: 'RC4-128 (broken stream cipher — RFC 7465 prohibited)', category: 'cipher' },
  { key: 'MAC Algorithm', value: 'SHA-1 (weak — collision resistance compromised)', category: 'cipher' },
  { key: 'Certificate Subject', value: 'mail.attacker-relay.example', category: 'certificate' },
  { key: 'Certificate Issuer', value: 'Self-Signed (no trusted CA chain)', category: 'certificate' },
  { key: 'Certificate Valid From', value: '2022-01-01', category: 'certificate' },
  { key: 'Certificate Valid Until', value: '2024-01-01 (EXPIRED)', category: 'certificate' },
  { key: 'Public Key Algorithm', value: 'RSA-1024 (below NIST SP 800-131A minimum of 2048)', category: 'certificate' },
  { key: 'OCSP Stapling', value: 'Not present — revocation status unverifiable', category: 'certificate' },
  { key: 'SMTP Protocol', value: 'Port 25 STARTTLS — opportunistic encryption only', category: 'transport' },
  { key: 'TCP Stream', value: 'Stream 0x4A — reconstructed from 14 packets', category: 'transport' },
  { key: 'POODLE (CVE-2014-3566)', value: 'VULNERABLE — TLS 1.0 + CBC padding oracle', category: 'vulnerability' },
  { key: 'BEAST (CVE-2011-3389)', value: 'VULNERABLE — TLS 1.0 + CBC IV predictability', category: 'vulnerability' },
];

export interface HeaderFact {
  id: string;
  fact: string;
  status: 'fail' | 'warn' | 'info';
  detail: string;
}

export const HEADER_FACTS: HeaderFact[] = [
  { id: 'HF1', fact: 'TLS 1.0 negotiated — deprecated protocol active', status: 'fail', detail: 'Both client and server completed TLS 1.0 handshake; RFC 8996 mandates TLS 1.2 minimum. Exposes session to BEAST and POODLE.' },
  { id: 'HF2', fact: 'RC4 stream cipher selected — cryptographically broken', status: 'fail', detail: 'TLS_RSA_WITH_RC4_128_SHA violates RFC 7465 which prohibits RC4 in all TLS versions; session confidentiality not guaranteed.' },
  { id: 'HF3', fact: 'Self-signed certificate from unknown CA', status: 'fail', detail: 'No verifiable certificate chain — any MITM attacker can present forged certificate without detection by standard clients.' },
  { id: 'HF4', fact: 'Certificate expired 236 days before session', status: 'fail', detail: 'Certificate expiry 2024-01-01 predates PCAP session date (2026-08-25) by over two years; indicates deliberate use of expired cert.' },
  { id: 'HF5', fact: 'RSA-1024 public key below NIST minimum', status: 'warn', detail: 'NIST SP 800-131A requires minimum 2048-bit RSA. 1024-bit keys are considered factorable with nation-state resources.' },
];

export interface HeaderInference {
  id: string;
  inference: string;
  confidence: number;
  basis: string;
}

export const HEADER_INFERENCES: HeaderInference[] = [
  { id: 'HI1', inference: 'Active STARTTLS stripping — adversary intercepted SMTP session before TLS negotiation', confidence: 89.3, basis: 'Hop 2 (mitm-proxy-01) exhibits pattern consistent with STARTTLS stripping; cipher downgrade occurred at that node' },
  { id: 'HI2', inference: 'Man-in-the-Middle proxy confirmed — relay chain suggests interception layer at AS20495', confidence: 76.8, basis: 'Bulletproof hosting origin, repeated RC4 across hops, no certificate chain validation enforced at recipient' },
  { id: 'HI3', inference: 'Session data at risk of historical decryption if RC4 key stream recovered via statistical analysis', confidence: 84.1, basis: 'RC4 key reuse patterns; session duration and payload size consistent with known RC4 recovery attack corpus' },
];


// ─── Phase 3: Certificate Vault (replaces Threat Intelligence) ───────────────

// X.509 Certificate vault entries
export interface X509Certificate {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  keyAlgo: string;
  keyLength: number;
  signatureAlgo: string;
  fingerprint: string;
  selfSigned: boolean;
  expired: boolean;
  weakKey: boolean;
  sessionId: string;
  tlsVersion: string;
  riskScore: number;
  severity: Severity;
}

export const X509_CERTIFICATES: X509Certificate[] = [
  {
    id: 'CERT-2026-001',
    subject: 'mail.attacker-relay.example',
    issuer: 'Self-Signed (Unknown CA)',
    serialNumber: '0x4E2A1F9C',
    validFrom: '2022-01-01',
    validUntil: '2024-01-01',
    keyAlgo: 'RSA',
    keyLength: 1024,
    signatureAlgo: 'SHA1withRSA',
    fingerprint: 'A3:F5:B8:C9:D2:E1:F4:A7:B6:C8:D5:E2:F1:A4:B7:C9',
    selfSigned: true,
    expired: true,
    weakKey: true,
    sessionId: 'NS-2026-0892',
    tlsVersion: 'TLS 1.0',
    riskScore: 98,
    severity: 'critical',
  },
  {
    id: 'CERT-2026-002',
    subject: 'mail.paypa1-secure.example',
    issuer: "Let's Encrypt Authority X3",
    serialNumber: '0x7C3B2E8A',
    validFrom: '2024-09-15',
    validUntil: '2025-03-15',
    keyAlgo: 'RSA',
    keyLength: 2048,
    signatureAlgo: 'SHA256withRSA',
    fingerprint: 'B4:C6:D7:E8:F9:A0:B1:C2:D3:E4:F5:A6:B7:C8:D9:E0',
    selfSigned: false,
    expired: false,
    weakKey: false,
    sessionId: 'NS-2026-0891',
    tlsVersion: 'TLS 1.1',
    riskScore: 64,
    severity: 'medium',
  },
  {
    id: 'CERT-2026-003',
    subject: 'mail.vendor-portal.example',
    issuer: 'DigiCert TLS RSA SHA256 2020 CA1',
    serialNumber: '0x1A9E4C72',
    validFrom: '2026-06-01',
    validUntil: '2027-06-01',
    keyAlgo: 'RSA',
    keyLength: 4096,
    signatureAlgo: 'SHA256withRSA',
    fingerprint: 'C5:D7:E8:F9:A0:B1:C2:D3:E4:F5:A6:B7:C8:D9:E0:F1',
    selfSigned: false,
    expired: false,
    weakKey: false,
    sessionId: 'NS-2026-0890',
    tlsVersion: 'TLS 1.2',
    riskScore: 18,
    severity: 'low',
  },
  {
    id: 'CERT-2026-004',
    subject: 'mail.acme-relay.example',
    issuer: 'Self-Signed (Unknown CA)',
    serialNumber: '0x9F2D6B41',
    validFrom: '2020-06-01',
    validUntil: '2023-12-31',
    keyAlgo: 'RSA',
    keyLength: 512,
    signatureAlgo: 'SHA1withRSA',
    fingerprint: 'D6:E8:F9:A0:B1:C2:D3:E4:F5:A6:B7:C8:D9:E0:F1:A2',
    selfSigned: true,
    expired: true,
    weakKey: true,
    sessionId: 'NS-2026-0889',
    tlsVersion: 'SSLv3',
    riskScore: 99,
    severity: 'critical',
  },
  {
    id: 'CERT-2026-005',
    subject: 'imap.acme-payroll.example',
    issuer: 'Self-Signed (Internal IT)',
    serialNumber: '0x3C7F1E29',
    validFrom: '2024-01-15',
    validUntil: '2025-01-15',
    keyAlgo: 'RSA',
    keyLength: 1024,
    signatureAlgo: 'SHA256withRSA',
    fingerprint: 'E7:F9:A0:B1:C2:D3:E4:F5:A6:B7:C8:D9:E0:F1:A2:B3',
    selfSigned: true,
    expired: false,
    weakKey: true,
    sessionId: 'NS-2026-0887',
    tlsVersion: 'TLS 1.3',
    riskScore: 72,
    severity: 'high',
  },
];

// Top Vulnerable Cipher Suites (replaces Top Malicious Domains)
export interface VulnerableCipherSuite {
  rank: number;
  cipherSuite: string;
  sessionCount: number;
  vulnerability: string;
  severity: Severity;
  rfc: string;
}

export const TOP_VULNERABLE_CIPHERS: VulnerableCipherSuite[] = [
  { rank: 1, cipherSuite: 'TLS_RSA_WITH_RC4_128_SHA', sessionCount: 47, vulnerability: 'RC4 broken stream cipher (RFC 7465)', severity: 'critical', rfc: 'RFC 7465' },
  { rank: 2, cipherSuite: 'TLS_RSA_WITH_DES_CBC_SHA', sessionCount: 31, vulnerability: 'DES 56-bit key — brute-forceable', severity: 'critical', rfc: 'NIST SP 800-131A' },
  { rank: 3, cipherSuite: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', sessionCount: 28, vulnerability: 'SWEET32 birthday attack (CVE-2016-2183)', severity: 'high', rfc: 'RFC 7568' },
  { rank: 4, cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA', sessionCount: 22, vulnerability: 'No forward secrecy + CBC padding oracle risk', severity: 'high', rfc: 'RFC 9325' },
  { rank: 5, cipherSuite: 'TLS_RSA_WITH_AES_128_CBC_SHA256', sessionCount: 19, vulnerability: 'No forward secrecy; static RSA key exchange', severity: 'medium', rfc: 'RFC 9325' },
];

// ─── Legacy: IP/Domain Intelligence (retained for Session Mapping / Origin Investigation) ──


export interface IPIntelligence {
  ip: string;
  reputation: 'malicious' | 'suspicious' | 'clean';
  reputationScore: number;
  asn: string;
  asnOrg: string;
  hosting: string;
  country: string;
  countryCode: string;
  networkType: string;
  firstSeen: string;
  lastSeen: string;
  relatedIndicators: string[];
  blocklists: string[];
}

export const IP_INTEL: IPIntelligence = {
  ip: '185.220.101.47',
  reputation: 'malicious',
  reputationScore: 12,
  asn: 'AS200651',
  asnOrg: 'FlokiNET Ltd (synthetic)',
  hosting: 'Bulletproof / abuse-tolerant VPS',
  country: 'Romania',
  countryCode: 'RO',
  networkType: 'Datacenter / VPN exit',
  firstSeen: '2026-08-22',
  lastSeen: '2026-08-25',
  relatedIndicators: ['micros0ft-support.example', 'secure-verification.example', 'WIRE-FAUD-247'],
  blocklists: ['Spamhaus XBL', 'SORBS DNSBL', 'UCEPROTECT L2', 'Barracuda'],
};

export interface DomainIntelligence {
  domain: string;
  reputation: 'malicious' | 'suspicious' | 'clean';
  registrationAge: string;
  registeredOn: string;
  registrar: string;
  dns: { type: string; value: string }[];
  nameservers: string[];
  hosting: string;
  relatedDomains: string[];
  lookalikeSimilarity: number;
  lookalikeTarget: string;
}

export const DOMAIN_INTEL: DomainIntelligence = {
  domain: 'micros0ft-support.example',
  reputation: 'malicious',
  registrationAge: '3 days',
  registeredOn: '2026-08-22',
  registrar: 'Njalla AB (synthetic privacy registrar)',
  dns: [
    { type: 'A', value: '185.220.101.47' },
    { type: 'MX', value: 'mail-micros0ft-support.example' },
    { type: 'TXT (SPF)', value: 'v=spf1 ip4:185.220.101.47 -all' },
    { type: 'TXT (DMARC)', value: 'v=DMARC1; p=none; rua=mailto:abuse@micros0ft-support.example' },
  ],
  nameservers: ['ns1.flokinet-dns.example', 'ns2.flokinet-dns.example'],
  hosting: 'FlokiNET Ltd — bulletproof hosting',
  relatedDomains: ['secure-verification.example', 'micros0ft-365.example', 'paypa1-secure.example'],
  lookalikeSimilarity: 92,
  lookalikeTarget: 'microsoft.example',
};

export const LOOKALIKE_ANALYSIS = {
  expected: 'microsoft.example',
  observed: 'micros0ft-support.example',
  similarity: 92,
  characteristics: [
    { trait: 'Homoglyph substitution', detail: 'Letter "o" replaced with digit "0" (zero) — visually near-identical in most fonts', severity: 'critical' as Severity },
    { trait: 'Subdomain appendage', detail: '"-support" appended to mimic legitimate support subdomains', severity: 'high' as Severity },
    { trait: 'TLD match', detail: 'Uses ".example" TLD — same as expected target domain', severity: 'medium' as Severity },
    { trait: 'Registration recency', detail: 'Domain registered only 3 days before the phishing email was sent', severity: 'critical' as Severity },
    { trait: 'Privacy registrar', detail: 'Registered via privacy-focused registrar that redacts WHOIS data', severity: 'high' as Severity },
  ],
};

export interface URLIntelligence {
  fullUrl: string;
  domain: string;
  reputation: 'malicious' | 'suspicious' | 'clean';
  reputationScore: number;
  redirectCount: number;
  redirectChain: string[];
  firstSeen: string;
  category: string;
  detectionSignals: string[];
  riskScore: number;
}

export const URL_INTEL: URLIntelligence = {
  fullUrl: 'https://micros0ft-support.example/verify?id=PX9471',
  domain: 'micros0ft-support.example',
  reputation: 'malicious',
  reputationScore: 8,
  redirectCount: 3,
  redirectChain: [
    'https://micros0ft-support.example/verify?id=PX9471',
    'https://secure-verification.example/login',
    'https://cred-harvest-flokinet.example/capture',
  ],
  firstSeen: '2026-08-23',
  category: 'Credential Harvesting / Phishing',
  detectionSignals: [
    'Domain registered <7 days before URL first seen',
    'Hosted on bulletproof infrastructure (AS200651)',
    'Redirect chain obfuscation — 3 hops to credential capture page',
    'URL parameter "id" used for tracking victim sessions',
    'No valid TLS certificate — self-signed on final hop',
    'Page title mimics Microsoft account login',
  ],
  riskScore: 94,
};

export interface RelatedIndicator {
  id: string;
  indicator: string;
  type: 'IP' | 'Domain' | 'URL' | 'Email' | 'Campaign';
  relationship: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
}

export const RELATED_INDICATORS: RelatedIndicator[] = [
  { id: 'IND1', indicator: '185.220.101.47', type: 'IP', relationship: 'Sending infrastructure', confidence: 96, firstSeen: '2026-08-22', lastSeen: '2026-08-25' },
  { id: 'IND2', indicator: 'micros0ft-support.example', type: 'Domain', relationship: 'Sender / URL domain', confidence: 98, firstSeen: '2026-08-22', lastSeen: '2026-08-25' },
  { id: 'IND3', indicator: 'secure-verification.example', type: 'Domain', relationship: 'Reply-To redirect', confidence: 91, firstSeen: '2026-08-22', lastSeen: '2026-08-25' },
  { id: 'IND4', indicator: 'https://micros0ft-support.example/verify?id=PX9471', type: 'URL', relationship: 'Embedded credential harvest link', confidence: 97, firstSeen: '2026-08-23', lastSeen: '2026-08-25' },
  { id: 'IND5', indicator: 'finance@micros0ft-support.example', type: 'Email', relationship: 'Spoofed sender address', confidence: 99, firstSeen: '2026-08-25', lastSeen: '2026-08-25' },
  { id: 'IND6', indicator: 'WIRE-FAUD-247', type: 'Campaign', relationship: 'Associated campaign cluster', confidence: 72, firstSeen: '2026-08-15', lastSeen: '2026-08-25' },
  { id: 'IND7', indicator: '45.137.21.88', type: 'IP', relationship: 'Intermediate relay', confidence: 68, firstSeen: '2026-08-20', lastSeen: '2026-08-25' },
  { id: 'IND8', indicator: 'micros0ft-365.example', type: 'Domain', relationship: 'Related lookalike domain', confidence: 64, firstSeen: '2026-08-21', lastSeen: '2026-08-24' },
  { id: 'IND9', indicator: 'paypa1-secure.example', type: 'Domain', relationship: 'Related lookalike domain', confidence: 58, firstSeen: '2026-08-19', lastSeen: '2026-08-23' },
  { id: 'IND10', indicator: 'cred-harvest-flokinet.example', type: 'Domain', relationship: 'Credential capture endpoint', confidence: 81, firstSeen: '2026-08-23', lastSeen: '2026-08-25' },
];

export const INTEL_RELATIONSHIP_FLOW = [
  { label: 'Email', value: 'finance@micros0ft-support.example' },
  { label: 'Lookalike Domain', value: 'micros0ft-support.example' },
  { label: 'Observed IP', value: '185.220.101.47' },
  { label: 'Hosting', value: 'FlokiNET Ltd (AS200651)' },
  { label: 'Suspicious URL', value: 'micros0ft-support.example/verify' },
];

// ─── Phase 4: Origin Investigation + Attack Graph ───────────────────────────

export interface InfraLocation {
  id: string;
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lng: number;
  ip: string;
  asn: string;
  asnOrg: string;
  hosting: string;
  confidence: number;
  role: string;
  evidence: string[];
}

export const INFRA_LOCATIONS: InfraLocation[] = [
  {
    id: 'LOC1', country: 'India', countryCode: 'IN', city: 'Mumbai',
    lat: 19.0760, lng: 72.8777, ip: '103.19.199.18', asn: 'AS55836',
    asnOrg: 'Reliance Jio Infocomm', hosting: 'Cloud Gateway',
    confidence: 78, role: 'Probable Source — Originating SMTP Server',
    evidence: ['SMTP relay origin (Received header hop 1)', 'ASN correlation with campaign cluster', 'DNS A record resolves to this IP', 'Domain registered 3 days prior via same registrar'],
  },
  {
    id: 'LOC2', country: 'Iceland', countryCode: 'IS', city: 'Reykjavik',
    lat: 64.13, lng: -21.94, ip: '45.137.21.88', asn: 'AS20495',
    asnOrg: 'ThorDatacenter (synthetic)', hosting: 'Privacy-focused datacenter',
    confidence: 54, role: 'Intermediate Relay — Redirect Node',
    evidence: ['Second hop in SMTP relay chain', 'Known proxy/redirect service', 'Shared ASN with other BEC campaign IOCs'],
  },
  {
    id: 'LOC3', country: 'United States', countryCode: 'US', city: 'Ashburn, VA',
    lat: 39.04, lng: -77.49, ip: '91.243.59.12', asn: 'AS40023',
    asnOrg: 'Acme Corp Networks (synthetic)', hosting: 'Corporate edge gateway',
    confidence: 99, role: 'Recipient Edge — Legitimate Infrastructure',
    evidence: ['Acme Corp edge gateway', 'Legitimate corporate ASN', 'Final delivery hop'],
  },
  {
    id: 'LOC4', country: 'Panama', countryCode: 'PA', city: 'Panama City',
    lat: 8.98, lng: -79.52, ip: '190.34.176.22', asn: 'AS26100',
    asnOrg: 'Privacy Hosting SA (synthetic)', hosting: 'Offshore bulletproof hosting',
    confidence: 41, role: 'Possible Credential Capture Server',
    evidence: ['Final redirect target in URL chain', 'Hosts cred-harvest-flokinet.example', 'WHOIS privacy redacted', 'ASN overlaps with 2 prior BEC campaigns'],
  },
];

export const ORIGIN_CONFIDENCE = {
  probableSource: 'Mumbai, India (AS55836 — Reliance Jio Infocomm)',
  confidence: 78,
  signals: [
    { signal: 'SMTP relay location', weight: 30, detail: 'Originating Received header resolves to 103.19.199.18, geolocated to Mumbai, India' },
    { signal: 'ASN correlation', weight: 25, detail: 'AS55836 appears in prior campaign IOCs' },
    { signal: 'DNS relationship', weight: 15, detail: 'Domain A record and MX both resolve to infrastructure within the same ASN' },
    { signal: 'Hosting relationship', weight: 8, detail: 'Infrastructure registered under high-velocity routing provider' },
  ],
};

// ─── Extended Attack Graph (image-matching) ─────────────────────────────────

export type GraphNodeType =
  | 'email' | 'sender' | 'domain' | 'ip' | 'url'
  | 'attachment' | 'hash' | 'mailserver' | 'asn' | 'campaign' | 'case';

export interface AttackGraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  sublabel?: string;
  details: { key: string; value: string }[];
  x: number;
  y: number;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
  style?: 'dashed'|'solid';
  color?: string;
}

export const ATTACK_GRAPH_NODES: AttackGraphNode[] = [
  // ── Col 0: Email ──────────────────────────────────────────────
  {
    id: 'n-email', type: 'email', label: 'Suspicious Email',
    sublabel: 'Subject: Urgent: Payment Confi...',
    details: [
      { key: 'subject', value: 'Urgent: Payment Confi...' },
      { key: 'target', value: 'cfo@acme-corp.example' },
      { key: 'risk', value: '96/100' },
    ],
    x: 50, y: 240,
  },
  // ── Col 1: Sender & Hash ──────────────────────────────────────
  {
    id: 'n-sender', type: 'sender', label: 'finance@paypal-security...',
    sublabel: 'finance@paypal-security.com',
    details: [
      { key: 'address', value: 'finance@paypal-security.com' },
      { key: 'display', value: 'Finance Department' },
    ],
    x: 380, y: 240,
  },
  {
    id: 'n-hash', type: 'hash', label: 'SHA-256: a0f8…c2d3',
    sublabel: 'SHA-256 file hash',
    details: [
      { key: 'algo', value: 'SHA-256' },
      { key: 'value', value: 'a0f8...c2d3' },
    ],
    x: 380, y: 620,
  },
  // ── Col 2: Domain1 & Domain2 ──────────────────────────────────
  {
    id: 'n-domain1', type: 'domain', label: 'paypa0-security.com',
    sublabel: 'age: 14 days  •  registrar: Njalla AB',
    details: [
      { key: 'age', value: '14 days' },
      { key: 'registrar', value: 'Njalla AB' },
    ],
    x: 710, y: 50,
  },
  {
    id: 'n-domain2', type: 'domain', label: 'paypa0-security.com',
    sublabel: 'age: 3 days',
    details: [
      { key: 'age', value: '3 days' },
      { key: 'intent', value: 'Sender Domain' },
    ],
    x: 710, y: 240,
  },
  // ── Col 3: IP & Mail Server ───────────────────────────────────
  {
    id: 'n-ip', type: 'ip', label: '185.220.101.47',
    sublabel: 'country: Germany',
    details: [
      { key: 'country', value: 'Germany' },
      { key: 'asn', value: 'AS31384' },
    ],
    x: 1040, y: 50,
  },
  {
    id: 'n-mailserver', type: 'mailserver', label: 'mx1.paypa0-security.com',
    sublabel: 'ip: 185.220.101.47',
    details: [
      { key: 'ip', value: '185.220.101.47' },
      { key: 'protocol', value: 'SMTP' },
    ],
    x: 1040, y: 240,
  },
  // ── Col 4: ASN, URL1, URL2 ────────────────────────────────────
  {
    id: 'n-asn', type: 'asn', label: 'AS24940 — Hetzner',
    sublabel: 'provider: Hetzner Online Stutt...',
    details: [
      { key: 'provider', value: 'Hetzner Online Stuttgart' },
      { key: 'abuse', value: 'High' },
    ],
    x: 1370, y: 50,
  },
  {
    id: 'n-url1', type: 'url', label: 'paypa0-security.com/wor...',
    sublabel: 'redirects: 3 hops  •  intent: Credential Theft',
    details: [
      { key: 'redirects', value: '3 hops' },
      { key: 'intent', value: 'Credential Theft' },
    ],
    x: 1370, y: 240,
  },
  {
    id: 'n-url2', type: 'domain', label: 'secure-banking-alert.com',
    sublabel: 'age: 21 days  •  intent: Data Exfil',
    details: [
      { key: 'age', value: '21 days' },
      { key: 'intent', value: 'Data Exfiltration' },
    ],
    x: 1370, y: 430,
  },
  // ── Col 5: Campaign, URL3, Case ───────────────────────────────
  {
    id: 'n-campaign', type: 'campaign', label: 'CMP-2026-0887',
    sublabel: 'emails: 37  •  targets: 91',
    details: [
      { key: 'emails', value: '37' },
      { key: 'targets', value: '91' },
    ],
    x: 1700, y: 50,
  },
  {
    id: 'n-url3', type: 'url', label: 'login-portal.xyz/auth0',
    sublabel: 'intent: Credential Capture  •  riskScore: Critical',
    details: [
      { key: 'intent', value: 'Credential Capture' },
      { key: 'riskScore', value: 'Critical' },
    ],
    x: 1700, y: 430,
  },
  {
    id: 'n-case', type: 'case', label: 'INV-2026-0082',
    sublabel: 'Status: Under Investigation  •  severity: Critical',
    details: [
      { key: 'status', value: 'Under Investigation' },
      { key: 'severity', value: 'Critical' },
    ],
    x: 1700, y: 620,
  },
];

export const ATTACK_GRAPH_EDGES: AttackGraphEdge[] = [
  { id: 'ae1',  source: 'n-email',      target: 'n-sender',     label: 'RECEIVES',   color: '#6366f1', animated: true },
  { id: 'ae2',  source: 'n-sender',     target: 'n-domain1',    label: 'RESOLVES',   color: '#22d3ee', animated: true },
  { id: 'ae3',  source: 'n-sender',     target: 'n-domain2',    label: 'FROM',       color: '#22d3ee', animated: true },
  { id: 'ae4',  source: 'n-domain1',    target: 'n-ip',         label: 'A-RECORD',   color: '#f97316', animated: true },
  { id: 'ae5',  source: 'n-ip',         target: 'n-asn',        label: 'BELONGS TO', color: '#a855f7', animated: true },
  { id: 'ae6',  source: 'n-asn',        target: 'n-campaign',   label: 'HOSTS',      color: '#f59e0b', animated: true },
  { id: 'ae7',  source: 'n-domain2',    target: 'n-mailserver', label: 'MX RECORD',  color: '#22d3ee', animated: true },
  { id: 'ae8',  source: 'n-mailserver', target: 'n-url1',       label: 'SERVES',     color: '#ef4444', animated: true },
  { id: 'ae9',  source: 'n-url1',       target: 'n-url2',       label: 'REDIRECT',   color: '#ef4444', animated: true },
  { id: 'ae10', source: 'n-url2',       target: 'n-url3',       label: 'REDIRECT',   color: '#ef4444', animated: true },
  { id: 'ae11', source: 'n-url3',       target: 'n-campaign',   label: 'PART OF',    color: '#f59e0b', animated: true },
  { id: 'ae12', source: 'n-campaign',   target: 'n-case',       label: 'LINKED TO',  color: '#22c55e', animated: true },
  { id: 'ae13', source: 'n-email',      target: 'n-hash',       label: 'HASHLINK',   color: '#6366f1', animated: true },
];

// ─── Phase 5: Investigations + Evidence Vault ────────────────────────────────

export type CaseStatus = 'open' | 'investigating' | 'contained' | 'resolved';

export interface InvestigationCase {
  id: string;
  title: string;
  severity: Severity;
  status: CaseStatus;
  created: string;
  assignedAnalyst: string;
  threatType: ThreatType;
  relatedCampaign: string;
  lastUpdated: string;
  summary: string;
  timeline: { time: string; event: string; actor: string }[];
  analystNotes: { author: string; timestamp: string; note: string }[];
  activityHistory: { time: string; action: string; actor: string }[];
  relatedEvidence: string[];
}

export const INVESTIGATION_CASES: InvestigationCase[] = [
  {
    id: 'CASE-2026-0471',
    title: 'BEC: Micros0ft-Support Payment Fraud',
    severity: 'critical',
    status: 'investigating',
    created: '2026-08-25 14:35:00',
    assignedAnalyst: 'Kaelen Richter',
    threatType: 'BEC',
    relatedCampaign: 'WIRE-FAUD-247',
    lastUpdated: '2026-08-25 15:02:00',
    summary: 'Business email compromise attempt targeting Acme Corp CFO via lookalike domain micros0ft-support.example. Email impersonates Microsoft billing with urgent payment verification request. Credential harvesting URL embedded. All authentication checks (SPF/DKIM/DMARC) failed. Infrastructure linked to campaign cluster WIRE-FAUD-247.',
    timeline: [
      { time: '2026-08-25 14:31:48', event: 'Email received by cfo@acme-corp.example', actor: 'System' },
      { time: '2026-08-25 14:32:11', event: 'Threat detected by SENTINEL-X engine — risk score 96', actor: 'Detection Engine' },
      { time: '2026-08-25 14:35:00', event: 'Investigation case opened', actor: 'Kaelen Richter' },
      { time: '2026-08-25 14:42:00', event: 'Header forensics analysis completed', actor: 'Kaelen Richter' },
      { time: '2026-08-25 14:51:00', event: 'Threat intelligence correlation — matched WIRE-FAUD-247', actor: 'System' },
      { time: '2026-08-25 15:00:00', event: 'Evidence preserved — SHA-256 hash generated', actor: 'Kaelen Richter' },
      { time: '2026-08-25 15:02:00', event: 'Origin investigation — probable source identified', actor: 'Kaelen Richter' },
    ],
    analystNotes: [
      { author: 'Kaelen Richter', timestamp: '2026-08-25 14:38:00', note: 'Domain uses homoglyph (zero for "o") — classic BEC tactic. Reply-To redirect confirms credential harvesting intent.' },
      { author: 'Kaelen Richter', timestamp: '2026-08-25 14:55:00', note: 'IP 185.220.101.47 matches 3 other IOCs in WIRE-FAUD-247 cluster. Recommending block at edge gateway.' },
    ],
    activityHistory: [
      { time: '2026-08-25 14:35:00', action: 'Case created', actor: 'Kaelen Richter' },
      { time: '2026-08-25 14:42:00', action: 'Status changed: Open → Investigating', actor: 'Kaelen Richter' },
      { time: '2026-08-25 15:00:00', action: 'Evidence linked: EV-2026-1129', actor: 'Kaelen Richter' },
    ],
    relatedEvidence: ['EV-2026-1129', 'EV-2026-1130'],
  },
  {
    id: 'CASE-2026-0468',
    title: 'Credential Harvesting: Paypa1-Secure Lookalike',
    severity: 'high',
    status: 'open',
    created: '2026-08-25 13:20:00',
    assignedAnalyst: 'Analyst Reyes',
    threatType: 'Credential Harvesting',
    relatedCampaign: 'WIRE-FAUD-247',
    lastUpdated: '2026-08-25 13:45:00',
    summary: 'Credential harvesting email targeting billing department via lookalike domain paypa1-secure.example. Spoofed PayPal notification with account limitation warning.',
    timeline: [
      { time: '2026-08-25 13:18:44', event: 'Email received by billing@acme-corp.example', actor: 'System' },
      { time: '2026-08-25 13:20:00', event: 'Case opened', actor: 'Analyst Reyes' },
    ],
    analystNotes: [
      { author: 'Analyst Reyes', timestamp: '2026-08-25 13:25:00', note: 'Related to CASE-2026-0471 — same campaign cluster.' },
    ],
    activityHistory: [
      { time: '2026-08-25 13:20:00', action: 'Case created', actor: 'Analyst Reyes' },
    ],
    relatedEvidence: ['EV-2026-1125'],
  },
  {
    id: 'CASE-2026-0462',
    title: 'Spoofing: CEO Wire Transfer Request',
    severity: 'critical',
    status: 'contained',
    created: '2026-08-25 11:50:00',
    assignedAnalyst: 'Kaelen Richter',
    threatType: 'Spoofing',
    relatedCampaign: 'EXEC-SPOOF-118',
    lastUpdated: '2026-08-25 12:30:00',
    summary: 'Executive impersonation attempt spoofing CEO address. Wire transfer request sent to finance department. Blocked at gateway after DMARC enforcement.',
    timeline: [
      { time: '2026-08-25 11:47:09', event: 'Email received by finance@acme-corp.example', actor: 'System' },
      { time: '2026-08-25 11:50:00', event: 'Case opened', actor: 'Kaelen Richter' },
      { time: '2026-08-25 12:15:00', event: 'Sender IP blocked at edge', actor: 'Kaelen Richter' },
      { time: '2026-08-25 12:30:00', event: 'Status changed: Investigating → Contained', actor: 'Kaelen Richter' },
    ],
    analystNotes: [
      { author: 'Kaelen Richter', timestamp: '2026-08-25 11:55:00', note: 'Display name spoofing only — From domain differs from CEO actual domain. No financial loss.' },
    ],
    activityHistory: [
      { time: '2026-08-25 11:50:00', action: 'Case created', actor: 'Kaelen Richter' },
      { time: '2026-08-25 12:00:00', action: 'Status changed: Open → Investigating', actor: 'Kaelen Richter' },
      { time: '2026-08-25 12:30:00', action: 'Status changed: Investigating → Contained', actor: 'Kaelen Richter' },
    ],
    relatedEvidence: ['EV-2026-1118', 'EV-2026-1119'],
  },
  {
    id: 'CASE-2026-0455',
    title: 'Malware: DHL Express Package Notification',
    severity: 'medium',
    status: 'resolved',
    created: '2026-08-25 10:35:00',
    assignedAnalyst: 'Analyst Tanaka',
    threatType: 'Malware',
    relatedCampaign: 'PKG-NOTIFY-093',
    lastUpdated: '2026-08-25 11:10:00',
    summary: 'Malware-laced email disguised as DHL package delivery failure. Attachment contained trojan downloader. Quarantined and endpoint scan completed.',
    timeline: [
      { time: '2026-08-25 10:33:51', event: 'Email received by warehouse@acme-corp.example', actor: 'System' },
      { time: '2026-08-25 10:35:00', event: 'Case opened', actor: 'Analyst Tanaka' },
      { time: '2026-08-25 10:50:00', event: 'Attachment quarantined', actor: 'System' },
      { time: '2026-08-25 11:10:00', event: 'Endpoint scan clean — case resolved', actor: 'Analyst Tanaka' },
    ],
    analystNotes: [
      { author: 'Analyst Tanaka', timestamp: '2026-08-25 10:40:00', note: 'Trojan downloader detected in .docm attachment. No execution on endpoint.' },
    ],
    activityHistory: [
      { time: '2026-08-25 10:35:00', action: 'Case created', actor: 'Analyst Tanaka' },
      { time: '2026-08-25 10:50:00', action: 'Status changed: Open → Contained', actor: 'Analyst Tanaka' },
      { time: '2026-08-25 11:10:00', action: 'Status changed: Contained → Resolved', actor: 'Analyst Tanaka' },
    ],
    relatedEvidence: ['EV-2026-1110'],
  },
  {
    id: 'CASE-2026-0448',
    title: 'BEC: HR Payroll Direct Deposit Update',
    severity: 'high',
    status: 'contained',
    created: '2026-08-25 09:25:00',
    assignedAnalyst: 'Analyst Reyes',
    threatType: 'BEC',
    relatedCampaign: 'PAYROLL-DD-301',
    lastUpdated: '2026-08-25 10:00:00',
    summary: 'BEC attempt targeting payroll department via spoofed HR address. Requested direct deposit update. Blocked after recipient reported suspicious.',
    timeline: [
      { time: '2026-08-25 09:22:17', event: 'Email received by payroll@acme-corp.example', actor: 'System' },
      { time: '2026-08-25 09:25:00', event: 'Case opened', actor: 'Analyst Reyes' },
      { time: '2026-08-25 09:45:00', event: 'Recipient reported email as suspicious', actor: 'Payroll Staff' },
      { time: '2026-08-25 10:00:00', event: 'Status changed: Investigating → Contained', actor: 'Analyst Reyes' },
    ],
    analystNotes: [
      { author: 'Analyst Reyes', timestamp: '2026-08-25 09:30:00', note: 'Good catch by payroll staff. No direct deposit changes were processed.' },
    ],
    activityHistory: [
      { time: '2026-08-25 09:25:00', action: 'Case created', actor: 'Analyst Reyes' },
      { time: '2026-08-25 09:35:00', action: 'Status changed: Open → Investigating', actor: 'Analyst Reyes' },
      { time: '2026-08-25 10:00:00', action: 'Status changed: Investigating → Contained', actor: 'Analyst Reyes' },
    ],
    relatedEvidence: ['EV-2026-1105'],
  },
  {
    id: 'CASE-2026-0441',
    title: 'Credential Harvest: Micros0ft 365 Fake Portal',
    severity: 'high',
    status: 'contained',
    created: '2026-08-24 16:10:00',
    assignedAnalyst: 'Kaelen Richter',
    threatType: 'Credential Harvesting',
    relatedCampaign: 'CRED-HARV-402',
    lastUpdated: '2026-08-24 17:30:00',
    summary: 'Fake Microsoft 365 login portal deployed on FlokiNET bulletproof infrastructure to capture user credentials.',
    timeline: [
      { time: '2026-08-24 16:05:00', event: 'Phishing domain observed in outbound traffic telemetry', actor: 'System' },
      { time: '2026-08-24 16:10:00', event: 'Investigation case opened', actor: 'Kaelen Richter' },
      { time: '2026-08-24 17:30:00', event: 'Domain sinkholed at enterprise DNS resolver', actor: 'Kaelen Richter' },
    ],
    analystNotes: [
      { author: 'Kaelen Richter', timestamp: '2026-08-24 16:20:00', note: 'Portal mirrors standard Entra ID login screen. Capture endpoint blocked.' },
    ],
    activityHistory: [
      { time: '2026-08-24 16:10:00', action: 'Case created', actor: 'Kaelen Richter' },
      { time: '2026-08-24 17:30:00', action: 'Status changed: Open → Contained', actor: 'Kaelen Richter' },
    ],
    relatedEvidence: [],
  },
  {
    id: 'CASE-2026-0435',
    title: 'Phishing: IT Support Ticket Urgency Lure',
    severity: 'medium',
    status: 'resolved',
    created: '2026-08-23 11:15:00',
    assignedAnalyst: 'Analyst Tanaka',
    threatType: 'Phishing',
    relatedCampaign: 'SUPPORT-TKT-065',
    lastUpdated: '2026-08-23 14:00:00',
    summary: 'Fake IT support ticket notification email attempting to lure users into submitting credentials.',
    timeline: [
      { time: '2026-08-23 11:10:00', event: 'Email intercepted by gateway filters', actor: 'System' },
      { time: '2026-08-23 11:15:00', event: 'Case opened and analyzed', actor: 'Analyst Tanaka' },
      { time: '2026-08-23 14:00:00', event: 'Threat confirmed neutral; case resolved', actor: 'Analyst Tanaka' },
    ],
    analystNotes: [
      { author: 'Analyst Tanaka', timestamp: '2026-08-23 11:30:00', note: 'Generic helpdesk lure with spoofed IT sender headers. Gateway blocked all deliveries.' },
    ],
    activityHistory: [
      { time: '2026-08-23 11:15:00', action: 'Case created', actor: 'Analyst Tanaka' },
      { time: '2026-08-23 14:00:00', action: 'Status changed: Open → Resolved', actor: 'Analyst Tanaka' },
    ],
    relatedEvidence: [],
  },
];

export interface EvidenceItem {
  id: string;
  filename: string;
  evidenceType: string;
  sha256: string;
  timestamp: string;
  caseId: string;
  collectedBy: string;
  integrityStatus: 'verified' | 'pending' | 'invalid';
  size: string;
  ledgerRef: string;
  blockRef: string;
  blockHash: string;
  prevBlockHash: string;
}

export const EVIDENCE_ITEMS: EvidenceItem[] = [
  {
    id: 'EV-2026-1129', filename: 'micros0ft-support_email.eml',
    evidenceType: 'Email Message (EML)', sha256: 'a3f5b8c9d2e1f4a7b6c8d5e2f1a4b7c9d6e3f0a1b4c7d2e5f8a3b6c9d1e4f7a2',
    timestamp: '2026-08-25 15:00:12 UTC', caseId: 'CASE-2026-0471',
    collectedBy: 'Kaelen Richter', integrityStatus: 'verified', size: '24.3 KB',
    ledgerRef: 'LEDGER-0x4F2A', blockRef: 'BLOCK-000847', blockHash: '0x8a3f...b7c9d1', prevBlockHash: '0x5e2f...a4b7c9',
  },
  {
    id: 'EV-2026-1130', filename: 'header_analysis_report.json',
    evidenceType: 'Forensic Report (JSON)', sha256: 'b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6',
    timestamp: '2026-08-25 15:01:45 UTC', caseId: 'CASE-2026-0471',
    collectedBy: 'Kaelen Richter', integrityStatus: 'verified', size: '8.7 KB',
    ledgerRef: 'LEDGER-0x4F2B', blockRef: 'BLOCK-000848', blockHash: '0x9b4c...c8d9e0', prevBlockHash: '0x8a3f...b7c9d1',
  },
  {
    id: 'EV-2026-1125', filename: 'paypa1-secure_email.eml',
    evidenceType: 'Email Message (EML)', sha256: 'c5d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7',
    timestamp: '2026-08-25 13:22:00 UTC', caseId: 'CASE-2026-0468',
    collectedBy: 'Analyst Reyes', integrityStatus: 'verified', size: '18.1 KB',
    ledgerRef: 'LEDGER-0x4F25', blockRef: 'BLOCK-000844', blockHash: '0x7c5d...d9e0f1', prevBlockHash: '0x4e2f...a4b7c9',
  },
  {
    id: 'EV-2026-1118', filename: 'ceo_spoof_email.eml',
    evidenceType: 'Email Message (EML)', sha256: 'd6e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8',
    timestamp: '2026-08-25 11:52:00 UTC', caseId: 'CASE-2026-0462',
    collectedBy: 'Kaelen Richter', integrityStatus: 'verified', size: '21.5 KB',
    ledgerRef: 'LEDGER-0x4F18', blockRef: 'BLOCK-000841', blockHash: '0x6d7e...e0f1a2', prevBlockHash: '0x3c5d...b7c8d9',
  },
  {
    id: 'EV-2026-1119', filename: 'gateway_block_log.txt',
    evidenceType: 'Network Log (TXT)', sha256: 'e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
    timestamp: '2026-08-25 12:16:00 UTC', caseId: 'CASE-2026-0462',
    collectedBy: 'Kaelen Richter', integrityStatus: 'pending', size: '142.8 KB',
    ledgerRef: 'LEDGER-0x4F19', blockRef: 'BLOCK-000842', blockHash: '0x5e8f...f1a2b3', prevBlockHash: '0x6d7e...e0f1a2',
  },
  {
    id: 'EV-2026-1110', filename: 'dhl_trojan_attachment.docm',
    evidenceType: 'Malware Sample (DOCM)', sha256: 'f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
    timestamp: '2026-08-25 10:36:00 UTC', caseId: 'CASE-2026-0455',
    collectedBy: 'Analyst Tanaka', integrityStatus: 'verified', size: '156.2 KB',
    ledgerRef: 'LEDGER-0x4F10', blockRef: 'BLOCK-000838', blockHash: '0x4f9a...a2b3c4', prevBlockHash: '0x2c5d...b7c8d9',
  },
  {
    id: 'EV-2026-1105', filename: 'payroll_spoof_email.eml',
    evidenceType: 'Email Message (EML)', sha256: 'a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1',
    timestamp: '2026-08-25 09:26:00 UTC', caseId: 'CASE-2026-0448',
    collectedBy: 'Analyst Reyes', integrityStatus: 'invalid', size: '19.7 KB',
    ledgerRef: 'LEDGER-0x4F05', blockRef: 'BLOCK-000835', blockHash: '0x3a8b...b3c4d5', prevBlockHash: '0x1c4d...b7c8d9',
  },
];

export const EVIDENCE_LEDGER_WORKFLOW = [
  { step: 'Evidence', detail: 'Email / file collected and timestamped', icon: 'file' },
  { step: 'SHA-256', detail: 'Cryptographic hash generated for integrity', icon: 'hash' },
  { step: 'Immutable Ledger', detail: 'Hash written to mock blockchain ledger', icon: 'ledger' },
  { step: 'Integrity Verified', detail: 'Hash re-verified against ledger entry', icon: 'verified' },
];

// ─── Phase 6: Campaigns ──────────────────────────────────────────────────────

export type CampaignStatus = 'active' | 'dormant' | 'disrupted' | 'monitoring';

export interface Campaign {
  id: string;
  name: string;
  threatType: ThreatType;
  severity: Severity;
  firstSeen: string;
  lastSeen: string;
  emails: number;
  indicators: number;
  status: CampaignStatus;
  confidence: number;
  description: string;
  relatedEmails: string[];
  relatedDomains: string[];
  relatedIPs: string[];
  relatedURLs: string[];
  relatedCases: string[];
  timeline: { time: string; event: string }[];
}

export const CAMPAIGNS: Campaign[] = [
  {
    id: 'WIRE-FAUD-247',
    name: 'Invoice Redirect Campaign',
    threatType: 'BEC',
    severity: 'critical',
    firstSeen: '2026-08-15',
    lastSeen: '2026-08-25',
    emails: 142,
    indicators: 47,
    status: 'active',
    confidence: 87,
    description: 'Coordinated BEC campaign using lookalike domains with homoglyph substitutions to impersonate Microsoft billing. Emails target CFOs and finance teams with urgent payment verification requests. Infrastructure hosted on bulletproof hosting (FlokiNET Ltd). Credential harvesting URLs embedded with multi-hop redirect chains.',
    relatedEmails: ['finance@micros0ft-support.example', 'no-reply@paypa1-secure.example'],
    relatedDomains: ['micros0ft-support.example', 'secure-verification.example', 'paypa1-secure.example', 'micros0ft-365.example', 'cred-harvest-flokinet.example'],
    relatedIPs: ['185.220.101.47', '45.137.21.88', '190.34.176.22'],
    relatedURLs: ['https://micros0ft-support.example/verify?id=PX9471', 'https://secure-verification.example/login', 'https://cred-harvest-flokinet.example/capture'],
    relatedCases: ['CASE-2026-0471'],
    timeline: [
      { time: '2026-08-15', event: 'Campaign cluster identified — 3 initial IOCs correlated' },
      { time: '2026-08-19', event: 'Lookalike domain paypa1-secure.example observed' },
      { time: '2026-08-22', event: 'Domain micros0ft-support.example registered' },
      { time: '2026-08-23', event: 'Credential harvesting URL first observed' },
      { time: '2026-08-25', event: 'BEC email targeting Acme Corp CFO detected' },
      { time: '2026-08-25', event: 'Investigation case CASE-2026-0471 opened' },
    ],
  },
  {
    id: 'EXEC-SPOOF-118',
    name: 'Executive Impersonation',
    threatType: 'Spoofing',
    severity: 'high',
    firstSeen: '2026-08-10',
    lastSeen: '2026-08-25',
    emails: 89,
    indicators: 31,
    status: 'active',
    confidence: 82,
    description: 'Executive impersonation campaign spoofing CEO and CFO display names. Wire transfer requests sent to finance departments. Uses display name spoofing without domain spoofing — relies on recipient trust in display name.',
    relatedEmails: ['ceo@acme-corp.example'],
    relatedDomains: ['exec-spoof-relay.example'],
    relatedIPs: ['203.0.113.55'],
    relatedURLs: [],
    relatedCases: ['CASE-2026-0462'],
    timeline: [
      { time: '2026-08-10', event: 'Campaign cluster identified — spoofed executive emails' },
      { time: '2026-08-25', event: 'CEO wire transfer request targeting finance' },
      { time: '2026-08-25', event: 'Blocked at gateway after DMARC enforcement' },
    ],
  },
  {
    id: 'PKG-NOTIFY-093',
    name: 'Package Notification Malware',
    threatType: 'Malware',
    severity: 'medium',
    firstSeen: '2026-08-08',
    lastSeen: '2026-08-25',
    emails: 67,
    indicators: 24,
    status: 'monitoring',
    confidence: 74,
    description: 'Malware distribution campaign disguised as package delivery failure notifications. Trojan downloader embedded in .docm attachments. Multiple courier brands impersonated (DHL, FedEx, UPS).',
    relatedEmails: ['tracking@dhl-express-notify.example'],
    relatedDomains: ['dhl-express-notify.example', 'fedex-portal-notify.example'],
    relatedIPs: ['198.51.100.77'],
    relatedURLs: [],
    relatedCases: ['CASE-2026-0455'],
    timeline: [
      { time: '2026-08-08', event: 'Campaign cluster identified — package notification lures' },
      { time: '2026-08-25', event: 'DHL-themed malware email detected and quarantined' },
    ],
  },
  {
    id: 'PAYROLL-DD-301',
    name: 'Payroll Direct Deposit Fraud',
    threatType: 'BEC',
    severity: 'high',
    firstSeen: '2026-08-18',
    lastSeen: '2026-08-25',
    emails: 53,
    indicators: 19,
    status: 'disrupted',
    confidence: 79,
    description: 'BEC campaign targeting payroll departments with direct deposit update requests. Spoofs HR department addresses. Aims to redirect employee payroll to attacker-controlled accounts.',
    relatedEmails: ['hr@acme-payroll.example'],
    relatedDomains: ['acme-payroll.example'],
    relatedIPs: ['203.0.113.91'],
    relatedURLs: [],
    relatedCases: ['CASE-2026-0448'],
    timeline: [
      { time: '2026-08-18', event: 'Campaign cluster identified — payroll BEC pattern' },
      { time: '2026-08-25', event: 'Payroll spoof detected and reported by staff' },
      { time: '2026-08-25', event: 'Campaign disrupted — sender IP blocked' },
    ],
  },
  {
    id: 'CRED-HARV-402',
    name: 'Credential Harvesting Portal',
    threatType: 'Credential Harvesting',
    severity: 'high',
    firstSeen: '2026-08-20',
    lastSeen: '2026-08-24',
    emails: 38,
    indicators: 16,
    status: 'dormant',
    confidence: 68,
    description: 'Credential harvesting campaign using fake login portals. Mimics Microsoft 365 and Google Workspace login pages. Captures credentials via multi-hop redirect chains on bulletproof hosting.',
    relatedEmails: ['support@micros0ft-365.example'],
    relatedDomains: ['micros0ft-365.example', 'cred-harvest-flokinet.example'],
    relatedIPs: ['45.137.21.88'],
    relatedURLs: ['https://cred-harvest-flokinet.example/capture'],
    relatedCases: ['CASE-2026-0441'],
    timeline: [
      { time: '2026-08-20', event: 'Campaign cluster identified — fake login portals' },
      { time: '2026-08-24', event: 'Campaign went dormant — no new emails in 24h' },
    ],
  },
  {
    id: 'SUPPORT-TKT-065',
    name: 'Support Ticket Phishing',
    threatType: 'Phishing',
    severity: 'medium',
    firstSeen: '2026-08-05',
    lastSeen: '2026-08-23',
    emails: 29,
    indicators: 12,
    status: 'dormant',
    confidence: 61,
    description: 'Phishing campaign using fake IT support ticket notifications. Urges recipients to click links to "resolve tickets." Links lead to credential capture pages.',
    relatedEmails: ['it-support@helpdesk-portal.example'],
    relatedDomains: ['helpdesk-portal.example'],
    relatedIPs: ['203.0.113.44'],
    relatedURLs: ['https://helpdesk-portal.example/ticket?id=verify'],
    relatedCases: ['CASE-2026-0435'],
    timeline: [
      { time: '2026-08-05', event: 'Campaign cluster identified — support ticket lures' },
      { time: '2026-08-23', event: 'Last observed activity — campaign now dormant' },
    ],
  },
];

export const CAMPAIGN_STATS = {
  emailsObserved: CAMPAIGNS.reduce((sum, c) => sum + c.emails, 0),
  uniqueDomains: [...new Set(CAMPAIGNS.flatMap((c) => c.relatedDomains))].length,
  uniqueIPs: [...new Set(CAMPAIGNS.flatMap((c) => c.relatedIPs))].length,
  suspiciousURLs: [...new Set(CAMPAIGNS.flatMap((c) => c.relatedURLs))].length,
  activeCases: CAMPAIGNS.flatMap((c) => c.relatedCases).length,
};

// ─── Phase 7: Reports + Sentinel AI ────────────────────────────────────────────

export interface ReportData {
  caseId: string;
  caseTitle: string;
  threatSummary: string;
  riskScore: number;
  keyFindings: string[];
  observedFacts: string[];
  aiInference: string[];
  indicators: { type: string; value: string }[];
  timeline: { time: string; event: string }[];
  investigationStatus: string;
  evidenceSummary: string[];
  recommendedActions: string[];
}

export const REPORT_DATA: ReportData = {
  caseId: 'CASE-2026-0471',
  caseTitle: 'BEC: Micros0ft-Support Payment Fraud',
  threatSummary:
    'A business email compromise (BEC) attempt was detected targeting the CFO of Acme Corp. The email originated from a lookalike domain (micros0ft-support.example) using a homoglyph attack — replacing the letter "o" in "microsoft" with the digit "0". The email impersonated Microsoft billing with an urgent payment verification request. All email authentication checks (SPF, DKIM, DMARC) failed. A credential harvesting URL was embedded, redirecting through 3 hops to a capture page on bulletproof hosting. The sending infrastructure is linked to campaign cluster WIRE-FAUD-247.',
  riskScore: 96,
  keyFindings: [
    'Sender domain micros0ft-support.example is a lookalike of microsoft.example with 92% similarity',
    'SPF, DKIM, and DMARC all failed — sender is not authorized by any domain',
    'Reply-To address (secure-verification.example) differs from From address — reply traffic redirected',
    'Embedded URL uses newly registered domain (3 days old) on bulletproof hosting',
    'Sending IP 185.220.101.47 listed on 4 blocklists',
    'Infrastructure matches known BEC campaign cluster WIRE-FAUD-247 (72.5% confidence)',
  ],
  observedFacts: [
    'From domain: micros0ft-support.example (differs from expected microsoft.com)',
    'Reply-To: secure-verification.example (differs from From)',
    'SPF: FAIL — IP 185.220.101.47 not authorized',
    'DKIM: FAIL — signature verification returned permerror',
    'DMARC: FAIL — no alignment with From domain',
    'URL: https://micros0ft-support.example/verify?id=PX9471 (newly observed domain)',
    'Sending IP: 185.220.101.47 (listed on Spamhaus XBL, SORBS, UCEPROTECT L2, Barracuda)',
    'Domain registration: 2026-08-22 (3 days before email sent)',
  ],
  aiInference: [
    'Likely business email compromise (BEC) targeting CFO for financial fraud — 94.7% confidence',
    'Possible executive impersonation — sender mimics legitimate vendor billing — 88.2% confidence',
    'Credential harvesting intent suspected via verification portal link — 91.3% confidence',
    'Sender infrastructure consistent with campaign cluster WIRE-FAUD-247 — 72.5% confidence',
  ],
  indicators: [
    { type: 'IP', value: '185.220.101.47' },
    { type: 'Domain', value: 'micros0ft-support.example' },
    { type: 'Domain', value: 'secure-verification.example' },
    { type: 'URL', value: 'https://micros0ft-support.example/verify?id=PX9471' },
    { type: 'Email', value: 'finance@micros0ft-support.example' },
    { type: 'Campaign', value: 'WIRE-FAUD-247' },
  ],
  timeline: [
    { time: '2026-08-25 14:31:48', event: 'Email received by cfo@acme-corp.example' },
    { time: '2026-08-25 14:32:11', event: 'Threat detected — risk score 96' },
    { time: '2026-08-25 14:35:00', event: 'Investigation case opened' },
    { time: '2026-08-25 14:42:00', event: 'Header forensics completed' },
    { time: '2026-08-25 14:51:00', event: 'Threat intelligence correlation — matched WIRE-FAUD-247' },
    { time: '2026-08-25 15:00:00', event: 'Evidence preserved — SHA-256 hash generated' },
    { time: '2026-08-25 15:02:00', event: 'Origin investigation — probable source identified' },
  ],
  investigationStatus: 'Investigating — assigned to Kaelen Richter',
  evidenceSummary: [
    'EV-2026-1129: Original EML file (24.3 KB) — SHA-256 verified — BLOCK-000847',
    'EV-2026-1130: Header analysis report (8.7 KB) — SHA-256 verified — BLOCK-000848',
  ],
  recommendedActions: [
    'Block sending IP 185.220.101.47 at the email gateway',
    'Add domain micros0ft-support.example to the denylist',
    'Notify CFO and finance team of the impersonation attempt',
    'Monitor for additional emails from WIRE-FAUD-247 campaign infrastructure',
    'Verify no credentials were entered on the credential harvesting URL',
    'Preserve all evidence in the immutable ledger for potential legal proceedings',
    'Update DMARC policy to p=reject for acme-corp.example',
  ],
};

export const REPORT_TYPES = [
  { id: 'executive', label: 'Executive Report', description: 'High-level summary for leadership' },
  { id: 'technical', label: 'Technical Report', description: 'Detailed technical analysis' },
  { id: 'forensic', label: 'Forensic Report', description: 'Full forensic documentation' },
] as const;

export type ReportType = (typeof REPORT_TYPES)[number]['id'];

export interface AIQuestion {
  id: string;
  question: string;
}

export const AI_SUGGESTED_QUESTIONS: AIQuestion[] = [
  { id: 'q1', question: 'Why is this session high risk?' },
  { id: 'q2', question: 'Summarize this case.' },
  { id: 'q3', question: 'What evidence supports the risk score?' },
  { id: 'q4', question: 'Explain the TLS handshake anomalies.' },
  { id: 'q5', question: 'What cipher vulnerabilities are present?' },
  { id: 'q6', question: 'Why is this classified as a downgrade attack?' },
];

export const AI_RESPONSES: Record<string, string> = {
  q1: 'This SMTP session is high risk for five compounding reasons. First, TLS 1.0 was negotiated — a deprecated protocol banned by RFC 8996 since March 2021. Second, the cipher suite TLS_RSA_WITH_RC4_128_SHA uses RC4, which is cryptographically broken and prohibited by RFC 7465. Third, the server presented a self-signed certificate from an unknown CA with no chain of trust, making MITM trivially possible. Fourth, the certificate expired on 2024-01-01 — over two years before the session date — indicating deliberate use of invalid credentials. Fifth, the public key is RSA-1024, below the NIST SP 800-131A minimum of 2048 bits. The combined cryptographic posture score is 4/100.',
  q2: 'Case CASE-2026-0471 involves an active TLS downgrade attack on an SMTP session at Acme Corp. The attacker at 185.220.101.47 (FlokiNET bulletproof hosting) forced negotiation to TLS 1.0 with the broken RC4 cipher suite. A self-signed, expired RSA-1024 certificate was presented — enabling trivial MITM. The session infrastructure matches the TLSDOWN-019 campaign cluster. The case is currently in "Investigating" status, assigned to Kaelen Richter. Two evidence items have been preserved with verified SHA-256 integrity.',
  q3: 'The risk score of 96/100 is supported by five critical factors: (1) Deprecated TLS 1.0 negotiated — BEAST and POODLE attack surface exposed. (2) RC4 cipher selected — broken stream cipher violates RFC 7465, session confidentiality not guaranteed. (3) Expired self-signed certificate — no chain of trust, certificate expired 236 days before session. (4) RSA-1024 public key — below NIST minimum 2048-bit, factorable with modern compute. (5) No forward secrecy — static RSA key exchange means past sessions can be decrypted if private key is compromised.',
  q4: 'The TLS handshake reveals five critical anomalies. The ClientHello proposed only TLS 1.0/1.1/1.2 — TLS 1.3 was absent, which is unusual for modern clients. The ServerHello selected TLS 1.0 + RC4 — both deprecated — indicating either a misconfigured or deliberately weakened server. The Certificate exchange presented a self-signed cert (SHA1withRSA, RSA-1024) expired January 2024 — no OCSP stapling or CRL extension present. The ServerKeyExchange used static RSA without ephemeral keys — eliminating forward secrecy. The ChangeCipherSpec confirmed the downgrade to RC4, exposing the session to BEAST/POODLE attacks.',
  q5: 'The session uses TLS_RSA_WITH_RC4_128_SHA — one of the most dangerous cipher suites. Key Exchange: RSA (static, no PFS). Encryption: RC4-128 (broken; RC4 biases enable plaintext recovery with sufficient ciphertext). MAC: SHA-1 (weak; collision resistance compromised). Attack surface includes: RC4 statistical bias (Fluhrer-Mantin-Shamir attack), BEAST via TLS 1.0 + CBC mode (CBC here is RC4, so BEAST does not apply, but POODLE-like padding attacks do), and session key recovery via RC4 invariance attacks. Recommended replacement: TLS 1.3 with TLS_AES_256_GCM_SHA384.',
  q6: 'This is classified as a Downgrade Attack because the client offered higher TLS versions but the server forcibly selected TLS 1.0. In a legitimate session, a properly configured server would negotiate the highest mutually supported version. The source IP 185.220.101.47 is on bulletproof hosting known for MITM proxy infrastructure. The hop-2 node (mitm-proxy-01.flokinet-redirect.example) exhibits STARTTLS stripping behavior — intercepting the initial SMTP STARTTLS exchange and re-establishing a weaker TLS 1.0 session. This is consistent with the TLSDOWN-019 campaign cluster (72.5% confidence).',
};


// ─── Phase 8: Crypto Alerts ──────────────────────────────────────────────────

export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved';
export type AlertType = 'Downgrade Attack' | 'Weak Cipher' | 'Expired Certificate' | 'Weak Key' | 'MitM Detected' | 'STARTTLS Stripping' | 'Protocol Violation' | 'Self-Signed Certificate';

export interface SecurityAlert {
  id: string;
  severity: Severity;
  type: AlertType;
  source: string;
  detected: string;
  status: AlertStatus;
  relatedCase: string;
  summary: string;
  observedFacts: string[];
  aiInference: string;
  relatedIndicators: string[];
  relatedCampaign: string;
  recommendedAction: string;
}

export const SECURITY_ALERTS: SecurityAlert[] = [
  {
    id: 'ALR-2026-0892',
    severity: 'critical',
    type: 'Downgrade Attack',
    source: 'SENTINEL-X Crypto Engine',
    detected: '2026-08-25 14:32:11',
    status: 'investigating',
    relatedCase: 'CASE-2026-0471',
    summary: 'Active TLS downgrade attack detected on inbound SMTP session. Negotiation forced down to TLS 1.0 with prohibited cipher TLS_RSA_WITH_RC4_128_SHA.',
    observedFacts: [
      'Client offered TLS 1.2 and TLS 1.3 in ClientHello',
      'Server forced downgrade to deprecated TLS 1.0 (RFC 8996 violation)',
      'Negotiated cipher: TLS_RSA_WITH_RC4_128_SHA (RFC 7465 violation)',
      'Cryptographic posture score: 4/100',
    ],
    aiInference: 'Adversary-controlled MITM proxy active in transit path — 94.7% confidence. Forced downgrade enables plaintext inspection.',
    relatedIndicators: ['185.220.101.47', 'mail.attacker-relay.example', 'TLS_RSA_WITH_RC4_128_SHA'],
    relatedCampaign: 'TLSDOWN-019',
    recommendedAction: 'Enforce MTA-STS policy to reject TLS < 1.2, quarantine incoming session, inspect intermediate routing nodes.',
  },
  {
    id: 'ALR-2026-0891',
    severity: 'critical',
    type: 'Expired Certificate',
    source: 'Certificate Posture Monitor',
    detected: '2026-08-25 13:18:44',
    status: 'acknowledged',
    relatedCase: 'CASE-2026-0468',
    summary: 'Server presented an expired digital certificate during IMAP over TLS session. Certificate expired over 200 days ago.',
    observedFacts: [
      'Certificate subject: CN=legacy-mail.partner-network.example',
      'Valid until: 2024-01-01 (Expired 236 days overdue)',
      'Chain validation: Certificate expired / revoked check failed',
      'Key length: RSA-1024',
    ],
    aiInference: 'Lax certificate lifecycle management or rogue certificate reuse — 88% confidence.',
    relatedIndicators: ['legacy-mail.partner-network.example', '203.0.113.91'],
    relatedCampaign: 'WEAKCERT-007',
    recommendedAction: 'Reject non-compliant connections, alert partner organization, revoke unpinned certs.',
  },
  {
    id: 'ALR-2026-0890',
    severity: 'high',
    type: 'Weak Cipher',
    source: 'Crypto Audit Daemon (acme-mailgw-03)',
    detected: '2026-08-25 14:31:53',
    status: 'investigating',
    relatedCase: 'CASE-2026-0471',
    summary: 'POP3S session negotiated with 3DES-EDE-CBC cipher suite vulnerable to Sweet32 64-bit block collision attack.',
    observedFacts: [
      'Negotiated cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA',
      '64-bit block size vulnerable to birthday attack (Sweet32 / CVE-2016-2183)',
      'No Forward Secrecy: Static RSA key exchange',
      'Client IP: 185.220.101.47',
    ],
    aiInference: 'Vulnerable cipher usage exposes session cookies and authentication tokens to statistical decryption.',
    relatedIndicators: ['185.220.101.47', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
    relatedCampaign: 'SWEET32-CLUSTER',
    recommendedAction: 'Disable 3DES cipher suites across all POP3/IMAP endpoints; require AES-GCM or CHACHA20-POLY1305.',
  },
  {
    id: 'ALR-2026-0889',
    severity: 'critical',
    type: 'STARTTLS Stripping',
    source: 'SMTP Protocol Inspector',
    detected: '2026-08-25 14:32:00',
    status: 'investigating',
    relatedCase: 'CASE-2026-0471',
    summary: 'STARTTLS command stripped from SMTP EHLO capability response by upstream network node, forcing cleartext transmission.',
    observedFacts: [
      'Original mail server advertised 250-STARTTLS in initial response',
      'Upstream hop 185.220.101.47 filtered STARTTLS capability token',
      'Client forced to transmit authentication and email payload in cleartext',
      'Traffic captured on Port 25',
    ],
    aiInference: 'Active Man-in-the-Middle (MitM) adversary executing network-level STARTTLS stripping — 96% confidence.',
    relatedIndicators: ['185.220.101.47', 'mitm-proxy-01.flokinet-redirect.example'],
    relatedCampaign: 'TLSDOWN-019',
    recommendedAction: 'Mandate DANE (RFC 7672) and MTA-STS (RFC 8461) enforcement to prevent unencrypted failover.',
  },
  {
    id: 'ALR-2026-0888',
    severity: 'high',
    type: 'Self-Signed Certificate',
    source: 'PKI Trust Validator',
    detected: '2026-08-25 14:51:00',
    status: 'investigating',
    relatedCase: 'CASE-2026-0471',
    summary: 'Self-signed digital certificate presented with no valid chain of trust to any public or internal Root CA.',
    observedFacts: [
      'Issuer: CN=Untrusted Self-Signed CA, O=Anonymous',
      'Subject: CN=mail.attacker-relay.example',
      'Authority Key Identifier missing',
      'Signature algorithm: SHA1withRSA (deprecated collision-vulnerable hash)',
    ],
    aiInference: 'Untrusted certificate exchange strongly indicates unauthorized interception proxy or adversary gateway — 91% confidence.',
    relatedIndicators: ['mail.attacker-relay.example', '185.220.101.47'],
    relatedCampaign: 'TLSDOWN-019',
    recommendedAction: 'Enforce strict certificate verification; terminate TCP session on untrusted CA.',
  },
  {
    id: 'ALR-2026-0887',
    severity: 'medium',
    type: 'Weak Key',
    source: 'Cryptographic Posture Scanner',
    detected: '2026-08-25 15:02:00',
    status: 'acknowledged',
    relatedCase: 'CASE-2026-0471',
    summary: 'Mail gateway accepted an inbound TLS connection utilizing an RSA-1024 bit server key, below NIST SP 800-131A standards.',
    observedFacts: [
      'Key algorithm: RSA',
      'Key length: 1024 bits (NIST requires minimum 2048 bits)',
      'Estimated factoring complexity within feasible academic cluster range',
      'Protocol: IMAP over TLS (Port 993)',
    ],
    aiInference: 'Sub-standard key strength violates security baseline policy; keys vulnerable to precomputation.',
    relatedIndicators: ['103.19.199.18', 'AS55836'],
    relatedCampaign: 'LEGACY-KEYS-04',
    recommendedAction: 'Upgrade server certificate to RSA-3072 or ECDSA P-256; reconfigure cryptographic minimums.',
  },
  {
    id: 'ALR-2026-0886',
    severity: 'critical',
    type: 'MitM Detected',
    source: 'SENTINEL-X Crypto Engine',
    detected: '2026-08-25 11:47:09',
    status: 'resolved',
    relatedCase: 'CASE-2026-0462',
    summary: 'Active TCP session injection and forged TLS Certificate Exchange detected in transit between SMTP relays.',
    observedFacts: [
      'TCP sequence numbers out of order with forged SYN/ACK flags',
      'Duplicate TLS ServerHello with mismatched server random parameters',
      'Session key renegotiation aborted by gateway',
      'Adversary IP isolated to autonomous system AS49505',
    ],
    aiInference: 'In-flight packet injection attempt detected and dropped at gateway — 94% confidence.',
    relatedIndicators: ['exec-spoof-relay.example', '203.0.113.55'],
    relatedCampaign: 'MITM-INJECT-01',
    recommendedAction: 'Update edge firewall routing rules, verify IPsec tunnel integrity, confirm session drop.',
  },
  {
    id: 'ALR-2026-0885',
    severity: 'medium',
    type: 'Protocol Violation',
    source: 'Network Protocol Analyzer',
    detected: '2026-08-25 10:33:51',
    status: 'resolved',
    relatedCase: 'CASE-2026-0455',
    summary: 'Mismatched TLS record layer version and ClientHello handshake version, indicating malformed or fuzzing probe.',
    observedFacts: [
      'Record layer version: TLS 1.0 (0x0301)',
      'Handshake message version: TLS 1.2 (0x0303)',
      'Missing supported_versions extension in ClientHello',
      'Session terminated by TCP RST',
    ],
    aiInference: 'Automated TLS scanner or handshake fuzzing attempt probed mail server endpoints.',
    relatedIndicators: ['198.51.100.77', 'scanner-probe.example'],
    relatedCampaign: 'RECON-PROBES',
    recommendedAction: 'Verify intrusion detection signature, block probe subnet if requests exceed threshold.',
  },
  {
    id: 'ALR-2026-0884',
    severity: 'low',
    type: 'Weak Cipher',
    source: 'Cryptographic Audit Daemon',
    detected: '2026-08-24 18:22:00',
    status: 'new',
    relatedCase: '',
    summary: 'CBC-mode cipher suite negotiated without Encrypt-then-MAC extension; theoretical Lucky Thirteen timing risk.',
    observedFacts: [
      'Cipher: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
      'Extension encrypt_then_mac: Not present',
      'Protocol: TLS 1.2',
      'No active exploitation observed',
    ],
    aiInference: 'CBC mode with MAC-then-Encrypt vulnerable to microsecond-level timing side channels — 45% confidence.',
    relatedIndicators: ['acme-c0rp.example'],
    relatedCampaign: '',
    recommendedAction: 'Prioritize AEAD ciphers (AES-GCM / CHACHA20) in cipher preference order list.',
  },
];

// ─── Phase 9: Settings ────────────────────────────────────────────────────────

export interface SettingSection {
  id: string;
  label: string;
  settings: SettingItem[];
}

export interface SettingItem {
  id: string;
  label: string;
  description: string;
  type: 'toggle';
  default: boolean;
}

export const SETTING_SECTIONS: SettingSection[] = [
  {
    id: 'general',
    label: 'General',
    settings: [
      { id: 'dark-mode', label: 'Dark Mode', description: 'Use the dark enterprise SOC theme', type: 'toggle', default: true },
      { id: 'compact-dashboard', label: 'Compact Dashboard', description: 'Reduce spacing and padding on dashboard cards', type: 'toggle', default: false },
    ],
  },
  {
    id: 'detection',
    label: 'Detection',
    settings: [
      { id: 'ai-analysis', label: 'AI Analysis', description: 'Enable SENTINEL AI analysis on detected threats', type: 'toggle', default: true },
      { id: 'auto-evidence-checks', label: 'Automatic Evidence Integrity Checks', description: 'Verify evidence hashes against the immutable ledger on schedule', type: 'toggle', default: true },
    ],
  },
  {
    id: 'notifications',
    label: 'Notifications',
    settings: [
      { id: 'email-analysis-notif', label: 'Email Analysis Notifications', description: 'Notify when email analysis completes', type: 'toggle', default: true },
      { id: 'critical-threat-alerts', label: 'Critical Threat Alerts', description: 'Real-time alerts for critical severity threats', type: 'toggle', default: true },
    ],
  },
  {
    id: 'appearance',
    label: 'Appearance',
    settings: [
      { id: 'compact-tables', label: 'Compact Tables', description: 'Reduce row padding in data tables', type: 'toggle', default: false },
      { id: 'show-synthetic-labels', label: 'Show Synthetic Data Labels', description: 'Display prototype/synthetic indicators on all pages', type: 'toggle', default: true },
    ],
  },
  {
    id: 'data-privacy',
    label: 'Data & Privacy',
    settings: [
      { id: 'auto-redact-pii', label: 'Auto-Redact PII', description: 'Automatically redact personal data in evidence exports', type: 'toggle', default: true },
      { id: 'retention-period', label: 'Evidence Retention (90 days)', description: 'Automatically archive evidence older than 90 days', type: 'toggle', default: true },
    ],
  },
];
