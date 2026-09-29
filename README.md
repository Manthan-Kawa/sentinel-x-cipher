# 🛡️ SENTINEL-X

### Sentinel-X: Cryptographic Posture Analyzer for Email Traffic

**Smart India Hackathon (SIH) Prototype** — *Cryptographic Security Posture Assessment & TLS/Cipher Forensics for Mail Gateways*

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://sentinel-x-defense.vercel.app/)
[![Repo](https://img.shields.io/badge/github-repo-blue)](https://github.com/Manthan-Kawa/Sentinel-X)
[![Built with React](https://img.shields.io/badge/React-Vite-61DAFB)](#tech-stack)
[![Status](https://img.shields.io/badge/status-prototype-orange)](#disclaimer)

🔗 **Live Demo:** [sentinel-x-defense.vercel.app](https://sentinel-x-defense.vercel.app/)
📦 **Repository:** [github.com/Manthan-Kawa/Sentinel-X](https://github.com/Manthan-Kawa/Sentinel-X)

---

## 📖 Overview

**SENTINEL-X: Cryptographic Posture Analyzer for Email Traffic** is a premium, dark-themed enterprise SOC/forensic-style web application built for cryptographic security posture assessment of mail protocols (SMTP, IMAP, POP3).

Rather than inspecting message bodies, SENTINEL-X inspects network captures (`.pcap` / `.pcapng`), reconstructs TCP streams, deconstructs TLS handshakes (ClientHello, ServerHello, Certificate Exchange), detects **Downgrade Attacks**, flags **Weak Ciphers**, and identifies **Man-in-the-Middle (MitM)** proxies and STARTTLS stripping in-flight.

> All data in this prototype is **synthetic/mock network session telemetry**, generated for demonstration purposes.

### Core Demo Flow

```
Reconstruct TCP Streams → Detect STARTTLS → Parse TLS Handshakes → Validate X.509 Certificates → Score Ciphers → Correlate Sessions → Preserve Evidence → Cryptographic Posture Report
```

---

## ✨ Key Features

### 🖥️ Dashboard
- KPI cards: PCAP Sessions Analyzed, Crypto Weaknesses Found, Critical Vulnerabilities, Active Investigations, Cryptographic Posture Score
- TLS Version Distribution (TLS 1.3, TLS 1.2, TLS 1.0)
- Top Vulnerable Cipher Suites & Cryptographic Posture Trend
- World map of **observed routing infrastructure & MitM proxies**

### 📦 PCAP Ingestion & Analysis
- Drag-and-drop `.pcap` / `.pcapng` upload
- **Load Demo PCAP Session** button with live 8-stage progress reconstruction:
  - Reconstructing TCP Streams...
  - Detecting STARTTLS Negotiations...
  - Parsing TLS Handshakes...
  - Validating X.509 Certificates...
- Sample verdict: `Risk 96/100 | Downgrade Attack | CRITICAL | Confidence 94.7%`
- Explainable cryptographic risk factors:
  - Deprecated TLS 1.0 protocol negotiation
  - Prohibited cipher suite (RC4 / 3DES / CBC padding oracle)
  - Expired and self-signed X.509 digital certificates
  - Insecure public keys (RSA-1024 below NIST thresholds)
  - Absence of Ephemeral Key Exchange (No Forward Secrecy)
- Clear separation between **Observed Facts** and **AI Inference**

### 🔍 Cryptographic Forensics
- TLS Handshake sequence visualization: ClientHello, ServerHello, Certificate, ServerKeyExchange, ChangeCipherSpec
- Cryptographic Guardrails compliance status (TLS Version Policy, Cipher Suite Strength, Certificate Trust)
- SMTP transport hop telemetry and cipher parameter inspection

### 🛡️ Certificate Vault
- Comprehensive X.509 digital certificate catalog
- Expiration date tracking and automated overdue alerts
- Public key strength analysis (highlighting sub-2048-bit RSA keys and weak signature hashes)
- CA issuer chain verification and OCSP stapling status

### 📍 Session Mapping & Origin Investigation
- Interactive map tracking network hops and intermediate proxies
- Geolocation of suspect autonomous systems (ASNs) associated with downgrade and interception activity
- Confidence-based origin inference

### 🕸️ Attack Graph
- Built with **React Flow**
- Visualizes correlated network entities: `Session → Mail Server → Source IP → Host / Proxy → Cipher Suite → TLS Campaign → Case`
- Interactive zoom, pan, and cryptographic attribute inspection

### 📁 Investigations & Evidence Vault
- Cryptographic incident management with severity, status, and timeline tracking
- Evidence Vault with SHA-256 session integrity hashing and immutable audit trails
- Cryptographic posture compliance verification

### 📊 Reports & Sentinel AI
- Conversational **Sentinel AI** assistant specializing in TLS RFCs, cipher suites, and downgrade attack diagnostics
- Posture assessment report exports for **Executive**, **Technical**, and **Cryptographic Auditor** audiences

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Framework | React + Vite + TypeScript |
| Styling | Tailwind CSS |
| Icons | Lucide |
| Charts | Recharts |
| Graph Visualization | React Flow |
| Deployment | Vercel |

---

## 🗂️ Sidebar / Navigation

`Dashboard` · `Email Analyzer` · `Header Forensics` · `Threat Intelligence` · `Origin Investigation` · `Attack Graph` · `Campaigns` · `Investigations` · `Evidence Vault` · `Reports` · `Alerts` · `Settings`

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+ recommended)
- npm / yarn / pnpm

### Installation

```bash
# Clone the repository
git clone https://github.com/Manthan-Kawa/Sentinel-X.git
cd Sentinel-X

# Install dependencies
npm install

# Start the development server
npm run dev
```

The app will be available at `http://localhost:5173` (default Vite port).

### Build for Production

```bash
npm run build
npm run preview
```

---

## 🎯 Design Principles

- **Judge-ready, not gimmicky** — enterprise SOC aesthetic over cyberpunk clichés (no excessive neon, skulls, or clutter)
- **Explainability first** — every AI verdict separates observed facts from inferred conclusions
- **Responsible language** — origin/geolocation findings are always framed as probabilistic, never definitive attribution
- **Fully interactive demo** — navigation, charts, the attack graph, and the analysis flow are functional, not static mockups

---

## 🔭 Future Scope

- **Companion App** — extend Sentinel-X beyond the web dashboard into a dedicated app for on-the-go threat monitoring and alerts
- **Direct Gmail Integration** — once user trust is established, allow Sentinel-X to connect directly to a user's Gmail inbox (via OAuth) for automatic, real-time email analysis — removing the need to manually upload/forward suspicious emails
- **Continuous Learning** — feed verified investigation outcomes back into the detection model to improve accuracy over time

---

## ⚠️ Disclaimer

This is a **hackathon prototype** built for demonstration purposes as part of Smart India Hackathon (SIH). All emails, IPs, domains, threat indicators, geolocation data, and "blockchain" ledger entries are **synthetic/mock data** and do not represent real investigations, real infrastructure, or real attackers.

---

## 👥 Team — Cyber Sentinels

- Manthan Kawa
- Manthan Raichura
- Dharmik Chavda
- Tirth Patel
- Omkar Patil
- Janvi Parmar

---

## 📄 License

This project was built for hackathon submission/demonstration purposes. Add a license (e.g., MIT) here if you intend to open-source it further.
