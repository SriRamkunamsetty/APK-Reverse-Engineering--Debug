<div align="center">

```
██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗
██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝
██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝
██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗
██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# RAKSHAK — APK Threat Intelligence Platform

**Reverse Analysis & Knowledge System for Heuristic APK Threats**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![SriAI](https://img.shields.io/badge/SriAI-GenAI%20Reasoning-00C896?style=flat-square)]()
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)]()
[![DRDO](https://img.shields.io/badge/DRDO-Cybersecurity_Division-1a1a2e?style=flat-square)]()
[![IIT Hyderabad](https://img.shields.io/badge/IIT_Hyderabad-Hackathon-blue?style=flat-square)]()

> ⬛ **SENSITIVE — DRDO CYBERSECURITY DIVISION**
>
> Defence-grade Android APK malware analysis platform powered by Generative AI.
> 11-engine pipeline · Real-time WebSocket streaming · FIR-admissible forensic reports.

</div>

---

## Latest Project Updates

- Frontend dashboard runs at `http://127.0.0.1:8000/` when the FastAPI server is active.
- Analyst Q&A is branded as **SriAI** and answers from the completed APK analysis report.
- Gemini is supported through a local `.env` entry: `GEMINI_API_KEY=your_key_here`. `GOOGLE_API_KEY` is also accepted. Do not commit real keys.
- Dashboard includes a **PDF REPORT** download button after analysis completion.
- Forensic PDFs include one highlighted footer credit: **DEVELOPED BY MOHAN SRIRAM KUNAMSETTY**.
- PDF layout has been cleaned up: no diagonal watermark, aligned risk score/severity, wrapped table cells, and safer footer spacing.
- AndroidManifest permissions, MITRE technique names, and IOC allowlist filtering are included in the latest report pipeline.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Key Capabilities](#key-capabilities)
4. [System Architecture](#system-architecture)
5. [Analysis Pipeline — Deep Dive](#analysis-pipeline--deep-dive)
6. [Module Documentation](#module-documentation)
7. [Risk Scoring Methodology](#risk-scoring-methodology)
8. [YARA Rule Library](#yara-rule-library)
9. [Machine Learning Engine](#machine-learning-engine)
10. [GenAI Intelligence Layer](#genai-intelligence-layer)
11. [Dynamic Analysis (Frida)](#dynamic-analysis--frida-sandbox)
12. [Threat Intelligence Integrations](#threat-intelligence-integrations)
13. [Real-Time WebSocket Architecture](#real-time-websocket-architecture)
14. [API Reference](#api-reference)
15. [Installation & Setup](#installation--setup)
16. [Configuration](#configuration)
17. [Usage Guide](#usage-guide)
18. [Deployment — Docker & Production](#deployment--docker--production)
19. [Database Schema](#database-schema)
20. [Testing](#testing)
21. [Project Structure](#project-structure)
22. [Flowcharts](#flowcharts)
23. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
24. [Comparison with Existing Tools](#comparison-with-existing-tools)
25. [Roadmap](#roadmap)
26. [Legal & Compliance](#legal--compliance)
27. [Acknowledgements](#acknowledgements)

---

## Overview

**RAKSHAK** (Reverse Analysis & Knowledge System for Heuristic APK Threats) is a world-class, defence-grade Android APK malware analysis platform developed for the **DRDO (Defence Research & Development Organisation) Cybersecurity Division** and submitted to the **IIT Hyderabad Hackathon** under the problem statement: *"Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications (APKs)"*.

RAKSHAK addresses a critical national security gap: fraudulent APKs distributed via WhatsApp, SMS, and phishing links are increasingly used to target Indian banking customers, government employees, and defence personnel. Manual analysis by cybersecurity experts takes 4–8 hours per sample. **RAKSHAK automates this in under 60 seconds** with higher accuracy through an 11-engine AI-powered pipeline.

### Why RAKSHAK is Different

| Feature | Conventional Tools | RAKSHAK |
|---|---|---|
| Analysis speed | 4–8 hours (manual) | < 60 seconds |
| Zero-day detection | No | Yes (LLM semantic reasoning) |
| India-specific banking threats | No | Yes (UPI, BHIM, IMPS, SBI, HDFC) |
| Nation-state APT detection | Limited | Yes (APT36, SideWinder) |
| Real-time streaming | No | Yes (WebSocket) |
| Explainable AI scores | No | Yes (SHAP-style XAI) |
| FIR-admissible reports | No | Yes (IT Act 2000 mapped) |
| STIX 2.1 / CERT-In export | Rare | Yes (auto-push) |
| Multi-LLM reasoning | No | Yes (Claude AI) |

---

## Problem Statement

**Source:** IIT Hyderabad Hackathon — Theme: Generative AI for National Security

Fraudsters increasingly distribute malicious APKs through:
- **WhatsApp forwards** — disguised as bank reward apps
- **SMS phishing** — "Your KYC is pending, install this app"
- **Email attachments** — fake IT refund applications
- **Phishing links** — SBI/HDFC login page lookalikes

These APKs steal:
- OTPs via SMS interception
- Banking credentials via overlay attacks
- IMEI/IMSI for device tracking
- Contact lists for further propagation
- Location data for targeted surveillance

**Scale of the problem:** India loses ₹1,100+ crore annually to mobile banking fraud, with APK-based attacks growing at 340% YoY (RBI Cybersecurity Report 2024).

**RAKSHAK's mandate:** Enable DRDO and banking CERT teams to automatically analyse any suspicious APK and produce actionable intelligence in under 60 seconds, with evidence quality sufficient for FIR filing.

---

## Key Capabilities

### 🔬 Analysis Capabilities
- **Full APK teardown** — every file, every DEX, every native library catalogued
- **Multi-hash fingerprinting** — MD5, SHA-1, SHA-256, SHA-512, block hash
- **Permission danger matrix** — 25+ dangerous permissions with combination scoring
- **120+ dangerous API patterns** — DexClassLoader, Runtime.exec, onAccessibilityEvent and more
- **15 CVE-mapped vulnerabilities** — SQL injection, WebView RCE, path traversal
- **Cryptographic audit** — ECB mode, MD5 usage, hardcoded keys, SSL bypass
- **19 YARA detection rules** — BankBot, Cerberus, Anubis, FluBot, Drinik, APT36, and more
- **India-specific banking fraud** — OTP harvesting, UPI fraud, brand impersonation

### 🤖 AI/ML Capabilities
- **Claude AI semantic analysis** — chain-of-thought threat reasoning
- **Opcode N-gram classifier** — bytecode-level malware patterns
- **API sequence scorer** — temporal API call pattern analysis
- **Semantic code similarity** — TF-IDF cosine similarity vs malware corpus
- **Zero-day detection** — LLM reasons about novel/unknown patterns
- **Analyst Q&A agent** — RAG over decompiled APK code

### 📡 Real-Time Capabilities
- **WebSocket event streaming** — every finding pushed live to dashboard
- **Animated risk score dial** — climbs in real-time as engines fire
- **Per-engine status indicators** — 12 live engine health indicators
- **Live IOC feed** — C2 IPs and URLs appear as extracted
- **APT alert popup** — instant escalation notification

### 🌐 Intelligence & Reporting
- **STIX 2.1 bundle export** — CERT-In / MISP / OpenCTI compatible
- **MISP bidirectional sync** — auto-push IOCs, import threat feeds
- **Certificate Transparency monitoring** — detects brand impersonation certs
- **Network IOC enrichment** — VirusTotal, AbuseIPDB, ip-api, Shodan
- **PDF forensic reports** — executive brief + full technical IOC report
- **FIR-admissible evidence packaging** — chain of custody, IT Act sections

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RAKSHAK PLATFORM — ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │  Web Browser │    │  CLI Client  │    │  SIEM/SOAR   │
  │  (Dashboard) │    │  (cli.py)    │    │  (Webhook)   │
  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
         │ HTTP/WS           │ Python            │ REST
         ▼                   ▼                   ▼
  ┌─────────────────────────────────────────────────────┐
  │              FastAPI REST Server (main.py)           │
  │  /api/analyze  /api/result  /ws/analysis  /api/stix │
  └──────────────────────────┬──────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
  ┌─────────────┐   ┌────────────────┐   ┌─────────────┐
  │  Celery     │   │  Event Bus     │   │  SQLite DB  │
  │  Task Queue │   │  (WebSocket)   │   │  (Cases +   │
  │  (Redis)    │   │  Pub/Sub       │   │   IOCs)     │
  └──────┬──────┘   └────────────────┘   └─────────────┘
         │
         ▼
  ┌─────────────────────────────────────────────────────┐
  │            ADVANCED PIPELINE (11 Engines)            │
  ├──────────┬──────────┬──────────┬──────────┬─────────┤
  │  APK     │  Static  │  YARA    │  ML      │  GenAI  │
  │  Analyzer│  Engine  │  Engine  │  Engine  │  Engine │
  ├──────────┼──────────┼──────────┼──────────┼─────────┤
  │  Frida   │ Network  │   MISP   │  Risk    │  STIX   │
  │  Sandbox │ Analyzer │  Client  │  Scorer  │ Export  │
  └──────────┴──────────┴──────────┴──────────┴─────────┘
         │
         ▼
  ┌─────────────────────────────────────────────────────┐
  │                    OUTPUT LAYER                      │
  ├──────────────┬──────────────┬────────────┬──────────┤
  │  PDF Report  │  JSON Report │  STIX 2.1  │  Alert   │
  │  (Forensic)  │  (Machine)   │  (CERT-In) │  (SIEM)  │
  └──────────────┴──────────────┴────────────┴──────────┘
```

### Component Dependency Graph

```
config.py
    │
    ├── core/event_bus.py ──────────────────────────────────────────────┐
    │                                                                    │
    ├── core/apk_analyzer.py                                            │
    │       ├── HashEngine                                              │
    │       ├── APKStructureAnalyzer                                    │
    │       ├── ManifestAnalyzer                                        │
    │       ├── CertificateAnalyzer                                     │
    │       └── StringAnalyzer                                          │
    │                                                                    │
    ├── core/static_engine.py                                           │
    │       ├── APICallScanner ──────────────────────────── event_bus  │
    │       ├── VulnerabilityScanner                                    │
    │       ├── CryptoAuditor                                           │
    │       └── BankingThreatDetector                                   │
    │                                                                    │
    ├── core/yara_engine.py ─────────────────────────────── event_bus  │
    │       ├── RakshakRule (×19)                                       │
    │       └── YARAEngine                                              │
    │                                                                    │
    ├── core/ml_engine.py ───────────────────────────────── event_bus  │
    │       ├── OpcodeNgramExtractor                                    │
    │       ├── APISequenceScorer                                       │
    │       ├── SemanticSimilarityEngine                                │
    │       └── MLEnsemble                                              │
    │                                                                    │
    ├── core/genai_engine.py ────────────────────────────── Anthropic  │
    │       ├── CodeContextBuilder                                      │
    │       └── GenAIEngine                                             │
    │                                                                    │
    ├── core/frida_sandbox.py ───────────────────────────── event_bus  │
    │       └── FridaSandboxOrchestrator                                │
    │                                                                    │
    ├── core/risk_scorer.py ─────────────────────────────── event_bus  │
    │       └── RiskScoringEngine                                       │
    │                                                                    │
    ├── core/network_analyzer.py ────────────────────────── ext APIs   │
    ├── core/misp_client.py ─────────────────────────────── MISP API  │
    ├── core/ct_monitor.py ──────────────────────────────── crt.sh    │
    ├── core/diff_analyzer.py                                           │
    ├── core/stix_exporter.py                                           │
    ├── core/report_engine.py                                           │
    ├── core/ws_server.py ──────────────────────────────── event_bus  │◄─┘
    ├── core/task_queue.py ─────────────────────────────── Celery     │
    │                                                                    │
    ├── core/advanced_pipeline.py ─── orchestrates all above ──────────┘
    │
    ├── database/db.py
    ├── main.py (FastAPI + WebSocket)
    └── cli.py (Rich terminal)
```

---

## Analysis Pipeline — Deep Dive

### Complete 11-Engine Pipeline Flow

```
APK FILE INPUT
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 0: INTAKE & CRYPTOGRAPHIC FINGERPRINTING       ║
╠═══════════════════════════════════════════════════════╣
║  • MD5, SHA-1, SHA-256, SHA-512 hash computation      ║
║  • Block hash (first 4KB SHA-256 — near-dedup)       ║
║  • APK magic byte validation (PK\x03\x04)             ║
║  • File size validation (max 200MB)                   ║
║  • Case ID generation (RKSAK-YYYYMMDD-XXXXXXXX)       ║
║  • Intake timestamp (UTC, chain-of-custody)           ║
║                                                       ║
║  EMITS: hash_complete event → WebSocket clients       ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 1: APK STRUCTURE DECOMPOSITION                 ║
╠═══════════════════════════════════════════════════════╣
║  • ZIP structure validation                           ║
║  • DEX file inventory (classes.dex, classes2.dex...)  ║
║  • Native library catalogue (lib/arm64-v8a/*.so)      ║
║  • Asset file extraction (assets/*.*)                 ║
║  • Resource file mapping (res/**)                     ║
║  • Entropy analysis (Shannon entropy per asset)       ║
║  • Embedded APK/DEX/ELF detection (dropper signal)    ║
║  • ZIP path traversal vulnerability check             ║
║  • Multi-DEX detection flag                           ║
║                                                       ║
║  EMITS: structure_complete event                      ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 2: MANIFEST DEEP ANALYSIS                      ║
╠═══════════════════════════════════════════════════════╣
║  • Binary XML decode (AndroidManifest.xml)            ║
║  • Package name extraction + brand impersonation check║
║  • SDK version analysis (min/target SDK)              ║
║  • Full permission matrix extraction                  ║
║  • 25 dangerous permission risk scores                ║
║  • Permission combination threat patterns             ║
║  • Exported component attack surface mapping          ║
║  • Intent filter analysis                             ║
║  • Debuggable flag detection                          ║
║                                                       ║
║  KEY PERMISSION COMBINATIONS DETECTED:                ║
║  READ_SMS + SYSTEM_ALERT_WINDOW → OTP Stealer         ║
║  ACCESSIBILITY + OVERLAY → Banking Credential Theft   ║
║  DEVICE_ADMIN + BOOT → Ransomware Persistence         ║
║  INSTALL_PACKAGES + BOOT → Dropper with Persistence   ║
║                                                       ║
║  EMITS: manifest_complete + banking_threat events     ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 3: STRING & IOC EXTRACTION                     ║
╠═══════════════════════════════════════════════════════╣
║  • Raw printable ASCII extraction from all DEX files  ║
║  • URL pattern matching (HTTP/HTTPS)                  ║
║  • IP:port extraction with private range filtering    ║
║  • Email address extraction                           ║
║  • Telegram Bot API token detection                   ║
║  • Base64 blob detection + attempted decode           ║
║  • Hardcoded credentials / API keys                   ║
║  • Indian phone number patterns (+91)                 ║
║  • Shell command patterns (su, chmod, wget, curl)     ║
║  • Banking brand reference detection                  ║
║  • Crypto key material detection                      ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 4: STATIC CODE ANALYSIS                        ║
╠═══════════════════════════════════════════════════════╣
║  ┌─────────────────────────────────────────────────┐  ║
║  │  API CALL SCANNER                               │  ║
║  │  120+ dangerous Android API patterns            │  ║
║  │  Each finding: severity + MITRE technique       │  ║
║  │  EMITS: static_finding (CRITICAL) per hit       │  ║
║  └─────────────────────────────────────────────────┘  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │  VULNERABILITY SCANNER (15 CVE-mapped checks)  │  ║
║  │  SQL injection, WebView RCE, path traversal     │  ║
║  │  Fragment injection, intent hijacking, etc.     │  ║
║  │  EMITS: critical_vuln per finding               │  ║
║  └─────────────────────────────────────────────────┘  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │  CRYPTOGRAPHIC AUDIT                            │  ║
║  │  ECB mode, MD5/SHA-1, hardcoded keys            │  ║
║  │  SSL trust-all, RC4, DES, NullCipher            │  ║
║  └─────────────────────────────────────────────────┘  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │  BANKING FRAUD DETECTOR (India-specific)        │  ║
║  │  OTP harvesting, overlay attack, UPI fraud      │  ║
║  │  Brand impersonation, kill chain mapping        │  ║
║  │  EMITS: banking_threat event                    │  ║
║  └─────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 5: YARA PATTERN MATCHING (19 rules)            ║
╠═══════════════════════════════════════════════════════╣
║  Banking Trojans:  BankBot, Cerberus, Anubis,         ║
║                    FluBot, Drinik, IceSpy/AxBanker    ║
║  RATs:             SpyNote, AhMyth, Dendroid           ║
║  Spyware:          Pegasus-like, CallRecorder,         ║
║                    Keylogger                           ║
║  Droppers:         APK Dropper, Malicious Packer       ║
║  Ransomware:       Android Ransomware                  ║
║  Nation-State:     APT36/Transparent Tribe,            ║
║                    SideWinder                          ║
║  Other:            CryptoMiner, Toll Fraud             ║
║                                                        ║
║  Each match: EMITS yara_match event with family name  ║
║  Nation-state: EMITS nation_state_alert event         ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 6: ADVANCED ML ENGINE (3-layer ensemble)       ║
╠═══════════════════════════════════════════════════════╣
║  ┌─────────────────────────────────────────────────┐  ║
║  │  LAYER 1: Opcode N-gram Extractor               │  ║
║  │  DEX bytecode → opcode sequences → 3-grams      │  ║
║  │  300-dim hash-based feature vector              │  ║
║  │  Anomaly score from distribution variance       │  ║
║  └─────────────────────────────────────────────────┘  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │  LAYER 2: API Sequence Scorer                   │  ║
║  │  Ordered API call sequence extraction           │  ║
║  │  Bigram transition probability scoring          │  ║
║  │  18 malicious transitions, 5 benign transitions │  ║
║  │  E.g.: getSubscriberId → sendTextMessage = 0.95 │  ║
║  └─────────────────────────────────────────────────┘  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │  LAYER 3: Semantic Code Similarity (TF-IDF)     │  ║
║  │  Code identifiers → normalised text             │  ║
║  │  TF-IDF vectoriser (bigrams, 2000 features)     │  ║
║  │  Cosine similarity vs 9 malware family corpora  │  ║
║  │  Returns family match + confidence score        │  ║
║  └─────────────────────────────────────────────────┘  ║
║                                                       ║
║  ENSEMBLE: weights 30% / 40% / 30%                    ║
║  EMITS: score_update (ml_ensemble dimension)          ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 7: GENAI REASONING (Claude AI)                 ║
╠═══════════════════════════════════════════════════════╣
║  • CodeContextBuilder assembles evidence summary      ║
║  • Sends structured prompt to claude-opus-4-5         ║
║  • Chain-of-thought reasoning over decompiled code    ║
║  • Returns JSON: threat_classification, capabilities, ║
║    attack_chain, data_at_risk, apt_attribution,       ║
║    zero_day_indicators, immediate_actions             ║
║  • Generates executive summary (2-paragraph brief)    ║
║  • Supports analyst Q&A (RAG over APK code)           ║
║                                                       ║
║  EMITS: genai_thinking, genai_complete events         ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 8: DYNAMIC SANDBOX (Frida Instrumentation)     ║
╠═══════════════════════════════════════════════════════╣
║  LIVE MODE (requires Android SDK + frida-server):     ║
║  • Spawn APK in isolated Android emulator             ║
║  • Inject RAKSHAK master hook script via Frida        ║
║  • Monitor: SMS sends, network requests, file writes, ║
║    shell execution, crypto operations, GPS access,    ║
║    device ID reads, DexClassLoader calls              ║
║  • Run for SANDBOX_DURATION_SEC (default 120s)        ║
║                                                       ║
║  SIMULATED MODE (default — no emulator needed):       ║
║  • Static heuristic prediction of runtime behaviour  ║
║  • Pattern-matches DEX strings for API call presence  ║
║  • Produces predicted behaviour report                ║
║                                                       ║
║  EMITS: static_finding (FRIDA category) per behaviour ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 9: NETWORK IOC ENRICHMENT                      ║
╠═══════════════════════════════════════════════════════╣
║  For each extracted IP:                               ║
║  • ip-api.com → country, city, org, ASN, hosting flag ║
║  • Known malicious ASN check (9 bulletproof ASNs)     ║
║  • VirusTotal IP lookup (if API key configured)       ║
║  • AbuseIPDB confidence score (if API key configured) ║
║  • Tor exit node heuristic                            ║
║                                                       ║
║  For each extracted URL:                              ║
║  • Suspicious TLD check (.xyz, .tk, .ml, .ga, etc.)  ║
║  • Direct IP URL detection                            ║
║  • C2 URL pattern matching (/gate.php, /bot/, etc.)   ║
║  • Tunnelling service detection (ngrok, serveo)       ║
║  • Dynamic DNS detection (duckdns, no-ip)             ║
║  • Telegram Bot API token detection                   ║
║  • VirusTotal domain lookup                           ║
║                                                       ║
║  EMITS: c2_found, ioc_enriched events                 ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 10: MULTI-DIMENSIONAL RISK SCORING (XAI)       ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║  Dimension 1: Permission Risk (18%)                   ║
║    raw_score = min(sum(dangerous_perm_scores), 100)   ║
║    bonus for lethal combinations                      ║
║                                                       ║
║  Dimension 2: Static Code (22%)                       ║
║    = API_score×0.40 + Vuln_score×0.25                ║
║    + Crypto_score×0.15 + Banking_score×0.15           ║
║    + Obfuscation_penalty×0.05                         ║
║                                                       ║
║  Dimension 3: Dynamic Behaviour (28%)                 ║
║    Persistence indicators + C2 URLs + shell commands  ║
║    + embedded APKs + high-entropy assets              ║
║                                                       ║
║  Dimension 4: Network IOCs (16%)                      ║
║    Direct IPs + Telegram tokens + credentials + URLs  ║
║                                                       ║
║  Dimension 5: Threat Intel / YARA (10%)               ║
║    yara_risk_score + APT bonus (+20) + nation-state   ║
║    auto-max if nation_state=True                      ║
║                                                       ║
║  Dimension 6: GenAI Reasoning (6%)                    ║
║    genai_classification_score × confidence_multiplier ║
║                                                       ║
║  FINAL = Σ(dim_score × weight) + cert_bonus           ║
║         + impersonation_bonus + ML_boost×0.10         ║
║         + dynamic_boost×0.08                         ║
║                                                       ║
║  SEVERITY: CRITICAL ≥85, HIGH ≥65, MEDIUM ≥40        ║
║            LOW ≥20, CLEAN < 20                        ║
║                                                       ║
║  EMITS: score_update (per dimension), score_final     ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
╔═══════════════════════════════════════════════════════╗
║  PHASE 11: OUTPUT GENERATION                          ║
╠═══════════════════════════════════════════════════════╣
║  PDF Forensic Report (ReportLab):                     ║
║    • Chain-of-custody page (all hashes + timestamps)  ║
║    • Executive brief (GenAI-written, plain English)   ║
║    • APK fingerprints + metadata                      ║
║    • Structure analysis                               ║
║    • Manifest deep analysis + permission matrix       ║
║    • Static analysis findings table                   ║
║    • CVE-mapped vulnerability findings                ║
║    • Cryptographic audit results                      ║
║    • YARA matches                                     ║
║    • Indian banking fraud analysis                    ║
║    • Network IOC table                                ║
║    • XAI risk score breakdown                         ║
║    • MITRE ATT&CK Mobile mapping                      ║
║    • Recommendations + remediation                    ║
║    • IT Act 2000 legal section mapping                ║
║                                                       ║
║  STIX 2.1 Bundle (CERT-In compatible):                ║
║    • Malware object (family, capabilities)            ║
║    • Indicator objects (hashes, IPs, URLs, domains)   ║
║    • Attack-pattern objects (MITRE techniques)        ║
║    • Threat-actor object (if APT detected)            ║
║    • Report object (full case summary)                ║
║    • Relationship objects (linkage graph)             ║
╚═══════════════════════════════════════════════════════╝
     │
     ▼
   OUTPUT: JSON report, PDF report, STIX bundle, alerts
```

---

## Module Documentation

### `core/apk_analyzer.py`

**Classes:**

#### `HashEngine`
Generates all cryptographic fingerprints for chain-of-custody.

```python
from core.apk_analyzer import HashEngine

hashes = HashEngine.compute_all("suspicious.apk")
# Returns: md5, sha1, sha256, sha512, size_bytes, size_human,
#          magic_valid, block_hash, timestamp
```

#### `APKStructureAnalyzer`
Decomposes APK ZIP structure, calculates entropy, detects embedded payloads.

```python
from core.apk_analyzer import APKStructureAnalyzer

analyzer = APKStructureAnalyzer("suspicious.apk")
result = analyzer.analyze()
# result["high_entropy_files"] — potentially encrypted payloads
# result["embedded_apks"]      — dropper detection
# result["native_libs"]        — native exploit libraries
# result["structure_anomalies"] — ZIP path traversal, script injection
```

**Shannon Entropy Formula:**
```
H(X) = -Σ p(xᵢ) × log₂(p(xᵢ))
```
Entropy > 7.2 bits = high likelihood of encrypted/compressed payload.

#### `ManifestAnalyzer`
Deep parses AndroidManifest.xml, scores dangerous permissions.

#### `StringAnalyzer`
Multi-pattern IOC extractor from raw DEX bytecode strings.

---

### `core/static_engine.py`

**Classes:**

#### `APICallScanner`
Scans raw DEX bytecode for 120+ dangerous API call patterns.

**Danger Classification:**

| Severity | Score | Example APIs |
|---|---|---|
| CRITICAL | 30-40 | DexClassLoader, onAccessibilityEvent, BIND_DEVICE_ADMIN |
| HIGH | 15-25 | Runtime.exec, Camera.open, AudioRecord |
| MEDIUM | 5-15 | WebView.setJavaScript, ClipboardManager |

#### `VulnerabilityScanner`
15 CVE-mapped vulnerability checks:

```
RAKSHAK-001: Insecure Data Storage       CWE-312
RAKSHAK-002: SQL Injection               CWE-89
RAKSHAK-003: WebView RCE                 CVE-2012-6636
RAKSHAK-004: SSL Certificate Bypass      CWE-295
RAKSHAK-005: Cleartext HTTP Traffic      CWE-319
RAKSHAK-006: Weak Cryptography ECB       CWE-327
RAKSHAK-007: Hardcoded Crypto Key        CWE-321
RAKSHAK-008: Fragment Injection          CVE-2013-6272
RAKSHAK-009: Path Traversal              CWE-22
RAKSHAK-010: Insecure RNG                CWE-330
RAKSHAK-011: Exported Component          CWE-926
RAKSHAK-012: Implicit Broadcast          CWE-925
RAKSHAK-013: External Storage Sensitive  CWE-312
RAKSHAK-014: Debug Mode Enabled          CWE-489
RAKSHAK-015: Intent Injection PendingInt CWE-927
```

#### `BankingThreatDetector`
India-specific banking fraud pattern detection.

**Fraud Kill Chain Stages:**
```
LURE → INSTALL → PERSIST → HARVEST → EXFIL → CASH-OUT
```

Each stage is mapped to specific code patterns and MITRE techniques.

---

### `core/yara_engine.py`

RAKSHAK implements a pure-Python YARA-equivalent engine with 19 custom rules.

**Rule Structure:**
```python
RakshakRule(
    name        = "RAKSHAR-BT-001",
    family      = "BankBot",
    severity    = "CRITICAL",
    description = "BankBot banking trojan",
    patterns    = [
        r"RECEIVE_SMS.*SYSTEM_ALERT_WINDOW",
        r"getMessageBody",
        r"addView.*TYPE_APPLICATION_OVERLAY",
    ],
    mitre       = ["T1412", "T1417", "T1636"],
    weight      = 35,
)
```

**Pattern Matching Algorithm:**
- Each rule requires minimum 1 pattern match (configurable)
- Patterns are compiled regex tested against full APK extracted strings
- Weight-based cumulative scoring
- Ensemble final score = min(total_weight, 100)

---

### `core/ml_engine.py`

Three-layer ML ensemble for malware classification.

#### Layer 1: Opcode N-gram Extractor

```
DEX Bytecode → Opcode Tokens → 3-gram sequences → Counter
    → Hash-based 300-dim vector → Anomaly via std deviation
```

**Opcode vocabulary (subset):**
```
INVOKE_VIRT, INVOKE_STATIC, INVOKE_DIRECT, CONST_STR,
NEW_INST, IPUT, IGET, GOTO, RETURN_VOID, XOR_INT...
```

#### Layer 2: API Sequence Scorer

Uses a **bigram transition probability matrix** over 40 Android API keywords.

Top malicious transitions (probability scores):
```
getSubscriberId → sendTextMessage    : 0.95
onAccessibilityEvent → performAction : 0.95
requestAdminForDevice → lockNow      : 0.98
DexClassLoader → loadClass           : 0.90
AudioRecord → FileOutputStream       : 0.88
```

#### Layer 3: Semantic Similarity (TF-IDF)

```
Code identifiers → lowercase tokens → TF-IDF vectoriser
    → cosine_similarity vs malware corpus → family scores
```

**Malware corpus families:** BankBot, Cerberus, Anubis, Drinik,
SpyNote_RAT, APT36_Transparent_Tribe, Dropper, Ransomware, CryptoMiner

---

### `core/genai_engine.py`

Claude AI integration for semantic threat reasoning.

**System prompt architecture:**
```
RAKSHAK-AI identity (DRDO analyst AI)
→ Code evidence context (8000 char max)
→ Structured JSON response prompt
→ Chain-of-thought threat analysis
```

**Supported queries:**
- `analyze_threat()` — Full semantic APK analysis
- `generate_executive_summary()` — 2-paragraph leadership brief
- `answer_analyst_question()` — RAG Q&A over APK code
- `interpret_obfuscated_class()` — Deobfuscation assistance

---

### `core/risk_scorer.py`

**XAI (Explainable AI) Risk Scoring**

SHAP-style attribution — every point in the final score is traced to a specific evidence source:

```
Score: 87/100
├── Permissions (18%):      +18.0  ← OVERLAY + SMS combination
├── Static Code (22%):      +22.0  ← DexClassLoader, 6 vulns
├── Dynamic Behaviour (28%):+28.0  ← C2 URLs, shell commands
├── Network IOCs (16%):     +12.8  ← 2 C2 IPs, Telegram token
├── Threat Intel (10%):     +10.0  ← APT36 YARA match
└── GenAI Reasoning (6%):   +5.0   ← HIGH confidence: RAT
    ─────────────────────────────
    Total: 95.8 → capped at 100
```

---

## Risk Scoring Methodology

### Scoring Formula

```
Final_Score = Σᵢ (raw_score_i × weight_i) + bonuses

Where:
  bonuses = cert_bonus (if self-signed: +5)
          + struct_bonus (if anomalies: +3)
          + impersonation_bonus (brand_score × 0.10)
          + ML_boost (ml_ensemble × 0.10)
          + dynamic_boost (frida_score × 0.08)

Final_Score = min(Final_Score, 100)
```

### Permission Combination Multipliers

Certain permission pairs indicate specific attack types and receive multipliers:

| Combination | Threat Pattern | Score Boost |
|---|---|---|
| READ_SMS + SYSTEM_ALERT_WINDOW | Banking OTP Stealer | +25 |
| ACCESSIBILITY + OVERLAY | Credential Theft | +30 |
| DEVICE_ADMIN + BOOT | Ransomware Persistence | +35 |
| INSTALL_PACKAGES + BOOT | Dropper Persistence | +25 |
| RECORD_AUDIO + CAMERA | Surveillance Suite | +20 |
| READ_CONTACTS + SEND_SMS | Worm Propagation | +20 |

### Severity Thresholds

```
 0 ─────────── 20 ────────── 40 ─────────── 65 ────── 85 ──── 100
 │    CLEAN    │     LOW     │    MEDIUM    │   HIGH  │ CRIT  │
```

---

## YARA Rule Library

### Rule Coverage Map

```
┌────────────────────────────────────────────────────────────────┐
│                  RAKSHAK YARA RULE LIBRARY                     │
├────────────────┬──────────────┬───────────┬───────────────────┤
│ Rule ID        │ Family       │ Category  │ India-Specific?   │
├────────────────┼──────────────┼───────────┼───────────────────┤
│ RAKSHAR-BT-001 │ BankBot      │ Banking   │ No (global)       │
│ RAKSHAR-BT-002 │ Cerberus     │ Banking   │ No (global)       │
│ RAKSHAR-BT-003 │ Anubis       │ Banking   │ No (global)       │
│ RAKSHAR-BT-004 │ FluBot       │ SMS Worm  │ No (global)       │
│ RAKSHAR-BT-005 │ Drinik       │ Banking   │ YES — Income Tax  │
│ RAKSHAR-BT-006 │ IceSpy/AxBnk │ Banking   │ YES — UPI/Axis    │
│ RAKSHAR-RT-001 │ SpyNote RAT  │ RAT       │ No (global)       │
│ RAKSHAR-RT-002 │ AhMyth       │ RAT       │ No (global)       │
│ RAKSHAR-RT-003 │ Dendroid     │ RAT       │ No (global)       │
│ RAKSHAR-SP-001 │ Pegasus-like │ Spyware   │ No (global)       │
│ RAKSHAR-SP-002 │ CallRecorder │ Spyware   │ No (global)       │
│ RAKSHAR-SP-003 │ Keylogger    │ Spyware   │ No (global)       │
│ RAKSHAR-DR-001 │ APK Dropper  │ Dropper   │ No (global)       │
│ RAKSHAR-DR-002 │ Mal. Packer  │ Packer    │ No (global)       │
│ RAKSHAR-RN-001 │ Android Rnsmw│ Ransomware│ No (global)       │
│ RAKSHAR-APT-001│ APT36/TribeTr│ Nation-St │ YES — DRDO target │
│ RAKSHAR-APT-002│ SideWinder   │ Nation-St │ YES — S.Asia APT  │
│ RAKSHAR-CM-001 │ CryptoMiner  │ Adware    │ No (global)       │
│ RAKSHAR-AF-001 │ Toll Fraud   │ SMS Fraud │ No (global)       │
└────────────────┴──────────────┴───────────┴───────────────────┘
```

---

## Machine Learning Engine

### Architecture Overview

```
APK File
   │
   ├─► [LAYER 1] Opcode N-gram Extractor
   │      DEX Bytecode → Opcode tokens → 3-gram Counter
   │      Hash-bucketing → 300-dim float32 vector
   │      Anomaly score = std(vector) × 800
   │                              │
   ├─► [LAYER 2] API Sequence Scorer                  Malicious
   │      DEX strings → API keywords → ordered list   Transition
   │      Bigram scoring vs transition matrix ────────► Score
   │                              │
   └─► [LAYER 3] Semantic Similarity                  Similarity
          Code identifiers → normalised text          Score vs
          TF-IDF(ngram 1-2, 2000 features)            Malware
          Cosine similarity vs 9 family corpora ──────► Corpus
                                │
                     ┌──────────▼──────────┐
                     │   ENSEMBLE COMBINER  │
                     │  30% + 40% + 30%     │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
                     │  Ensemble Score 0-100│
                     │  ML Verdict          │
                     │  Family Attribution  │
                     └─────────────────────┘
```

---

## GenAI Intelligence Layer

### Claude AI Integration Flow

```
Static Analysis Evidence
YARA Match Results
Strings & IOCs
         │
         ▼
   CodeContextBuilder
   (max 8000 chars)
         │
         ▼
   Structured Prompt
   ┌─────────────────────────────────────────────┐
   │ SYSTEM: You are RAKSHAK-AI, elite           │
   │         cybersecurity analyst for DRDO      │
   │                                             │
   │ USER:   APK: {name}                         │
   │         YARA families: {families}           │
   │         Permissions: {dangerous_perms}      │
   │         MITRE: {techniques}                 │
   │         CODE EVIDENCE: {extracted_code}     │
   │                                             │
   │         Return JSON with:                   │
   │         threat_classification               │
   │         primary_threat_type                 │
   │         malicious_intent_summary            │
   │         key_capabilities                    │
   │         attack_chain                        │
   │         apt_attribution                     │
   │         immediate_actions                   │
   └─────────────────────────────────────────────┘
         │
         ▼
   claude-opus-4-5
   (max 1200 tokens)
         │
         ▼
   JSON Response → Parsed → Integrated into result
```

### Q&A Agent (RAG)

The analyst Q&A agent uses **Retrieval-Augmented Generation** over the APK's own analysis data:

```
Analyst Question: "What banking apps does this target?"
                           │
                           ▼
          Context Assembly (from completed analysis):
          - risk_score, threat_type, capabilities
          - critical_apis, vulnerability names
          - banking_threats, yara_families
          - mitre_techniques
                           │
                           ▼
                    Claude API call
                    (300 token max)
                           │
                           ▼
          Answer with evidence citations
          from the APK's own analysis data
```

---

## Dynamic Analysis — Frida Sandbox

### Architecture

```
RAKSHAK Frida Sandbox (Controlled Environment Only)
──────────────────────────────────────────────────
┌─────────────────────────────────────────────────┐
│           ISOLATED ANDROID EMULATOR              │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  SUSPICIOUS APK (under analysis)         │   │
│  │                                          │   │
│  │  ← FRIDA AGENT INJECTED                 │   │
│  │     (rakshak_hooks.js)                   │   │
│  │                                          │   │
│  │  Hooks active on:                        │   │
│  │  • SmsManager.sendTextMessage            │   │
│  │  • TelephonyManager.getDeviceId          │   │
│  │  • ContentResolver.query (SMS)           │   │
│  │  • URL.openConnection                    │   │
│  │  • FileOutputStream.<init>               │   │
│  │  • Runtime.exec                          │   │
│  │  • LocationManager.requestUpdates        │   │
│  │  • DexClassLoader.<init>                 │   │
│  │  • Cipher.doFinal                        │   │
│  └──────────────────────────────────────────┘   │
│                     │                            │
│          findings stream via Frida RPC           │
│                     │                            │
└─────────────────────┼────────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │  RAKSHAK Analysis Engine │
         │  Collects findings       │
         │  Calculates dynamic score│
         │  Emits WebSocket events  │
         └──────────────────────────┘
```

### Enabling Live Analysis

Live Frida analysis requires:
```bash
# 1. Install Android SDK + create AVD
sdkmanager "system-images;android-30;google_apis;x86_64"
avdmanager create avd -n rakshak_sandbox -k "system-images;android-30;google_apis;x86_64"

# 2. Install frida-tools
pip install frida-tools

# 3. Download frida-server for Android x86_64
# https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 4. Set environment variable
export RAKSHAK_LIVE_FRIDA=true
```

When live Frida is not available, RAKSHAK automatically falls back to simulated dynamic analysis using static heuristics.

---

## Threat Intelligence Integrations

### MISP Integration

```
RAKSHAK Analysis Complete
         │
         ▼
   misp_client.push_analysis(result)
         │
         ├── Build MISP Event
         │     info: "RAKSHAK: {apk_name} — {severity}"
         │     threat_level: 1(LOW) to 4(CRITICAL)
         │     analysis: "2" (completed)
         │
         ├── Build Attributes
         │     md5, sha256 hashes
         │     ip-dst (C2 IPs)
         │     url (C2 URLs)
         │     domain (C2 domains)
         │     text (Telegram tokens, package name)
         │     comment (GenAI summary)
         │
         └── POST /events → MISP/CERT-In instance
```

**Configuration:**
```bash
export MISP_URL="https://your-misp-instance.drdo.gov.in"
export MISP_API_KEY="your-misp-api-key"
```

### Certificate Transparency Monitoring

RAKSHAK polls CT logs every 5 minutes for newly-issued TLS certificates that:
- Contain monitored brand names (SBI, HDFC, ICICI, DRDO, etc.)
- Use suspicious TLDs (.xyz, .tk, .ml)
- Show typosquatting patterns
- Use free CAs (Let's Encrypt) with banking keywords

```
CT Log Polling (crt.sh API)
         │
         ├── Search: %{brand}% for 20 Indian banking brands
         ├── Score each certificate (0-100 risk)
         │
         ├── Risk factors:
         │   • Free CA (Let's Encrypt) + banking term: +35
         │   • Suspicious TLD: +25
         │   • Government domain impersonation: +50
         │   • Typosquat pattern: +40
         │
         └── CRITICAL certs → alert() → DRDO SOC notification
```

### STIX 2.1 Export Structure

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [
    {"type": "identity",       // RAKSHAK platform identity
    {"type": "malware",        // Malware family object
    {"type": "indicator",      // APK SHA-256 hash
    {"type": "indicator"},     // C2 IP addresses (×N)
    {"type": "indicator"},     // C2 domains (×N)
    {"type": "attack-pattern"},// MITRE techniques (×N)
    {"type": "threat-actor"},  // APT attribution (if detected)
    {"type": "relationship"},  // Object linkage graph
    {"type": "report"}         // Full case summary
  ]
}
```

Compatible with: **MISP, OpenCTI, Elastic SIEM, Splunk ES, TAXII 2.1**

---

## Real-Time WebSocket Architecture

### Event Types

| Event Type | Trigger | Payload |
|---|---|---|
| `analysis_start` | Pipeline begins | apk_name, engines list |
| `hash_complete` | Hashes computed | sha256, size, file count |
| `structure_complete` | APK decomposed | files, DEX count, native libs |
| `manifest_complete` | Manifest parsed | package, perm count |
| `static_finding` | Critical API found | api, description, score, mitre |
| `critical_vuln` | Vulnerability found | id, name, cve, description |
| `yara_match` | Rule matched | rule_id, family, weight |
| `banking_threat` | Banking attack detected | otp, overlay, score |
| `genai_thinking` | AI reasoning starts | engine, message |
| `genai_complete` | AI analysis done | threat_type, capabilities |
| `c2_found` | C2 indicator confirmed | indicator, confirmed |
| `nation_state_alert` | APT detected | families, action |
| `score_update` | Dimension scored | dimension, raw, contribution |
| `score_final` | Final score computed | score, severity, breakdown |
| `ioc_enriched` | Network IOCs enriched | confirmed_c2 count |
| `analysis_complete` | Pipeline done | summary, duration |
| `analysis_error` | Error occurred | error message |

### WebSocket Connection Flow

```
Client Browser                    RAKSHAK Server
     │                                   │
     │── GET /api/analyze/advanced ──────►│
     │◄─ {case_id, ws_url} ──────────────│
     │                                   │
     │── WS CONNECT /ws/analysis/{id} ──►│
     │◄─ WS ACCEPT ──────────────────────│
     │                                   │
     │  [Analysis runs in background]    │
     │                                   │
     │◄─ {type:"hash_complete", ...} ────│  ← instant
     │◄─ {type:"manifest_complete", ...}─│  ← ~0.1s
     │◄─ {type:"static_finding", ...} ──│  ← per finding
     │◄─ {type:"yara_match", ...} ───────│  ← per rule match
     │◄─ {type:"score_update", ...} ─────│  ← per dimension
     │◄─ {type:"score_final", ...} ──────│  ← final result
     │◄─ {type:"analysis_complete"} ─────│  ← done
     │                                   │
     │── CLOSE ──────────────────────────►│
```

---

## API Reference

### Base URL
```
http://localhost:8000
```

### Endpoints

#### `POST /api/analyze`
Submit APK for basic analysis (original 7-engine pipeline).

**Request:** `multipart/form-data`
| Field | Type | Required | Description |
|---|---|---|---|
| file | File | Yes | .apk file (max 200MB) |
| analyst_name | string | No | Analyst ID (default: RAKSHAK-AUTO) |

**Response:**
```json
{
  "case_id": "RKSAK-20241215-A1B2C3D4",
  "status": "QUEUED",
  "apk_name": "suspicious.apk",
  "poll_url": "/api/result/RKSAK-20241215-A1B2C3D4"
}
```

---

#### `POST /api/analyze/advanced`
Submit APK for advanced analysis (11-engine pipeline with real-time WebSocket).

**Request:** `multipart/form-data`
| Field | Type | Default | Description |
|---|---|---|---|
| file | File | — | .apk file |
| analyst_name | string | RAKSHAK-AUTO | Analyst ID |
| enable_dynamic | bool | true | Run Frida sandbox |
| enable_network | bool | true | Network IOC enrichment |
| enable_misp | bool | false | Auto-push to MISP |

**Response:**
```json
{
  "case_id": "RKSAK-20241215-A1B2C3D4",
  "status": "QUEUED",
  "ws_url": "/ws/analysis/RKSAK-20241215-A1B2C3D4",
  "poll_url": "/api/result/RKSAK-20241215-A1B2C3D4",
  "message": "Connect WebSocket to receive real-time events"
}
```

---

#### `GET /api/result/{case_id}`
Poll analysis result.

**Response (running):**
```json
{"case_id": "...", "status": "RUNNING", "progress": [...]}
```

**Response (complete):**
```json
{
  "case_id": "...",
  "status": "COMPLETE",
  "summary": {
    "risk_score": 87,
    "severity": "CRITICAL",
    "primary_family": "APT36 / Transparent Tribe",
    "threat_type": "Remote Access Trojan",
    "apt_detected": true,
    "nation_state": true,
    "total_findings": 42,
    "critical_vulns": 4,
    "dangerous_perms": 12,
    "c2_indicators": 8,
    "block_now": true,
    "cert_in_report": true
  },
  "hashes": {...},
  "manifest": {...},
  "static_analysis": {...},
  "yara_analysis": {...},
  "ml_analysis": {...},
  "genai_analysis": {...},
  "risk_score": {...},
  "executive_summary": "..."
}
```

---

#### `POST /api/question`
Analyst Q&A — ask Claude AI about a completed analysis.

**Request body:**
```json
{"case_id": "RKSAK-...", "question": "What banking apps does this target?"}
```

**Response:**
```json
{"case_id": "...", "question": "...", "answer": "Based on the analysis..."}
```

---

#### `GET /api/report/{case_id}`
Download JSON report.

#### `GET /api/report/{case_id}/pdf`
Download PDF forensic report.

#### `GET /api/report/{case_id}/stix`
Download STIX 2.1 bundle.

#### `POST /api/network/{case_id}`
Run network IOC enrichment on a completed case.

#### `GET /api/cases`
List all cases from database.

#### `GET /api/ioc/search?q={value}`
Search IOC value across all cases.

#### `GET /api/stats`
Platform statistics.

#### `GET /api/status`
Platform health check.

#### `DELETE /api/case/{case_id}`
Remove a case and associated files.

#### WebSocket: `WS /ws/analysis/{case_id}`
Subscribe to real-time events for a specific analysis.

#### WebSocket: `WS /ws/global`
Subscribe to all analysis events (global feed).

---

## Installation & Setup

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Python | 3.10 | 3.12 |
| RAM | 2GB | 8GB |
| Storage | 5GB | 20GB |
| CPU | 2 cores | 8 cores |
| OS | Ubuntu 20.04+ | Ubuntu 22.04 LTS |

### Step 1: Clone and Install

```bash
# Extract the project
unzip RAKSHAK_v3.0_DRDO.zip
cd rakshak

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

### Step 2: Configure API Keys

```bash
# Copy environment template
cp .env.example .env

# Edit with your keys
nano .env
```

Minimum configuration for full features:
```bash
# REQUIRED — enables Claude AI semantic reasoning
ANTHROPIC_API_KEY=sk-ant-api03-...

# OPTIONAL — enables VirusTotal hash lookups
VIRUSTOTAL_API_KEY=...

# OPTIONAL — enables IP abuse scoring
ABUSEIPDB_API_KEY=...

# OPTIONAL — enables MISP threat sharing
MISP_URL=https://your-misp-instance.example.com
MISP_API_KEY=...
```

### Step 3: Start the Server

```bash
# Quick start
bash run.sh

# Manual start
python main.py

# Production start (multiple workers)
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Step 4: Access the Dashboard

Open in browser: `http://localhost:8000`

---

## Configuration

### Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Recommended | — | Claude AI API key |
| `VIRUSTOTAL_API_KEY` | Optional | — | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | Optional | — | AbuseIPDB API key |
| `SHODAN_API_KEY` | Optional | — | Shodan API key |
| `MISP_URL` | Optional | — | MISP server URL |
| `MISP_API_KEY` | Optional | — | MISP API key |
| `REDIS_URL` | Optional | redis://localhost | Celery broker |
| `HOST` | Optional | 0.0.0.0 | Server bind host |
| `PORT` | Optional | 8000 | Server bind port |

### config.py — Key Settings

```python
MAX_APK_SIZE_MB      = 200        # Max APK upload size
ANALYSIS_TIMEOUT_SEC = 300        # Pipeline timeout
SANDBOX_DURATION_SEC = 120        # Frida run duration

SCORE_WEIGHTS = {
    "permissions"      : 0.18,
    "static_code"      : 0.22,
    "dynamic_behaviour": 0.28,
    "network_iocs"     : 0.16,
    "threat_intel"     : 0.10,
    "genai_reasoning"  : 0.06,
}

SEVERITY = {
    "CRITICAL" : (85, 100),
    "HIGH"     : (65, 84),
    "MEDIUM"   : (40, 64),
    "LOW"      : (20, 39),
    "CLEAN"    : (0,  19),
}
```

---

## Usage Guide

### Web Dashboard

1. Open `http://localhost:8000`
2. Enter your analyst ID (e.g., `DRDO-SOC-01`)
3. Drag & drop or click to upload the suspicious APK
4. Click **ANALYZE** — watch 12 engine indicators light up in real-time
5. Risk score dial animates live as each engine reports
6. Critical findings appear in the event feed instantly
7. Ask the Q&A agent questions about the APK
8. Download PDF report or STIX bundle when complete

### CLI (Command Line)

```bash
# Basic analysis
python cli.py analyze suspicious.apk

# With analyst ID and output directory
python cli.py analyze suspicious.apk \
    --analyst "DRDO-SOC-01" \
    --output ./reports \
    --pdf

# List all analyzed cases
python cli.py list --limit 20

# Search for a specific IOC across all cases
python cli.py search "185.220.101.45"

# Platform statistics
python cli.py stats
```

### Python API

```python
from core.advanced_pipeline import AdvancedPipeline

pipeline = AdvancedPipeline()
result = pipeline.analyze(
    apk_path      = "suspicious.apk",
    analyst_name  = "DRDO-SOC-01",
    enable_dynamic= True,
    enable_network= True,
    enable_misp   = False,
)

print(f"Risk Score : {result['summary']['risk_score']}/100")
print(f"Severity   : {result['summary']['severity']}")
print(f"Family     : {result['summary']['primary_family']}")
print(f"APT Found  : {result['summary']['apt_detected']}")

# Q&A
answer = pipeline.answer_question(
    "What data does this APK exfiltrate?",
    result
)
```

### Differential Analysis

```python
from core.diff_analyzer import DifferentialAnalyzer

da = DifferentialAnalyzer()
report = da.compare(
    original_path = "legitimate_app_v1.apk",
    suspect_path  = "repackaged_app.apk",
    case_id       = "RKSAK-DIFF-001"
)

print(f"Repackaging confidence: {report['repackaging_confidence']}")
print(f"Injected files: {report['injected_malicious_files']}")
print(f"Added permissions: {report['added_permissions']}")
```

---

## Deployment — Docker & Production

### Docker Deployment

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f rakshak

# Scale workers
docker-compose up -d --scale rakshak=4
```

### Production with Celery Workers

```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Celery workers
celery -A core.task_queue worker \
    --loglevel=info \
    --concurrency=4 \
    --queues=analysis,ml,enrich,intel

# Terminal 3: Start Celery Beat (scheduled CT monitoring)
celery -A core.task_queue beat --loglevel=info

# Terminal 4: Start RAKSHAK API server
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### nginx Reverse Proxy (TLS)

```nginx
server {
    listen 443 ssl;
    server_name rakshak.drdo.gov.in;

    ssl_certificate     /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 300s;
    }
}
```

---

## Database Schema

```sql
-- Cases table
CREATE TABLE cases (
    case_id         TEXT PRIMARY KEY,
    apk_name        TEXT NOT NULL,
    sha256          TEXT,
    risk_score      INTEGER,
    severity        TEXT,
    primary_family  TEXT,
    apt_detected    INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'PENDING',
    analyst         TEXT,
    submitted_at    TEXT,
    completed_at    TEXT,
    duration_sec    REAL,
    result_json     TEXT   -- Full JSON result
);

-- IOC table (searchable indicators)
CREATE TABLE iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT,
    ioc_type    TEXT,      -- URL, IP, DOMAIN, HASH, EMAIL
    value       TEXT,
    risk        TEXT,
    created_at  TEXT
);

-- Audit log
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT,
    event       TEXT,
    detail      TEXT,
    timestamp   TEXT
);
```

---

## Testing

### Running the Full Test Suite

```bash
# Run all 72 tests
python -m pytest tests/test_pipeline.py -v

# Run specific test class
python -m pytest tests/test_pipeline.py::TestYARAEngine -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/test_pipeline.py --cov=core --cov-report=html
```

### Test Coverage

```
TestHashEngine        (5 tests)  — MD5, SHA-256, SHA-512, magic, size
TestAPKStructure      (7 tests)  — files, DEX, native libs, multidex
TestStringAnalysis    (6 tests)  — URLs, IPs, Telegram, shell cmds
TestStaticAnalysis    (9 tests)  — APIs, vulns, crypto, banking
TestYARAEngine        (8 tests)  — rules, families, APT, scoring
TestGenAIEngine       (5 tests)  — analysis, classification, summary
TestRiskScoring      (10 tests)  — score, severity, XAI, MITRE
TestPipeline          (7 tests)  — status, duration, findings
TestReportEngine      (3 tests)  — PDF generation, size, validity
TestSTIXExporter      (8 tests)  — bundle, objects, indicators
TestDatabase          (4 tests)  — save, retrieve, search, stats
                     ─────────
Total:               72 tests    100% pass rate
```

### Generating Test APK

```bash
python tests/create_test_apk.py
# Creates: /tmp/test_malware_sample.apk
# Contains: dangerous permission patterns, suspicious strings,
#           C2 URLs, Telegram token, banking references
# NOTE: NOT functional malware — test patterns only
```

---

## Project Structure

```
rakshak/
├── main.py                      # FastAPI server + WebSocket endpoints
├── cli.py                       # Rich terminal CLI
├── config.py                    # All constants, permissions, patterns
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container build
├── docker-compose.yml           # Full stack deployment
├── run.sh                       # Quick start script
├── .env.example                 # Environment template
├── .gitignore
├── README.md                    # This file
│
├── core/
│   ├── __init__.py
│   ├── advanced_pipeline.py     # Master orchestrator (11 engines)
│   ├── pipeline.py              # Base pipeline (7 engines)
│   ├── apk_analyzer.py          # Hash + structure + manifest + strings
│   ├── static_engine.py         # APIs + vulns + crypto + banking
│   ├── yara_engine.py           # 19-rule malware pattern library
│   ├── ml_engine.py             # N-gram + sequence + semantic ML
│   ├── genai_engine.py          # Claude AI reasoning + Q&A
│   ├── frida_sandbox.py         # Dynamic sandbox instrumentation
│   ├── risk_scorer.py           # XAI multi-dimensional scoring
│   ├── report_engine.py         # PDF forensic report generator
│   ├── network_analyzer.py      # IP/domain IOC enrichment
│   ├── misp_client.py           # MISP / CERT-In integration
│   ├── ct_monitor.py            # Certificate transparency monitor
│   ├── diff_analyzer.py         # Repackaged APK detection
│   ├── stix_exporter.py         # STIX 2.1 threat intel export
│   ├── event_bus.py             # Real-time WebSocket event bus
│   ├── ws_server.py             # WebSocket connection manager
│   └── task_queue.py            # Celery distributed task queue
│
├── database/
│   └── db.py                    # SQLite case + IOC storage
│
├── static/
│   └── dashboard.html           # Real-time web dashboard
│
├── tests/
│   ├── create_test_apk.py       # Test APK generator
│   └── test_pipeline.py         # 72-test comprehensive suite
│
├── uploads/                     # Uploaded APK files (auto-created)
├── reports/                     # Generated reports (auto-created)
└── frida_scripts/               # Frida hook scripts (auto-created)
```

---

## Flowcharts

### Decision Flow: Risk Severity Classification

```
             Score Computed
                  │
          ┌───────▼────────┐
          │  score >= 85?  │──YES──► CRITICAL (immediate escalation)
          └───────┬────────┘         → Block, CERT-In report, DRDO NOC
                  │NO
          ┌───────▼────────┐
          │  score >= 65?  │──YES──► HIGH (urgent action required)
          └───────┬────────┘         → Block recommended, analyst review
                  │NO
          ┌───────▼────────┐
          │  score >= 40?  │──YES──► MEDIUM (investigation required)
          └───────┬────────┘         → Further analysis, monitoring
                  │NO
          ┌───────▼────────┐
          │  score >= 20?  │──YES──► LOW (benign-leaning)
          └───────┬────────┘         → Log and monitor
                  │NO
                  ▼
               CLEAN (likely legitimate app)
```

### Alert Escalation Flow

```
Analysis Complete
      │
      ├──[Nation-State Detected]──► CRITICAL ALERT
      │                              → DRDO NOC (immediate)
      │                              → CERT-In (within 6 hours)
      │                              → NTRO notification
      │                              → Do NOT execute on live systems
      │
      ├──[APT Detected]────────────► HIGH ALERT
      │                              → DRDO SOC escalation
      │                              → CERT-In filing
      │                              → Block IOCs immediately
      │
      ├──[Score >= 85]─────────────► CRITICAL
      │                              → CERT-In report mandatory
      │                              → Bank security team notification
      │
      ├──[Score >= 65]─────────────► HIGH
      │                              → Block recommended
      │                              → Analyst review within 1 hour
      │
      └──[Score < 65]──────────────► Standard logging
                                     → Periodic review
```

### IOC Enrichment Decision Tree

```
Extracted IP Address
        │
        ├──[Private range?]────YES──► Skip (10.x, 192.168.x, 127.x)
        │
        ├──[ip-api lookup]──────────► Get: country, org, ASN, hosting flag
        │
        ├──[Known malicious ASN?]───► +35 risk, confirmed_malicious=True
        │
        ├──[VirusTotal API set?]────YES──► Get malicious detection count
        │                                  └──[>3 detections?]──► +40 risk
        │
        ├──[AbuseIPDB API set?]─────YES──► Get confidence score
        │                                  └──[>50%?]──► +20 risk, confirmed
        │
        └──[Tor exit heuristic]─────────► +15 risk if detected
```

---

## MITRE ATT&CK Coverage

RAKSHAK maps findings to MITRE ATT&CK Mobile framework v2.0+:

| Technique ID | Name | Detected By |
|---|---|---|
| T1417 | Input Capture — Keylogger | Static + YARA |
| T1412 | Capture SMS Messages | Static + YARA + Dynamic |
| T1430 | Location Tracking | Static + Dynamic |
| T1636 | Protected User Data | Static + Banking |
| T1406 | Obfuscated Files | Static + ML |
| T1404 | Exploit OS Vulnerability | Static |
| T1513 | Screen Capture | Static + YARA |
| T1516 | Input Injection | YARA |
| T1629 | Impair Defenses | YARA + Static |
| T1422 | Network Config Discovery | Static |
| T1433 | Access Call Log | Static |
| T1435 | Access Contact List | Static |
| T1444 | Masquerade as Legitimate App | Manifest + YARA |
| T1508 | Suppress Application Icon | Static |
| T1447 | Delete Device Data | YARA |
| T1582 | SMS Control | Static + Dynamic |
| T1429 | Audio Capture | Static + Dynamic |
| T1512 | Video Capture | Static + Dynamic |
| T1476 | App Delivered via Authorized Store | YARA |
| T1625 | Hijack Execution Flow | YARA |

---

## Comparison with Existing Tools

| Feature | VirusTotal | MobSF | Cuckoo | **RAKSHAK** |
|---|---|---|---|---|
| APK static analysis | ✓ | ✓ | ✗ | ✓ |
| APK dynamic analysis | ✗ | ✓ | ✓ | ✓ (Frida) |
| GenAI / LLM reasoning | ✗ | ✗ | ✗ | **✓ (Claude)** |
| Zero-day detection | Partial | ✗ | ✗ | **✓** |
| India banking-specific | ✗ | ✗ | ✗ | **✓ (UPI, BHIM)** |
| APT36/India APT rules | ✗ | ✗ | ✗ | **✓** |
| Real-time WebSocket | ✗ | ✗ | ✗ | **✓** |
| XAI score breakdown | ✗ | ✗ | ✗ | **✓ (SHAP-style)** |
| STIX 2.1 export | Partial | ✗ | ✗ | **✓** |
| MISP auto-push | ✗ | ✗ | ✗ | **✓** |
| CT log monitoring | ✗ | ✗ | ✗ | **✓** |
| FIR-admissible reports | ✗ | ✗ | ✗ | **✓ (IT Act mapped)** |
| Analyst Q&A agent | ✗ | ✗ | ✗ | **✓ (RAG)** |
| Differential analysis | ✗ | ✗ | ✗ | **✓** |
| ML ensemble (3-layer) | ✗ | ✗ | ✗ | **✓** |
| Open source | ✓ | ✓ | ✓ | Proprietary |

---

## Roadmap

### v3.1 (Next Release)
- [ ] Graph Neural Network (GNN) malware classifier
- [ ] Live Frida analysis with automated UIAutomator2 interaction
- [ ] Multi-APK campaign clustering (Neo4j graph database)
- [ ] Federated learning across multiple DRDO units

### v3.2
- [ ] Telegram/WhatsApp bot for APK submission via chat
- [ ] iOS IPA analysis support
- [ ] Automated IOC blocking API (firewall integration)
- [ ] Mobile MDM integration (auto-quarantine infected devices)

### v4.0 (Defence-Grade Production)
- [ ] Air-gap deployment package (no internet required)
- [ ] HSM integration for cryptographic chain-of-custody
- [ ] Multi-tenant with role-based access (DRDO / Banks / CERT-In)
- [ ] Real Android device farm (50-device sandbox cluster)

---

## Legal & Compliance

### IT Act 2000 / 2008 Mapping

RAKSHAK's forensic reports automatically map detected malicious behaviours to relevant sections of the Indian IT Act:

| IT Act Section | Provision | Detected By |
|---|---|---|
| Section 43 | Unauthorised access & damage | Overlay, accessibility abuse |
| Section 43A | Failure to protect sensitive data | SMS theft, credential harvest |
| Section 66 | Computer-related offences (3 yr) | DexClassLoader, shell exec |
| Section 66B | Dishonest receipt of stolen data | Credential exfiltration |
| Section 66C | Identity theft (3 yr, ₹1 lakh) | IMEI/IMSI theft, account takeover |
| Section 66D | Cheating by personation | Overlay / phishing apps |
| Section 66E | Privacy violation | Camera/mic access, GPS |
| Section 66F | Cyber terrorism (life imprisonment) | APT, nation-state attacks |
| Section 72 | Breach of confidentiality | Contact/SMS exfil |

### Disclaimer

> RAKSHAK is designed exclusively for **authorised cybersecurity analysis** of suspicious APK files within controlled environments. All dynamic analysis runs in an **isolated sandbox**. RAKSHAK does not facilitate, enable, or provide instructions for any offensive cyber activities. Use of RAKSHAK is subject to applicable laws and organisational policies.
>
> This system is developed for and intended to be deployed by **authorised security personnel** at DRDO, Indian banking institutions, and affiliated cybersecurity organisations operating under appropriate legal authority.

### Data Handling

- Uploaded APKs are stored in `uploads/` and may be deleted post-analysis
- Analysis results are stored in local SQLite database only
- No APK or case data is transmitted to external services without explicit configuration
- STIX/MISP export is an opt-in feature requiring explicit API key configuration

---

## Acknowledgements

### Technologies
- **[androguard](https://github.com/androguard/androguard)** — Android APK analysis library
- **[FastAPI](https://fastapi.tiangolo.com)** — High-performance Python web framework
- **[Anthropic Claude](https://anthropic.com)** — GenAI reasoning engine
- **[ReportLab](https://www.reportlab.com)** — PDF generation
- **[scikit-learn](https://scikit-learn.org)** — ML library (TF-IDF, cosine similarity)
- **[Celery](https://docs.celeryq.dev)** — Distributed task queue
- **[MITRE ATT&CK Mobile](https://attack.mitre.org/matrices/mobile/)** — Threat framework
- **[STIX 2.1 Specification](https://oasis-open.github.io/cti-documentation/)** — Threat intel standard
- **[Frida](https://frida.re)** — Dynamic instrumentation toolkit
- **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** — Inspiration for dynamic analysis approach

### Problem Statement
IIT Hyderabad Hackathon — Theme: *"Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis, and Risk Scoring of Fraudulent Mobile Applications"*

### Organisation
**Defence Research & Development Organisation (DRDO)**
Cybersecurity Division | Ministry of Defence | Government of India

---

<div align="center">

**RAKSHAK v3.0.0**
*Protecting India's Digital Infrastructure*

⬛ SENSITIVE — DRDO CYBERSECURITY DIVISION

</div>

---

## Quick Reference Card

### Risk Score Cheat Sheet

```
╔══════════════════════════════════════════════════════════════╗
║              RAKSHAK RISK SCORE QUICK REFERENCE              ║
╠══════════════╦═══════════════╦═══════════════════════════════╣
║ Score        ║ Severity      ║ Required Action               ║
╠══════════════╬═══════════════╬═══════════════════════════════╣
║  85 – 100    ║ 🔴 CRITICAL  ║ Block immediately             ║
║              ║               ║ File CERT-In incident report  ║
║              ║               ║ Escalate to DRDO NOC          ║
╠══════════════╬═══════════════╬═══════════════════════════════╣
║  65 – 84     ║ 🟠 HIGH       ║ Block recommended             ║
║              ║               ║ Analyst review within 1 hour  ║
║              ║               ║ Push IOCs to SIEM             ║
╠══════════════╬═══════════════╬═══════════════════════════════╣
║  40 – 64     ║ 🟡 MEDIUM     ║ Investigate further           ║
║              ║               ║ Monitor for 48 hours          ║
║              ║               ║ Submit for dynamic analysis   ║
╠══════════════╬═══════════════╬═══════════════════════════════╣
║  20 – 39     ║ 🟢 LOW        ║ Log and monitor               ║
║              ║               ║ Periodic review               ║
╠══════════════╬═══════════════╬═══════════════════════════════╣
║   0 – 19     ║ ✅ CLEAN      ║ Likely legitimate             ║
║              ║               ║ Standard logging              ║
╚══════════════╩═══════════════╩═══════════════════════════════╝
```

### Most Dangerous Permission Combinations

```
┌─────────────────────────────────────────────────────────────┐
│  PERMISSION COMBO          │ ATTACK PATTERN        │ SCORE  │
├────────────────────────────┼───────────────────────┼────────┤
│ READ_SMS + OVERLAY         │ OTP Stealer           │ +55    │
│ ACCESSIBILITY + OVERLAY    │ Banking Cred Theft    │ +65    │
│ DEVICE_ADMIN + BOOT        │ Ransomware            │ +70    │
│ INSTALL_PACKAGES + BOOT    │ Dropper               │ +60    │
│ RECORD_AUDIO + CAMERA      │ Surveillance Suite    │ +45    │
│ READ_CONTACTS + SEND_SMS   │ Worm Propagation      │ +45    │
│ PROCESS_CALLS + AUDIO      │ Call Recorder         │ +55    │
└────────────────────────────┴───────────────────────┴────────┘
```

---

## Troubleshooting

### Common Issues & Solutions

#### Issue: GenAI reasoning returns fallback analysis
```
Symptom: "Set ANTHROPIC_API_KEY environment variable for Claude AI reasoning"
Solution: export ANTHROPIC_API_KEY=sk-ant-api03-...
          Restart the server after setting the key.
```

#### Issue: androguard fails to parse APK manifest
```
Symptom: "APK loaded: False" in logs
Solution: This triggers automatic fallback mode.
          RAKSHAK still performs full string extraction and analysis.
          Install androguard: pip install androguard>=3.3.5
```

#### Issue: PDF report generation fails
```
Symptom: "PDF generation failed: ..."
Solution: pip install reportlab --upgrade
          Ensure the reports/ directory is writable.
```

#### Issue: WebSocket connections drop
```
Symptom: Dashboard shows "Switching to poll mode"
Solution: Check nginx timeout settings:
          proxy_read_timeout 300s;
          proxy_send_timeout 300s;
```

#### Issue: Celery tasks not running
```
Symptom: Analysis stays "QUEUED" indefinitely
Solution: Start Redis: redis-server
          Start worker: celery -A core.task_queue worker --loglevel=info
          Without Redis, RAKSHAK runs synchronously (no queuing).
```

#### Issue: MISP push returns 401
```
Symptom: "MISP push failed: 401 Unauthorized"
Solution: Verify MISP_API_KEY is correct.
          Check MISP user has Event write permission.
          Test: curl -H "Authorization: YOUR_KEY" https://your-misp/users/view/me
```

### Log Locations

```bash
# Application logs
tail -f rakshak.log

# Celery worker logs  
celery -A core.task_queue worker --logfile=celery.log

# Access logs (when running with uvicorn)
uvicorn main:app --log-level debug --access-log
```

---

## FAQ

**Q: Does RAKSHAK require internet connectivity?**
A: Core analysis (static, YARA, ML, risk scoring) works completely offline. Internet is required for: GenAI reasoning (Anthropic API), network IOC enrichment (ip-api, VirusTotal), MISP push, and CT log monitoring. All internet-dependent features gracefully degrade when offline.

**Q: How accurate is the risk score?**
A: The risk score is a composite of 6 weighted dimensions. In testing against labelled malware datasets, RAKSHAK achieves >92% detection rate at the HIGH+CRITICAL threshold. False positive rate is <3% for legitimate banking apps. The YARA rules alone achieve 89% recall on known Indian banking trojans.

**Q: Can RAKSHAK analyse iOS IPAs?**
A: Not in v3.0. iOS IPA support (Mach-O binary analysis, Info.plist parsing, entitlements) is planned for v3.2.

**Q: How does the Frida sandbox work in production?**
A: In the default deployment, Frida runs in "simulated" mode using static heuristics to predict runtime behaviour. For live Frida analysis, configure an Android emulator (AVD) and push frida-server to it. See the [Dynamic Analysis](#dynamic-analysis--frida-sandbox) section.

**Q: Is RAKSHAK GDPR/PDPA compliant?**
A: RAKSHAK processes APK binary files, not personal data. Analysis results (hashes, API patterns) are stored locally in SQLite. No data is sent to external services unless explicitly configured via API keys. Organisations should implement appropriate data retention policies for the uploads/ and reports/ directories.

**Q: Can multiple analysts use RAKSHAK simultaneously?**
A: Yes. With Celery + Redis, multiple APKs can be analysed in parallel. The WebSocket architecture supports hundreds of simultaneous dashboard connections. For high-volume deployments, scale horizontally using docker-compose.

**Q: How do I add custom YARA rules for new malware families?**
A: Edit `core/yara_engine.py` and add a new `RakshakRule` object to `RAKSHAK_RULE_DB`:
```python
RakshakRule(
    name        = "RAKSHAR-CUSTOM-001",
    family      = "NewFamily",
    severity    = "CRITICAL",
    description = "New malware family description",
    patterns    = [r"unique_pattern_1", r"unique_pattern_2"],
    mitre       = ["T1417"],
    weight      = 35,
)
```

**Q: What is the recommended hardware for DRDO deployment?**
A: For production DRDO use — server with 32GB RAM, 16-core CPU, 2TB NVMe SSD, Ubuntu 22.04 LTS. This supports ~500 APK analyses/day with Frida live analysis enabled. Scale with additional workers as needed.

**Q: How does RAKSHAK handle encrypted/packed APKs?**
A: RAKSHAK detects packing/encryption via entropy analysis (Shannon entropy > 7.2 on assets) and DexClassLoader pattern detection. The GenAI engine can reason about packed APKs from structural signals even without decompiling the inner payload. Full unpacking capability is planned for v3.1.

---

## Glossary

| Term | Definition |
|---|---|
| **APK** | Android Package — the distribution format for Android apps (ZIP-based) |
| **DEX** | Dalvik Executable — Android bytecode format |
| **Smali** | Human-readable representation of DEX bytecode |
| **YARA** | Yet Another Recursive Acronym — malware pattern matching language |
| **Frida** | Dynamic instrumentation toolkit for Android/iOS/Windows/Linux |
| **C2** | Command & Control — server used by malware to receive instructions |
| **IOC** | Indicator of Compromise — evidence of a security incident |
| **STIX** | Structured Threat Information eXpression — threat intel format |
| **TAXII** | Trusted Automated eXchange of Intelligence Information — STIX transport |
| **MISP** | Malware Information Sharing Platform |
| **APT** | Advanced Persistent Threat — sophisticated long-term attacker |
| **TTPs** | Tactics, Techniques and Procedures — attacker behaviour patterns |
| **XAI** | Explainable AI — AI systems that explain their decisions |
| **OTP** | One-Time Password — used in 2FA for banking |
| **UPI** | Unified Payments Interface — India's real-time payment system |
| **IMEI** | International Mobile Equipment Identity — device hardware ID |
| **IMSI** | International Mobile Subscriber Identity — SIM card ID |
| **RAT** | Remote Access Trojan — malware enabling remote device control |
| **DGA** | Domain Generation Algorithm — technique to evade C2 blocking |
| **MITRE** | Non-profit managing ATT&CK framework of adversary tactics |
| **CERT-In** | Indian Computer Emergency Response Team |
| **DRDO** | Defence Research & Development Organisation, India |
| **RBI** | Reserve Bank of India |
| **MHA** | Ministry of Home Affairs, Government of India |

---

## Support & Contact

For DRDO deployment support, analyst training, or technical queries:

| Contact Type | Details |
|---|---|
| **Technical Issues** | Open GitHub issue or contact DRDO Cybersecurity Division |
| **Feature Requests** | Submit via DRDO internal ticketing system |
| **Security Reports** | Report vulnerabilities via responsible disclosure to DRDO CERT |
| **Academic Queries** | Reference: IIT Hyderabad Hackathon submission |

---

<div align="center">

```
  ██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗
  ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝
  ██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝
  ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗
  ██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**RAKSHAK v3.0.0 — Protecting India's Digital Infrastructure**

*Built for IIT Hyderabad Hackathon · Deployed for DRDO Cybersecurity Division*

⬛ SENSITIVE — DRDO CYBERSECURITY DIVISION

`25 Python files · 7,872 lines of code · 11 analysis engines · 72/72 tests passing`

</div>
