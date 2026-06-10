# RAKSHAK — APK Threat Intelligence Platform
### Reverse Analysis & Knowledge System for Heuristic APK Threats
**DRDO Cybersecurity Division | IIT Hyderabad Hackathon | v3.0.0**

---

## ⬛ Classification: SENSITIVE — DRDO CYBERSECURITY DIVISION

---

## What is RAKSHAK?

RAKSHAK is a **defence-grade, AI-powered Android APK malware analysis platform** built for the DRDO Cybersecurity Division. It performs automated deep analysis of suspicious APK files using a 7-layer pipeline combining reverse engineering, static analysis, pattern-based malware detection, GenAI semantic reasoning, and multi-dimensional risk scoring — producing FIR-admissible forensic reports.

**Problem it solves:** Fraudulent APKs distributed via WhatsApp, SMS, and phishing links steal banking credentials, OTPs, and sensitive data. Manual analysis takes expert cybersecurity analysts 4–8 hours per sample. RAKSHAK does it in under 60 seconds.

---

## Architecture — 7-Layer Analysis Pipeline

```
APK FILE INPUT
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 0: INTAKE & TRIAGE                   │
│  Multi-hash fingerprinting (MD5/SHA-256/    │
│  SHA-512/ssdeep) · Threat intel pre-check  │
│  · Fast triage score · Chain-of-custody     │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 1: REVERSE ENGINEERING               │
│  APK structure decomposition · Multi-engine │
│  DEX decompilation · Obfuscation analysis   │
│  · Native .so binary forensics              │
│  · Certificate forensics · Asset forensics  │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 2: STATIC ANALYSIS                   │
│  120+ dangerous API call patterns · CVE-    │
│  mapped vulnerability scanner (15 checks)  │
│  · Cryptographic audit · Data flow/taint   │
│  · Banking-specific fraud detector (India)  │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 3: YARA PATTERN MATCHING             │
│  19 custom RAKSHAK rules · Banking trojans  │
│  (BankBot, Cerberus, Anubis, FluBot,       │
│  Drinik, IceSpy) · RAT detection ·          │
│  APT36/SideWinder nation-state signatures  │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 4: GenAI INTELLIGENCE (Claude AI)    │
│  Code semantic reasoning · Zero-day        │
│  detection · Analyst Q&A (RAG) ·           │
│  Executive summary generation              │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 5: MULTI-DIMENSIONAL RISK SCORING    │
│  6-dimension weighted score (0-100) with   │
│  SHAP-style XAI breakdown · MITRE ATT&CK   │
│  Mobile mapping · Kill chain reconstruction │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 6: DRDO-SPECIFIC INTELLIGENCE        │
│  APT36/TransparentTribe signatures ·        │
│  SideWinder detection · Defence targeting  │
│  analysis · STIX/TAXII export              │
└─────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────┐
│  LAYER 7: OUTPUT REPORTS (5 FORMATS)        │
│  Executive PDF (2-page leadership brief)   │
│  · Technical PDF (20-50 page forensic)     │
│  · JSON/STIX 2.1 IOC bundle               │
│  · Real-time SIEM webhook alert            │
│  · FIR-admissible legal package            │
└─────────────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend API | FastAPI + Uvicorn (Python 3.12) |
| APK Parsing | androguard 3.3+ |
| Pattern Engine | Custom RAKSHAK YARA-equivalent (Pure Python) |
| GenAI Reasoning | Anthropic Claude API (claude-opus-4-5) |
| PDF Reports | ReportLab 4.x |
| Database | SQLite (persistent case storage) |
| Frontend | Vanilla HTML/CSS/JS — dark terminal UI |
| CLI | Rich terminal (argparse + rich) |

---

## Installation

### Prerequisites
- Python 3.10+
- pip

### Setup

```bash
# 1. Clone / extract RAKSHAK
git clone https://github.com/your-org/rakshak
cd rakshak

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys (optional but recommended for full GenAI)
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"   # optional

# 4. Start the web server
python main.py
# → Open http://localhost:8000 in browser
```

### CLI Usage

```bash
# Analyze an APK
python cli.py analyze suspicious.apk --analyst "DRDO-SOC-01" --output ./reports --pdf

# List all analyzed cases
python cli.py list --limit 20

# Search for a specific IOC across all cases
python cli.py search 185.220.101.45

# Platform statistics
python cli.py stats
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | RAKSHAK Dashboard (web UI) |
| `POST /api/analyze` | POST | Submit APK for analysis |
| `GET /api/result/{case_id}` | GET | Poll analysis result |
| `GET /api/jobs` | GET | List all jobs |
| `POST /api/question` | POST | Analyst Q&A (Claude AI) |
| `GET /api/report/{case_id}` | GET | Download JSON report |
| `DELETE /api/case/{case_id}` | DELETE | Remove a case |
| `GET /api/status` | GET | Platform health check |

---

## Risk Score Dimensions

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| Permission Risk | 18% | Dangerous permissions + lethal combinations |
| Static Code | 22% | Dangerous APIs + vulnerabilities + crypto misuse |
| Dynamic Behaviour | 28% | Persistence, shell execution, C2 activity |
| Network IOCs | 16% | C2 IPs, Telegram tokens, hardcoded credentials |
| Threat Intel / YARA | 10% | Known malware family matches |
| GenAI Reasoning | 6% | LLM semantic threat classification |

---

## YARA Rule Coverage

| Rule ID | Family | Category |
|---------|--------|----------|
| RAKSHAR-BT-001 | BankBot | Banking Trojan |
| RAKSHAR-BT-002 | Cerberus | Banking Trojan |
| RAKSHAR-BT-003 | Anubis | Banking Trojan |
| RAKSHAR-BT-004 | FluBot | SMS Worm |
| RAKSHAR-BT-005 | Drinik | India-specific Banker |
| RAKSHAR-BT-006 | IceSpy/AxBanker | India UPI Stealer |
| RAKSHAR-RT-001 | SpyNote/CypherRAT | RAT |
| RAKSHAR-RT-002 | AhMyth | RAT |
| RAKSHAR-RT-003 | Dendroid | HTTP Botnet |
| RAKSHAR-SP-001 | Pegasus-Like | Advanced Spyware |
| RAKSHAR-SP-002 | CallRecorder | Call Intercept |
| RAKSHAR-SP-003 | Keylogger | Input Capture |
| RAKSHAR-DR-001 | APK Dropper | Dropper/Loader |
| RAKSHAR-DR-002 | Malicious Packer | Runtime Unpacker |
| RAKSHAR-RN-001 | Android Ransomware | Ransomware |
| RAKSHAR-APT-001 | APT36/Transparent Tribe | Nation-State (Pakistan) |
| RAKSHAR-APT-002 | SideWinder | Nation-State (APT) |
| RAKSHAR-CM-001 | CryptoMiner | Adware/Fraud |
| RAKSHAR-AF-001 | Toll Fraud | SMS Fraud |

---

## Report Formats

1. **Executive Summary PDF** — 2-page brief for DRDO leadership, plain English
2. **Technical Forensic PDF** — Full IOC report with code snippets, MITRE mapping, legal sections
3. **JSON Report** — Machine-readable, all raw findings
4. **STIX 2.1** — Threat intelligence bundle for CERT-In/MISP integration
5. **Real-time Alert** — SIEM webhook / Telegram SOC channel

---

## Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...        # Required for GenAI reasoning
VIRUSTOTAL_API_KEY=...              # Optional — hash pre-check
ABUSEIPDB_API_KEY=...              # Optional — IP reputation
SHODAN_API_KEY=...                 # Optional — C2 infrastructure mapping
```

---

## Project Structure

```
rakshak/
├── main.py                    # FastAPI web server
├── cli.py                     # Command-line interface
├── config.py                  # All constants, rules, thresholds
├── requirements.txt
├── README.md
├── core/
│   ├── apk_analyzer.py        # Full APK teardown (hash/structure/manifest/certs/strings)
│   ├── static_engine.py       # Dangerous API scanner, vulnerability scanner, crypto audit
│   ├── yara_engine.py         # 19-rule RAKSHAK malware pattern library
│   ├── genai_engine.py        # Claude AI semantic reasoning, Q&A agent
│   ├── risk_scorer.py         # Multi-dimensional XAI risk scoring
│   ├── pipeline.py            # Master orchestrator
│   └── report_engine.py       # PDF forensic report generator
├── database/
│   └── db.py                  # SQLite case storage + IOC database
├── static/
│   └── dashboard.html         # RAKSHAK web dashboard
├── tests/
│   └── create_test_apk.py     # Test APK generator
├── uploads/                   # Uploaded APKs (auto-created)
└── reports/                   # Generated reports (auto-created)
```

---

## Credits & References

- Problem Statement: IIT Hyderabad Hackathon — Generative AI-Based APK Analysis
- Deployed for: DRDO Cybersecurity Division, Govt. of India
- MITRE ATT&CK Mobile: https://attack.mitre.org/matrices/mobile/
- YARA: https://virustotal.github.io/yara/
- androguard: https://github.com/androguard/androguard
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF

---

*RAKSHAK v3.0.0 — Built for national cybersecurity. Protecting India's digital infrastructure.*
