"""
RAKSHAK — GenAI Intelligence Engine
Claude-powered code semantic reasoning, threat summarization, analyst Q&A
"""

import os, json, re, zipfile
from typing import Any
import requests
from config import (
    ANTHROPIC_API_KEY, GEMINI_API_KEY, GEMINI_MODEL,
    PLATFORM_NAME, MITRE_TECHNIQUES
)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# CODE CONTEXT BUILDER — feeds relevant code to LLM
# ══════════════════════════════════════════════════════════════════════════════
class CodeContextBuilder:
    """Extracts the most suspicious/relevant code sections for LLM analysis"""

    MAX_CHARS = 8000  # Keep prompt manageable

    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def build_context(self, static_results: dict, strings_results: dict) -> str:
        sections = []

        # Critical API findings
        api_findings = static_results.get("api_analysis", {}).get("findings", [])
        if api_findings:
            critical = [f for f in api_findings if f["severity"] == "CRITICAL"]
            sections.append("=== CRITICAL API CALLS FOUND ===")
            for f in critical[:6]:
                sections.append(f"- {f['api']}: {f['description']}")
                for sample in f.get("sample_calls", [])[:2]:
                    sections.append(f"  CODE: {sample[:100]}")

        # Vulnerability findings
        vulns = static_results.get("vulnerabilities", {}).get("findings", [])
        if vulns:
            sections.append("\n=== VULNERABILITIES ===")
            for v in vulns[:5]:
                sections.append(f"- [{v['severity']}] {v['name']}: {v['description']}")

        # Suspicious strings
        urls = strings_results.get("urls", [])[:5]
        ips  = strings_results.get("ips", [])[:5]
        if urls or ips:
            sections.append("\n=== NETWORK INDICATORS ===")
            for u in urls:
                sections.append(f"- URL [{u.get('risk','?')}]: {u.get('url','')[:80]}")
            for ip in ips:
                sections.append(f"- IP: {ip.get('ip','')} — {ip.get('type','')}")

        # Shell commands
        cmds = strings_results.get("shell_commands", [])[:5]
        if cmds:
            sections.append("\n=== SHELL COMMANDS ===")
            for c in cmds:
                sections.append(f"- {c[:100]}")

        # Banking threats
        banking = static_results.get("banking_threats", {})
        if banking.get("otp_harvesting"):
            sections.append("\n=== BANKING THREAT INDICATORS ===")
            sections.append("- OTP Harvesting capability detected")
        if banking.get("overlay_attack"):
            sections.append("- Overlay attack (fake banking screen) capability")
        if banking.get("upi_fraud_indicators"):
            sections.append(f"- UPI fraud terms: {', '.join(banking['upi_fraud_indicators'][:5])}")

        # Obfuscation
        obf = static_results.get("api_analysis", {}).get("obfuscation_signals", [])
        if obf:
            sections.append("\n=== OBFUSCATION ===")
            for o in obf[:3]:
                sections.append(f"- {o['type']}: {o['evidence']}")

        # Raw code samples from DEX
        sections.append("\n=== RAW CODE SAMPLES ===")
        sections.append(self._extract_suspicious_code_sample())

        full = "\n".join(sections)
        return full[:self.MAX_CHARS]

    def _extract_suspicious_code_sample(self) -> str:
        """Pull raw printable strings from DEX for LLM context"""
        sample = []
        SUSPICIOUS_KEYWORDS = [
            b"sms", b"otp", b"password", b"bank", b"credit",
            b"overlay", b"accessibility", b"admin", b"root",
            b"shell", b"exec", b"inject", b"stealth", b"encrypt"
        ]
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex") and len(sample) < 30:
                        data = zf.read(name)
                        strings = re.findall(b'[\x20-\x7e]{8,}', data)
                        for s in strings:
                            sl = s.lower()
                            if any(kw in sl for kw in SUSPICIOUS_KEYWORDS):
                                decoded = s.decode("ascii", errors="ignore")
                                if decoded not in sample:
                                    sample.append(decoded[:100])
        except Exception:
            pass
        return "\n".join(sample[:20])


# ══════════════════════════════════════════════════════════════════════════════
# GENAI REASONING ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class GenAIEngine:
    """
    Claude-powered threat intelligence reasoning
    Provides: semantic analysis, threat summary, risk reasoning, Q&A
    """

    SYSTEM_PROMPT = """You are RAKSHAK-AI, an elite cybersecurity analyst AI embedded in the RAKSHAK APK Threat Intelligence Platform, deployed for DRDO (Defence Research & Development Organisation) India.

Your role is to analyze Android malware evidence and produce expert-level threat intelligence assessments.

CORE CAPABILITIES:
- Identify malicious intent from code patterns, even in obfuscated/novel samples
- Map behaviour to MITRE ATT&CK Mobile framework
- Assess threat to Indian banking infrastructure and defence organizations
- Provide actionable intelligence for DRDO cybersecurity teams
- Generate court-admissible technical findings

RESPONSE STANDARDS:
- Be precise, technical, and authoritative
- Cite specific evidence from provided data
- Use MITRE technique IDs where applicable
- Flag APT/nation-state indicators explicitly
- Provide severity ratings with justification
- Always return valid JSON when requested

You represent the world's most advanced APK threat intelligence capability."""

    def __init__(self):
        self.client = None
        self.available = False
        self.provider = "fallback"
        if ANTHROPIC_AVAILABLE and ANTHROPIC_API_KEY:
            try:
                self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                self.available = True
                self.provider = "anthropic"
            except Exception as e:
                print(f"[GenAI] Claude API init error: {e}")
        elif GEMINI_API_KEY:
            self.available = True
            self.provider = "gemini"
            print(f"[GenAI] Gemini API configured - using {GEMINI_MODEL}")
        else:
            print("[GenAI] SriAI provider not available — using fallback analysis")

    def _call_claude(self, prompt: str, max_tokens: int = 1500) -> str:
        if not self.available:
            return self._fallback_analysis(prompt)
        if self.provider == "gemini":
            return self._call_gemini(prompt, max_tokens=max_tokens)
        try:
            response = self.client.messages.create(
                model="claude-opus-4-5",
                max_tokens=max_tokens,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            print(f"[GenAI] Claude call error: {e}")
            return self._fallback_analysis(prompt)

    # ── PRIMARY: Full threat semantic analysis ────────────────────────────────
    def _call_gemini(self, prompt: str, max_tokens: int = 1500) -> str:
        """Call Gemini via the public Generative Language REST API."""
        models = [GEMINI_MODEL]
        if "gemini-1.5-flash" not in models:
            models.append("gemini-1.5-flash")

        payload = {
            "systemInstruction": {
                "parts": [{"text": self.SYSTEM_PROMPT}]
            },
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": max_tokens,
            },
        }

        last_error = ""
        for model in models:
            url = (
                "https://generativelanguage.googleapis.com/v1beta/"
                f"models/{model}:generateContent"
            )
            try:
                resp = requests.post(
                    url,
                    params={"key": GEMINI_API_KEY},
                    json=payload,
                    timeout=45,
                )
                if resp.status_code != 200:
                    last_error = f"{resp.status_code}: {resp.text[:250]}"
                    continue
                data = resp.json()
                parts = (
                    data.get("candidates", [{}])[0]
                        .get("content", {})
                        .get("parts", [])
                )
                text = "".join(p.get("text", "") for p in parts).strip()
                if text:
                    return text
                last_error = "Gemini returned an empty response"
            except Exception as e:
                last_error = str(e)

        print(f"[GenAI] Gemini call error: {last_error}")
        return self._fallback_analysis(prompt)

    def analyze_threat(self, apk_name: str, code_context: str,
                       manifest: dict, yara_results: dict) -> dict:
        perms = [p["permission"].split(".")[-1]
                 for p in manifest.get("dangerous_permissions", [])]
        families = yara_results.get("malware_families", [])
        mitre    = yara_results.get("mitre_techniques", [])

        prompt = f"""ANALYZE THIS ANDROID APK SAMPLE FOR DRDO CYBERSECURITY DIVISION

APK: {apk_name}
DETECTED MALWARE FAMILIES: {', '.join(families) or 'Unknown'}
DANGEROUS PERMISSIONS: {', '.join(perms[:15])}
MITRE ATT&CK TECHNIQUES: {', '.join(mitre[:10])}
NATION-STATE THREAT: {yara_results.get('nation_state_threat', False)}
APT DETECTED: {yara_results.get('apt_detected', False)}

CODE EVIDENCE:
{code_context}

Provide your analysis as a JSON object with exactly these fields:
{{
  "threat_classification": "CRITICAL|HIGH|MEDIUM|LOW",
  "primary_threat_type": "Banking Trojan|RAT|Spyware|Dropper|Ransomware|APT|Unknown",
  "malicious_intent_summary": "2-3 sentence summary of what this APK actually does",
  "key_capabilities": ["capability1", "capability2", ...],
  "target_victims": "Who this targets specifically",
  "attack_chain": ["Step 1 of attack", "Step 2", ...],
  "data_at_risk": ["SMS/OTP", "Banking credentials", ...],
  "apt_attribution": "nation-state group if detected or None",
  "zero_day_indicators": "any novel/unknown patterns",
  "immediate_actions": ["Action 1 for DRDO team", "Action 2", ...],
  "intelligence_confidence": "HIGH|MEDIUM|LOW",
  "analyst_notes": "Additional expert observations"
}}

Return ONLY the JSON object, no other text."""

        raw = self._call_claude(prompt, max_tokens=1200)
        return self._parse_json_response(raw, {
            "threat_classification"  : "HIGH",
            "primary_threat_type"    : "Unknown",
            "malicious_intent_summary": "Analysis inconclusive — manual review required",
            "key_capabilities"       : [],
            "target_victims"         : "Unknown",
            "attack_chain"           : [],
            "data_at_risk"           : [],
            "apt_attribution"        : None,
            "zero_day_indicators"    : "None detected",
            "immediate_actions"      : ["Submit for manual expert review"],
            "intelligence_confidence": "LOW",
            "analyst_notes"          : raw[:500] if raw else "No analysis available",
        })

    # ── EXECUTIVE SUMMARY (for DRDO leadership) ───────────────────────────────
    def generate_executive_summary(self, apk_name: str, risk_score: int,
                                   threat_analysis: dict, banking: dict) -> str:
        if not self.available:
            return self._local_executive_summary(apk_name, risk_score, threat_analysis, banking)

        classification = threat_analysis.get("threat_classification", "HIGH")
        capabilities   = threat_analysis.get("key_capabilities", [])
        actions        = threat_analysis.get("immediate_actions", [])

        prompt = f"""Write a 3-paragraph executive summary for DRDO leadership about this APK threat.

APK NAME: {apk_name}
RISK SCORE: {risk_score}/100 ({classification})
THREAT TYPE: {threat_analysis.get('primary_threat_type', 'Unknown')}
CAPABILITIES: {', '.join(capabilities[:5])}
BANKING THREAT: {'YES — OTP harvesting detected' if banking.get('otp_harvesting') else 'No specific banking threat'}
IMMEDIATE ACTIONS: {', '.join(actions[:3])}

Write in clear, non-technical language suitable for senior DRDO officials.
Paragraph 1: What this threat is and who is at risk
Paragraph 2: What the malware can do (capabilities in plain English)
Paragraph 3: Recommended immediate actions

Keep total length under 200 words. Use assertive, clear language. No bullet points."""

        summary = self._call_claude(prompt, max_tokens=400)
        try:
            parsed = json.loads(summary)
            if isinstance(parsed, dict):
                return self._local_executive_summary(apk_name, risk_score, threat_analysis, banking)
        except Exception:
            pass
        return summary

    def _local_executive_summary(self, apk_name: str, risk_score: int,
                                 threat_analysis: dict, banking: dict) -> str:
        threat_type = threat_analysis.get("primary_threat_type", "Suspicious APK requiring analyst review")
        classification = threat_analysis.get("threat_classification", "UNKNOWN")
        victims = threat_analysis.get("target_victims", "mobile users and financial customers")
        capabilities = threat_analysis.get("key_capabilities", []) or ["suspicious static and malware-family indicators"]
        actions = [
            a for a in threat_analysis.get("immediate_actions", [])
            if "GEMINI_API_KEY" not in a and "ANTHROPIC_API_KEY" not in a
        ] or ["quarantine the APK", "preserve the sample and report", "review extracted IOCs"]
        banking_note = " Banking-fraud markers were detected." if banking.get("banking_risk_score", 0) > 0 else ""

        return (
            f"{apk_name} is assessed as {classification} with a risk score of {risk_score}/100. "
            f"The primary assessment is: {threat_type}. The likely target set is {victims}.{banking_note}\n\n"
            f"Key observed capabilities include {', '.join(capabilities[:5])}. "
            "This summary is generated from static analysis, YARA matches, IOC extraction, dynamic indicators, and risk scoring evidence.\n\n"
            f"Immediate response should include: {', '.join(actions[:4])}."
        )

    # ── ANALYST Q&A AGENT ────────────────────────────────────────────────────
    def answer_analyst_question(self, question: str, full_analysis: dict) -> str:
        if not self.available:
            return self._fallback_question_answer(question, full_analysis)

        context = json.dumps({
            "risk_score"    : full_analysis.get("risk_score", {}),
            "threat_type"   : full_analysis.get("genai_analysis", {}).get("primary_threat_type"),
            "capabilities"  : full_analysis.get("genai_analysis", {}).get("key_capabilities", []),
            "critical_apis" : full_analysis.get("static_analysis", {}).get(
                                "api_analysis", {}).get("critical_apis", []),
            "vulnerabilities": [v["name"] for v in full_analysis.get("static_analysis", {}).get(
                                "vulnerabilities", {}).get("findings", [])[:5]],
            "banking_threats": full_analysis.get("static_analysis", {}).get("banking_threats", {}),
            "yara_families"  : full_analysis.get("yara_analysis", {}).get("malware_families", []),
            "mitre"          : full_analysis.get("yara_analysis", {}).get("mitre_techniques", []),
        }, indent=2)[:3000]

        prompt = f"""RAKSHAK SOC ANALYST Q&A — DRDO Cybersecurity Division

ANALYST QUESTION: {question}

ANALYSIS CONTEXT:
{context}

Answer the analyst's question precisely and technically. 
Cite specific evidence from the analysis data above.
If asked about specific code sections, reference the relevant findings.
Keep answer under 150 words. Be direct and actionable."""

        answer = self._call_claude(prompt, max_tokens=500)
        try:
            parsed = json.loads(answer)
            if isinstance(parsed, dict) and "malicious_intent_summary" in parsed:
                return self._fallback_question_answer(question, full_analysis)
        except Exception:
            pass
        return answer

    def _fallback_question_answer(self, question: str, full_analysis: dict) -> str:
        summary = full_analysis.get("summary", {})
        risk = full_analysis.get("risk_score", {})
        strings = full_analysis.get("strings", {})
        static = full_analysis.get("static_analysis", {})
        yara = full_analysis.get("yara_analysis", {})
        dynamic = full_analysis.get("dynamic_analysis", {})
        genai = full_analysis.get("genai_analysis", {})

        families = yara.get("malware_families", []) or [summary.get("primary_family")]
        families = [f for f in families if f]
        urls = strings.get("urls", [])
        ips = strings.get("ips", [])
        emails = strings.get("emails", [])
        phones = strings.get("hardcoded_phones", [])
        banks = strings.get("bank_references", [])
        commands = strings.get("shell_commands", [])
        crypto = strings.get("crypto_keys", [])
        vuln_findings = static.get("vulnerabilities", {}).get("findings", [])
        crypto_findings = static.get("crypto_analysis", {}).get("findings", [])
        banking = static.get("banking_threats", {})
        dyn_findings = dynamic.get("all_findings", [])

        q = question.lower()
        focus = []
        if any(term in q for term in ["steal", "data", "credential", "otp", "sms"]):
            focus.append("Data at risk: " + ", ".join(genai.get("data_at_risk", []) or [
                "banking credentials", "SMS/OTP data", "personal identifiers"
            ]))
            if phones:
                focus.append(f"Evidence includes {len(phones)} hardcoded phone-like values.")
            if banks:
                focus.append(f"The string scan found {len(banks)} banking/financial references.")
        elif any(term in q for term in ["network", "ioc", "url", "domain", "ip", "c2"]):
            focus.append(f"Network evidence: {len(urls)} URLs, {len(ips)} IPs, and {len(emails)} email indicators were extracted.")
            if urls:
                focus.append("Top URL samples: " + "; ".join(str(u.get("url", u))[:90] for u in urls[:3]))
        elif any(term in q for term in ["family", "actor", "apt", "who"]):
            focus.append("Matched malware/intel families: " + (", ".join(families[:8]) if families else "no named family confirmed."))
            focus.append(f"APT/nation-state flags: APT={bool(risk.get('apt_detected') or summary.get('apt_detected'))}, nation_state={bool(risk.get('nation_state') or summary.get('nation_state'))}.")
        elif any(term in q for term in ["action", "recommend", "mitigate", "block"]):
            focus.append("Recommended actions: quarantine the APK, block extracted suspicious URLs/domains, preserve the sample and report, review affected devices, and escalate to SOC/CERT-In if deployed to users.")
        else:
            focus.append(f"Risk is {risk.get('final_score', summary.get('risk_score', 'unknown'))}/100 with severity {risk.get('severity', summary.get('severity', 'unknown'))}.")
            focus.append("Primary family/type: " + (summary.get("primary_family") or genai.get("primary_threat_type") or "manual review required."))

        evidence = [
            f"Static findings: {summary.get('total_findings', static.get('total_findings', 0))}",
            f"YARA matches: {len(yara.get('matches', []))}",
            f"URLs: {len(urls)}",
            f"Dynamic findings: {len(dyn_findings)}",
            f"Vulnerabilities: {len(vuln_findings)}",
            f"Crypto indicators: {len(crypto_findings) or len(crypto)}",
            f"Shell commands: {len(commands)}",
        ]

        if banking:
            banking_hits = [k for k, v in banking.items() if v is True or (isinstance(v, list) and v)]
            if banking_hits:
                evidence.append("Banking threat markers: " + ", ".join(banking_hits[:5]))

        return (
            "SriAI answer based on the completed RAKSHAK report:\n\n"
            + "\n".join(f"- {item}" for item in focus)
            + "\n\nEvidence used:\n"
            + "\n".join(f"- {item}" for item in evidence)
            + "\n\nAnalyst note: this is a local evidence-based explanation. Configure GEMINI_API_KEY for deeper generative reasoning."
        )

    # ── OBFUSCATION DEOBFUSCATOR HINT ────────────────────────────────────────
    def interpret_obfuscated_class(self, class_name: str, methods: list[str]) -> str:
        prompt = f"""Given this obfuscated Android class from a malware sample, identify its purpose.

OBFUSCATED CLASS NAME: {class_name}
METHODS: {', '.join(methods[:10])}

Based on these method signatures, what does this class likely do?
Answer in ONE sentence with high confidence. Example: "This class is an SMS harvester that reads incoming messages and forwards OTPs to a remote server."

Return ONLY the one-sentence answer."""
        return self._call_claude(prompt, max_tokens=80)

    # ── FALLBACK ANALYSIS (no API key) ───────────────────────────────────────
    def _fallback_analysis(self, prompt: str) -> str:
        return json.dumps({
            "threat_classification"  : "HIGH",
            "primary_threat_type"    : "Suspicious APK — Manual Review Required",
            "malicious_intent_summary": "GenAI analysis unavailable. Static and YARA analysis indicates suspicious behaviour. Manual expert review strongly recommended.",
            "key_capabilities"       : ["Static analysis detected suspicious patterns"],
            "target_victims"         : "Indian banking users and/or government personnel",
            "attack_chain"           : ["Install", "Request permissions", "Execute payload"],
            "data_at_risk"           : ["Banking credentials", "SMS/OTP", "Personal data"],
            "apt_attribution"        : None,
            "zero_day_indicators"    : "Cannot assess without GenAI — configure GEMINI_API_KEY",
            "immediate_actions"      : [
                "Quarantine the APK immediately",
                "Block associated domains and IPs",
                "Submit to CERT-In for national threat assessment",
                "Configure GEMINI_API_KEY for full GenAI analysis"
            ],
            "intelligence_confidence": "MEDIUM",
            "analyst_notes"          : "Set GEMINI_API_KEY environment variable for SriAI reasoning."
        })

    @staticmethod
    def _parse_json_response(raw: str, fallback: dict) -> dict:
        try:
            # Strip markdown code fences
            clean = re.sub(r'```(?:json)?', '', raw).strip()
            # Find first { ... }
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception:
            pass
        return fallback
