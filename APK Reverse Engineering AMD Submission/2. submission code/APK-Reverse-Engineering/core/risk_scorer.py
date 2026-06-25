"""
RAKSHAK — Risk Scoring Engine
Multi-dimensional weighted scoring with full XAI (Explainable AI) breakdown
"""

from config import SCORE_WEIGHTS, SEVERITY, MITRE_TECHNIQUES


class RiskScoringEngine:
    """
    RAKSHAK Multi-Dimensional Risk Scorer
    Produces a 0-100 score with SHAP-style explainability
    """

    def compute(self,
                manifest     : dict,
                static       : dict,
                yara         : dict,
                strings      : dict,
                structure    : dict,
                certs        : dict,
                genai        : dict) -> dict:

        breakdown  = {}
        attribution = []

        # ── DIMENSION 1: Permission Risk (18%) ────────────────────────────────
        perm_raw   = manifest.get("permission_risk_total", 0)
        perm_score = min(perm_raw, 100)
        perm_contrib = perm_score * SCORE_WEIGHTS["permissions"]
        combos     = manifest.get("permission_combos", [])

        breakdown["permissions"] = {
            "raw_score"   : perm_score,
            "weight"      : SCORE_WEIGHTS["permissions"],
            "contribution": round(perm_contrib, 2),
            "evidence"    : [
                f"{len(manifest.get('dangerous_permissions', []))} dangerous permissions",
                *combos[:3],
            ],
        }
        if combos:
            attribution.append({
                "factor"      : "Dangerous permission combinations",
                "points"      : round(perm_contrib, 1),
                "detail"      : combos[0] if combos else "",
            })

        # ── DIMENSION 2: Static Code Signals (22%) ────────────────────────────
        api_score    = static.get("api_analysis", {}).get("total_risk_score", 0)
        vuln_score   = static.get("vulnerabilities", {}).get("total_risk_score", 0)
        crypto_score = static.get("crypto_audit", {}).get("total_risk_score", 0)
        banking_score= static.get("banking_threats", {}).get("banking_risk_score", 0)
        obf_penalty  = 15 if static.get("api_analysis", {}).get("obfuscation_signals") else 0

        static_raw   = min((api_score * 0.4 + vuln_score * 0.25 +
                            crypto_score * 0.15 + banking_score * 0.15 +
                            obf_penalty * 0.05), 100)
        static_contrib = static_raw * SCORE_WEIGHTS["static_code"]

        breakdown["static_code"] = {
            "raw_score"   : round(static_raw, 1),
            "weight"      : SCORE_WEIGHTS["static_code"],
            "contribution": round(static_contrib, 2),
            "sub_scores"  : {
                "dangerous_apis"   : api_score,
                "vulnerabilities"  : vuln_score,
                "crypto_weaknesses": crypto_score,
                "banking_threats"  : banking_score,
                "obfuscation"      : obf_penalty,
            },
            "evidence": [
                f"{len(static.get('api_analysis', {}).get('critical_apis', []))} critical API calls",
                f"{static.get('vulnerabilities', {}).get('critical_count', 0)} critical vulnerabilities",
                f"{static.get('crypto_audit', {}).get('total_crypto_issues', 0)} crypto issues",
            ],
        }

        if api_score > 30:
            attribution.append({
                "factor": "Critical dangerous API calls",
                "points": round(api_score * SCORE_WEIGHTS["static_code"] * 0.4, 1),
                "detail": f"APIs: {', '.join(static.get('api_analysis', {}).get('critical_apis', [])[:3])}",
            })
        if banking_score > 30:
            attribution.append({
                "factor": "Banking fraud capabilities",
                "points": round(banking_score * SCORE_WEIGHTS["static_code"] * 0.15, 1),
                "detail": "OTP harvesting / overlay attack / UPI fraud patterns",
            })

        # ── DIMENSION 3: Dynamic Behaviour (28%) ─────────────────────────────
        # Dynamic analysis signals from static proxies
        dynamic_score = 0
        dynamic_evidence = []

        # Persistence indicators
        perms = {p["permission"] for p in manifest.get("dangerous_permissions", [])}
        if "android.permission.RECEIVE_BOOT_COMPLETED" in perms:
            dynamic_score += 20
            dynamic_evidence.append("Boot persistence — survives device restart")
        if "android.permission.BIND_DEVICE_ADMIN" in perms:
            dynamic_score += 30
            dynamic_evidence.append("Device admin — resists uninstallation")

        # RAT indicators
        if "android.permission.RECORD_AUDIO" in perms:
            dynamic_score += 15
            dynamic_evidence.append("Microphone access — covert recording")
        if "android.permission.CAMERA" in perms and "android.permission.RECORD_AUDIO" in perms:
            dynamic_score += 10
            dynamic_evidence.append("Camera + Mic combined — surveillance suite")

        # Network exfiltration
        suspicious_urls = [u for u in strings.get("urls", []) if u.get("risk") == "HIGH"]
        if suspicious_urls:
            dynamic_score += min(len(suspicious_urls) * 5, 20)
            dynamic_evidence.append(f"{len(suspicious_urls)} suspicious C2 URLs")

        # Shell commands
        if strings.get("shell_commands"):
            dynamic_score += 15
            dynamic_evidence.append("Shell command execution patterns")

        # Dropper indicators
        if structure.get("embedded_apks"):
            dynamic_score += 25
            dynamic_evidence.append(f"Embedded APK dropper: {structure['embedded_apks'][:1]}")

        # High entropy assets (encrypted payloads)
        if structure.get("high_entropy_files"):
            dynamic_score += 10
            dynamic_evidence.append("High-entropy encrypted payload in assets")

        dynamic_score    = min(dynamic_score, 100)
        dynamic_contrib  = dynamic_score * SCORE_WEIGHTS["dynamic_behaviour"]

        breakdown["dynamic_behaviour"] = {
            "raw_score"   : dynamic_score,
            "weight"      : SCORE_WEIGHTS["dynamic_behaviour"],
            "contribution": round(dynamic_contrib, 2),
            "evidence"    : dynamic_evidence,
        }
        if dynamic_score > 20:
            attribution.append({
                "factor": "Malicious runtime behaviour indicators",
                "points": round(dynamic_contrib, 1),
                "detail": "; ".join(dynamic_evidence[:2]),
            })

        # ── DIMENSION 4: Network IOCs (16%) ───────────────────────────────────
        net_score = 0
        net_evidence = []

        direct_ips = strings.get("ips", [])
        if direct_ips:
            net_score += min(len(direct_ips) * 8, 30)
            net_evidence.append(f"{len(direct_ips)} hardcoded C2 IPs")

        tg_tokens = strings.get("telegram_tokens", [])
        if tg_tokens:
            net_score += 25
            net_evidence.append(f"Telegram Bot C2 tokens: {len(tg_tokens)}")

        secrets = strings.get("hardcoded_secrets", [])
        if secrets:
            net_score += 20
            net_evidence.append(f"{len(secrets)} hardcoded credentials/API keys")

        if suspicious_urls:
            net_score += min(len(suspicious_urls) * 4, 20)
            net_evidence.append(f"Suspicious URLs: {suspicious_urls[0].get('url','')[:50]}")

        net_score   = min(net_score, 100)
        net_contrib = net_score * SCORE_WEIGHTS["network_iocs"]

        breakdown["network_iocs"] = {
            "raw_score"   : net_score,
            "weight"      : SCORE_WEIGHTS["network_iocs"],
            "contribution": round(net_contrib, 2),
            "evidence"    : net_evidence,
        }
        if net_score > 15:
            attribution.append({
                "factor": "Network C2 indicators",
                "points": round(net_contrib, 1),
                "detail": "; ".join(net_evidence[:2]),
            })

        # ── DIMENSION 5: Threat Intel / YARA (10%) ────────────────────────────
        yara_score   = yara.get("yara_risk_score", 0)
        families     = yara.get("malware_families", [])
        apt_detected = yara.get("apt_detected", False)
        nation_state = yara.get("nation_state_threat", False)

        if apt_detected:
            yara_score = min(yara_score + 20, 100)
        if nation_state:
            yara_score = 100  # Nation-state = automatic maximum

        ti_contrib = yara_score * SCORE_WEIGHTS["threat_intel"]

        breakdown["threat_intel"] = {
            "raw_score"   : yara_score,
            "weight"      : SCORE_WEIGHTS["threat_intel"],
            "contribution": round(ti_contrib, 2),
            "evidence"    : [
                f"YARA families matched: {', '.join(families) or 'None'}",
                f"APT detected: {apt_detected}",
                f"Nation-state threat: {nation_state}",
                f"Rules matched: {yara.get('rules_matched', 0)}/{yara.get('total_rules_scanned', 0)}",
            ],
        }
        if families:
            attribution.append({
                "factor": "Known malware family match",
                "points": round(ti_contrib, 1),
                "detail": f"Families: {', '.join(families[:3])}",
            })

        # ── DIMENSION 6: GenAI Reasoning (6%) ────────────────────────────────
        genai_conf = genai.get("intelligence_confidence", "LOW")
        genai_class = genai.get("threat_classification", "LOW")
        genai_score = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 45, "LOW": 20}.get(genai_class, 30)
        genai_conf_mult = {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5}.get(genai_conf, 0.5)
        genai_weighted = genai_score * genai_conf_mult
        genai_contrib  = genai_weighted * SCORE_WEIGHTS["genai_reasoning"]

        breakdown["genai_reasoning"] = {
            "raw_score"   : round(genai_weighted, 1),
            "weight"      : SCORE_WEIGHTS["genai_reasoning"],
            "contribution": round(genai_contrib, 2),
            "evidence"    : [
                f"LLM threat classification: {genai_class}",
                f"Confidence: {genai_conf}",
                f"Primary type: {genai.get('primary_threat_type', 'Unknown')}",
            ],
        }

        # ── FINAL SCORE ───────────────────────────────────────────────────────
        raw_total = (perm_contrib + static_contrib + dynamic_contrib +
                     net_contrib + ti_contrib + genai_contrib)

        # Certificate bonus
        if certs.get("self_signed"):
            raw_total = min(raw_total + 5, 100)
        if certs.get("cert_risk_score", 0) > 20:
            raw_total = min(raw_total + 3, 100)

        # Structure anomaly bonus
        if structure.get("structure_anomalies"):
            raw_total = min(raw_total + 3, 100)

        # Impersonation bonus
        imp_score = manifest.get("bank_impersonation_score", 0)
        if imp_score > 0:
            raw_total = min(raw_total + imp_score * 0.1, 100)

        final_score = round(min(raw_total, 100))

        # ── SEVERITY CLASSIFICATION ───────────────────────────────────────────
        severity = "CLEAN"
        for sev, (low, high) in SEVERITY.items():
            if low <= final_score <= high:
                severity = sev
                break

        # ── MITRE TECHNIQUE COMPILATION ───────────────────────────────────────
        all_mitre = set(yara.get("mitre_techniques", []))
        for f in static.get("api_analysis", {}).get("findings", []):
            if f.get("mitre"):
                all_mitre.add(f["mitre"])
        mitre_mapped = [
            {"id": t, "name": MITRE_TECHNIQUES.get(t, "Unknown")}
            for t in all_mitre
        ]

        # ── KILL CHAIN ────────────────────────────────────────────────────────
        kill_chain = static.get("banking_threats", {}).get("fraud_kill_chain", [])

        return {
            "final_score"    : final_score,
            "severity"       : severity,
            "severity_color" : {
                "CRITICAL": "#FF2222",
                "HIGH"    : "#FF8800",
                "MEDIUM"  : "#FFCC00",
                "LOW"     : "#44BB44",
                "CLEAN"   : "#00CC88",
            }.get(severity, "#888888"),
            "breakdown"      : breakdown,
            "attribution"    : sorted(attribution, key=lambda x: x["points"], reverse=True),
            "mitre_techniques": mitre_mapped,
            "kill_chain"     : kill_chain,
            "nation_state"   : yara.get("nation_state_threat", False),
            "apt_detected"   : yara.get("apt_detected", False),
            "primary_family" : yara.get("primary_family", "Unknown"),
            "immediate_block_recommended": final_score >= 65,
            "cert_in_report_required"    : final_score >= 85 or yara.get("apt_detected", False),
        }
