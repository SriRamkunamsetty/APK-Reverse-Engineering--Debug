"""
RAKSHAK — Advanced Pipeline v2 (Real-Time, All Engines)
Orchestrates ALL 16 analysis engines with live WebSocket event emission.
Every finding fires an event to connected dashboard clients as it happens.
"""

import json, time, traceback
from pathlib import Path
from datetime import datetime

from core.apk_analyzer   import APKAnalyzer
from core.static_engine  import StaticAnalysisEngine
from core.yara_engine    import YARAEngine
from core.genai_engine   import GenAIEngine, CodeContextBuilder
from core.risk_scorer    import RiskScoringEngine
from core.ml_engine      import MLEnsemble
from core.frida_sandbox  import FridaSandboxOrchestrator
from core.network_analyzer import NetworkAnalyzer
from core.misp_client    import misp_client
from core.stix_exporter  import export_stix
from core.event_bus      import emit, EventType
from config              import PLATFORM_NAME, PLATFORM_VERSION, CLASSIFICATION_LEVEL, REPORT_DIR


class AdvancedPipeline:
    """
    RAKSHAK Advanced Analysis Pipeline v2
    16-engine parallel+sequential analysis with real-time event streaming.
    Every engine emits WebSocket events as findings are discovered.
    """

    def __init__(self):
        self.genai    = GenAIEngine()
        self.risk     = RiskScoringEngine()
        self.ml       = MLEnsemble()
        self.frida    = FridaSandboxOrchestrator()
        self.network  = NetworkAnalyzer(timeout=8)

    def analyze(self, apk_path: str, analyst_name: str = "RAKSHAK-AUTO",
                case_id: str = None, enable_dynamic: bool = True,
                enable_network: bool = True, enable_misp: bool = False) -> dict:

        start = time.time()
        apk_path = str(apk_path)
        apk_name = Path(apk_path).name
        if not case_id:
            case_id = f"RKSAK-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # ── Fire analysis start event ──────────────────────────────────────
        emit(EventType.ANALYSIS_START, case_id, {
            "apk_name"    : apk_name,
            "analyst"     : analyst_name,
            "engines"     : ["hash","structure","manifest","strings",
                             "static","yara","ml","genai","scoring",
                             "frida","network","misp"],
        })

        result = {
            "case_id"        : case_id,
            "platform"       : f"{PLATFORM_NAME} v{PLATFORM_VERSION}",
            "classification" : CLASSIFICATION_LEVEL,
            "analyst"        : analyst_name,
            "apk_name"       : apk_name,
            "status"         : "RUNNING",
            "error"          : None,
            "analysis_start" : datetime.utcnow().isoformat() + "Z",
            "progress"       : [],
        }

        def log(stage, msg):
            entry = {"stage": stage, "message": msg,
                     "time": datetime.utcnow().isoformat() + "Z"}
            result["progress"].append(entry)

        try:
            # ════════════════════════════════════════════════════════════
            # PHASE 1: APK TEARDOWN
            # ════════════════════════════════════════════════════════════
            log("INTAKE", f"Processing: {apk_name}")
            emit(EventType.HASH_COMPLETE, case_id,
                 {"message": "Computing cryptographic fingerprints..."})

            apk_analyzer = APKAnalyzer(apk_path)
            apk_data     = apk_analyzer.full_analyze()

            result.update({
                "hashes"      : apk_data["hashes"],
                "structure"   : apk_data["structure"],
                "manifest"    : apk_data["manifest"],
                "certificates": apk_data["certificates"],
                "strings"     : apk_data["strings"],
            })

            emit(EventType.HASH_COMPLETE, case_id, {
                "sha256"      : apk_data["hashes"]["sha256"],
                "size"        : apk_data["hashes"]["size_human"],
                "files"       : apk_data["structure"]["total_files"],
                "dex_count"   : len(apk_data["structure"]["dex_files"]),
                "native_libs" : len(apk_data["structure"]["native_libs"]),
                "multidex"    : apk_data["structure"]["multidex"],
            })
            log("HASH", f"SHA256={apk_data['hashes']['sha256'][:16]}...")

            emit(EventType.MANIFEST_COMPLETE, case_id, {
                "package"     : apk_data["manifest"].get("package_name","?"),
                "perms"       : len(apk_data["manifest"].get("permissions",[])),
                "dangerous"   : len(apk_data["manifest"].get("dangerous_permissions",[])),
                "combos"      : apk_data["manifest"].get("permission_combos",[]),
            })

            # Alert if bank impersonation
            if apk_data["manifest"].get("bank_impersonation_score", 0) > 0:
                emit(EventType.BANKING_THREAT, case_id, {
                    "type"   : "BRAND_IMPERSONATION",
                    "package": apk_data["manifest"].get("package_name",""),
                    "score"  : apk_data["manifest"]["bank_impersonation_score"],
                }, severity="CRITICAL")

            # ════════════════════════════════════════════════════════════
            # PHASE 2: STATIC ANALYSIS
            # ════════════════════════════════════════════════════════════
            log("STATIC", "Running static analysis...")
            static_engine = StaticAnalysisEngine(apk_path, apk_analyzer.dx_obj)
            static_data   = static_engine.analyze(result["manifest"], result["strings"])

            # Emit each CRITICAL finding immediately
            for finding in static_data["api_analysis"]["findings"]:
                if finding["severity"] == "CRITICAL":
                    emit(EventType.STATIC_FINDING, case_id, {
                        "engine"     : "STATIC",
                        "api"        : finding["api"],
                        "description": finding["description"],
                        "score"      : finding["risk_score"],
                        "mitre"      : finding.get("mitre",""),
                    }, severity="CRITICAL")

            # Banking threats
            bt = static_data["banking_threats"]
            if bt["otp_harvesting"] or bt["overlay_attack"]:
                emit(EventType.BANKING_THREAT, case_id, {
                    "otp_harvesting"  : bt["otp_harvesting"],
                    "overlay_attack"  : bt["overlay_attack"],
                    "accessibility"   : bt["accessibility_abuse"],
                    "banking_score"   : bt["banking_risk_score"],
                    "upi_indicators"  : bt["upi_fraud_indicators"],
                    "kill_chain"      : bt["fraud_kill_chain"],
                }, severity="CRITICAL" if bt["banking_risk_score"] > 60 else "HIGH")

            # Vulnerability findings
            for vuln in static_data["vulnerabilities"]["findings"]:
                if vuln["severity"] == "CRITICAL":
                    emit(EventType.CRITICAL_VULN, case_id, {
                        "id"          : vuln["id"],
                        "name"        : vuln["name"],
                        "cve"         : vuln["cve"],
                        "description" : vuln["description"],
                    }, severity="CRITICAL")

            result["static_analysis"] = static_data
            emit(EventType.STATIC_COMPLETE, case_id, {
                "critical_apis"   : len(static_data["api_analysis"]["critical_apis"]),
                "vulns"           : static_data["vulnerabilities"]["total_vulnerabilities"],
                "crypto_issues"   : static_data["crypto_audit"]["total_crypto_issues"],
                "banking_score"   : bt["banking_risk_score"],
            })
            log("STATIC", f"Critical APIs: {len(static_data['api_analysis']['critical_apis'])}")

            # ════════════════════════════════════════════════════════════
            # PHASE 3: YARA MATCHING
            # ════════════════════════════════════════════════════════════
            log("YARA", "Running YARA pattern matching...")
            yara_engine = YARAEngine(apk_path)
            yara_data   = yara_engine.scan()

            # Emit each rule match live
            for match in yara_data["matches"]:
                emit(EventType.YARA_MATCH, case_id, {
                    "rule_id"    : match["rule_id"],
                    "family"     : match["family"],
                    "weight"     : match["risk_weight"],
                    "mitre"      : match["mitre"],
                }, severity=match["severity"])

            # Nation-state / APT alert
            if yara_data["nation_state_threat"] or yara_data["apt_detected"]:
                emit(EventType.NATION_STATE, case_id, {
                    "families"   : yara_data["malware_families"],
                    "apt_score"  : yara_data["yara_risk_score"],
                    "action"     : "ESCALATE TO DRDO NOC + CERT-In IMMEDIATELY",
                }, severity="CRITICAL")

            result["yara_analysis"] = yara_data
            emit(EventType.YARA_COMPLETE, case_id, {
                "matched"     : yara_data["rules_matched"],
                "families"    : yara_data["malware_families"],
                "apt"         : yara_data["apt_detected"],
                "nation_state": yara_data["nation_state_threat"],
            })
            log("YARA", f"{yara_data['rules_matched']} rules matched, APT={yara_data['apt_detected']}")

            # ════════════════════════════════════════════════════════════
            # PHASE 4: ADVANCED ML ENGINE
            # ════════════════════════════════════════════════════════════
            log("ML", "Running advanced ML analysis...")
            emit(EventType.GENAI_THINKING, case_id,
                 {"engine": "ML", "message": "Computing opcode N-grams and semantic embeddings..."})

            ml_result = self.ml.analyse(apk_path, case_id=case_id)
            result["ml_analysis"] = ml_result

            emit(EventType.SCORE_UPDATE, case_id, {
                "dimension"    : "ml_ensemble",
                "score"        : ml_result["ensemble_score"],
                "verdict"      : ml_result["ml_verdict"],
                "top_family"   : ml_result["top_family_match"],
                "chains"       : ml_result["malicious_api_chains"][:3],
            })
            log("ML", f"Ensemble={ml_result['ensemble_score']}, verdict={ml_result['ml_verdict']}")

            # ════════════════════════════════════════════════════════════
            # PHASE 5: GENAI REASONING
            # ════════════════════════════════════════════════════════════
            log("GENAI", "Invoking SriAI semantic reasoning...")
            emit(EventType.GENAI_THINKING, case_id,
                 {"engine": "GENAI", "message": "SriAI analyzing threat semantics..."})

            code_ctx     = CodeContextBuilder(apk_path).build_context(
                result["static_analysis"], result["strings"]
            )
            genai_result = self.genai.analyze_threat(
                apk_name, code_ctx, result["manifest"], yara_data
            )
            result["genai_analysis"] = genai_result

            emit(EventType.GENAI_COMPLETE, case_id, {
                "threat_type"    : genai_result.get("primary_threat_type","?"),
                "classification" : genai_result.get("threat_classification","?"),
                "confidence"     : genai_result.get("intelligence_confidence","?"),
                "capabilities"   : genai_result.get("key_capabilities",[])[:5],
                "apt"            : genai_result.get("apt_attribution"),
            })
            log("GENAI", f"Type={genai_result.get('primary_threat_type','?')}")

            # ════════════════════════════════════════════════════════════
            # PHASE 6: DYNAMIC SANDBOX (Frida)
            # ════════════════════════════════════════════════════════════
            if enable_dynamic:
                log("FRIDA", "Running dynamic sandbox analysis...")
                emit(EventType.STATIC_FINDING, case_id, {
                    "engine" : "FRIDA",
                    "message": "Starting Frida sandbox instrumentation..."
                })
                frida_result = self.frida.run_analysis(apk_path, case_id=case_id)
                result["dynamic_analysis"] = frida_result
                emit(EventType.STATIC_COMPLETE, case_id, {
                    "engine"    : "FRIDA",
                    "mode"      : frida_result.get("mode",""),
                    "findings"  : frida_result.get("total_findings",0),
                    "score"     : frida_result.get("dynamic_risk_score",0),
                    "behaviours": frida_result.get("behaviours_detected",[]),
                })
                log("FRIDA", f"Findings={frida_result.get('total_findings',0)}, "
                             f"Score={frida_result.get('dynamic_risk_score',0)}")

            # ════════════════════════════════════════════════════════════
            # PHASE 7: NETWORK IOC ENRICHMENT
            # ════════════════════════════════════════════════════════════
            if enable_network:
                log("NETWORK", "Enriching network IOCs...")
                net_result = self.network.analyze(
                    result["strings"].get("urls", []),
                    result["strings"].get("ips",  []),
                )
                result["network_analysis"] = net_result

                for c2 in net_result.get("c2_confirmed", [])[:5]:
                    emit(EventType.C2_FOUND, case_id, {
                        "indicator" : c2,
                        "confirmed" : True,
                    }, severity="CRITICAL")

                emit(EventType.IOC_ENRICHED, case_id, {
                    "confirmed_c2"  : len(net_result.get("c2_confirmed",[])),
                    "network_score" : net_result.get("network_risk_score",0),
                    "geo_summary"   : net_result.get("geolocation_summary",{}),
                })
                log("NETWORK", f"C2 confirmed: {len(net_result.get('c2_confirmed',[]))}")

            # ════════════════════════════════════════════════════════════
            # PHASE 8: MULTI-DIMENSIONAL RISK SCORING
            # ════════════════════════════════════════════════════════════
            log("SCORING", "Computing final risk score...")
            risk_data = self.risk.compute(
                manifest  = result["manifest"],
                static    = result["static_analysis"],
                yara      = result["yara_analysis"],
                strings   = result["strings"],
                structure = result["structure"],
                certs     = result["certificates"],
                genai     = result["genai_analysis"],
            )

            # Boost score with ML and dynamic results
            ml_boost  = ml_result.get("ensemble_score",0) * 0.10
            dyn_boost = result.get("dynamic_analysis",{}).get("dynamic_risk_score",0) * 0.08
            final_score = min(risk_data["final_score"] + ml_boost + dyn_boost, 100)
            risk_data["final_score"] = round(final_score)

            # Re-classify after boost
            for sev, (lo, hi) in [
                ("CRITICAL",(85,100)),("HIGH",(65,84)),
                ("MEDIUM",(40,64)),("LOW",(20,39)),("CLEAN",(0,19))
            ]:
                if lo <= risk_data["final_score"] <= hi:
                    risk_data["severity"] = sev
                    break

            result["risk_score"] = risk_data

            emit(EventType.SCORE_FINAL, case_id, {
                "final_score"   : risk_data["final_score"],
                "severity"      : risk_data["severity"],
                "severity_color": risk_data["severity_color"],
                "nation_state"  : risk_data["nation_state"],
                "apt_detected"  : risk_data["apt_detected"],
                "block_now"     : risk_data["immediate_block_recommended"],
                "cert_in"       : risk_data["cert_in_report_required"],
                "breakdown"     : risk_data["breakdown"],
                "attribution"   : risk_data["attribution"][:5],
                "mitre"         : risk_data["mitre_techniques"],
            })
            log("SCORING", f"FINAL={risk_data['final_score']}/100 ({risk_data['severity']})")

            # ════════════════════════════════════════════════════════════
            # PHASE 9: GENAI EXECUTIVE SUMMARY
            # ════════════════════════════════════════════════════════════
            exec_summary = self.genai.generate_executive_summary(
                apk_name, risk_data["final_score"], genai_result,
                result["static_analysis"]["banking_threats"]
            )
            result["executive_summary"] = exec_summary

            # ════════════════════════════════════════════════════════════
            # PHASE 10: STIX 2.1 EXPORT
            # ════════════════════════════════════════════════════════════
            stix_bundle = export_stix(result)
            stix_path   = REPORT_DIR / f"{case_id}-stix.json"
            stix_path.write_text(json.dumps(stix_bundle, indent=2))
            result["stix_bundle_path"] = str(stix_path)

            # ════════════════════════════════════════════════════════════
            # PHASE 11: MISP PUSH (if configured)
            # ════════════════════════════════════════════════════════════
            if enable_misp:
                log("MISP", "Pushing to MISP/CERT-In...")
                misp_result = misp_client.push_analysis(result, case_id=case_id)
                result["misp_push"] = misp_result

            # ════════════════════════════════════════════════════════════
            # FINALISE
            # ════════════════════════════════════════════════════════════
            duration = round(time.time() - start, 2)
            result.update({
                "status"       : "COMPLETE",
                "analysis_end" : datetime.utcnow().isoformat() + "Z",
                "duration_sec" : duration,
                "summary"      : {
                    "risk_score"      : risk_data["final_score"],
                    "severity"        : risk_data["severity"],
                    "primary_family"  : risk_data["primary_family"],
                    "threat_type"     : genai_result.get("primary_threat_type","Unknown"),
                    "apt_detected"    : risk_data["apt_detected"],
                    "nation_state"    : risk_data["nation_state"],
                    "total_findings"  : (
                        len(static_data["api_analysis"]["critical_apis"]) +
                        static_data["vulnerabilities"]["total_vulnerabilities"] +
                        yara_data["rules_matched"] +
                        ml_result.get("ensemble_score", 0) // 10
                    ),
                    "critical_vulns"  : static_data["vulnerabilities"]["critical_count"],
                    "dangerous_perms" : len(result["manifest"].get("dangerous_permissions",[])),
                    "c2_indicators"   : len(result["strings"].get("ips",[])) +
                                        len(result["strings"].get("urls",[])),
                    "dynamic_findings": result.get("dynamic_analysis",{}).get("total_findings",0),
                    "ml_verdict"      : ml_result["ml_verdict"],
                    "block_now"       : risk_data["immediate_block_recommended"],
                    "cert_in_report"  : risk_data["cert_in_report_required"],
                },
            })

            emit(EventType.ANALYSIS_COMPLETE, case_id, {
                **result["summary"],
                "duration_sec": duration,
                "stix_path"   : str(stix_path),
            })
            log("COMPLETE", f"Done in {duration}s")

        except Exception as e:
            result.update({
                "status"    : "ERROR",
                "error"     : str(e),
                "traceback" : traceback.format_exc(),
                "analysis_end": datetime.utcnow().isoformat() + "Z",
                "duration_sec": round(time.time() - start, 2),
            })
            emit(EventType.ANALYSIS_ERROR, case_id,
                 {"error": str(e)}, severity="CRITICAL")
            log("ERROR", str(e))

        return result

    def answer_question(self, question: str, analysis: dict) -> str:
        return self.genai.answer_analyst_question(question, analysis)
