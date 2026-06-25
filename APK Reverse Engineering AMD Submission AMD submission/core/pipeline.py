"""
RAKSHAK — Master Analysis Pipeline
Orchestrates all engines: APK → Static → YARA → GenAI → Risk Score → Report
"""

import json, time, traceback
from pathlib import Path
from datetime import datetime

from core.apk_analyzer    import APKAnalyzer
from core.static_engine   import StaticAnalysisEngine
from core.yara_engine     import YARAEngine
from core.genai_engine    import GenAIEngine, CodeContextBuilder
from core.risk_scorer     import RiskScoringEngine
from config               import PLATFORM_NAME, PLATFORM_VERSION, CLASSIFICATION_LEVEL


class RakshakPipeline:
    """
    RAKSHAK Master Analysis Pipeline
    Single entry point for complete APK threat intelligence
    """

    def __init__(self):
        self.genai_engine  = GenAIEngine()
        self.risk_engine   = RiskScoringEngine()

    def analyze(self, apk_path: str,
                analyst_name: str = "RAKSHAK-AUTO",
                case_id: str = None) -> dict:

        start_time = time.time()
        apk_path   = str(apk_path)
        apk_name   = Path(apk_path).name

        if not case_id:
            case_id = f"RKSAK-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        result = {
            "case_id"        : case_id,
            "platform"       : f"{PLATFORM_NAME} v{PLATFORM_VERSION}",
            "classification" : CLASSIFICATION_LEVEL,
            "analyst"        : analyst_name,
            "apk_name"       : apk_name,
            "status"         : "RUNNING",
            "error"          : None,
            "analysis_start" : datetime.utcnow().isoformat() + "Z",
            "analysis_end"   : None,
            "duration_sec"   : None,
            "progress"       : [],
        }

        def log(stage: str, msg: str):
            entry = {"stage": stage, "message": msg,
                     "time": datetime.utcnow().isoformat() + "Z"}
            result["progress"].append(entry)
            print(f"[{stage}] {msg}")

        try:
            # ── PHASE 1: APK Deep Teardown ────────────────────────────────────
            log("INTAKE", f"Processing APK: {apk_name}")
            apk_analyzer = APKAnalyzer(apk_path)
            apk_data     = apk_analyzer.full_analyze()

            result["hashes"]       = apk_data["hashes"]
            result["structure"]    = apk_data["structure"]
            result["manifest"]     = apk_data["manifest"]
            result["certificates"] = apk_data["certificates"]
            result["strings"]      = apk_data["strings"]

            log("INTAKE", f"SHA-256: {result['hashes']['sha256']}")
            log("STRUCTURE", f"Files: {result['structure']['total_files']} | "
                             f"DEX: {len(result['structure']['dex_files'])} | "
                             f"Native libs: {len(result['structure']['native_libs'])}")
            log("MANIFEST", f"Package: {result['manifest'].get('package_name','?')} | "
                            f"Permissions: {len(result['manifest'].get('permissions',[]))}")

            # ── PHASE 2: Static Analysis ──────────────────────────────────────
            log("STATIC", "Running comprehensive static analysis...")
            static_engine = StaticAnalysisEngine(apk_path, apk_analyzer.dx_obj)
            static_data   = static_engine.analyze(result["manifest"], result["strings"])
            result["static_analysis"] = static_data

            log("STATIC", f"Critical APIs: {len(static_data['api_analysis']['critical_apis'])} | "
                          f"Vulnerabilities: {static_data['vulnerabilities']['total_vulnerabilities']} | "
                          f"Banking threat score: {static_data['banking_threats']['banking_risk_score']}")

            # ── PHASE 3: YARA Pattern Matching ────────────────────────────────
            log("YARA", "Running malware pattern recognition...")
            yara_engine  = YARAEngine(apk_path)
            yara_data    = yara_engine.scan()
            result["yara_analysis"] = yara_data

            log("YARA", f"Rules matched: {yara_data['rules_matched']}/{yara_data['total_rules_scanned']} | "
                        f"Families: {', '.join(yara_data['malware_families'][:3]) or 'None'} | "
                        f"APT: {yara_data['apt_detected']}")

            # ── PHASE 4: GenAI Reasoning ──────────────────────────────────────
            log("GENAI", "Invoking SriAI for semantic threat reasoning...")
            code_ctx = CodeContextBuilder(apk_path).build_context(
                result["static_analysis"], result["strings"]
            )
            genai_analysis = self.genai_engine.analyze_threat(
                apk_name, code_ctx, result["manifest"], yara_data
            )
            result["genai_analysis"] = genai_analysis

            log("GENAI", f"Threat type: {genai_analysis.get('primary_threat_type','?')} | "
                         f"Classification: {genai_analysis.get('threat_classification','?')} | "
                         f"Confidence: {genai_analysis.get('intelligence_confidence','?')}")

            # ── PHASE 5: Multi-dimensional Risk Scoring ───────────────────────
            log("SCORING", "Computing multi-dimensional risk score...")
            risk_data = self.risk_engine.compute(
                manifest  = result["manifest"],
                static    = result["static_analysis"],
                yara      = result["yara_analysis"],
                strings   = result["strings"],
                structure = result["structure"],
                certs     = result["certificates"],
                genai     = result["genai_analysis"],
            )
            result["risk_score"] = risk_data

            log("SCORING", f"FINAL SCORE: {risk_data['final_score']}/100 | "
                           f"SEVERITY: {risk_data['severity']} | "
                           f"Block recommended: {risk_data['immediate_block_recommended']}")

            # ── PHASE 6: Executive Summary (GenAI) ───────────────────────────
            log("REPORT", "Generating executive summary...")
            exec_summary = self.genai_engine.generate_executive_summary(
                apk_name       = apk_name,
                risk_score     = risk_data["final_score"],
                threat_analysis= genai_analysis,
                banking        = result["static_analysis"]["banking_threats"],
            )
            result["executive_summary"] = exec_summary

            # ── PHASE 7: Final Metadata ───────────────────────────────────────
            result["status"] = "COMPLETE"
            result["analysis_end"] = datetime.utcnow().isoformat() + "Z"
            result["duration_sec"]  = round(time.time() - start_time, 2)

            # Top-level summary card
            result["summary"] = {
                "risk_score"     : risk_data["final_score"],
                "severity"       : risk_data["severity"],
                "primary_family" : risk_data["primary_family"],
                "threat_type"    : genai_analysis.get("primary_threat_type", "Unknown"),
                "apt_detected"   : risk_data["apt_detected"],
                "nation_state"   : risk_data["nation_state"],
                "total_findings" : (
                    len(static_data["api_analysis"]["critical_apis"]) +
                    static_data["vulnerabilities"]["total_vulnerabilities"] +
                    yara_data["rules_matched"]
                ),
                "critical_vulns" : static_data["vulnerabilities"]["critical_count"],
                "dangerous_perms": len(result["manifest"].get("dangerous_permissions", [])),
                "c2_indicators"  : len(result["strings"].get("ips", [])) + len(result["strings"].get("urls", [])),
                "block_now"      : risk_data["immediate_block_recommended"],
                "cert_in_report" : risk_data["cert_in_report_required"],
            }

            log("COMPLETE", f"Analysis complete in {result['duration_sec']}s")

        except Exception as e:
            result["status"]   = "ERROR"
            result["error"]    = str(e)
            result["traceback"] = traceback.format_exc()
            result["analysis_end"] = datetime.utcnow().isoformat() + "Z"
            result["duration_sec"]  = round(time.time() - start_time, 2)
            log("ERROR", f"Pipeline error: {e}")

        return result

    def answer_question(self, question: str, analysis: dict) -> str:
        """Analyst Q&A — answer questions about a completed analysis"""
        return self.genai_engine.answer_analyst_question(question, analysis)
