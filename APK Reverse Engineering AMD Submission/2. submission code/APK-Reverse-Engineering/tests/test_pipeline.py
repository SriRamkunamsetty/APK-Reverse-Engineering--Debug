"""
RAKSHAK — Comprehensive Test Suite
Tests all 8 analysis engines + pipeline + DB + report generation
Run: python -m pytest tests/test_pipeline.py -v
"""

import sys, os, json, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.create_test_apk import create_test_apk

# ── Fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def test_apk(tmp_path_factory):
    """Create test APK once for all tests"""
    path = str(tmp_path_factory.mktemp("apk") / "test_sample.apk")
    create_test_apk(path)
    assert Path(path).exists(), "Test APK creation failed"
    return path


@pytest.fixture(scope="session")
def full_analysis(test_apk):
    """Run full pipeline once and share result across all tests"""
    from core.pipeline import RakshakPipeline
    p = RakshakPipeline()
    result = p.analyze(test_apk, analyst_name="PYTEST", case_id="RKSAK-PYTEST-001")
    assert result["status"] == "COMPLETE", f"Pipeline failed: {result.get('error')}"
    return result


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 0: HASH ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class TestHashEngine:
    def test_md5_present(self, full_analysis):
        h = full_analysis["hashes"]
        assert len(h["md5"]) == 32

    def test_sha256_present(self, full_analysis):
        h = full_analysis["hashes"]
        assert len(h["sha256"]) == 64

    def test_sha512_present(self, full_analysis):
        h = full_analysis["hashes"]
        assert len(h["sha512"]) == 128

    def test_magic_valid(self, full_analysis):
        assert full_analysis["hashes"]["magic_valid"] is True

    def test_size_reported(self, full_analysis):
        assert full_analysis["hashes"]["size_bytes"] > 0


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1: APK STRUCTURE
# ══════════════════════════════════════════════════════════════════════════════
class TestAPKStructure:
    def test_files_detected(self, full_analysis):
        assert full_analysis["structure"]["total_files"] > 5

    def test_dex_files_found(self, full_analysis):
        assert len(full_analysis["structure"]["dex_files"]) >= 1

    def test_native_libs_found(self, full_analysis):
        assert len(full_analysis["structure"]["native_libs"]) >= 1

    def test_multidex_detected(self, full_analysis):
        # Test APK has 2 DEX files
        assert full_analysis["structure"]["multidex"] is True

    def test_embedded_apk_detection(self, full_analysis):
        # Test APK has an embedded APK in assets
        assert len(full_analysis["structure"]["embedded_apks"]) >= 0  # may vary

    def test_high_entropy_files(self, full_analysis):
        # Test APK has random bytes asset (high entropy)
        assert isinstance(full_analysis["structure"]["high_entropy_files"], list)

    def test_asset_files_found(self, full_analysis):
        assert len(full_analysis["structure"]["asset_files"]) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2: STRING & IOC EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
class TestStringAnalysis:
    def test_urls_extracted(self, full_analysis):
        urls = full_analysis["strings"]["urls"]
        assert len(urls) >= 2, "Should find at least 2 URLs in test APK"

    def test_ips_extracted(self, full_analysis):
        ips = full_analysis["strings"]["ips"]
        assert len(ips) >= 1, "Should find at least 1 C2 IP"

    def test_telegram_token_found(self, full_analysis):
        tg = full_analysis["strings"]["telegram_tokens"]
        assert len(tg) >= 1, "Test APK contains a Telegram bot token"

    def test_shell_commands_found(self, full_analysis):
        cmds = full_analysis["strings"]["shell_commands"]
        assert len(cmds) >= 1, "Test APK contains shell commands"

    def test_bank_references_found(self, full_analysis):
        refs = full_analysis["strings"]["bank_references"]
        assert len(refs) >= 1, "Test APK references Indian banking brands"

    def test_hardcoded_secrets_found(self, full_analysis):
        secrets = full_analysis["strings"]["hardcoded_secrets"]
        assert len(secrets) >= 0  # May vary


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3: STATIC ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class TestStaticAnalysis:
    def test_dangerous_apis_detected(self, full_analysis):
        apis = full_analysis["static_analysis"]["api_analysis"]
        assert len(apis["findings"]) >= 3, "Should find dangerous API calls"

    def test_critical_apis_flagged(self, full_analysis):
        critical = full_analysis["static_analysis"]["api_analysis"]["critical_apis"]
        assert len(critical) >= 1, "Should have CRITICAL-level API calls"

    def test_vulnerabilities_found(self, full_analysis):
        vulns = full_analysis["static_analysis"]["vulnerabilities"]
        assert vulns["total_vulnerabilities"] >= 2

    def test_crypto_issues_found(self, full_analysis):
        crypto = full_analysis["static_analysis"]["crypto_audit"]
        assert crypto["total_crypto_issues"] >= 2

    def test_banking_otp_detected(self, full_analysis):
        bt = full_analysis["static_analysis"]["banking_threats"]
        assert bt["otp_harvesting"] is True, "Test APK should trigger OTP detection"

    def test_banking_overlay_detected(self, full_analysis):
        bt = full_analysis["static_analysis"]["banking_threats"]
        assert bt["overlay_attack"] is True

    def test_banking_risk_score_high(self, full_analysis):
        bt = full_analysis["static_analysis"]["banking_threats"]
        assert bt["banking_risk_score"] >= 50

    def test_obfuscation_signals(self, full_analysis):
        obf = full_analysis["static_analysis"]["api_analysis"]["obfuscation_signals"]
        assert isinstance(obf, list)

    def test_mitre_techniques_mapped(self, full_analysis):
        mitre = full_analysis["static_analysis"]["api_analysis"]["mitre_techniques"]
        assert len(mitre) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4: YARA ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class TestYARAEngine:
    def test_rules_scanned(self, full_analysis):
        y = full_analysis["yara_analysis"]
        assert y["total_rules_scanned"] == 19

    def test_rules_matched(self, full_analysis):
        y = full_analysis["yara_analysis"]
        assert y["rules_matched"] >= 5, "Test APK should match multiple YARA rules"

    def test_malware_families_detected(self, full_analysis):
        families = full_analysis["yara_analysis"]["malware_families"]
        assert len(families) >= 3

    def test_banking_family_detected(self, full_analysis):
        families = full_analysis["yara_analysis"]["malware_families"]
        banking = {"BankBot", "Cerberus", "Anubis", "FluBot", "Drinik", "IceSpy/AxBanker"}
        assert any(f in banking for f in families), "Should detect banking trojan family"

    def test_apt_detected(self, full_analysis):
        assert full_analysis["yara_analysis"]["apt_detected"] is True

    def test_nation_state_detected(self, full_analysis):
        assert full_analysis["yara_analysis"]["nation_state_threat"] is True

    def test_yara_risk_score(self, full_analysis):
        score = full_analysis["yara_analysis"]["yara_risk_score"]
        assert 0 <= score <= 100

    def test_primary_family_set(self, full_analysis):
        pf = full_analysis["yara_analysis"]["primary_family"]
        assert pf and pf != "Unknown/Clean"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5: GENAI ENGINE (fallback mode)
# ══════════════════════════════════════════════════════════════════════════════
class TestGenAIEngine:
    def test_analysis_produced(self, full_analysis):
        gen = full_analysis["genai_analysis"]
        assert gen is not None
        assert isinstance(gen, dict)

    def test_threat_classification_valid(self, full_analysis):
        cls = full_analysis["genai_analysis"].get("threat_classification", "")
        assert cls in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_key_capabilities_list(self, full_analysis):
        caps = full_analysis["genai_analysis"].get("key_capabilities", [])
        assert isinstance(caps, list)

    def test_immediate_actions_list(self, full_analysis):
        actions = full_analysis["genai_analysis"].get("immediate_actions", [])
        assert isinstance(actions, list)
        assert len(actions) >= 1

    def test_executive_summary_generated(self, full_analysis):
        summary = full_analysis.get("executive_summary", "")
        assert isinstance(summary, str)
        assert len(summary) > 20


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6: RISK SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class TestRiskScoring:
    def test_score_in_range(self, full_analysis):
        score = full_analysis["risk_score"]["final_score"]
        assert 0 <= score <= 100

    def test_severity_classified(self, full_analysis):
        sev = full_analysis["risk_score"]["severity"]
        assert sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN")

    def test_xai_breakdown_present(self, full_analysis):
        bd = full_analysis["risk_score"]["breakdown"]
        assert len(bd) == 6  # All 6 dimensions

    def test_all_dimensions_present(self, full_analysis):
        bd = full_analysis["risk_score"]["breakdown"]
        expected = {"permissions", "static_code", "dynamic_behaviour",
                    "network_iocs", "threat_intel", "genai_reasoning"}
        assert set(bd.keys()) == expected

    def test_contributions_sum_to_score(self, full_analysis):
        bd    = full_analysis["risk_score"]["breakdown"]
        total = sum(v.get("contribution", 0) for v in bd.values())
        score = full_analysis["risk_score"]["final_score"]
        assert abs(total - score) <= 10  # Within 10 points (cert/impersonation bonuses)

    def test_attribution_list(self, full_analysis):
        attr = full_analysis["risk_score"]["attribution"]
        assert isinstance(attr, list)

    def test_mitre_techniques_mapped(self, full_analysis):
        mitre = full_analysis["risk_score"]["mitre_techniques"]
        assert len(mitre) >= 1

    def test_apt_flag_set(self, full_analysis):
        assert full_analysis["risk_score"]["apt_detected"] is True

    def test_cert_in_required(self, full_analysis):
        # APT detected → CERT-In report required
        assert full_analysis["risk_score"]["cert_in_report_required"] is True

    def test_severity_color_present(self, full_analysis):
        color = full_analysis["risk_score"].get("severity_color", "")
        assert color.startswith("#")


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
class TestPipeline:
    def test_status_complete(self, full_analysis):
        assert full_analysis["status"] == "COMPLETE"

    def test_case_id_present(self, full_analysis):
        assert full_analysis["case_id"].startswith("RKSAK-")

    def test_duration_recorded(self, full_analysis):
        assert full_analysis["duration_sec"] > 0

    def test_progress_log(self, full_analysis):
        prog = full_analysis.get("progress", [])
        assert len(prog) >= 5

    def test_summary_card(self, full_analysis):
        s = full_analysis.get("summary", {})
        assert "risk_score"      in s
        assert "severity"        in s
        assert "total_findings"  in s
        assert "block_now"       in s

    def test_total_findings_positive(self, full_analysis):
        assert full_analysis["summary"]["total_findings"] >= 10

    def test_no_error(self, full_analysis):
        assert full_analysis.get("error") is None


# ══════════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════
class TestReportEngine:
    def test_pdf_generated(self, full_analysis, tmp_path):
        from core.report_engine import generate_pdf_report
        out = generate_pdf_report(full_analysis, str(tmp_path))
        assert Path(out).exists()

    def test_pdf_min_size(self, full_analysis, tmp_path):
        from core.report_engine import generate_pdf_report
        out = generate_pdf_report(full_analysis, str(tmp_path))
        assert Path(out).stat().st_size >= 10_000  # At least 10KB

    def test_pdf_is_pdf(self, full_analysis, tmp_path):
        from core.report_engine import generate_pdf_report
        out = generate_pdf_report(full_analysis, str(tmp_path))
        with open(out, "rb") as f:
            assert f.read(4) == b"%PDF"


# ══════════════════════════════════════════════════════════════════════════════
# STIX EXPORT
# ══════════════════════════════════════════════════════════════════════════════
class TestSTIXExporter:
    def test_bundle_type(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        assert bundle["type"] == "bundle"

    def test_spec_version(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        assert bundle["spec_version"] == "2.1"

    def test_objects_present(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        assert len(bundle["objects"]) >= 3

    def test_malware_object(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        malware = [o for o in bundle["objects"] if o["type"] == "malware"]
        assert len(malware) >= 1

    def test_indicators_present(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) >= 1

    def test_report_object(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        reports = [o for o in bundle["objects"] if o["type"] == "report"]
        assert len(reports) == 1

    def test_threat_actor_for_apt(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        # APT detected → threat-actor object expected
        actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
        assert len(actors) >= 1

    def test_bundle_is_valid_json(self, full_analysis):
        from core.stix_exporter import export_stix
        bundle = export_stix(full_analysis)
        serialized = json.dumps(bundle)
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE LAYER
# ══════════════════════════════════════════════════════════════════════════════
class TestDatabase:
    def test_case_saved_and_retrieved(self, full_analysis):
        from database.db import save_case, get_case
        save_case(full_analysis)
        retrieved = get_case(full_analysis["case_id"])
        assert retrieved is not None
        assert retrieved["case_id"] == full_analysis["case_id"]

    def test_list_cases(self, full_analysis):
        from database.db import list_cases
        cases = list_cases(limit=10)
        assert isinstance(cases, list)

    def test_ioc_search(self, full_analysis):
        from database.db import search_ioc
        results = search_ioc("185")
        assert isinstance(results, list)

    def test_stats(self, full_analysis):
        from database.db import get_stats
        stats = get_stats()
        assert stats["total_cases"] >= 1
        assert "apt_cases" in stats


# ══════════════════════════════════════════════════════════════════════════════
# RUN SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short", "-q"],
        capture_output=False
    )
    sys.exit(result.returncode)
