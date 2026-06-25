"""
RAKSHAK — STIX 2.1 Threat Intelligence Exporter
Exports analysis results as STIX 2.1 bundles for CERT-In / MISP / OpenCTI
"""

import json, uuid
from datetime import datetime, timezone
from config import PLATFORM_NAME, PLATFORM_VERSION, ORGANISATION


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def export_stix(analysis: dict) -> dict:
    """
    Convert RAKSHAK analysis result to STIX 2.1 bundle.
    Compatible with CERT-In TAXII 2.1, MISP, OpenCTI, Elastic SIEM.
    """
    rs      = analysis.get("risk_score", {})
    gen     = analysis.get("genai_analysis", {})
    strings = analysis.get("strings", {})
    hashes  = analysis.get("hashes", {})
    yara    = analysis.get("yara_analysis", {})
    case_id = analysis.get("case_id", "UNKNOWN")
    apk     = analysis.get("apk_name", "unknown.apk")
    now     = _now()

    objects = []

    # ── Identity: RAKSHAK Platform ────────────────────────────────────────────
    identity_id = _stix_id("identity")
    objects.append({
        "type"            : "identity",
        "spec_version"    : "2.1",
        "id"              : identity_id,
        "created"         : now,
        "modified"        : now,
        "name"            : f"{PLATFORM_NAME} v{PLATFORM_VERSION}",
        "identity_class"  : "system",
        "description"     : f"Automated malware analysis by {ORGANISATION}",
    })

    # ── Malware Object ────────────────────────────────────────────────────────
    malware_id = _stix_id("malware")
    families   = yara.get("malware_families", [])
    mal_types  = _map_malware_types(families)

    objects.append({
        "type"             : "malware",
        "spec_version"     : "2.1",
        "id"               : malware_id,
        "created"          : now,
        "modified"         : now,
        "name"             : families[0] if families else "Unknown Android Malware",
        "description"      : gen.get("malicious_intent_summary", "Analysed by RAKSHAK"),
        "malware_types"    : mal_types,
        "is_family"        : len(families) > 0,
        "aliases"          : families[:5],
        "capabilities"     : gen.get("key_capabilities", [])[:10],
        "operating_system_refs": [],
        "labels"           : [f.lower().replace(" ", "-") for f in families[:3]],
    })

    # ── Indicator: APK File Hash ───────────────────────────────────────────────
    sha256 = hashes.get("sha256", "")
    if sha256:
        ind_hash_id = _stix_id("indicator")
        objects.append({
            "type"             : "indicator",
            "spec_version"     : "2.1",
            "id"               : ind_hash_id,
            "created"          : now,
            "modified"         : now,
            "name"             : f"APK SHA-256: {apk}",
            "description"      : f"SHA-256 hash of malicious APK '{apk}' — Case {case_id}",
            "indicator_types"  : ["malicious-activity", "file-hash-watchlist"],
            "pattern"          : f"[file:hashes.'SHA-256' = '{sha256}']",
            "pattern_type"     : "stix",
            "valid_from"       : now,
            "confidence"       : 90,
            "labels"           : ["android-malware", "apk"],
        })
        # Relationship: indicator → malware
        objects.append(_rel("indicates", ind_hash_id, malware_id, identity_id, now))

    # ── Indicators: Network IOCs (IPs) ────────────────────────────────────────
    for ip_entry in strings.get("ips", [])[:10]:
        ip = ip_entry.get("ip", "").split(":")[0]
        if not ip:
            continue
        ind_id = _stix_id("indicator")
        objects.append({
            "type"           : "indicator",
            "spec_version"   : "2.1",
            "id"             : ind_id,
            "created"        : now,
            "modified"       : now,
            "name"           : f"C2 IP: {ip}",
            "description"    : "Command & Control IP extracted from malicious APK",
            "indicator_types": ["malicious-activity", "compromised"],
            "pattern"        : f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ip}']",
            "pattern_type"   : "stix",
            "valid_from"     : now,
            "confidence"     : 80,
            "labels"         : ["c2", "android-malware"],
        })
        objects.append(_rel("indicates", ind_id, malware_id, identity_id, now))

    # ── Indicators: Network IOCs (URLs/Domains) ───────────────────────────────
    for url_entry in strings.get("urls", [])[:10]:
        url = url_entry.get("url", "")
        if not url:
            continue
        import re
        domain_match = re.search(r"https?://([^/?\s:]{4,})", url)
        domain = domain_match.group(1) if domain_match else ""
        if not domain:
            continue
        ind_id = _stix_id("indicator")
        objects.append({
            "type"           : "indicator",
            "spec_version"   : "2.1",
            "id"             : ind_id,
            "created"        : now,
            "modified"       : now,
            "name"           : f"C2 Domain/URL: {domain[:60]}",
            "description"    : f"C2 URL extracted from malicious APK. Risk: {url_entry.get('risk','')}",
            "indicator_types": ["malicious-activity"],
            "pattern"        : f"[domain-name:value = '{domain}']",
            "pattern_type"   : "stix",
            "valid_from"     : now,
            "confidence"     : 75,
            "labels"         : ["c2-url", "android-malware"],
        })
        objects.append(_rel("indicates", ind_id, malware_id, identity_id, now))

    # ── Attack Pattern (MITRE ATT&CK Mobile) ─────────────────────────────────
    for tech in rs.get("mitre_techniques", [])[:8]:
        ap_id = _stix_id("attack-pattern")
        objects.append({
            "type"          : "attack-pattern",
            "spec_version"  : "2.1",
            "id"            : ap_id,
            "created"       : now,
            "modified"      : now,
            "name"          : tech.get("name", tech.get("id", "")),
            "description"   : f"MITRE ATT&CK Mobile: {tech.get('id','')}",
            "external_references": [{
                "source_name": "mitre-attack-mobile",
                "external_id": tech.get("id", ""),
                "url"        : f"https://attack.mitre.org/techniques/{tech.get('id','').replace('.','/')}/",
            }],
        })
        objects.append(_rel("uses", malware_id, ap_id, identity_id, now))

    # ── Threat Actor (if APT detected) ────────────────────────────────────────
    if rs.get("apt_detected") or rs.get("nation_state"):
        apt_attr = gen.get("apt_attribution")
        ta_id    = _stix_id("threat-actor")
        objects.append({
            "type"              : "threat-actor",
            "spec_version"      : "2.1",
            "id"                : ta_id,
            "created"           : now,
            "modified"          : now,
            "name"              : apt_attr or "Unknown APT",
            "description"       : "Nation-state or APT threat actor attributed by RAKSHAK analysis",
            "threat_actor_types": ["nation-state"],
            "sophistication"    : "advanced",
            "resource_level"    : "government",
            "primary_motivation": "organizational-gain",
            "labels"            : ["apt", "nation-state"],
        })
        objects.append(_rel("attributed-to", malware_id, ta_id, identity_id, now))

    # ── Report Object ─────────────────────────────────────────────────────────
    report_id = _stix_id("report")
    all_ids   = [o["id"] for o in objects]
    objects.append({
        "type"          : "report",
        "spec_version"  : "2.1",
        "id"            : report_id,
        "created"       : now,
        "modified"      : now,
        "name"          : f"RAKSHAK Analysis: {apk} — {case_id}",
        "description"   : (
            f"RAKSHAK v{PLATFORM_VERSION} automated analysis of '{apk}'. "
            f"Risk Score: {rs.get('final_score',0)}/100 ({rs.get('severity','?')}). "
            f"Malware families: {', '.join(families[:3]) or 'Unknown'}. "
            f"Case ID: {case_id}."
        ),
        "published"     : now,
        "report_types"  : ["malware", "threat-actor", "indicator"],
        "object_refs"   : all_ids,
        "labels"        : ["android-malware", "india", "banking-fraud", "drdo"],
        "confidence"    : rs.get("final_score", 50),
        "external_references": [{
            "source_name": "RAKSHAK",
            "description": f"DRDO Cybersecurity Division — Case {case_id}",
        }],
    })

    bundle = {
        "type"         : "bundle",
        "id"           : _stix_id("bundle"),
        "spec_version" : "2.1",
        "created"      : now,
        "objects"      : objects,
    }

    return bundle


def _rel(rel_type: str, src: str, tgt: str, created_by: str, now: str) -> dict:
    return {
        "type"              : "relationship",
        "spec_version"      : "2.1",
        "id"                : _stix_id("relationship"),
        "created"           : now,
        "modified"          : now,
        "relationship_type" : rel_type,
        "source_ref"        : src,
        "target_ref"        : tgt,
        "created_by_ref"    : created_by,
    }


def _map_malware_types(families: list[str]) -> list[str]:
    banking    = {"BankBot","Cerberus","Anubis","FluBot","Drinik","IceSpy/AxBanker"}
    rat        = {"SpyNote/CypherRAT","AhMyth","Dendroid"}
    spyware    = {"Pegasus-Like Spyware","CallRecorder Spyware","Keylogger"}
    dropper    = {"APK Dropper","Malicious Packer"}
    ransomware = {"Android Ransomware"}
    miner      = {"CryptoMiner"}

    types = set()
    for f in families:
        if f in banking    : types.add("trojan")
        if f in rat        : types.add("remote-access-trojan")
        if f in spyware    : types.add("spyware")
        if f in dropper    : types.add("dropper")
        if f in ransomware : types.add("ransomware")
        if f in miner      : types.add("resource-exploitation")

    return list(types) if types else ["trojan"]
