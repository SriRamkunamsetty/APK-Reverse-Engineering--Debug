"""
RAKSHAK — MISP Threat Intelligence Integration
Bidirectional sync with MISP / CERT-In national threat intelligence platform.
Auto-push new IOCs from analysis. Auto-import global threat feeds.
"""

import json, hashlib, re
from datetime import datetime, timezone
from typing import Optional
import requests

from config import BASE_DIR
from core.event_bus import emit, EventType


class MISPClient:
    """
    MISP 2.4+ REST API client for RAKSHAK threat intelligence sharing.
    Compatible with: MISP, OpenCTI (TAXII), CERT-In national platform.
    """

    def __init__(self, url: str = "", api_key: str = ""):
        self.url     = url.rstrip("/") if url else ""
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": self.api_key,
            "Accept"       : "application/json",
            "Content-Type" : "application/json",
        })
        self.available = bool(url and api_key)

    # ── Health check ──────────────────────────────────────────────────────────
    def ping(self) -> bool:
        if not self.available:
            return False
        try:
            resp = self.session.get(f"{self.url}/users/view/me",
                                    timeout=5, verify=False)
            return resp.status_code == 200
        except Exception:
            return False

    # ── Create MISP event from RAKSHAK analysis ───────────────────────────────
    def push_analysis(self, analysis: dict, case_id: str = "") -> dict:
        """
        Convert RAKSHAK analysis result into a full MISP event
        and push to the configured MISP instance.
        """
        if not self.available:
            return self._simulate_push(analysis)

        rs      = analysis.get("risk_score", {})
        hashes  = analysis.get("hashes",     {})
        strings = analysis.get("strings",    {})
        yara    = analysis.get("yara_analysis", {})
        gen     = analysis.get("genai_analysis", {})

        severity_map = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0
        }
        threat_level = severity_map.get(rs.get("severity", "MEDIUM"), 2)

        # Build MISP event
        event = {
            "Event": {
                "info"         : f"RAKSHAK: {analysis.get('apk_name','Unknown')} — {rs.get('severity','?')}",
                "distribution" : 1,           # Organisation only (DRDO internal)
                "threat_level_id": str(threat_level),
                "analysis"     : "2",          # Completed
                "date"         : datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "tags"         : [
                    {"name": "android-malware"},
                    {"name": "india"},
                    {"name": f"family:{f}" for f in yara.get("malware_families", [])[:3]},
                ],
                "Attribute"    : self._build_attributes(analysis),
            }
        }

        try:
            resp = self.session.post(
                f"{self.url}/events",
                json    = event,
                timeout = 15,
                verify  = False,
            )
            if resp.status_code in (200, 201):
                misp_event = resp.json()
                event_id   = misp_event.get("Event", {}).get("id", "?")
                if case_id:
                    emit(EventType.REPORT_READY, case_id, {
                        "type"    : "MISP_EVENT",
                        "event_id": event_id,
                        "url"     : f"{self.url}/events/view/{event_id}",
                    })
                return {"success": True, "event_id": event_id,
                        "url": f"{self.url}/events/view/{event_id}"}
            return {"success": False, "error": resp.text[:200]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _build_attributes(self, analysis: dict) -> list[dict]:
        """Build MISP attributes (IOCs) from RAKSHAK analysis."""
        attrs = []
        h     = analysis.get("hashes",  {})
        s     = analysis.get("strings", {})
        gen   = analysis.get("genai_analysis", {})

        # File hashes
        if h.get("md5"):
            attrs.append(self._attr("md5",     h["md5"],    "Malicious APK MD5"))
        if h.get("sha256"):
            attrs.append(self._attr("sha256",  h["sha256"], "Malicious APK SHA-256"))

        # Network IOCs
        for ip in s.get("ips", [])[:10]:
            attrs.append(self._attr("ip-dst", ip.get("ip", ""), "C2 IP Address"))

        for url in s.get("urls", [])[:10]:
            u = url.get("url", "")
            if u:
                attrs.append(self._attr("url", u[:200], "C2 URL"))
                # Extract domain too
                m = re.search(r"https?://([^/?\s:]+)", u)
                if m:
                    attrs.append(self._attr("domain", m.group(1), "C2 Domain"))

        # Telegram bot tokens
        for token in s.get("telegram_tokens", []):
            attrs.append(self._attr("text", f"TG:{token}", "Telegram C2 Bot Token"))

        # Package name
        pkg = analysis.get("manifest", {}).get("package_name", "")
        if pkg:
            attrs.append(self._attr("text", pkg, "Malicious APK package name"))

        # GenAI summary as comment
        summary = gen.get("malicious_intent_summary", "")
        if summary:
            attrs.append(self._attr("comment", summary[:500], "RAKSHAK AI Analysis"))

        # MITRE techniques as tags
        for tech in analysis.get("risk_score", {}).get("mitre_techniques", []):
            attrs.append(self._attr("text",
                f"MITRE: {tech['id']} — {tech['name']}", "MITRE ATT&CK Mobile"))

        return attrs

    @staticmethod
    def _attr(type_: str, value: str, comment: str = "") -> dict:
        return {
            "type"          : type_,
            "value"         : value,
            "comment"       : comment,
            "to_ids"        : True,
            "distribution"  : 1,
        }

    def _simulate_push(self, analysis: dict) -> dict:
        """Simulated MISP push when server not configured."""
        attrs  = self._build_attributes(analysis)
        rs     = analysis.get("risk_score", {})
        return {
            "success"      : True,
            "simulated"    : True,
            "event_summary": {
                "title"      : f"RAKSHAK: {analysis.get('apk_name','?')} — {rs.get('severity','?')}",
                "ioc_count"  : len(attrs),
                "families"   : analysis.get("yara_analysis",{}).get("malware_families",[]),
                "threat_level": rs.get("severity","?"),
                "attributes" : attrs[:5],
            },
            "note": "Configure MISP_URL and MISP_API_KEY env vars for live push to CERT-In",
        }

    # ── Import threat feeds ───────────────────────────────────────────────────
    def pull_ioc_feed(self, feed_url: str = "") -> dict:
        """Pull IOC feed from MISP and return as list of indicators."""
        if not self.available:
            return {"available": False, "iocs": []}
        try:
            resp = self.session.get(
                f"{self.url}/attributes/restSearch",
                json    = {"type": ["ip-dst","domain","url","md5","sha256"],
                           "last": "7d", "to_ids": True},
                timeout = 15,
                verify  = False,
            )
            if resp.status_code == 200:
                data = resp.json()
                iocs = [
                    {"type" : a.get("type"),
                     "value": a.get("value"),
                     "tags" : [t.get("name","") for t in a.get("Tag", [])]}
                    for a in data.get("response", {}).get("Attribute", [])[:100]
                ]
                return {"available": True, "ioc_count": len(iocs), "iocs": iocs}
        except Exception as e:
            return {"available": False, "error": str(e)}
        return {"available": False}


# ── Singleton (configure via env vars) ───────────────────────────────────────
import os
misp_client = MISPClient(
    url     = os.getenv("MISP_URL",     ""),
    api_key = os.getenv("MISP_API_KEY", ""),
)
