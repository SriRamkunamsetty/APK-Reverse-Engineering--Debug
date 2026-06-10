"""
RAKSHAK — Network Intelligence Analyzer
C2 IP/domain enrichment: WHOIS · VirusTotal · AbuseIPDB · DNS · Geo-IP
Builds full threat actor infrastructure picture
"""

import re, socket, json
from datetime import datetime
from typing import Optional
import requests

from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY


# ── Known Malicious ASNs (bulletproof hosting, C2 infra) ─────────────────────
MALICIOUS_ASNS = {
    "AS60068" : ("Datacamp Limited", "Known bulletproof hosting"),
    "AS209588": ("Flyservers S.A.",  "Known C2 hosting"),
    "AS202425": ("IP Volume inc",    "Bulletproof / fraud infra"),
    "AS49581"  : ("Ferdinand Zink",  "Malware distribution hosting"),
    "AS42926" : ("Radore Hosting",   "C2 / botnet hosting"),
    "AS197414" : ("Aeza Group",      "Russian bulletproof hosting"),
    "AS9009"  : ("M247 Ltd",         "Known for hosting malware C2"),
}

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".pw",
                   ".top", ".click", ".loan", ".win", ".bid", ".stream"}

# ── Known C2 Patterns ─────────────────────────────────────────────────────────
C2_URL_PATTERNS = [
    r"/gate\.php", r"/panel/", r"/c2/", r"/bot/", r"/cmd/",
    r"/upload\.php", r"/recv\.php", r"/collect", r"/exfil",
    r"/check\.php", r"/ping\.php", r"/update\.php",
]


class NetworkAnalyzer:
    """
    RAKSHAK Network Intelligence Engine
    Enriches extracted URLs and IPs with threat context
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RAKSHAK-ThreatIntel/3.0"})

    # ════════════════════════════════════════════════════════════════════════
    # MASTER ENRICHMENT
    # ════════════════════════════════════════════════════════════════════════
    def analyze(self, urls: list[dict], ips: list[dict]) -> dict:
        result = {
            "enriched_ips"          : [],
            "enriched_urls"         : [],
            "c2_confirmed"          : [],
            "suspicious_domains"    : [],
            "threat_actor_infra"    : [],
            "geolocation_summary"   : {},
            "network_risk_score"    : 0,
            "infrastructure_report" : "",
        }

        total_risk = 0

        # Enrich IPs
        for ip_entry in ips[:15]:
            ip = ip_entry.get("ip", "").split(":")[0]
            if not self._is_valid_public_ip(ip):
                continue
            enriched = self._enrich_ip(ip)
            result["enriched_ips"].append(enriched)
            total_risk += enriched.get("risk_score", 0)
            if enriched.get("confirmed_malicious"):
                result["c2_confirmed"].append(ip)
            geo = enriched.get("country", "Unknown")
            result["geolocation_summary"][geo] = result["geolocation_summary"].get(geo, 0) + 1

        # Enrich URLs
        for url_entry in urls[:15]:
            url = url_entry.get("url", "")
            if not url:
                continue
            enriched = self._enrich_url(url)
            result["enriched_urls"].append(enriched)
            total_risk += enriched.get("risk_score", 0)
            if enriched.get("is_suspicious_domain"):
                result["suspicious_domains"].append(url[:80])
            if enriched.get("c2_pattern_match"):
                result["c2_confirmed"].append(url[:80])

        result["network_risk_score"] = min(total_risk, 100)
        result["infrastructure_report"] = self._build_infra_report(result)
        return result

    # ════════════════════════════════════════════════════════════════════════
    # IP ENRICHMENT
    # ════════════════════════════════════════════════════════════════════════
    def _enrich_ip(self, ip: str) -> dict:
        info = {
            "ip"                : ip,
            "hostname"          : "",
            "country"           : "Unknown",
            "city"              : "Unknown",
            "org"               : "Unknown",
            "asn"               : "",
            "is_tor"            : False,
            "is_datacenter"     : False,
            "abuse_score"       : 0,
            "vt_detections"     : 0,
            "vt_total"          : 0,
            "confirmed_malicious": False,
            "malicious_asn"     : False,
            "risk_score"        : 0,
            "intelligence_sources": [],
            "threat_tags"       : [],
        }

        # Reverse DNS
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        # ip-api (free geo-IP with ASN)
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,org,as,hosting,proxy",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    info["country"]       = data.get("country", "Unknown")
                    info["city"]          = data.get("city", "Unknown")
                    info["org"]           = data.get("org", "Unknown")
                    info["asn"]           = data.get("as", "")
                    info["is_datacenter"] = data.get("hosting", False)
                    info["is_proxy"]      = data.get("proxy", False)
                    info["intelligence_sources"].append("ip-api")
        except Exception:
            pass

        # Check against known malicious ASNs
        for asn, (name, reason) in MALICIOUS_ASNS.items():
            if asn in info.get("asn", ""):
                info["malicious_asn"]    = True
                info["confirmed_malicious"] = True
                info["threat_tags"].append(f"Malicious ASN: {name} — {reason}")
                info["risk_score"] += 35

        # VirusTotal IP lookup
        if VIRUSTOTAL_API_KEY:
            vt_result = self._vt_ip_lookup(ip)
            info["vt_detections"]    = vt_result.get("malicious", 0)
            info["vt_total"]         = vt_result.get("total", 0)
            if vt_result.get("malicious", 0) > 3:
                info["confirmed_malicious"] = True
                info["threat_tags"].append(f"VirusTotal: {vt_result['malicious']} engines flagged")
                info["risk_score"] += min(vt_result.get("malicious", 0) * 4, 40)
            info["intelligence_sources"].append("VirusTotal")

        # AbuseIPDB
        if ABUSEIPDB_API_KEY:
            abuse = self._abuseipdb_check(ip)
            info["abuse_score"] = abuse.get("abuseConfidenceScore", 0)
            if abuse.get("abuseConfidenceScore", 0) > 50:
                info["confirmed_malicious"] = True
                info["threat_tags"].append(f"AbuseIPDB confidence: {abuse['abuseConfidenceScore']}%")
                info["risk_score"] += 20
            info["intelligence_sources"].append("AbuseIPDB")

        # Tor exit node heuristic
        if "tor" in info.get("org", "").lower() or "exit" in info.get("hostname", "").lower():
            info["is_tor"] = True
            info["threat_tags"].append("Possible Tor exit node")
            info["risk_score"] += 15

        # Datacenter penalty (C2s rarely use residential IPs)
        if info["is_datacenter"]:
            info["risk_score"] += 10
            info["threat_tags"].append("Datacenter IP — common C2 hosting")

        info["risk_score"] = min(info["risk_score"], 100)
        return info

    # ════════════════════════════════════════════════════════════════════════
    # URL ENRICHMENT
    # ════════════════════════════════════════════════════════════════════════
    def _enrich_url(self, url: str) -> dict:
        info = {
            "url"                  : url[:150],
            "domain"               : "",
            "tld"                  : "",
            "is_suspicious_tld"    : False,
            "is_suspicious_domain" : False,
            "c2_pattern_match"     : False,
            "matched_c2_patterns"  : [],
            "domain_age_days"      : None,
            "vt_detections"        : 0,
            "ip_resolved"          : "",
            "risk_score"           : 0,
            "threat_tags"          : [],
        }

        # Extract domain
        domain_match = re.search(r"https?://([^/?\s:]+)", url, re.IGNORECASE)
        if domain_match:
            info["domain"] = domain_match.group(1).lower()
            parts = info["domain"].split(".")
            info["tld"] = "." + parts[-1] if len(parts) > 1 else ""

        # Check suspicious TLD
        if info["tld"] in SUSPICIOUS_TLDS:
            info["is_suspicious_tld"]    = True
            info["is_suspicious_domain"] = True
            info["threat_tags"].append(f"Suspicious TLD: {info['tld']}")
            info["risk_score"] += 20

        # Direct IP URL
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            info["is_suspicious_domain"] = True
            info["threat_tags"].append("Direct IP URL — bypasses DNS monitoring")
            info["risk_score"] += 25

        # C2 URL pattern matching
        for pattern in C2_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                info["c2_pattern_match"] = True
                info["matched_c2_patterns"].append(pattern)
                info["threat_tags"].append(f"C2 pattern: {pattern}")
                info["risk_score"] += 15

        # Tunneling / temporary services
        tunnel_services = ["ngrok.io", "serveo.net", "localhost.run",
                           "pagekite.me", "tunnel.us.com", "bore.pub"]
        if any(svc in url for svc in tunnel_services):
            info["is_suspicious_domain"] = True
            info["threat_tags"].append("Tunneling service — evades static C2 detection")
            info["risk_score"] += 30

        # Dynamic DNS
        ddns = ["duckdns.org", "ddns.net", "no-ip.org", "hopto.org",
                "myftp.biz", "3utilities.com", "bounceme.net"]
        if any(d in url for d in ddns):
            info["threat_tags"].append("Dynamic DNS — C2 infrastructure common")
            info["risk_score"] += 20

        # Telegram Bot API (C2 channel)
        if "api.telegram.org/bot" in url:
            info["c2_pattern_match"] = True
            info["threat_tags"].append("Telegram Bot API — covert C2 channel")
            info["risk_score"] += 35

        # Paste sites (config delivery)
        paste_sites = ["pastebin.com", "paste.ee", "hastebin.com",
                       "controlc.com", "ghostbin.co", "paste.sh"]
        if any(p in url for p in paste_sites):
            info["threat_tags"].append("Paste site — remote config / payload delivery")
            info["risk_score"] += 20

        # VirusTotal URL scan
        if VIRUSTOTAL_API_KEY and info["domain"]:
            vt = self._vt_domain_lookup(info["domain"])
            info["vt_detections"] = vt.get("malicious", 0)
            if vt.get("malicious", 0) > 2:
                info["threat_tags"].append(f"VirusTotal: {vt['malicious']} engines flagged domain")
                info["risk_score"] += min(vt.get("malicious", 0) * 5, 30)

        # DNS resolve attempt
        try:
            if info["domain"]:
                info["ip_resolved"] = socket.gethostbyname(info["domain"])
        except Exception:
            pass

        info["risk_score"] = min(info["risk_score"], 100)
        return info

    # ════════════════════════════════════════════════════════════════════════
    # THREAT INTEL API WRAPPERS
    # ════════════════════════════════════════════════════════════════════════
    def _vt_ip_lookup(self, ip: str) -> dict:
        try:
            resp = self.session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {})
                return {
                    "malicious"  : stats.get("malicious", 0),
                    "suspicious" : stats.get("suspicious", 0),
                    "total"      : sum(stats.values()),
                }
        except Exception:
            pass
        return {}

    def _vt_domain_lookup(self, domain: str) -> dict:
        try:
            resp = self.session.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {})
                return {"malicious": stats.get("malicious", 0),
                        "total"    : sum(stats.values())}
        except Exception:
            pass
        return {}

    def _abuseipdb_check(self, ip: str) -> dict:
        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json().get("data", {})
        except Exception:
            pass
        return {}

    # ════════════════════════════════════════════════════════════════════════
    # INFRASTRUCTURE REPORT
    # ════════════════════════════════════════════════════════════════════════
    def _build_infra_report(self, result: dict) -> str:
        lines = []
        c2s = result.get("c2_confirmed", [])
        if c2s:
            lines.append(f"CONFIRMED C2 INFRASTRUCTURE ({len(c2s)} indicators):")
            for c in c2s[:5]:
                lines.append(f"  • {c}")
        geo = result.get("geolocation_summary", {})
        if geo:
            lines.append(f"THREAT ACTOR GEOLOCATION: {', '.join(f'{c}({n})' for c, n in geo.items())}")
        score = result.get("network_risk_score", 0)
        lines.append(f"NETWORK RISK SCORE: {score}/100")
        return "\n".join(lines)

    @staticmethod
    def _is_valid_public_ip(ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            nums = [int(p) for p in parts]
            if any(n < 0 or n > 255 for n in nums):
                return False
            # Skip private/loopback
            if nums[0] in (10, 127) or (nums[0] == 192 and nums[1] == 168):
                return False
            if nums[0] == 172 and 16 <= nums[1] <= 31:
                return False
            return True
        except Exception:
            return False
