"""
RAKSHAK — Certificate Transparency Monitor
Watches public CT logs in real-time for TLS certificates being issued
that impersonate Indian banking brands or government domains.
Alerts DRDO before phishing infrastructure is even deployed.
"""

import re, json, time, threading
from datetime import datetime, timezone
from typing import Callable
import requests

from config import INDIAN_BANK_BRANDS
from core.event_bus import emit, EventType


# ── Monitored brand keywords ───────────────────────────────────────────────────
MONITORED_TERMS = [
    # Indian banks
    "sbi", "statebank", "hdfc", "icici", "axis", "kotak", "yesbank",
    "pnb", "punjabnat", "bankofbaroda", "canara", "unionbank", "idfc",
    "indusind", "federalbank", "rbl", "bandhan",
    # Payment apps
    "paytm", "phonepe", "bhim", "gpay", "googlepay", "amazonpay",
    # Government
    "drdo", "isro", "gov-in", "nic-in", "incometax", "epfindia",
    # Fraud indicators
    "secure-login", "net-banking", "online-bank", "customer-care",
    "kyc-update", "reward-claim", "refund-portal",
]

# ── CT Log sources ─────────────────────────────────────────────────────────────
CT_SOURCES = [
    "https://crt.sh/?q={domain}&output=json",
    "https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
]


class CTLogMonitor:
    """
    Real-time Certificate Transparency log monitor.
    Polls crt.sh and CertSpotter for newly issued certificates
    matching monitored brand names.
    """

    def __init__(self):
        self.session   = requests.Session()
        self.session.headers.update({"User-Agent": "RAKSHAK-CTMonitor/3.0"})
        self._running  = False
        self._thread   : threading.Thread | None = None
        self._callbacks: list[Callable]           = []
        self._seen_ids : set[str]                 = set()

    def add_callback(self, fn: Callable):
        """Register a callback to receive alert dicts."""
        self._callbacks.append(fn)

    def _alert(self, alert: dict):
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    # ── One-shot domain search ────────────────────────────────────────────────
    def search_domain(self, domain_keyword: str, days_back: int = 7) -> list[dict]:
        """
        Search CT logs for certificates containing a keyword.
        Returns list of certificate records.
        """
        results  = []
        seen     = set()
        url = f"https://crt.sh/?q=%25{domain_keyword}%25&output=json"

        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs[:200]:
                    cert_id  = str(cert.get("id", ""))
                    if cert_id in seen:
                        continue
                    seen.add(cert_id)

                    names    = cert.get("name_value", "").lower()
                    issuer   = cert.get("issuer_name", "").lower()
                    logged   = cert.get("entry_timestamp", "")[:10]

                    # Score the certificate
                    risk_score, risk_reasons = self._score_cert(names, issuer)

                    results.append({
                        "cert_id"     : cert_id,
                        "domain_names": cert.get("name_value", ""),
                        "issuer"      : cert.get("issuer_name", ""),
                        "logged_date" : logged,
                        "not_before"  : cert.get("not_before", ""),
                        "not_after"   : cert.get("not_after",  ""),
                        "risk_score"  : risk_score,
                        "risk_reasons": risk_reasons,
                        "severity"    : "CRITICAL" if risk_score >= 70
                                        else "HIGH" if risk_score >= 40
                                        else "MEDIUM",
                    })
        except Exception as e:
            results.append({"error": str(e)})

        # Sort by risk score
        return sorted(
            [r for r in results if "error" not in r],
            key=lambda x: x["risk_score"], reverse=True
        )

    def _score_cert(self, names: str, issuer: str) -> tuple[int, list[str]]:
        """Score a certificate for phishing risk."""
        score   = 0
        reasons = []

        # Free CA issuers (phishing common)
        if "let's encrypt" in issuer or "zerossl" in issuer:
            score += 15
            reasons.append(f"Free CA: {issuer[:30]}")

        # Suspicious TLDs
        for tld in [".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".click"]:
            if tld in names:
                score += 25
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # Brand name in cert but not official domain
        for brand in MONITORED_TERMS:
            if brand in names and f"{brand}.com" not in names and f"{brand}.co.in" not in names:
                if any(kw in names for kw in ["-", "secure", "login", "bank", "verify"]):
                    score += 35
                    reasons.append(f"Brand impersonation: '{brand}' + suspicious keyword")
                else:
                    score += 20
                    reasons.append(f"Brand mention: '{brand}'")

        # Homograph / typosquat patterns
        for brand in ["sbi", "hdfc", "icici", "axis", "paytm"]:
            typos = [
                brand.replace("i", "1"), brand.replace("l", "1"),
                brand.replace("o", "0"), brand + "bank",
                brand + "secure", brand + "online",
            ]
            if any(t in names for t in typos):
                score += 40
                reasons.append(f"Typosquat of '{brand}' detected")

        # Government domain impersonation
        if any(g in names for g in ["gov-in", "nic-in", "drdo-", "isro-"]):
            score += 50
            reasons.append("Government domain impersonation")

        return min(score, 100), reasons[:5]

    # ── Bulk brand scan ───────────────────────────────────────────────────────
    def scan_all_brands(self, case_id: str = "") -> dict:
        """Scan all monitored brands and return consolidated threat report."""
        all_threats = []

        for brand in MONITORED_TERMS[:15]:  # Throttle requests
            certs = self.search_domain(brand, days_back=7)
            threats = [c for c in certs if c.get("risk_score", 0) >= 40]
            all_threats.extend(threats)

            for t in threats:
                if case_id:
                    emit(EventType.C2_FOUND, case_id, {
                        "type"     : "PHISHING_CERT",
                        "domain"   : t.get("domain_names", "")[:80],
                        "risk"     : t.get("risk_score", 0),
                        "reasons"  : t.get("risk_reasons", []),
                    }, severity=t.get("severity", "HIGH"))

            time.sleep(0.5)  # Rate limit

        # Deduplicate by cert ID
        seen     = set()
        unique   = []
        for t in all_threats:
            cid = t.get("cert_id", "")
            if cid not in seen:
                seen.add(cid)
                unique.append(t)

        return {
            "scan_timestamp"   : datetime.now(timezone.utc).isoformat(),
            "brands_scanned"   : len(MONITORED_TERMS[:15]),
            "total_threats"    : len(unique),
            "critical"         : [t for t in unique if t.get("severity") == "CRITICAL"],
            "high"             : [t for t in unique if t.get("severity") == "HIGH"],
            "all_threats"      : sorted(unique, key=lambda x: x.get("risk_score",0), reverse=True)[:30],
        }

    # ── Continuous background monitoring ──────────────────────────────────────
    def start_monitoring(self, interval_seconds: int = 300):
        """Start background thread polling CT logs every N seconds."""
        self._running = True
        self._thread  = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self._thread.start()
        print(f"[CT-MONITOR] Started — polling every {interval_seconds}s")

    def stop_monitoring(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[CT-MONITOR] Stopped")

    def _monitor_loop(self, interval: int):
        while self._running:
            try:
                results = self.scan_all_brands()
                critical = results.get("critical", [])
                if critical:
                    alert = {
                        "timestamp"     : datetime.now(timezone.utc).isoformat(),
                        "alert_type"    : "PHISHING_CERT_DETECTED",
                        "severity"      : "CRITICAL",
                        "count"         : len(critical),
                        "top_threat"    : critical[0] if critical else None,
                        "recommendation": "Block domains and alert banking security teams",
                    }
                    self._alert(alert)
            except Exception as e:
                print(f"[CT-MONITOR] Error: {e}")

            time.sleep(interval)


# ── Singleton monitor ─────────────────────────────────────────────────────────
ct_monitor = CTLogMonitor()
