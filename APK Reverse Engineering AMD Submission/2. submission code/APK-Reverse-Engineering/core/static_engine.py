"""
RAKSHAK — Static Analysis Engine
Dangerous API mapping, taint analysis, vulnerability scanner, code pattern detection
"""

import re, zipfile, os
from pathlib import Path
from typing import Any
from config import DANGEROUS_API_PATTERNS, DANGEROUS_PERMISSIONS, MITRE_TECHNIQUES


# ══════════════════════════════════════════════════════════════════════════════
# DANGEROUS API CALL SCANNER
# ══════════════════════════════════════════════════════════════════════════════
class APICallScanner:
    """Scans decompiled smali bytecode for every dangerous API call"""

    def __init__(self, apk_path: str, dx: Any = None):
        self.apk_path = apk_path
        self.dx = dx

    def scan(self) -> dict:
        result = {
            "findings"          : [],
            "critical_apis"     : [],
            "high_apis"         : [],
            "medium_apis"       : [],
            "total_risk_score"  : 0,
            "mitre_techniques"  : [],
            "obfuscation_signals": [],
            "reflection_calls"  : [],
            "dynamic_loading"   : [],
        }

        raw_code = self._extract_smali_code()
        smali_lines = self._get_smali_lines()

        # ── Scan against dangerous API pattern database ───────────────────────
        seen_patterns = set()
        for pattern, (severity, score, description) in DANGEROUS_API_PATTERNS.items():
            regex = re.compile(pattern, re.IGNORECASE)
            matches_in_code = []
            for line in smali_lines:
                if regex.search(line):
                    matches_in_code.append(line.strip()[:120])
            if matches_in_code:
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    finding = {
                        "api"          : pattern,
                        "severity"     : severity,
                        "risk_score"   : score,
                        "description"  : description,
                        "occurrences"  : len(matches_in_code),
                        "sample_calls" : matches_in_code[:3],
                        "mitre"        : self._map_to_mitre(pattern),
                    }
                    result["findings"].append(finding)
                    result["total_risk_score"] = min(result["total_risk_score"] + score, 100)
                    if severity == "CRITICAL":
                        result["critical_apis"].append(pattern)
                    elif severity == "HIGH":
                        result["high_apis"].append(pattern)
                    else:
                        result["medium_apis"].append(pattern)

        # ── Reflection & dynamic loading ──────────────────────────────────────
        reflection_patterns = [
            r"Class\.forName\s*\(",
            r"getDeclaredMethod\s*\(",
            r"getMethod\s*\(",
            r"\.invoke\s*\(",
            r"getDeclaredField\s*\(",
            r"setAccessible\s*\(true\)",
        ]
        for pat in reflection_patterns:
            matches = re.findall(pat, raw_code, re.IGNORECASE)
            if matches:
                result["reflection_calls"].append({
                    "pattern": pat,
                    "count"  : len(matches),
                    "risk"   : "Evades static analysis — hides true API calls"
                })

        dynamic_patterns = [
            r"DexClassLoader\s*\(",
            r"PathClassLoader\s*\(",
            r"InMemoryDexClassLoader\s*\(",
            r"BaseDexClassLoader\s*\(",
            r"dalvik\.system",
        ]
        for pat in dynamic_patterns:
            matches = re.findall(pat, raw_code, re.IGNORECASE)
            if matches:
                result["dynamic_loading"].append({
                    "pattern": pat,
                    "count"  : len(matches),
                    "risk"   : "Runtime DEX loading — dropper/loader behaviour"
                })

        # ── Obfuscation signals ───────────────────────────────────────────────
        result["obfuscation_signals"] = self._detect_obfuscation(smali_lines, raw_code)

        # ── MITRE technique compilation ───────────────────────────────────────
        all_mitre = set()
        for f in result["findings"]:
            if f.get("mitre"):
                all_mitre.add(f["mitre"])
        result["mitre_techniques"] = [
            {"id": t, "name": MITRE_TECHNIQUES.get(t, "Unknown")}
            for t in all_mitre
        ]

        return result

    def _extract_smali_code(self) -> str:
        """Extract all raw bytes from DEX files as string"""
        code = ""
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        data = zf.read(name)
                        printable = re.findall(b'[\x20-\x7e]{4,}', data)
                        code += " ".join(p.decode("ascii", errors="ignore") for p in printable)
        except Exception:
            pass
        return code

    def _get_smali_lines(self) -> list[str]:
        """Get smali-like lines from raw DEX string extraction"""
        raw = self._extract_smali_code()
        return [line for line in raw.split() if line]

    def _detect_obfuscation(self, lines: list[str], raw_code: str) -> list[dict]:
        signals = []

        # Short class/method names (ProGuard pattern)
        short_names = [l for l in lines if re.match(r'^[a-z]{1,3}$', l)]
        if len(short_names) > 50:
            signals.append({
                "type"       : "Name Obfuscation (ProGuard/R8)",
                "evidence"   : f"{len(short_names)} single/double-letter identifiers found",
                "severity"   : "HIGH",
                "description": "Obfuscated class/method names prevent static analysis"
            })

        # String encryption patterns
        if re.search(r'AES|Cipher\.getInstance', raw_code, re.IGNORECASE):
            signals.append({
                "type"       : "String Encryption",
                "evidence"   : "AES/Cipher usage suggests runtime string decryption",
                "severity"   : "HIGH",
                "description": "Strings encrypted at rest — decrypted only at runtime"
            })

        # XOR obfuscation
        xor_count = raw_code.count("xor") + raw_code.count("XOR")
        if xor_count > 20:
            signals.append({
                "type"       : "XOR Obfuscation",
                "evidence"   : f"{xor_count} XOR operations detected",
                "severity"   : "MEDIUM",
                "description": "XOR commonly used to encrypt strings/payloads"
            })

        # Base64 encoded strings
        b64_count = len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', raw_code))
        if b64_count > 5:
            signals.append({
                "type"       : "Base64 Encoded Content",
                "evidence"   : f"{b64_count} base64 blobs found",
                "severity"   : "MEDIUM",
                "description": "Content hidden behind base64 encoding"
            })

        # Anti-debugging patterns
        anti_debug = ["isDebuggerConnected", "Debug.isDebuggerConnected",
                      "TracerPid", "PPID", "android.os.Debug"]
        found_anti = [p for p in anti_debug if p in raw_code]
        if found_anti:
            signals.append({
                "type"       : "Anti-Debugging",
                "evidence"   : f"Patterns: {', '.join(found_anti)}",
                "severity"   : "HIGH",
                "description": "Detects and evades analysis tools/debuggers"
            })

        # Emulator detection
        emu_patterns = ["Build.FINGERPRINT", "generic", "Genymotion",
                        "BlueStacks", "QEMU", "goldfish", "ro.kernel.qemu"]
        found_emu = [p for p in emu_patterns if p in raw_code]
        if found_emu:
            signals.append({
                "type"       : "Emulator Detection",
                "evidence"   : f"Patterns: {', '.join(found_emu[:3])}",
                "severity"   : "HIGH",
                "description": "APK checks if running in emulator — evades sandbox analysis"
            })

        return signals

    def _map_to_mitre(self, pattern: str) -> str:
        mapping = {
            "DexClassLoader"         : "T1406",
            "Runtime.exec"           : "T1404",
            "onAccessibilityEvent"   : "T1417",
            "addView.*OVERLAY"       : "T1417",
            "sendTextMessage"        : "T1582",
            "getRunningTasks"        : "T1424",
            "getSubscriberId"        : "T1422",
            "AudioRecord"            : "T1429",
            "Camera.open"            : "T1512",
            "requestAdminForDevice"  : "T1629",
            "ClipboardManager"       : "T1414",
            "ContentResolver.*sms"   : "T1636",
            "ContentResolver.*contacts": "T1636",
            "setComponentEnabledSetting": "T1508",
        }
        for key, technique in mapping.items():
            if re.search(key, pattern, re.IGNORECASE):
                return technique
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNER
# ══════════════════════════════════════════════════════════════════════════════
class VulnerabilityScanner:
    """CVE-mapped vulnerability detection in APK code"""

    VULNS = [
        {
            "id"         : "RAKSHAK-001",
            "name"       : "Insecure Data Storage — SharedPreferences",
            "pattern"    : r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
            "severity"   : "HIGH",
            "cve"        : "CWE-312",
            "description": "Sensitive data stored in world-readable SharedPreferences",
            "remediation": "Use EncryptedSharedPreferences or MODE_PRIVATE",
        },
        {
            "id"         : "RAKSHAK-002",
            "name"       : "SQL Injection in ContentProvider",
            "pattern"    : r'rawQuery\s*\([^)]*\+|execSQL\s*\([^)]*\+',
            "severity"   : "HIGH",
            "cve"        : "CWE-89",
            "description": "String concatenation in SQL query — injection vulnerable",
            "remediation": "Use parameterized queries with ? placeholders",
        },
        {
            "id"         : "RAKSHAK-003",
            "name"       : "WebView JavaScript Interface RCE",
            "pattern"    : r'addJavascriptInterface\s*\(',
            "severity"   : "CRITICAL",
            "cve"        : "CVE-2012-6636",
            "description": "WebView JS bridge exposes Java objects to JavaScript — RCE on Android < 4.2",
            "remediation": "Set targetSdkVersion >= 17, use @JavascriptInterface annotation",
        },
        {
            "id"         : "RAKSHAK-004",
            "name"       : "SSL Certificate Validation Disabled",
            "pattern"    : r'checkServerTrusted|onReceivedSslError.*proceed|ALLOW_ALL_HOSTNAME',
            "severity"   : "CRITICAL",
            "cve"        : "CWE-295",
            "description": "SSL/TLS certificate validation bypassed — MITM attacks possible",
            "remediation": "Never override SSL validation; implement proper certificate pinning",
        },
        {
            "id"         : "RAKSHAK-005",
            "name"       : "Cleartext HTTP Traffic",
            "pattern"    : r'http://(?!localhost|127\.0\.0\.1)',
            "severity"   : "HIGH",
            "cve"        : "CWE-319",
            "description": "Application transmits data over unencrypted HTTP",
            "remediation": "Enforce HTTPS; set cleartextTrafficPermitted=false in network config",
        },
        {
            "id"         : "RAKSHAK-006",
            "name"       : "Weak Cryptography — ECB Mode",
            "pattern"    : r'AES/ECB|DES/ECB|Cipher\.getInstance\("AES"\)',
            "severity"   : "HIGH",
            "cve"        : "CWE-327",
            "description": "ECB mode reveals patterns in encrypted data",
            "remediation": "Use AES/GCM/NoPadding or AES/CBC with random IV",
        },
        {
            "id"         : "RAKSHAK-007",
            "name"       : "Hardcoded Cryptographic Key",
            "pattern"    : r'(?:SecretKeySpec|SecretKey).*(?:["\'][A-Za-z0-9+/]{16,}["\'])',
            "severity"   : "CRITICAL",
            "cve"        : "CWE-321",
            "description": "Cryptographic key hardcoded in source — trivially extractable",
            "remediation": "Use Android Keystore System for key storage",
        },
        {
            "id"         : "RAKSHAK-008",
            "name"       : "Fragment Injection",
            "pattern"    : r'PreferenceActivity|isValidFragment',
            "severity"   : "HIGH",
            "cve"        : "CVE-2013-6272",
            "description": "PreferenceActivity vulnerable to fragment injection on Android < 4.4",
            "remediation": "Override isValidFragment() to return false or upgrade SDK",
        },
        {
            "id"         : "RAKSHAK-009",
            "name"       : "Path Traversal in File Operations",
            "pattern"    : r'openFileInput\s*\([^)]*\+|new File\s*\([^)]*\.\.',
            "severity"   : "HIGH",
            "cve"        : "CWE-22",
            "description": "File path constructed from external input — directory traversal",
            "remediation": "Validate and sanitize file paths; use getCanonicalPath()",
        },
        {
            "id"         : "RAKSHAK-010",
            "name"       : "Insecure Random Number Generator",
            "pattern"    : r'new Random\(\)|Math\.random\(\)',
            "severity"   : "MEDIUM",
            "cve"        : "CWE-330",
            "description": "java.util.Random is not cryptographically secure",
            "remediation": "Use SecureRandom for security-sensitive randomness",
        },
        {
            "id"         : "RAKSHAK-011",
            "name"       : "Exported Component Without Permission",
            "pattern"    : r'android:exported="true"(?!.*android:permission)',
            "severity"   : "HIGH",
            "cve"        : "CWE-926",
            "description": "Component exported without permission — any app can access",
            "remediation": "Add android:permission or set android:exported=false",
        },
        {
            "id"         : "RAKSHAK-012",
            "name"       : "Implicit Broadcast Receiver",
            "pattern"    : r'registerReceiver\s*\([^,]+,\s*new IntentFilter',
            "severity"   : "MEDIUM",
            "cve"        : "CWE-925",
            "description": "Unprotected broadcast receiver — intent hijacking possible",
            "remediation": "Use LocalBroadcastManager or specify permission in registerReceiver",
        },
        {
            "id"         : "RAKSHAK-013",
            "name"       : "External Storage Sensitive Data",
            "pattern"    : r'getExternalStorage|Environment\.DIRECTORY',
            "severity"   : "HIGH",
            "cve"        : "CWE-312",
            "description": "Sensitive data written to world-readable external storage",
            "remediation": "Use app-private internal storage (getFilesDir())",
        },
        {
            "id"         : "RAKSHAK-014",
            "name"       : "Debug Mode Enabled in Production",
            "pattern"    : r'android:debuggable="true"',
            "severity"   : "HIGH",
            "cve"        : "CWE-489",
            "description": "Application has debugging enabled — allows ADB access and code injection",
            "remediation": "Remove android:debuggable or set to false in release builds",
        },
        {
            "id"         : "RAKSHAK-015",
            "name"       : "Intent Injection via Pending Intent",
            "pattern"    : r'PendingIntent\.getActivity\s*\([^)]*null[^)]*\)',
            "severity"   : "HIGH",
            "cve"        : "CWE-927",
            "description": "Mutable PendingIntent with null/empty base intent — hijackable",
            "remediation": "Always specify explicit action and component in base intent",
        },
    ]

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self._raw_code = None

    def _get_code(self) -> str:
        if self._raw_code is None:
            code = ""
            try:
                with zipfile.ZipFile(self.apk_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith((".dex", ".xml")) or name.startswith("assets/"):
                            try:
                                data = zf.read(name)
                                found = re.findall(b'[\x20-\x7e]{4,}', data)
                                code += " ".join(p.decode("ascii", errors="ignore") for p in found) + "\n"
                            except Exception:
                                pass
            except Exception:
                pass
            self._raw_code = code
        return self._raw_code

    def scan(self) -> dict:
        code = self._get_code()
        findings = []
        total_score = 0

        for vuln in self.VULNS:
            if re.search(vuln["pattern"], code, re.IGNORECASE | re.DOTALL):
                score = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(vuln["severity"], 5)
                findings.append({
                    **vuln,
                    "risk_score" : score,
                    "confirmed"  : True,
                })
                total_score += score

        return {
            "total_vulnerabilities" : len(findings),
            "critical_count"        : sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count"            : sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium_count"          : sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "total_risk_score"      : min(total_score, 100),
            "findings"              : findings,
            "cwe_ids"               : list({f["cve"] for f in findings}),
        }


# ══════════════════════════════════════════════════════════════════════════════
# CRYPTO AUDIT ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class CryptoAuditor:
    """Detects weak, broken, or misused cryptographic implementations"""

    def audit(self, apk_path: str) -> dict:
        code = ""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        data = zf.read(name)
                        printable = re.findall(b'[\x20-\x7e]{4,}', data)
                        code += " ".join(p.decode("ascii", errors="ignore") for p in printable)
        except Exception:
            pass

        issues = []

        checks = [
            (r'MD5',                 "CRITICAL", "MD5 used for security — cryptographically broken"),
            (r'SHA-?1\b',            "HIGH",     "SHA-1 deprecated for security use since 2017"),
            (r'DES\b',               "CRITICAL", "DES cipher — 56-bit key, easily brute-forced"),
            (r'3DES|DESede',         "HIGH",     "Triple-DES — deprecated, use AES"),
            (r'RC4|ARCFOUR',         "CRITICAL", "RC4 cipher — broken, prohibited in TLS 1.3"),
            (r'ECB',                 "HIGH",     "ECB mode — identical plaintext → identical ciphertext"),
            (r'new Random\(\)',      "HIGH",     "java.util.Random — not cryptographically secure"),
            (r'SecretKeySpec.*hardcoded|hardcoded.*SecretKeySpec',
                                     "CRITICAL", "Hardcoded encryption key in source"),
            (r'TrustAllCerts|TRUST_ALL|trustAll',
                                     "CRITICAL", "Trust-all SSL certificates — disables TLS security"),
            (r'SSLContext\.getInstance\("SSL"\)',
                                     "HIGH",     "Obsolete SSL protocol — use TLSv1.3"),
            (r'setHostnameVerifier.*ALLOW_ALL',
                                     "CRITICAL", "All hostnames trusted — MITM vulnerability"),
            (r'NullCipher',          "CRITICAL", "NullCipher provides no encryption whatsoever"),
        ]

        for pattern, severity, description in checks:
            if re.search(pattern, code, re.IGNORECASE):
                issues.append({
                    "pattern"    : pattern,
                    "severity"   : severity,
                    "description": description,
                    "risk_score" : {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8}.get(severity, 5),
                })

        return {
            "total_crypto_issues": len(issues),
            "issues"             : issues,
            "ssl_pinning_present": bool(re.search(r'CertificatePinner|TrustManagerFactory', code)),
            "keystore_used"      : bool(re.search(r'AndroidKeyStore|KeyStore\.getInstance', code)),
            "total_risk_score"   : min(sum(i["risk_score"] for i in issues), 100),
        }


# ══════════════════════════════════════════════════════════════════════════════
# BANKING THREAT DETECTOR (India-specific)
# ══════════════════════════════════════════════════════════════════════════════
class BankingThreatDetector:
    """Specialized detector for Indian banking fraud patterns"""

    @staticmethod
    def _raw_dex_scan(apk_path: str) -> str:
        """Extract all printable strings from DEX for direct pattern matching"""
        code = ""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex") or name == "AndroidManifest.xml":
                        try:
                            data = zf.read(name)
                            found = re.findall(b'[\x20-\x7e]{4,}', data)
                            code += " ".join(p.decode("ascii", errors="ignore") for p in found)
                        except Exception:
                            pass
        except Exception:
            pass
        return code

    def detect(self, apk_path: str, manifest: dict, strings: dict) -> dict:
        result = {
            "otp_harvesting"         : False,
            "upi_fraud_indicators"   : [],
            "overlay_attack"         : False,
            "brand_impersonation"    : [],
            "sms_forward_patterns"   : [],
            "accessibility_abuse"    : False,
            "banking_app_targeting"  : [],
            "fraud_kill_chain"       : [],
            "banking_risk_score"     : 0,
        }

        score = 0

        # OTP harvesting detection — check manifest permissions AND raw DEX scan (fallback)
        perms        = [p["permission"] for p in manifest.get("dangerous_permissions", [])]
        raw_code     = self._raw_dex_scan(apk_path)  # Direct DEX string scan fallback

        def has_perm(perm_name: str, *extra_patterns: str) -> bool:
            if f"android.permission.{perm_name}" in perms:
                return True
            if perm_name in raw_code:
                return True
            return any(p in raw_code for p in extra_patterns)

        has_sms_read = has_perm("READ_SMS", "getMessageBody", "SmsMessage", "content://sms")
        has_sms_recv = has_perm("RECEIVE_SMS", "onReceive", "SMS_RECEIVED", "abortBroadcast")
        has_overlay  = has_perm("SYSTEM_ALERT_WINDOW", "TYPE_APPLICATION_OVERLAY",
                                "TYPE_SYSTEM_OVERLAY", "WindowManager.LayoutParams")
        has_access   = has_perm("BIND_ACCESSIBILITY_SERVICE", "onAccessibilityEvent",
                                "AccessibilityNodeInfo", "performAction")

        if has_sms_read or has_sms_recv:
            result["otp_harvesting"] = True
            score += 30
            result["fraud_kill_chain"].append({
                "stage"      : "HARVEST",
                "indicator"  : "SMS read permission → OTP interception",
                "mitre"      : "T1412 — Capture SMS Messages"
            })

        # UPI fraud patterns
        upi_terms = ["upi", "bhim", "phonepe", "gpay", "paytm", "neft", "imps",
                     "vpa", "transaction", "pin", "mpin"]
        bank_refs  = " ".join(strings.get("bank_references", [])).lower()
        url_str    = " ".join(u.get("url","") for u in strings.get("urls", [])).lower()

        for term in upi_terms:
            if term in bank_refs or term in url_str:
                result["upi_fraud_indicators"].append(term)
                score += 5

        # Overlay attack
        if has_overlay or has_access:
            result["overlay_attack"] = True
            score += 25
            result["fraud_kill_chain"].append({
                "stage"      : "ATTACK",
                "indicator"  : "Overlay/Accessibility → fake banking login screen",
                "mitre"      : "T1417 — Input Capture via Accessibility"
            })

        # Brand impersonation from strings
        for ref in strings.get("bank_references", []):
            result["brand_impersonation"].append(ref[:80])
            score += 10

        # SMS forwarding
        sms_urls = [u for u in strings.get("urls", []) if "sms" in u.get("url","").lower()]
        if sms_urls:
            result["sms_forward_patterns"] = sms_urls
            score += 20
            result["fraud_kill_chain"].append({
                "stage"      : "EXFIL",
                "indicator"  : f"SMS forwarding to {len(sms_urls)} remote URL(s)",
                "mitre"      : "T1582 — SMS Control"
            })

        # Accessibility abuse
        if has_access:
            result["accessibility_abuse"] = True
            score += 20
            result["fraud_kill_chain"].append({
                "stage"      : "PERSIST",
                "indicator"  : "Accessibility service — survives app close, automates UI",
                "mitre"      : "T1625 — Hijack Execution Flow"
            })

        # Banking app targeting
        from config import INDIAN_BANK_BRANDS
        targeting = []
        for brand in INDIAN_BANK_BRANDS:
            if brand in bank_refs:
                targeting.append(brand)
        result["banking_app_targeting"] = targeting[:10]
        if targeting:
            score += 15
            result["fraud_kill_chain"].append({
                "stage"      : "LURE",
                "indicator"  : f"Targets brands: {', '.join(targeting[:5])}",
                "mitre"      : "T1444 — Masquerade as Legitimate App"
            })

        result["banking_risk_score"] = min(score, 100)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# MASTER STATIC ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class StaticAnalysisEngine:
    """Orchestrates all static analysis modules"""

    def __init__(self, apk_path: str, dx: Any = None):
        self.apk_path = apk_path
        self.dx = dx

    def analyze(self, manifest: dict, strings: dict) -> dict:
        print("[RAKSHAK] Running dangerous API scan...")
        api_scan = APICallScanner(self.apk_path, self.dx).scan()

        print("[RAKSHAK] Running vulnerability scanner...")
        vuln_scan = VulnerabilityScanner(self.apk_path).scan()

        print("[RAKSHAK] Running crypto audit...")
        crypto = CryptoAuditor().audit(self.apk_path)

        print("[RAKSHAK] Running banking threat detector...")
        banking = BankingThreatDetector().detect(self.apk_path, manifest, strings)

        return {
            "api_analysis"         : api_scan,
            "vulnerabilities"      : vuln_scan,
            "crypto_audit"         : crypto,
            "banking_threats"      : banking,
            "static_summary"       : {
                "critical_apis"        : len(api_scan["critical_apis"]),
                "total_vulnerabilities": vuln_scan["total_vulnerabilities"],
                "crypto_issues"        : crypto["total_crypto_issues"],
                "obfuscation_detected" : len(api_scan["obfuscation_signals"]) > 0,
                "banking_threat_level" : "CRITICAL" if banking["banking_risk_score"] > 60
                                        else "HIGH" if banking["banking_risk_score"] > 35
                                        else "MEDIUM",
            }
        }
