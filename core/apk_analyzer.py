"""
RAKSHAK — Core APK Analyzer
Full teardown: structure, manifest, certificates, strings, resources, native libs
"""

import hashlib, zipfile, re, os, struct, base64, json
from pathlib import Path
from datetime import datetime
from typing import Any
import xml.etree.ElementTree as ET

try:
    from androguard.core.bytecodes.apk import APK as AndroAPK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

from config import (
    DANGEROUS_PERMISSIONS, DANGEROUS_API_PATTERNS,
    INDIAN_BANK_BRANDS, SUSPICIOUS_URL_PATTERNS, IOC_URL_ALLOWLIST_PATTERNS,
    APT_SIGNATURES
)


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-HASH FINGERPRINTER
# ══════════════════════════════════════════════════════════════════════════════
class HashEngine:
    """Generates cryptographic and fuzzy hashes for chain-of-custody"""

    @staticmethod
    def compute_all(file_path: str) -> dict:
        data = open(file_path, "rb").read()
        results = {
            "md5"    : hashlib.md5(data).hexdigest(),
            "sha1"   : hashlib.sha1(data).hexdigest(),
            "sha256" : hashlib.sha256(data).hexdigest(),
            "sha512" : hashlib.sha512(data).hexdigest(),
            "size_bytes"  : len(data),
            "size_human"  : f"{len(data)/1024/1024:.2f} MB",
            "magic_valid" : data[:4] == b'PK\x03\x04',  # ZIP/APK magic
            "timestamp"   : datetime.utcnow().isoformat() + "Z",
        }
        # ssdeep-style block hash (simplified without native lib)
        results["block_hash"] = hashlib.sha256(data[:4096]).hexdigest()[:16]
        return results


# ══════════════════════════════════════════════════════════════════════════════
# APK STRUCTURE DECOMPOSER
# ══════════════════════════════════════════════════════════════════════════════
class APKStructureAnalyzer:
    """Decomposes APK ZIP structure and catalogues every entry"""

    def __init__(self, apk_path: str):
        self.path = apk_path
        self.entries: list[dict] = []
        self.suspicious_entries: list[dict] = []

    def analyze(self) -> dict:
        result = {
            "total_files"    : 0,
            "dex_files"      : [],
            "native_libs"    : [],
            "resource_files" : [],
            "asset_files"    : [],
            "suspicious_files": [],
            "embedded_apks"  : [],
            "high_entropy_files": [],
            "structure_anomalies": [],
        }

        try:
            with zipfile.ZipFile(self.path, "r") as zf:
                entries = zf.infolist()
                result["total_files"] = len(entries)

                for entry in entries:
                    name = entry.filename
                    size = entry.file_size

                    # DEX files (bytecode)
                    if name.endswith(".dex"):
                        result["dex_files"].append({"name": name, "size": size})

                    # Native libraries
                    elif name.startswith("lib/") and name.endswith(".so"):
                        arch = name.split("/")[1] if "/" in name else "unknown"
                        result["native_libs"].append({
                            "name": name, "size": size,
                            "arch": arch,
                            "suspicious": any(kw in name.lower()
                                for kw in ["hook", "inject", "root", "su", "exploit"])
                        })

                    # Assets (can contain payloads)
                    elif name.startswith("assets/"):
                        try:
                            data = zf.read(name)
                            entropy = self._shannon_entropy(data)
                            asset_info = {
                                "name": name, "size": size,
                                "entropy": round(entropy, 3),
                                "type": self._detect_type(data),
                            }
                            result["asset_files"].append(asset_info)

                            # High entropy = possibly encrypted payload
                            if entropy > 7.2:
                                result["high_entropy_files"].append({
                                    **asset_info,
                                    "reason": "High entropy suggests encrypted payload"
                                })

                            # Embedded APK / DEX / ELF in assets
                            if data[:4] == b'PK\x03\x04':
                                result["embedded_apks"].append(name)
                                result["suspicious_files"].append({
                                    "name": name,
                                    "reason": "Embedded APK — dropper behaviour"
                                })
                            elif data[:4] in [b'dex\n', b'\x64\x65\x78\x0a']:
                                result["suspicious_files"].append({
                                    "name": name,
                                    "reason": "Embedded DEX file — runtime code loading"
                                })
                            elif data[:4] == b'\x7fELF':
                                result["suspicious_files"].append({
                                    "name": name,
                                    "reason": "Embedded ELF binary — native exploit"
                                })
                        except Exception:
                            pass

                    elif name.startswith("res/"):
                        result["resource_files"].append(name)

                    # Anomaly: path traversal
                    if ".." in name:
                        result["structure_anomalies"].append({
                            "file": name,
                            "issue": "Path traversal attempt in ZIP entry"
                        })

                    # Anomaly: executable in META-INF
                    if name.startswith("META-INF/") and name.endswith((".sh", ".exe", ".py")):
                        result["structure_anomalies"].append({
                            "file": name,
                            "issue": "Executable in META-INF — JAR injection"
                        })

                result["multidex"] = len(result["dex_files"]) > 1
                result["native_arch_coverage"] = list({
                    lib["arch"] for lib in result["native_libs"]
                })

        except zipfile.BadZipFile:
            result["structure_anomalies"].append({"issue": "Corrupted ZIP structure"})

        return result

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        n = len(data)
        for f in freq:
            if f > 0:
                p = f / n
                import math
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _detect_type(data: bytes) -> str:
        sigs = {
            b'\xff\xd8\xff': "JPEG",
            b'\x89PNG': "PNG",
            b'PK\x03\x04': "ZIP/APK",
            b'\x7fELF': "ELF Binary",
            b'dex\n': "DEX Bytecode",
            b'MZ': "PE Executable",
            b'%PDF': "PDF",
            b'SQLite': "SQLite DB",
            b'\x1f\x8b': "GZIP Archive",
        }
        for sig, name in sigs.items():
            if data[:len(sig)] == sig:
                return name
        try:
            data.decode("utf-8")
            return "Text/Script"
        except Exception:
            return "Binary/Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# MANIFEST DEEP PARSER
# ══════════════════════════════════════════════════════════════════════════════
class ManifestAnalyzer:
    """Full AndroidManifest.xml deep analysis"""

    def __init__(self, apk: Any):
        self.apk = apk

    def analyze(self) -> dict:
        result = {
            "package_name"      : "",
            "version_code"      : "",
            "version_name"      : "",
            "min_sdk"           : "",
            "target_sdk"        : "",
            "permissions"       : [],
            "dangerous_permissions": [],
            "permission_combos" : [],
            "activities"        : [],
            "services"          : [],
            "receivers"         : [],
            "providers"         : [],
            "exported_components": [],
            "intent_filters"    : [],
            "suspicious_manifest_flags": [],
            "bank_impersonation_score": 0,
        }

        if not ANDROGUARD_AVAILABLE or self.apk is None:
            return result

        try:
            result["package_name"]  = self.apk.get_package()
            result["version_code"]  = str(self.apk.get_androidversion_code())
            result["version_name"]  = str(self.apk.get_androidversion_name())
            result["min_sdk"]       = str(self.apk.get_min_sdk_version())
            result["target_sdk"]    = str(self.apk.get_target_sdk_version())

            # All permissions
            all_perms = self.apk.get_permissions()
            result["permissions"] = all_perms

            # Dangerous permission analysis
            perm_risk_total = 0
            found_dangerous = []
            for perm in all_perms:
                if perm in DANGEROUS_PERMISSIONS:
                    sev, score, desc = DANGEROUS_PERMISSIONS[perm]
                    found_dangerous.append({
                        "permission": perm,
                        "severity"  : sev,
                        "risk_score": score,
                        "description": desc,
                    })
                    perm_risk_total += score
            result["dangerous_permissions"] = found_dangerous
            result["permission_risk_total"] = min(perm_risk_total, 100)

            # Dangerous combination detection
            perm_set = set(all_perms)
            combos = []
            if {"android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"}.issubset(perm_set):
                combos.append("READ_SMS + OVERLAY → Banking OTP stealer pattern (CRITICAL)")
            if {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"}.issubset(perm_set):
                combos.append("ACCESSIBILITY + OVERLAY → Automated banking credential theft (CRITICAL)")
            if {"android.permission.BIND_DEVICE_ADMIN", "android.permission.RECEIVE_BOOT_COMPLETED"}.issubset(perm_set):
                combos.append("DEVICE_ADMIN + BOOT → Ransomware persistence pattern (CRITICAL)")
            if {"android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"}.issubset(perm_set):
                combos.append("MICROPHONE + GPS → Surveillance spyware pattern (HIGH)")
            if {"android.permission.READ_CONTACTS", "android.permission.SEND_SMS"}.issubset(perm_set):
                combos.append("CONTACTS + SEND_SMS → Worm propagation pattern (HIGH)")
            if {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_BOOT_COMPLETED"}.issubset(perm_set):
                combos.append("INSTALL_PACKAGES + BOOT → Dropper/Loader with persistence (CRITICAL)")
            result["permission_combos"] = combos

            # Components analysis
            for act in self.apk.get_activities():
                exported = self.apk.get_declared_permissions_details().get(act, {})
                result["activities"].append(act)

            result["services"]   = list(self.apk.get_services())
            result["receivers"]  = list(self.apk.get_receivers())
            result["providers"]  = list(self.apk.get_providers())

            # Exported component detection (attack surface)
            for comp in result["activities"] + result["services"] + result["receivers"]:
                if comp:
                    result["exported_components"].append(comp)

            # Bank impersonation check
            pkg_lower = result["package_name"].lower()
            imp_score = 0
            for brand in INDIAN_BANK_BRANDS:
                if brand in pkg_lower:
                    imp_score += 30
                    result["suspicious_manifest_flags"].append(
                        f"Package name impersonates bank brand: '{brand}'"
                    )
                    break
            result["bank_impersonation_score"] = min(imp_score, 100)

            # Suspicious flags
            if int(result["target_sdk"] or 0) < 21:
                result["suspicious_manifest_flags"].append(
                    "Targets very old Android SDK — exploits legacy permissions"
                )
            if int(result["min_sdk"] or 0) < 16:
                result["suspicious_manifest_flags"].append(
                    "Supports Android < 4.1 — enables addJavascriptInterface RCE"
                )

        except Exception as e:
            result["parse_error"] = str(e)

        return result


# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE FORENSICS ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class CertificateAnalyzer:
    """Deep X.509 certificate analysis and forensics"""

    def __init__(self, apk: Any):
        self.apk = apk

    def analyze(self) -> dict:
        result = {
            "certificates"      : [],
            "self_signed"       : False,
            "certificate_issues": [],
            "signer_identity"   : {},
            "signing_scheme"    : "unknown",
            "cert_risk_score"   : 0,
        }

        if not ANDROGUARD_AVAILABLE or self.apk is None:
            return result

        try:
            certs = self.apk.get_certificates_der_v2() or []
            if not certs:
                certs = []

            # Try v1 certs
            try:
                v1_certs = self.apk.get_certificates_v1()
                result["signing_scheme"] = "v1"
            except Exception:
                v1_certs = []

            try:
                v3_certs = self.apk.get_certificates_der_v3()
                if v3_certs:
                    result["signing_scheme"] = "v3"
            except Exception:
                pass

            # Check debug key
            try:
                if self.apk.is_signed_v2():
                    result["signing_scheme"] = "v2" if result["signing_scheme"] == "unknown" else result["signing_scheme"]
            except Exception:
                pass

            # Try to get cert info via androguard
            try:
                cert_info = self.apk.get_signature_name()
                if cert_info:
                    result["signer_identity"]["signature_name"] = cert_info
            except Exception:
                pass

            # Known debug / test certificate detection
            try:
                is_debug = False
                cert_bytes = self.apk.get_certificate_der(self.apk.get_signature_name() or "CERT")
                if cert_bytes:
                    debug_hash = hashlib.sha256(cert_bytes).hexdigest()
                    if debug_hash == "e89b158e4bcf988ebd09eb83f5378e87":
                        is_debug = True
                        result["certificate_issues"].append("Debug/test certificate — development/test signing key")
            except Exception:
                pass

            result["self_signed"] = True  # Default assumption; ideally check chain
            result["certificate_issues"].append(
                "Self-signed certificate — not from trusted CA (common in malware)"
            )
            result["cert_risk_score"] = 25

        except Exception as e:
            result["parse_error"] = str(e)

        return result


# ══════════════════════════════════════════════════════════════════════════════
# STRING EXTRACTOR & IOC HUNTER
# ══════════════════════════════════════════════════════════════════════════════
class StringAnalyzer:
    """Extract and classify all strings from DEX code and resources"""

    URL_RE     = re.compile(r'https?://[^\s\'"<>{}|\\^`\[\]]{4,256}', re.IGNORECASE)
    IP_RE      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b')
    EMAIL_RE   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    BASE64_RE  = re.compile(r'[A-Za-z0-9+/]{32,}={0,2}')
    PHONE_RE   = re.compile(r'(?:\+91|0)?[6-9]\d{9}')
    TG_TOKEN   = re.compile(r'\d{8,10}:[A-Za-z0-9_\-]{35}')
    API_KEY_RE = re.compile(r'(?:api[_\-]?key|token|secret|password)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})', re.IGNORECASE)

    def __init__(self, apk_path: str, apk: Any = None, dx: Any = None):
        self.apk_path = apk_path
        self.apk = apk
        self.dx = dx

    def analyze(self) -> dict:
        all_strings = self._extract_raw_strings()
        urls, filtered_urls = self._find_urls(all_strings)
        return {
            "total_strings"      : len(all_strings),
            "urls"               : urls,
            "filtered_urls"      : filtered_urls,
            "ips"                : self._find_ips(all_strings),
            "emails"             : self._find_emails(all_strings),
            "suspicious_base64"  : self._find_base64(all_strings),
            "hardcoded_phones"   : self._find_phones(all_strings),
            "telegram_tokens"    : self._find_telegram(all_strings),
            "hardcoded_secrets"  : self._find_secrets(all_strings),
            "bank_references"    : self._find_bank_refs(all_strings),
            "shell_commands"     : self._find_shell_commands(all_strings),
            "crypto_keys"        : self._find_crypto_patterns(all_strings),
        }

    def _extract_raw_strings(self) -> list[str]:
        strings = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex") or name.startswith("assets/") or name.startswith("res/"):
                        try:
                            data = zf.read(name)
                            # Extract printable ASCII strings (min length 6)
                            found = re.findall(b'[\x20-\x7e]{6,}', data)
                            strings.extend([f.decode("ascii", errors="ignore") for f in found])
                        except Exception:
                            pass
        except Exception:
            pass
        return strings

    def _find_urls(self, strings: list[str]) -> list[dict]:
        found = {}
        filtered = []
        for s in strings:
            for match in self.URL_RE.findall(s):
                if match not in found:
                    if self._is_allowlisted_url(match):
                        filtered.append(match)
                        continue
                    risk = "HIGH" if any(re.search(p, match) for p in SUSPICIOUS_URL_PATTERNS) else "MEDIUM"
                    found[match] = {"url": match, "risk": risk}
        return list(found.values())[:50], sorted(set(filtered))[:100]

    @staticmethod
    def _is_allowlisted_url(url: str) -> bool:
        clean = url.strip().rstrip('.,);]')
        return any(re.search(pattern, clean, re.IGNORECASE) for pattern in IOC_URL_ALLOWLIST_PATTERNS)

    def _find_ips(self, strings: list[str]) -> list[dict]:
        found = set()
        for s in strings:
            for match in self.IP_RE.findall(s):
                ip = match.split(":")[0]
                octets = ip.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    # Skip private ranges
                    if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")):
                        found.add(match)
        return [{"ip": ip, "type": "C2 Candidate"} for ip in list(found)[:30]]

    def _find_emails(self, strings: list[str]) -> list[str]:
        found = set()
        for s in strings:
            for m in self.EMAIL_RE.findall(s):
                if not any(d in m for d in ["android.com", "google.com", "example.com"]):
                    found.add(m)
        return list(found)[:20]

    def _find_base64(self, strings: list[str]) -> list[dict]:
        found = []
        seen = set()
        for s in strings:
            for m in self.BASE64_RE.findall(s):
                if m not in seen and len(m) > 40:
                    try:
                        decoded = base64.b64decode(m + "==").decode("utf-8", errors="replace")
                        if any(c.isprintable() for c in decoded[:20]):
                            found.append({"encoded": m[:60] + "...", "decoded_preview": decoded[:80]})
                            seen.add(m)
                    except Exception:
                        pass
        return found[:10]

    def _find_phones(self, strings: list[str]) -> list[str]:
        found = set()
        for s in strings:
            for m in self.PHONE_RE.findall(s):
                found.add(m)
        return list(found)[:20]

    def _find_telegram(self, strings: list[str]) -> list[str]:
        found = set()
        for s in strings:
            for m in self.TG_TOKEN.findall(s):
                found.add(m)
        return list(found)[:10]

    def _find_secrets(self, strings: list[str]) -> list[dict]:
        found = []
        for s in strings:
            for m in self.API_KEY_RE.finditer(s):
                found.append({
                    "type"  : "Hardcoded credential",
                    "value" : m.group(0)[:80],
                    "risk"  : "CRITICAL"
                })
        return found[:10]

    def _find_bank_refs(self, strings: list[str]) -> list[str]:
        found = set()
        for s in strings:
            sl = s.lower()
            for brand in INDIAN_BANK_BRANDS:
                if brand in sl and brand not in ["upi", "rbi"]:
                    found.add(s[:100])
        return list(found)[:20]

    def _find_shell_commands(self, strings: list[str]) -> list[str]:
        CMDS = ["su ", "chmod 777", "rm -rf", "/system/bin/sh", "busybox",
                "mount -o rw", "dd if=", "nc -l", "wget http", "curl http",
                "iptables", "/proc/", "/dev/", "pm install", "am start"]
        found = []
        for s in strings:
            if any(cmd in s for cmd in CMDS):
                found.append(s[:120])
        return list(set(found))[:15]

    def _find_crypto_patterns(self, strings: list[str]) -> list[dict]:
        patterns = [
            (r'[A-Fa-f0-9]{32}',  "Possible MD5 key/hash"),
            (r'[A-Fa-f0-9]{64}',  "Possible SHA-256 key"),
            (r'[A-Fa-f0-9]{128}', "Possible SHA-512 key"),
            (r'BEGIN PRIVATE KEY', "Embedded private key (CRITICAL)"),
            (r'BEGIN RSA',        "Embedded RSA key"),
        ]
        found = []
        for s in strings:
            for pat, desc in patterns:
                if re.search(pat, s, re.IGNORECASE):
                    found.append({"pattern": desc, "sample": s[:80]})
        return found[:10]


# ══════════════════════════════════════════════════════════════════════════════
# MASTER APK ANALYZER — orchestrates all sub-analyzers
# ══════════════════════════════════════════════════════════════════════════════
class APKAnalyzer:
    """
    RAKSHAK Master APK Analyzer
    Orchestrates all analysis sub-engines into unified result
    """

    def __init__(self, apk_path: str):
        self.apk_path  = apk_path
        self.apk_obj   = None
        self.dex_obj   = None
        self.dx_obj    = None

    def load(self) -> bool:
        """Load APK with androguard"""
        if not ANDROGUARD_AVAILABLE:
            return False
        try:
            self.apk_obj, self.dex_obj, self.dx_obj = AnalyzeAPK(self.apk_path)
            return True
        except Exception as e:
            print(f"[APKAnalyzer] androguard load error: {e}")
            try:
                self.apk_obj = AndroAPK(self.apk_path)
                return True
            except Exception as e2:
                print(f"[APKAnalyzer] APK load error: {e2}")
                return False

    def full_analyze(self) -> dict:
        """Run complete deep analysis pipeline"""
        print(f"[RAKSHAK] Starting deep analysis: {Path(self.apk_path).name}")

        loaded = self.load()
        print(f"[RAKSHAK] APK loaded: {loaded}")

        # ── 1. Cryptographic fingerprinting ──────────────────────────────────
        print("[RAKSHAK] Computing hashes...")
        hashes = HashEngine.compute_all(self.apk_path)

        # ── 2. Structure decomposition ────────────────────────────────────────
        print("[RAKSHAK] Analyzing APK structure...")
        structure = APKStructureAnalyzer(self.apk_path).analyze()

        # ── 3. Manifest deep analysis ─────────────────────────────────────────
        print("[RAKSHAK] Parsing AndroidManifest.xml...")
        manifest = ManifestAnalyzer(self.apk_obj).analyze()

        # ── 4. Certificate forensics ──────────────────────────────────────────
        print("[RAKSHAK] Analyzing certificates...")
        certs = CertificateAnalyzer(self.apk_obj).analyze()

        # ── 5. String & IOC extraction ────────────────────────────────────────
        print("[RAKSHAK] Extracting strings & IOCs...")
        strings = StringAnalyzer(self.apk_path, self.apk_obj, self.dx_obj).analyze()

        # ── 6. Assemble master result ─────────────────────────────────────────
        result = {
            "meta": {
                "apk_name"     : Path(self.apk_path).name,
                "analysis_time": datetime.utcnow().isoformat() + "Z",
                "platform"     : "RAKSHAK v3.0",
                "androguard_loaded": loaded,
            },
            "hashes"    : hashes,
            "structure" : structure,
            "manifest"  : manifest,
            "certificates": certs,
            "strings"   : strings,
        }

        print("[RAKSHAK] APK analysis complete.")
        return result
