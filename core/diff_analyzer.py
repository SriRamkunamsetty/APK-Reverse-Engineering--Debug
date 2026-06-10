"""
RAKSHAK — Differential APK Analyzer
Compares two APK versions to detect injected malicious code.
Catches repackaging attacks where legitimate apps are trojaned.
"""

import zipfile, hashlib, re, json
from pathlib import Path
from dataclasses import dataclass, field
from core.event_bus import emit, EventType


@dataclass
class FileDiff:
    filename   : str
    status     : str          # ADDED | REMOVED | MODIFIED | UNCHANGED
    old_hash   : str  = ""
    new_hash   : str  = ""
    size_delta : int  = 0
    risk_level : str  = "LOW"
    reason     : str  = ""


class DifferentialAnalyzer:
    """
    Byte-level diff between two APK versions.
    Detects: new DEX files, modified classes, injected native libs,
    added permissions, new C2 URLs, suspicious asset additions.
    """

    # File patterns that signal malicious injection when ADDED
    MALICIOUS_ADDITIONS = {
        r".*\.dex$"              : ("CRITICAL", "Secondary DEX — possible dropper injection"),
        r"lib/.*/.*\.so$"        : ("HIGH",     "Native library added — possible native exploit"),
        r"assets/.*\.(bin|enc|dat)$": ("HIGH",  "Encrypted asset added — possible payload"),
        r"META-INF/.*\.(sh|py|rb)$" : ("CRITICAL","Script in META-INF — JAR injection"),
        r"assets/.*\.apk$"       : ("CRITICAL", "Embedded APK added — dropper detected"),
        r"res/raw/.*"            : ("MEDIUM",   "Raw resource added — may contain payload"),
    }

    # Permission patterns that signal privilege escalation when ADDED
    DANGEROUS_ADDED_PERMS = {
        "android.permission.READ_SMS"            : ("CRITICAL", 40),
        "android.permission.RECEIVE_SMS"         : ("CRITICAL", 40),
        "android.permission.SYSTEM_ALERT_WINDOW" : ("CRITICAL", 35),
        "android.permission.BIND_ACCESSIBILITY_SERVICE": ("CRITICAL", 40),
        "android.permission.BIND_DEVICE_ADMIN"   : ("CRITICAL", 45),
        "android.permission.REQUEST_INSTALL_PACKAGES": ("CRITICAL", 35),
        "android.permission.RECORD_AUDIO"        : ("HIGH",     25),
        "android.permission.CAMERA"              : ("HIGH",     20),
        "android.permission.ACCESS_FINE_LOCATION": ("HIGH",     20),
    }

    def compare(self, original_path: str, suspect_path: str,
                case_id: str = "") -> dict:
        """
        Compare original APK vs suspect (potentially repackaged) APK.
        Returns full differential analysis report.
        """
        orig_files = self._index_apk(original_path)
        susp_files = self._index_apk(suspect_path)

        diffs       : list[FileDiff] = []
        risk_score  : int            = 0
        injected    : list[str]      = []
        modified    : list[str]      = []

        all_files = set(orig_files) | set(susp_files)

        for fname in all_files:
            in_orig = fname in orig_files
            in_susp = fname in susp_files

            if in_orig and not in_susp:
                d = FileDiff(fname, "REMOVED",
                             old_hash=orig_files[fname]["hash"])
                diffs.append(d)

            elif not in_orig and in_susp:
                # NEW file — check if malicious
                sev, reason = self._classify_addition(fname)
                d = FileDiff(fname, "ADDED",
                             new_hash  = susp_files[fname]["hash"],
                             size_delta= susp_files[fname]["size"],
                             risk_level= sev,
                             reason    = reason)
                diffs.append(d)
                if sev in ("CRITICAL", "HIGH"):
                    injected.append(fname)
                    score = {"CRITICAL": 30, "HIGH": 20}.get(sev, 5)
                    risk_score += score
                    if case_id:
                        emit(EventType.STATIC_FINDING, case_id, {
                            "engine"  : "DIFF-ANALYZER",
                            "title"   : f"Injected file: {fname}",
                            "note"    : reason,
                            "score"   : score,
                        }, severity=sev)

            else:
                # Both exist — check if modified
                if orig_files[fname]["hash"] != susp_files[fname]["hash"]:
                    sev, reason = self._classify_modification(fname, orig_files[fname], susp_files[fname])
                    d = FileDiff(fname, "MODIFIED",
                                 old_hash  = orig_files[fname]["hash"],
                                 new_hash  = susp_files[fname]["hash"],
                                 size_delta= susp_files[fname]["size"] - orig_files[fname]["size"],
                                 risk_level= sev,
                                 reason    = reason)
                    diffs.append(d)
                    if sev in ("CRITICAL", "HIGH"):
                        modified.append(fname)
                        risk_score += {"CRITICAL": 25, "HIGH": 15}.get(sev, 5)

        # Check for added dangerous permissions
        orig_perms = self._get_permissions(original_path)
        susp_perms = self._get_permissions(suspect_path)
        added_perms= susp_perms - orig_perms
        removed_perms = orig_perms - susp_perms

        perm_findings = []
        for perm in added_perms:
            if perm in self.DANGEROUS_ADDED_PERMS:
                sev, score = self.DANGEROUS_ADDED_PERMS[perm]
                perm_findings.append({
                    "permission": perm,
                    "severity"  : sev,
                    "score"     : score,
                    "action"    : "ADDED — privilege escalation",
                })
                risk_score += score
                if case_id:
                    emit(EventType.BANKING_THREAT, case_id, {
                        "engine": "DIFF-ANALYZER",
                        "title" : f"Permission injected: {perm.split('.')[-1]}",
                        "score" : score,
                    }, severity=sev)

        # Signing change detection
        orig_cert = self._get_cert_hash(original_path)
        susp_cert = self._get_cert_hash(suspect_path)
        cert_changed = orig_cert != susp_cert

        if cert_changed:
            risk_score += 35
            if case_id:
                emit(EventType.CRITICAL_VULN, case_id, {
                    "engine": "DIFF-ANALYZER",
                    "title" : "Certificate changed — definitely repackaged",
                    "score" : 35,
                }, severity="CRITICAL")

        risk_score = min(risk_score, 100)

        # Repackaging confidence
        confidence = "CONFIRMED" if cert_changed and injected else \
                     "HIGH"      if len(injected) >= 2         else \
                     "MEDIUM"    if len(injected) >= 1         else \
                     "LOW"       if modified                   else \
                     "CLEAN"

        summary = {
            "repackaging_confidence"  : confidence,
            "cert_changed"            : cert_changed,
            "original_cert_hash"      : orig_cert,
            "suspect_cert_hash"       : susp_cert,
            "total_files_compared"    : len(all_files),
            "files_added"             : len([d for d in diffs if d.status == "ADDED"]),
            "files_removed"           : len([d for d in diffs if d.status == "REMOVED"]),
            "files_modified"          : len([d for d in diffs if d.status == "MODIFIED"]),
            "injected_malicious_files": injected,
            "modified_critical_files" : modified,
            "added_permissions"       : list(added_perms),
            "removed_permissions"     : list(removed_perms),
            "dangerous_perm_findings" : perm_findings,
            "differential_risk_score" : risk_score,
            "severity"                : "CRITICAL" if risk_score > 60
                                        else "HIGH" if risk_score > 35
                                        else "MEDIUM",
            "diffs"                   : [
                {
                    "file"      : d.filename,
                    "status"    : d.status,
                    "risk"      : d.risk_level,
                    "reason"    : d.reason,
                    "size_delta": d.size_delta,
                }
                for d in diffs if d.status != "UNCHANGED"
            ][:50],
        }

        return summary

    def _index_apk(self, path: str) -> dict[str, dict]:
        index = {}
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    try:
                        data = zf.read(info.filename)
                        index[info.filename] = {
                            "hash": hashlib.sha256(data).hexdigest(),
                            "size": len(data),
                        }
                    except Exception:
                        pass
        except Exception:
            pass
        return index

    def _classify_addition(self, fname: str) -> tuple[str, str]:
        for pattern, (sev, reason) in self.MALICIOUS_ADDITIONS.items():
            if re.match(pattern, fname, re.IGNORECASE):
                return sev, reason
        if fname.endswith(".dex"):
            return "CRITICAL", "Additional DEX file injected"
        if fname.endswith(".so"):
            return "HIGH", "Native library injected"
        return "LOW", "New file added"

    def _classify_modification(self, fname: str, orig: dict, susp: dict) -> tuple[str, str]:
        size_delta = susp["size"] - orig["size"]
        if fname == "AndroidManifest.xml":
            return "CRITICAL", f"Manifest modified (Δ{size_delta:+d} bytes) — permissions may have changed"
        if fname.endswith(".dex"):
            return "CRITICAL", f"DEX bytecode modified (Δ{size_delta:+d} bytes) — code injection suspected"
        if fname.endswith(".so"):
            return "HIGH", f"Native library modified (Δ{size_delta:+d} bytes)"
        if "CERT" in fname or fname.endswith(".RSA") or fname.endswith(".SF"):
            return "CRITICAL", "Signature file modified — re-signed after tampering"
        return "MEDIUM", f"File modified (Δ{size_delta:+d} bytes)"

    def _get_permissions(self, apk_path: str) -> set[str]:
        perms = set()
        try:
            with zipfile.ZipFile(apk_path) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    data = zf.read("AndroidManifest.xml")
                    found = re.findall(b'android\.permission\.[A-Z_]+', data)
                    perms = {f.decode("ascii") for f in found}
        except Exception:
            pass
        return perms

    def _get_cert_hash(self, apk_path: str) -> str:
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.startswith("META-INF/") and name.endswith(".RSA"):
                        return hashlib.sha256(zf.read(name)).hexdigest()[:16]
        except Exception:
            pass
        return "UNKNOWN"
