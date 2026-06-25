"""
RAKSHAK — Frida Dynamic Sandbox Integration
Instruments suspicious APKs inside an ISOLATED Android emulator.
Uses Frida to hook sensitive APIs and capture runtime behaviour.
Purpose: Controlled malware analysis ONLY. Never used on real devices.
"""

import subprocess, json, time, re, os, platform
from pathlib import Path
from typing import Optional
from config import BASE_DIR, SANDBOX_DURATION_SEC

FRIDA_SCRIPTS_DIR = BASE_DIR / "frida_scripts"
FRIDA_SCRIPTS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# FRIDA HOOK SCRIPTS (injected into sandbox)
# ══════════════════════════════════════════════════════════════════════════════

FRIDA_MASTER_SCRIPT = """
/**
 * RAKSHAK Frida Master Hook Script
 * Intercepts all sensitive Android APIs in isolated sandbox.
 * Captures arguments/return values for forensic analysis.
 */

var findings = [];
var startTime = Date.now();

function log(category, api, args, note) {
    var entry = {
        ts: Date.now() - startTime,
        category: category,
        api: api,
        args: args,
        note: note || ""
    };
    findings.push(entry);
    send({type: "finding", data: entry});
}

// ── SMS interception ────────────────────────────────────────────────────────
try {
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessage.overload(
        "java.lang.String","java.lang.String","java.lang.String",
        "android.app.PendingIntent","android.app.PendingIntent"
    ).implementation = function(dest, sc, text, si, di) {
        log("SMS_SEND", "SmsManager.sendTextMessage",
            {destination: dest, message_preview: text ? text.substring(0,50) : ""},
            "OTP or C2 SMS transmission detected");
        return this.sendTextMessage(dest, sc, text, si, di);
    };
} catch(e) {}

// ── Network / HTTP ──────────────────────────────────────────────────────────
try {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        log("NETWORK", "URL.openConnection",
            {url: this.toString()}, "Network connection initiated");
        return this.openConnection();
    };
} catch(e) {}

try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    OkHttpClient.newCall.implementation = function(req) {
        log("NETWORK", "OkHttp.newCall",
            {url: req.url().toString(), method: req.method()},
            "HTTP request via OkHttp");
        return this.newCall(req);
    };
} catch(e) {}

// ── Device identity exfiltration ────────────────────────────────────────────
try {
    var TM = Java.use("android.telephony.TelephonyManager");
    TM.getDeviceId.overload().implementation = function() {
        var id = this.getDeviceId();
        log("DEVICE_ID", "TelephonyManager.getDeviceId",
            {imei: id}, "IMEI extraction — device tracking/fingerprinting");
        return id;
    };
    TM.getSubscriberId.overload().implementation = function() {
        var imsi = this.getSubscriberId();
        log("DEVICE_ID", "TelephonyManager.getSubscriberId",
            {imsi: imsi}, "IMSI extraction — SIM identity theft");
        return imsi;
    };
} catch(e) {}

// ── SMS reading ─────────────────────────────────────────────────────────────
try {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        "android.net.Uri","[Ljava.lang.String;",
        "java.lang.String","[Ljava.lang.String;","java.lang.String"
    ).implementation = function(uri, proj, sel, args, order) {
        var uriStr = uri.toString();
        if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
            log("SMS_READ", "ContentResolver.query",
                {uri: uriStr}, "SMS database query — OTP harvesting");
        }
        return this.query(uri, proj, sel, args, order);
    };
} catch(e) {}

// ── File system ──────────────────────────────────────────────────────────────
try {
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.lang.String").implementation = function(path) {
        log("FILE_WRITE", "FileOutputStream.<init>",
            {path: path}, "File write — possible data exfiltration staging");
        return this.$init(path);
    };
} catch(e) {}

// ── Runtime shell execution ──────────────────────────────────────────────────
try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        log("SHELL_EXEC", "Runtime.exec",
            {command: cmd}, "CRITICAL: Shell command execution");
        return this.exec(cmd);
    };
} catch(e) {}

// ── Crypto / keys ────────────────────────────────────────────────────────────
try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(data) {
        log("CRYPTO", "Cipher.doFinal",
            {algo: this.getAlgorithm(), data_len: data.length},
            "Cryptographic operation — possible payload decryption");
        return this.doFinal(data);
    };
} catch(e) {}

// ── Accessibility / overlay ──────────────────────────────────────────────────
try {
    var AccService = Java.use("android.accessibilityservice.AccessibilityService");
    AccService.performGlobalAction.implementation = function(action) {
        log("ACCESSIBILITY", "AccessibilityService.performGlobalAction",
            {action: action}, "Accessibility global action — UI automation");
        return this.performGlobalAction(action);
    };
} catch(e) {}

// ── DexClassLoader (dropper) ─────────────────────────────────────────────────
try {
    var DCL = Java.use("dalvik.system.DexClassLoader");
    DCL.$init.implementation = function(dexPath, optDir, libPath, parent) {
        log("DROPPER", "DexClassLoader.<init>",
            {dex_path: dexPath, opt_dir: optDir},
            "CRITICAL: Runtime DEX loading — dropper behaviour");
        return this.$init(dexPath, optDir, libPath, parent);
    };
} catch(e) {}

// ── Location ─────────────────────────────────────────────────────────────────
try {
    var LM = Java.use("android.location.LocationManager");
    LM.requestLocationUpdates.overload(
        "java.lang.String","long","float","android.location.LocationListener"
    ).implementation = function(provider, minTime, minDist, listener) {
        log("LOCATION", "LocationManager.requestLocationUpdates",
            {provider: provider, interval_ms: minTime},
            "GPS tracking initiated");
        return this.requestLocationUpdates(provider, minTime, minDist, listener);
    };
} catch(e) {}

console.log("[RAKSHAK-FRIDA] All hooks installed. Monitoring started.");

// Send summary every 5 seconds
setInterval(function() {
    send({type: "heartbeat", findings_count: findings.length,
          elapsed_ms: Date.now() - startTime});
}, 5000);
"""


def write_frida_script() -> str:
    """Write the master Frida hook script to disk."""
    path = FRIDA_SCRIPTS_DIR / "rakshak_hooks.js"
    path.write_text(FRIDA_MASTER_SCRIPT)
    return str(path)


# ══════════════════════════════════════════════════════════════════════════════
# SANDBOX ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════
class FridaSandboxOrchestrator:
    """
    Orchestrates dynamic APK analysis inside an isolated Android emulator.

    Architecture:
        1. Start Android emulator (AVD) in headless mode
        2. Install APK via adb
        3. Attach Frida server to emulator
        4. Inject RAKSHAK hook script via frida-tools
        5. Launch APK and simulate user interactions (UIAutomator2)
        6. Collect findings for SANDBOX_DURATION_SEC
        7. Terminate emulator, generate runtime report

    Requirements (DRDO deployment):
        - Android SDK with AVD configured
        - frida-tools: pip install frida-tools
        - frida-server binary pushed to emulator
        - UIAutomator2: pip install uiautomator2

    NOTE: This module is designed for CONTROLLED SANDBOX ANALYSIS ONLY.
    It operates exclusively on flagged suspicious APKs within an isolated
    emulator. It is never used on real production devices.
    """

    def __init__(self):
        self.frida_available   = self._check_frida()
        self.adb_available     = self._check_adb()
        self.emulator_running  = False
        self.findings: list    = []

    @staticmethod
    def _check_frida() -> bool:
        try:
            import frida
            return True
        except ImportError:
            return False

    @staticmethod
    def _check_adb() -> bool:
        try:
            result = subprocess.run(
                ["adb", "version"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_analysis(self, apk_path: str, case_id: str = "") -> dict:
        """
        Full dynamic sandbox analysis pipeline.
        Returns structured findings report.
        """
        from core.event_bus import emit, EventType

        if emit:
            emit(EventType.ANALYSIS_START, case_id, {
                "phase"  : "dynamic_analysis",
                "engine" : "frida_sandbox",
                "message": "Starting dynamic sandbox analysis..."
            })

        if not self.frida_available or not self.adb_available:
            return self._simulated_analysis(apk_path, case_id)

        return self._live_analysis(apk_path, case_id)

    def _live_analysis(self, apk_path: str, case_id: str) -> dict:
        """Full Frida live analysis (requires emulator + frida-server)."""
        import frida
        from core.event_bus import emit, EventType

        findings = []
        script_path = write_frida_script()

        try:
            # Connect to running emulator
            device   = frida.get_usb_device(timeout=10)
            pkg_name = self._get_package_name(apk_path)

            # Install APK
            subprocess.run(["adb", "install", "-r", apk_path],
                           capture_output=True, timeout=30)

            # Spawn and attach
            pid    = device.spawn([pkg_name])
            session = device.attach(pid)
            script = session.create_script(FRIDA_MASTER_SCRIPT)

            def on_message(message, _data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "finding":
                        finding = payload["data"]
                        findings.append(finding)
                        if case_id and emit:
                            emit(EventType.STATIC_FINDING, case_id, {
                                "engine"  : "FRIDA-DYNAMIC",
                                "category": finding.get("category", ""),
                                "api"     : finding.get("api", ""),
                                "args"    : finding.get("args", {}),
                                "note"    : finding.get("note", ""),
                                "ts_ms"   : finding.get("ts", 0),
                            }, severity="CRITICAL")

            script.on("message", on_message)
            script.load()
            device.resume(pid)

            # Let the APK run for analysis window
            time.sleep(min(SANDBOX_DURATION_SEC, 60))

            session.detach()
            subprocess.run(["adb", "uninstall", pkg_name],
                           capture_output=True, timeout=10)

        except Exception as e:
            return {"error": str(e), "findings": findings, "mode": "live_partial"}

        return self._build_report(findings, apk_path, mode="live")

    def _simulated_analysis(self, apk_path: str, case_id: str) -> dict:
        """
        Simulated dynamic analysis when emulator is unavailable.
        Uses static heuristics to predict runtime behaviour.
        Clearly marked as simulated in the report.
        """
        import zipfile, re
        from core.event_bus import emit, EventType

        simulated_findings = []

        # Read raw strings and predict runtime API calls
        patterns = {
            "sendTextMessage"    : ("SMS_SEND",    "OTP/C2 SMS transmission predicted"),
            "getDeviceId"        : ("DEVICE_ID",   "IMEI extraction predicted"),
            "getSubscriberId"    : ("DEVICE_ID",   "IMSI extraction predicted"),
            "AudioRecord"        : ("AUDIO",       "Microphone recording predicted"),
            "Camera"             : ("CAMERA",      "Camera access predicted"),
            "DexClassLoader"     : ("DROPPER",     "Secondary payload loading predicted"),
            "Runtime.exec"       : ("SHELL_EXEC",  "Shell command execution predicted"),
            "requestLocationUpd" : ("LOCATION",    "GPS tracking predicted"),
            "ContentResolver.*sms":("SMS_READ",    "SMS database query predicted"),
        }

        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        data = zf.read(name)
                        text = re.sub(b'[^\x20-\x7e]', b' ', data).decode('ascii', errors='ignore')
                        for pattern, (category, note) in patterns.items():
                            if re.search(pattern, text, re.IGNORECASE):
                                entry = {
                                    "ts"        : 0,
                                    "category"  : category,
                                    "api"       : pattern,
                                    "note"      : note,
                                    "simulated" : True,
                                }
                                simulated_findings.append(entry)
                                if case_id and emit:
                                    emit(EventType.STATIC_FINDING, case_id, {
                                        "engine"  : "FRIDA-SIMULATED",
                                        "category": category,
                                        "api"     : pattern,
                                        "note"    : note + " [SIMULATED]",
                                    }, severity="HIGH")
        except Exception:
            pass

        return self._build_report(simulated_findings, apk_path, mode="simulated")

    def _build_report(self, findings: list, apk_path: str, mode: str) -> dict:
        """Compile findings into structured dynamic analysis report."""
        categories = {}
        for f in findings:
            cat = f.get("category", "UNKNOWN")
            categories[cat] = categories.get(cat, 0) + 1

        critical_findings = [
            f for f in findings
            if f.get("category") in ("SHELL_EXEC", "DROPPER", "SMS_SEND")
        ]

        dynamic_risk_score = min(
            len(critical_findings) * 20 +
            len(findings) * 3, 100
        )

        return {
            "mode"               : mode,
            "analysis_engine"    : "RAKSHAK-FRIDA v3.0",
            "apk_name"           : Path(apk_path).name,
            "total_findings"     : len(findings),
            "category_breakdown" : categories,
            "critical_findings"  : critical_findings[:10],
            "all_findings"       : findings[:50],
            "dynamic_risk_score" : dynamic_risk_score,
            "severity"           : "CRITICAL" if dynamic_risk_score > 60
                                   else "HIGH" if dynamic_risk_score > 35
                                   else "MEDIUM",
            "behaviours_detected": list(categories.keys()),
            "runtime_note"       : (
                "Live Frida analysis on isolated Android emulator"
                if mode == "live"
                else "Simulated analysis — deploy Android SDK for live analysis"
            ),
        }

    @staticmethod
    def _get_package_name(apk_path: str) -> str:
        try:
            from androguard.core.bytecodes.apk import APK
            return APK(apk_path).get_package()
        except Exception:
            return "com.unknown.app"
