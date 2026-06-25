"""
RAKSHAK — APK Threat Intelligence Platform
Defence-Grade Configuration Module
DRDO Cybersecurity Division | IIT Hyderabad Hackathon
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ─── PROJECT ROOT ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
YARA_DIR   = BASE_DIR / "yara_rules"
STATIC_DIR = BASE_DIR / "static"

for d in [UPLOAD_DIR, REPORT_DIR, YARA_DIR, STATIC_DIR]:
    d.mkdir(exist_ok=True)

# ─── API CONFIGURATION ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY       = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
GEMINI_MODEL         = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY       = os.getenv("SHODAN_API_KEY", "")

# ─── PLATFORM META ─────────────────────────────────────────────────────────────
PLATFORM_NAME        = "RAKSHAK"
PLATFORM_VERSION     = "3.0.0"
PLATFORM_FULLNAME    = "Reverse Analysis & Knowledge System for Heuristic APK threats"
CLASSIFICATION_LEVEL = "SENSITIVE — DRDO CYBERSECURITY DIVISION"
ORGANISATION         = "Defence Research & Development Organisation (DRDO)"

# ─── ANALYSIS SETTINGS ─────────────────────────────────────────────────────────
MAX_APK_SIZE_MB      = 200
ANALYSIS_TIMEOUT_SEC = 300
MAX_CONCURRENT_JOBS  = 5
SANDBOX_DURATION_SEC = 120

# ─── RISK SCORE WEIGHTS ────────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "permissions"      : 0.18,
    "static_code"      : 0.22,
    "dynamic_behaviour": 0.28,
    "network_iocs"     : 0.16,
    "threat_intel"     : 0.10,
    "genai_reasoning"  : 0.06,
}

# ─── SEVERITY THRESHOLDS ───────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL" : (85, 100),
    "HIGH"     : (65, 84),
    "MEDIUM"   : (40, 64),
    "LOW"      : (20, 39),
    "CLEAN"    : (0,  19),
}

# ─── DANGEROUS ANDROID PERMISSIONS ────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS"                        : ("CRITICAL", 30, "SMS content access — OTP harvesting"),
    "android.permission.RECEIVE_SMS"                     : ("CRITICAL", 28, "SMS interception — OTP theft"),
    "android.permission.SEND_SMS"                        : ("CRITICAL", 25, "Premium SMS fraud / C2 comms"),
    "android.permission.RECORD_AUDIO"                    : ("CRITICAL", 25, "Microphone — call/meeting recording"),
    "android.permission.CAMERA"                          : ("HIGH",     18, "Camera — visual surveillance"),
    "android.permission.READ_CONTACTS"                   : ("HIGH",     15, "Contact exfiltration"),
    "android.permission.ACCESS_FINE_LOCATION"            : ("HIGH",     15, "Precise GPS tracking"),
    "android.permission.READ_CALL_LOG"                   : ("HIGH",     18, "Call history exfiltration"),
    "android.permission.PROCESS_OUTGOING_CALLS"          : ("HIGH",     15, "Call interception"),
    "android.permission.SYSTEM_ALERT_WINDOW"             : ("CRITICAL", 30, "Overlay attack — fake banking UI"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE"      : ("CRITICAL", 35, "Accessibility abuse — UI automation/keylogger"),
    "android.permission.BIND_DEVICE_ADMIN"               : ("CRITICAL", 35, "Device admin — ransomware / uninstall prevention"),
    "android.permission.RECEIVE_BOOT_COMPLETED"          : ("HIGH",     20, "Boot persistence — survives reboot"),
    "android.permission.REQUEST_INSTALL_PACKAGES"        : ("CRITICAL", 25, "Dropper — installs secondary malware"),
    "android.permission.WRITE_EXTERNAL_STORAGE"          : ("MEDIUM",   10, "File system write"),
    "android.permission.READ_EXTERNAL_STORAGE"           : ("MEDIUM",   10, "File exfiltration from SD card"),
    "android.permission.GET_TASKS"                       : ("HIGH",     18, "Foreground app detection — banking spy"),
    "android.permission.KILL_BACKGROUND_PROCESSES"       : ("MEDIUM",   8,  "Process manipulation"),
    "android.permission.CHANGE_NETWORK_STATE"            : ("MEDIUM",   8,  "Network manipulation"),
    "android.permission.READ_PHONE_STATE"                : ("HIGH",     15, "IMEI / IMSI / phone identity theft"),
    "android.permission.USE_BIOMETRIC"                   : ("HIGH",     15, "Biometric bypass attempt"),
    "android.permission.FOREGROUND_SERVICE"              : ("MEDIUM",   8,  "Persistent background service"),
    "android.permission.WAKE_LOCK"                       : ("LOW",      5,  "Battery drain / C2 keep-alive"),
    "android.permission.MANAGE_EXTERNAL_STORAGE"         : ("HIGH",     20, "Full storage access — mass exfiltration"),
    "android.permission.READ_MEDIA_IMAGES"               : ("HIGH",     15, "Photo access — document theft"),
    "android.permission.NFC"                             : ("MEDIUM",   10, "NFC relay attack potential"),
    "android.permission.BLUETOOTH_ADMIN"                 : ("MEDIUM",   8,  "Bluetooth device scanning"),
}

# ─── DANGEROUS API PATTERNS ────────────────────────────────────────────────────
DANGEROUS_API_PATTERNS = {
    "DexClassLoader"                    : ("CRITICAL", 30, "Runtime code loading — dropper behaviour"),
    "PathClassLoader"                   : ("HIGH",     20, "Dynamic class loading"),
    "Runtime.exec"                      : ("CRITICAL", 35, "Shell command execution — root exploit"),
    "ProcessBuilder"                    : ("CRITICAL", 30, "Process spawning — shell commands"),
    "Class.forName"                     : ("HIGH",     20, "Reflection — evades static analysis"),
    "Method.invoke"                     : ("HIGH",     18, "Reflective invocation"),
    "getRunningTasks"                   : ("HIGH",     22, "Foreground app detection — banking spy"),
    "getRunningServices"                : ("HIGH",     15, "Service enumeration"),
    "sendTextMessage"                   : ("CRITICAL", 28, "SMS sending — OTP forward / premium SMS"),
    "onAccessibilityEvent"              : ("CRITICAL", 35, "Accessibility event handler — keylogger"),
    "performAction"                     : ("CRITICAL", 30, "Accessibility UI automation — overlay attack"),
    "dispatchGesture"                   : ("CRITICAL", 30, "Automated touch injection"),
    "addView.*TYPE_APPLICATION_OVERLAY" : ("CRITICAL", 35, "Overlay window — fake banking screen"),
    "addView.*TYPE_SYSTEM_OVERLAY"      : ("CRITICAL", 35, "System overlay — phishing UI"),
    "KeyEvent"                          : ("HIGH",     20, "Key event capture — keylogger"),
    "InputMethodService"                : ("CRITICAL", 28, "Custom keyboard — credential theft"),
    "TelephonyManager"                  : ("HIGH",     18, "Phone identity access"),
    "getSubscriberId"                   : ("HIGH",     20, "IMSI extraction"),
    "getDeviceId"                       : ("HIGH",     18, "IMEI extraction"),
    "ContentResolver.*sms"              : ("CRITICAL", 28, "SMS database read"),
    "ContentResolver.*contacts"         : ("HIGH",     20, "Contacts database read"),
    "ContentResolver.*call_log"         : ("HIGH",     20, "Call log database read"),
    "ClipboardManager"                  : ("HIGH",     22, "Clipboard sniffing — password theft"),
    "PackageManager.*getInstalledPackages" : ("HIGH",  18, "App enumeration — targets banking apps"),
    "Camera.open"                       : ("HIGH",     20, "Covert camera activation"),
    "AudioRecord"                       : ("CRITICAL", 28, "Audio recording API — microphone access"),
    "MediaRecorder"                     : ("HIGH",     22, "Media recording"),
    "requestAdminForDevice"             : ("CRITICAL", 35, "Device admin escalation — ransomware"),
    "PackageInstaller"                  : ("CRITICAL", 25, "App installation — dropper"),
    "setComponentEnabledSetting"        : ("HIGH",     20, "App hiding — icon removal"),
    "cipher.*AES.*ECB"                  : ("HIGH",     15, "Weak encryption — ECB mode"),
    "MessageDigest.*MD5"                : ("MEDIUM",   8,  "Deprecated hash — MD5"),
    "X509TrustManager"                  : ("HIGH",     22, "SSL trust bypass — MITM vulnerability"),
    "HostnameVerifier"                  : ("HIGH",     20, "Certificate validation bypass"),
    "setJavaScriptEnabled"              : ("MEDIUM",   10, "JavaScript in WebView"),
    "addJavascriptInterface"            : ("HIGH",     22, "WebView JS bridge — RCE risk"),
}

# ─── INDIAN BANKING BRANDS (impersonation detection) ──────────────────────────
INDIAN_BANK_BRANDS = [
    "sbi", "state bank", "hdfc", "icici", "axis", "kotak", "yes bank",
    "pnb", "punjab national", "bank of baroda", "canara", "union bank",
    "idfc", "indusind", "federal bank", "rbl", "bandhan", "paytm",
    "phonepe", "bhim", "gpay", "google pay", "amazon pay", "airtel payments",
    "mobikwik", "freecharge", "upi", "imps", "neft", "rtgs",
    "rbi", "reserve bank", "sebi", "irda", "nabard",
]

# ─── KNOWN MALWARE FAMILIES ────────────────────────────────────────────────────
MALWARE_FAMILIES = {
    "BankBot"    : ["bankbot", "overlay_bank", "smsstealer"],
    "Cerberus"   : ["cerberus", "accessibility_keylogger"],
    "FluBot"     : ["flubot", "smishing", "parcel_delivery"],
    "Anubis"     : ["anubis", "toast_overlay", "screenlocker"],
    "SpyNote"    : ["spynote", "rat_android", "remote_control"],
    "Drinik"     : ["drinik", "india_banking", "income_tax_fake"],
    "IceSpy"     : ["icespy", "upi_stealer", "india_otp"],
    "AxBanker"   : ["axbanker", "india_axis", "fake_axis"],
    "Transparent_Tribe": ["apt36", "crimsonrat", "pcrat_android"],
    "SideWinder" : ["sidewinder", "razor_tiger", "rattlesnake"],
}

# ─── MITRE ATT&CK MOBILE TECHNIQUES ──────────────────────────────────────────
MITRE_TECHNIQUES = {
    "T1417": "Input Capture — Keylogger",
    "T1430": "Location Tracking",
    "T1636": "Protected User Data — SMS Messages",
    "T1507": "Network Information Discovery",
    "T1406": "Obfuscated Files or Information",
    "T1603": "Scheduled Task/Job — Reoccurring",
    "T1404": "Exploit OS Vulnerability",
    "T1579": "Keychain — Credential Access",
    "T1409": "Stored Application Data",
    "T1513": "Screen Capture",
    "T1516": "Input Injection",
    "T1422": "System Network Configuration Discovery",
    "T1433": "Access Call Log",
    "T1435": "Access Contact List",
    "T1412": "Capture SMS Messages",
    "T1476": "Deliver Malicious App via Authorized App Store",
    "T1444": "Masquerade as Legitimate Application",
    "T1508": "Suppress Application Icon",
    "T1447": "Delete Device Data",
    "T1629": "Impair Defenses — Device Administrator Permission",
    "T1512": "Use API/Framework",
    "T1429": "Audio Capture",
    "T1582": "SMS Control",
}

# ─── C2 INDICATOR PATTERNS ─────────────────────────────────────────────────────
SUSPICIOUS_URL_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Direct IP URLs
    r"\.xyz$", r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$",  # Free/suspicious TLDs
    r"ngrok\.io", r"serveo\.net", r"localhost\.run",      # Tunnelling services
    r"t\.me/", r"api\.telegram\.org",                     # Telegram C2
    r"pastebin\.com", r"paste\.ee", r"hastebin",          # Paste sites (config)
    r"bit\.ly", r"tinyurl", r"ow\.ly", r"goo\.gl",       # URL shorteners
    r"duckdns\.org", r"ddns\.net", r"no-ip\.org",         # Dynamic DNS
    r"\.onion",                                            # Tor
]

# Trusted framework/license/certificate infrastructure URLs that are common in
# benign Android resources and should not be treated as analyst-facing IOCs.
IOC_URL_ALLOWLIST_PATTERNS = [
    r"^https?://schemas\.android\.com/",
    r"^https?://www\.w3\.org/",
    r"^https?://purl\.org/",
    r"^https?://www\.apache\.org/licenses/",
    r"^https?://ns\.adobe\.com/",
    r"^https?://www\.adobe\.com/type/",
    r"^https?://www\.verisign\.com/rpa",
    r"^https?://ocsp\.verisign\.com",
    r"^https?://crl\.verisign\.com/",
    r"^https?://[^/]*verisign\.com/.*(?:crl|aia|cer)",
    r"^https?://firebase\.google\.com/support/privacy/init-options",
    r"^https?://tizen\.org/",
]

# ─── APT GROUP SIGNATURES (India-specific) ────────────────────────────────────
APT_SIGNATURES = {
    "APT36_TransparentTribe": {
        "description": "Pakistani state-sponsored group targeting Indian defence & govt",
        "indicators": ["crimsonrat", "pcrat", "poseidon", "transparent_tribe"],
        "targets": ["DRDO", "Indian Army", "MoD", "BSF", "CRPF"],
        "ttps": ["T1476", "T1444", "T1417", "T1430"],
    },
    "SideWinder": {
        "description": "Suspected Indian APT targeting Pakistan, China, Nepal, Afghanistan",
        "indicators": ["sidewinder", "rattlesnake", "razor_tiger"],
        "targets": ["Military", "Government", "Law enforcement"],
        "ttps": ["T1444", "T1406", "T1417"],
    },
    "DoNot_Team": {
        "description": "APT targeting Kashmir region, Pakistani government entities",
        "indicators": ["donot", "apt_c_35", "viceroy_tiger"],
        "targets": ["Government", "Military", "NGOs"],
        "ttps": ["T1444", "T1412", "T1636"],
    },
}

print(f"[RAKSHAK] Config loaded — {PLATFORM_VERSION}")
