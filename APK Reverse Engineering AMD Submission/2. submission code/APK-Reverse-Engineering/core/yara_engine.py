"""
RAKSHAK — YARA Rules Engine
Pattern-based malware family detection with custom DRDO rule library
"""

import re, zipfile
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════════
# YARA-EQUIVALENT PYTHON RULE ENGINE
# (Pure Python implementation — works without native yara-python install)
# ══════════════════════════════════════════════════════════════════════════════

class RakshakRule:
    """A YARA-equivalent rule definition"""
    def __init__(self, name: str, family: str, severity: str,
                 description: str, patterns: list[str],
                 mitre: list[str], weight: int = 20):
        self.name        = name
        self.family      = family
        self.severity    = severity
        self.description = description
        self.patterns    = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
        self.mitre       = mitre
        self.weight      = weight

    def match(self, code: str, min_patterns: int = 1) -> tuple[bool, list[str]]:
        matched = [p.pattern for p in self.patterns if p.search(code)]
        return (len(matched) >= min_patterns), matched


RAKSHAK_RULE_DB: list[RakshakRule] = [

    # ── BANKING TROJANS ──────────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-BT-001",
        family="BankBot",
        severity="CRITICAL",
        description="BankBot banking trojan — SMS OTP theft with overlay attack",
        patterns=[
            r"RECEIVE_SMS.*SYSTEM_ALERT_WINDOW",
            r"onReceive.*SmsMessage",
            r"getMessageBody",
            r"addView.*TYPE_APPLICATION_OVERLAY",
            r"getRunningTasks",
        ],
        mitre=["T1412", "T1417", "T1636"],
        weight=35,
    ),
    RakshakRule(
        name="RAKSHAR-BT-002",
        family="Cerberus",
        severity="CRITICAL",
        description="Cerberus banking trojan — accessibility keylogger with C2 control",
        patterns=[
            r"onAccessibilityEvent",
            r"AccessibilityNodeInfo",
            r"performAction",
            r"dispatchGesture",
            r"BIND_ACCESSIBILITY_SERVICE",
            r"getPackageName.*bank|bank.*getPackageName",
        ],
        mitre=["T1417", "T1516", "T1629"],
        weight=38,
    ),
    RakshakRule(
        name="RAKSHAR-BT-003",
        family="Anubis",
        severity="CRITICAL",
        description="Anubis Android banker — screen capture with toast overlay",
        patterns=[
            r"MediaProjectionManager",
            r"createVirtualDisplay",
            r"Toast.*makeText",
            r"BIND_DEVICE_ADMIN",
            r"onReceive.*SCREEN_OFF",
        ],
        mitre=["T1513", "T1629", "T1417"],
        weight=35,
    ),
    RakshakRule(
        name="RAKSHAR-BT-004",
        family="FluBot",
        severity="CRITICAL",
        description="FluBot SMS worm — spreads via smishing, steals banking credentials",
        patterns=[
            r"SEND_SMS.*READ_CONTACTS",
            r"sendTextMessage.*getContactList|getContactList.*sendTextMessage",
            r"DexClassLoader",
            r"parcel|delivery|package.*tracking",
        ],
        mitre=["T1582", "T1636", "T1406"],
        weight=32,
    ),
    RakshakRule(
        name="RAKSHAR-BT-005",
        family="Drinik",
        severity="CRITICAL",
        description="Drinik — India-specific banking trojan targeting income tax portal",
        patterns=[
            r"incometax|income.tax",
            r"efiling|e-filing",
            r"SYSTEM_ALERT_WINDOW.*RECEIVE_SMS",
            r"aadhaar|aadhar|pan.card",
            r"READ_SMS.*ACCESS_FINE_LOCATION",
        ],
        mitre=["T1417", "T1412", "T1430"],
        weight=40,
    ),
    RakshakRule(
        name="RAKSHAR-BT-006",
        family="IceSpy/AxBanker",
        severity="CRITICAL",
        description="India-specific UPI/Axis Bank credential stealer",
        patterns=[
            r"axis|upi.*stealer|otp.*forward",
            r"sendTextMessage.*\+91|\+91.*sendTextMessage",
            r"bhim|phonepe|googlepay|paytm",
            r"RECEIVE_SMS.*SEND_SMS",
        ],
        mitre=["T1412", "T1582", "T1636"],
        weight=38,
    ),

    # ── REMOTE ACCESS TROJANS ────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-RT-001",
        family="SpyNote/CypherRAT",
        severity="CRITICAL",
        description="SpyNote RAT — full device control, camera, microphone, GPS",
        patterns=[
            r"AudioRecord.*startRecording|startRecording.*AudioRecord",
            r"Camera.*open|open.*Camera",
            r"ACCESS_FINE_LOCATION.*RECORD_AUDIO.*CAMERA",
            r"onAccessibilityEvent.*getPackageName",
            r"Socket.*connect|ServerSocket",
        ],
        mitre=["T1429", "T1512", "T1430", "T1417"],
        weight=40,
    ),
    RakshakRule(
        name="RAKSHAR-RT-002",
        family="AhMyth",
        severity="CRITICAL",
        description="AhMyth Android RAT — open source RAT widely used by threat actors",
        patterns=[
            r"AhMyth|ahmyth",
            r"ServerSocket.*8888|ServerSocket.*9999",
            r"RECORD_AUDIO.*CAMERA.*READ_CONTACTS.*ACCESS_FINE_LOCATION",
            r"getRunningProcesses",
        ],
        mitre=["T1429", "T1512", "T1422"],
        weight=38,
    ),
    RakshakRule(
        name="RAKSHAR-RT-003",
        family="Dendroid",
        severity="CRITICAL",
        description="Dendroid RAT — HTTP botnet protocol with web admin panel",
        patterns=[
            r"dendroid|DendroidService",
            r"HttpClient.*post.*php",
            r"getImei.*getImsi.*sendSms",
            r"intercept.*call.*recording",
        ],
        mitre=["T1417", "T1429", "T1412"],
        weight=35,
    ),

    # ── SPYWARE / STALKERWARE ────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-SP-001",
        family="Pegasus-Like Spyware",
        severity="CRITICAL",
        description="Advanced spyware — continuous location, audio, contacts exfiltration",
        patterns=[
            r"LocationManager.*requestLocationUpdates.*1000",
            r"AudioRecord.*VOICE_COMMUNICATION",
            r"READ_CONTACTS.*ACCESS_FINE_LOCATION.*RECORD_AUDIO.*READ_CALL_LOG",
            r"startForeground.*FOREGROUND_SERVICE",
        ],
        mitre=["T1430", "T1429", "T1636", "T1433"],
        weight=42,
    ),
    RakshakRule(
        name="RAKSHAR-SP-002",
        family="CallRecorder Spyware",
        severity="HIGH",
        description="Call recording spyware — intercepts voice calls covertly",
        patterns=[
            r"PROCESS_OUTGOING_CALLS.*RECORD_AUDIO",
            r"TelephonyManager.*CALL_STATE",
            r"MediaRecorder.*VOICE_CALL|VOICE_UPLINK|VOICE_DOWNLINK",
            r"onCallStateChanged.*AudioRecord",
        ],
        mitre=["T1429", "T1433"],
        weight=30,
    ),
    RakshakRule(
        name="RAKSHAR-SP-003",
        family="Keylogger",
        severity="CRITICAL",
        description="Accessibility-based keylogger capturing all user input",
        patterns=[
            r"TYPE_VIEW_TEXT_CHANGED",
            r"AccessibilityEvent.*getText",
            r"onAccessibilityEvent.*TYPE_VIEW_FOCUSED",
            r"InputMethodService.*onText",
            r"KeyEvent.*getUnicodeChar",
        ],
        mitre=["T1417"],
        weight=38,
    ),

    # ── DROPPERS & LOADERS ───────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-DR-001",
        family="APK Dropper",
        severity="CRITICAL",
        description="Dropper — downloads and installs secondary malicious APK",
        patterns=[
            r"DexClassLoader.*assets|assets.*DexClassLoader",
            r"REQUEST_INSTALL_PACKAGES",
            r"PackageInstaller.*installPackage",
            r"downloadFile.*\.apk|\.apk.*downloadFile",
            r"RECEIVE_BOOT_COMPLETED.*DexClassLoader",
        ],
        mitre=["T1406", "T1476"],
        weight=35,
    ),
    RakshakRule(
        name="RAKSHAR-DR-002",
        family="Malicious Packer",
        severity="HIGH",
        description="Runtime DEX decryption — packed malware unpacks payload in memory",
        patterns=[
            r"Cipher\.getInstance.*AES.*DexClassLoader",
            r"decrypt.*dex|dex.*decrypt",
            r"InMemoryDexClassLoader",
            r"ByteArrayOutputStream.*DexClassLoader",
        ],
        mitre=["T1406"],
        weight=30,
    ),

    # ── RANSOMWARE ───────────────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-RN-001",
        family="Android Ransomware",
        severity="CRITICAL",
        description="Ransomware — encrypts files and demands payment",
        patterns=[
            r"BIND_DEVICE_ADMIN.*Cipher|Cipher.*BIND_DEVICE_ADMIN",
            r"lockNow\(\)|lockDevice",
            r"resetPassword",
            r"File.*encrypt|encrypt.*File",
            r"bitcoin|btc.*wallet|ransom",
        ],
        mitre=["T1629", "T1447"],
        weight=40,
    ),

    # ── APT / NATION-STATE ───────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-APT-001",
        family="APT36 / Transparent Tribe",
        severity="CRITICAL",
        description="Pakistani APT36 targeting Indian defence/government — CrimsonRAT variant",
        patterns=[
            r"crimsonrat|CrimsonRAT|pcrat",
            r"drdo|isro|mod\.gov|army\.mil\.in",
            r"RECORD_AUDIO.*ACCESS_FINE_LOCATION.*READ_CONTACTS.*RECEIVE_SMS",
            r"postman|ngrok.*api",
        ],
        mitre=["T1476", "T1444", "T1417", "T1430"],
        weight=50,
    ),
    RakshakRule(
        name="RAKSHAR-APT-002",
        family="SideWinder",
        severity="CRITICAL",
        description="SideWinder APT — suspected Indian group targeting South/SE Asia military",
        patterns=[
            r"sidewinder|SideWinder|RattleSnake",
            r"military|defence|army|airforce|navy",
            r"DexClassLoader.*http.*\.php",
            r"getImei.*getImsi.*postData",
        ],
        mitre=["T1444", "T1406", "T1417"],
        weight=48,
    ),

    # ── CRYPTOMINER ──────────────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-CM-001",
        family="CryptoMiner",
        severity="HIGH",
        description="Cryptocurrency miner abusing device CPU/GPU",
        patterns=[
            r"stratum\+tcp|mining\.pool",
            r"monero|xmr|coinhive|cryptonight",
            r"hashrate|hash_rate",
            r"WAKE_LOCK.*Thread.*nativeHash",
        ],
        mitre=["T1603"],
        weight=25,
    ),

    # ── ADWARE / FRAUD ───────────────────────────────────────────────────────
    RakshakRule(
        name="RAKSHAR-AF-001",
        family="Toll Fraud Malware",
        severity="HIGH",
        description="Premium rate SMS fraud — silently sends paid SMS messages",
        patterns=[
            r"sendTextMessage.*PREMIUM|PREMIUM.*sendTextMessage",
            r"SmsManager.*short.?code",
            r"subscribeToPremium|WAP.?click",
            r"SEND_SMS.*BroadcastReceiver.*onReceive",
        ],
        mitre=["T1582"],
        weight=28,
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# YARA ENGINE — orchestrates all rules
# ══════════════════════════════════════════════════════════════════════════════
class YARAEngine:
    """
    RAKSHAK YARA-equivalent rule engine
    Matches against full APK extracted code
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self._code_cache: str | None = None

    def _get_full_code(self) -> str:
        if self._code_cache:
            return self._code_cache
        code_parts = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    try:
                        data = zf.read(name)
                        if len(data) > 100:
                            printable = re.findall(b'[\x20-\x7e]{4,}', data)
                            code_parts.append(
                                " ".join(p.decode("ascii", errors="ignore") for p in printable)
                            )
                    except Exception:
                        pass
        except Exception:
            pass
        self._code_cache = "\n".join(code_parts)
        return self._code_cache

    def scan(self) -> dict:
        code = self._get_full_code()
        matches      = []
        families     = set()
        total_weight = 0
        mitre_all    = set()

        for rule in RAKSHAK_RULE_DB:
            matched, hit_patterns = rule.match(code, min_patterns=1)
            if matched:
                families.add(rule.family)
                total_weight += rule.weight
                mitre_all.update(rule.mitre)
                matches.append({
                    "rule_id"     : rule.name,
                    "family"      : rule.family,
                    "severity"    : rule.severity,
                    "description" : rule.description,
                    "mitre"       : rule.mitre,
                    "risk_weight" : rule.weight,
                    "pattern_hits": len(hit_patterns),
                    "matched_patterns": hit_patterns[:3],
                })

        # Determine primary family
        if matches:
            primary = max(matches, key=lambda x: x["risk_weight"])
        else:
            primary = None

        return {
            "total_rules_scanned"  : len(RAKSHAK_RULE_DB),
            "rules_matched"        : len(matches),
            "malware_families"     : list(families),
            "primary_family"       : primary["family"] if primary else "Unknown/Clean",
            "yara_risk_score"      : min(total_weight, 100),
            "matches"              : matches,
            "mitre_techniques"     : list(mitre_all),
            "apt_detected"         : any("APT" in m["rule_id"] for m in matches),
            "nation_state_threat"  : any(m["family"] in ["APT36 / Transparent Tribe", "SideWinder"]
                                         for m in matches),
        }
