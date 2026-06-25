"""
RAKSHAK — Test APK Generator
Creates a minimal but realistic test APK containing malware-like patterns
for pipeline validation WITHOUT using real malware
"""

import zipfile, struct, io, os, hashlib
from pathlib import Path


def create_test_apk(output_path: str) -> str:
    """
    Creates a minimal APK (ZIP) containing:
    - AndroidManifest.xml with dangerous permissions
    - classes.dex with suspicious string patterns
    - assets/ with suspicious content
    """

    # ── Fake binary AndroidManifest.xml (readable strings embedded) ───────────
    manifest_content = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.sbi.rewardz.fake"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="28" />

    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.BIND_DEVICE_ADMIN"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.GET_TASKS"/>

    <application android:label="SBI Rewards" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true"/>
        <service android:name=".MalService" android:exported="true"/>
        <receiver android:name=".SmsReceiver" android:exported="true">
            <intent-filter android:priority="2147483647">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    # ── Fake DEX with malware-like strings ────────────────────────────────────
    dex_strings = b"""
RAKSHAK-TEST-SAMPLE-NOT-REAL-MALWARE
DexClassLoader dalvik.system.DexClassLoader
Runtime.exec shell command execution test
onAccessibilityEvent AccessibilityNodeInfo performAction
SmsManager sendTextMessage getMessageBody
WindowManager.LayoutParams TYPE_APPLICATION_OVERLAY addView
getRunningTasks ActivityManager foreground spy
getSubscriberId getDeviceId IMEI IMSI
AudioRecord startRecording MediaRecorder
ClipboardManager getPrimaryClip password theft
ContentResolver sms inbox read uri content://sms/inbox
ContentResolver contacts content://contacts/phones
ContentResolver call_log content://call_log/calls
camera.open covert surveillance
requestAdminForDevice device admin bind
setComponentEnabledSetting hide icon launcher
Class.forName reflection getDeclaredMethod invoke setAccessible
AES/ECB weak encryption MD5 SHA-1 deprecated
TrustAllCerts trustAll X509TrustManager bypass SSL
http://185.220.101.45:8080/c2/collect
http://45.142.212.100/bot/otp_forward.php
https://api.telegram.org/bot1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789/sendMessage
otp@stealer.xyz crimsonrat backdoor
bhim phonepe gpay upi paytm sbi hdfc icici axis bank
aadhaar income tax efiling pan card
su chmod 777 /system/bin/sh busybox root exploit
android:debuggable=true MODE_WORLD_READABLE SQL injection rawQuery
addJavascriptInterface WebView RCE exploit
pastebin.com ngrok.io payload download
bitcoin wallet ransom encrypt lockDevice resetPassword
AhMyth SpyNote CrimsonRAT APT36 TransparentTribe
drdo.gov.in isro.gov.in mod.nic.in army.mil.in
BEGIN PRIVATE KEY RSA PRIVATE KEY hardcoded
stratum+tcp mining.pool monero xmr hashrate
SecretKeySpec AES hardcoded_key_12345678
INSERT INTO passwords VALUES username password
    """

    # ── Fake native lib strings ───────────────────────────────────────────────
    native_strings = b"""
ELF native library simulation
su /system/bin/su root escalation
/proc/self/mem memory injection
mmap shellcode injection
ptrace anti-debug detection bypass
TracerPid 0 debugger check
ro.kernel.qemu emulator detection
Build.FINGERPRINT generic emulator
    """

    # ── Fake assets ───────────────────────────────────────────────────────────
    config_json = b"""{
  "c2_url": "http://185.220.101.45:8080/api/v1/",
  "telegram_token": "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ12345678",
  "telegram_chat": "-100987654321",
  "otp_forward": "http://45.142.212.100/forward.php",
  "target_apps": ["com.sbi.mobile", "com.hdfc.hdfcbank", "net.one97.paytm"],
  "c2_backup": "http://ngrok.io/backup-c2/endpoint",
  "encryption_key": "ThisIsAHardcodedKey32BytesLongXX",
  "mode": "stealth",
  "persistence": true
}"""

    # ── Build APK ZIP ─────────────────────────────────────────────────────────
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('AndroidManifest.xml',  manifest_content)
        zf.writestr('classes.dex',          b'dex\n035\x00' + dex_strings + b'\x00' * 32)
        zf.writestr('classes2.dex',         b'dex\n035\x00MultiDexPayload' + b'\x00' * 32)
        zf.writestr('lib/arm64-v8a/libmalicious.so', b'\x7fELF' + native_strings)
        zf.writestr('lib/armeabi-v7a/libroot.so',    b'\x7fELF' + b'su exploit shell' * 10)
        zf.writestr('assets/config.json',   config_json)
        zf.writestr('assets/payload.bin',   os.urandom(512))  # High entropy
        zf.writestr('assets/fake_sbi.xml',  b'<LinearLayout>\n<TextView text="SBI Login"/>\n</LinearLayout>')
        zf.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\nCreated-By: RAKSHAK-TEST\n')
        zf.writestr('META-INF/CERT.RSA',    b'FAKE_CERT_FOR_TESTING_ONLY')
        zf.writestr('res/layout/activity_main.xml',
                    b'<LinearLayout><TextView android:text="SBI Rewards"/></LinearLayout>')
        zf.writestr('res/values/strings.xml',
                    b'<resources><string name="app_name">SBI Rewards</string></resources>')

    apk_bytes = buf.getvalue()

    with open(output_path, 'wb') as f:
        f.write(apk_bytes)

    sha256 = hashlib.sha256(apk_bytes).hexdigest()
    print(f"[TEST APK] Created: {output_path}")
    print(f"[TEST APK] Size: {len(apk_bytes)/1024:.1f} KB")
    print(f"[TEST APK] SHA-256: {sha256}")
    return output_path


if __name__ == "__main__":
    out = "/tmp/test_malware_sample.apk"
    create_test_apk(out)
    print(f"Test APK ready at: {out}")
