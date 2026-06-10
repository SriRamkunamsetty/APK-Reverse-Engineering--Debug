"""
RAKSHAK — Advanced ML Detection Engine
Three-layer ML pipeline working in parallel:
  1. Opcode N-gram classifier (structural patterns)
  2. API call sequence scorer (temporal behaviour)
  3. Semantic embedding similarity (code intent)
All three vote → ensemble confidence score
"""

import re, zipfile, json, os, hashlib
import numpy as np
from pathlib import Path
from typing import Any
from collections import Counter
from config import BASE_DIR

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — OPCODE N-GRAM FEATURE EXTRACTOR
# Converts DEX bytecode opcode sequences into ML feature vectors
# Malware has characteristic opcode patterns even after renaming obfuscation
# ══════════════════════════════════════════════════════════════════════════════
class OpcodeNgramExtractor:
    """
    Extracts Dalvik opcode N-grams from DEX bytecode.
    Returns a frequency-normalised feature vector of length N_FEATURES.
    """
    N_FEATURES = 300

    # Core Dalvik opcodes mapped to index tokens
    OPCODE_MAP = {
        b'\x00': 'NOP',    b'\x01': 'MOVE',    b'\x0e': 'RETURN_VOID',
        b'\x12': 'CONST4', b'\x1a': 'CONST_STR', b'\x1c': 'CONST_CLS',
        b'\x1f': 'CHECK_CAST', b'\x20': 'INSTANCE_OF',
        b'\x22': 'NEW_INST', b'\x23': 'NEW_ARR',
        b'\x35': 'INVOKE_VIRT', b'\x36': 'INVOKE_SUPER',
        b'\x38': 'INVOKE_DIRECT', b'\x39': 'INVOKE_STATIC',
        b'\x3b': 'INVOKE_INTF',
        b'\x54': 'IGET', b'\x55': 'IGET_WIDE', b'\x59': 'IPUT',
        b'\x60': 'SGET', b'\x67': 'SPUT',
        b'\x6e': 'INVOKE_VIRT_RANGE',
        b'\x28': 'GOTO', b'\x29': 'GOTO16', b'\x2a': 'GOTO32',
        b'\x2b': 'PACKED_SWITCH', b'\x2c': 'SPARSE_SWITCH',
        b'\xd0': 'ADD_INT', b'\xd1': 'SUB_INT',
        b'\xd2': 'MUL_INT', b'\xd3': 'DIV_INT',
        b'\xa1': 'AND_INT', b'\xa2': 'OR_INT',  b'\xa3': 'XOR_INT',
        b'\x44': 'AGET', b'\x4b': 'APUT',
        b'\x0f': 'RETURN', b'\x10': 'RETURN_WIDE', b'\x11': 'RETURN_OBJ',
    }

    def extract(self, apk_path: str) -> np.ndarray:
        """Extract N-gram feature vector from APK's DEX files."""
        opcodes = self._extract_opcodes(apk_path)
        ngrams  = self._build_ngrams(opcodes, n=3)
        return self._vectorise(ngrams)

    def _extract_opcodes(self, apk_path: str) -> list[str]:
        opcodes = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        data = zf.read(name)
                        for i in range(0, min(len(data) - 1, 50000), 2):
                            byte = data[i:i+1]
                            tok  = self.OPCODE_MAP.get(byte)
                            if tok:
                                opcodes.append(tok)
        except Exception:
            pass
        return opcodes

    def _build_ngrams(self, seq: list[str], n: int) -> Counter:
        return Counter(
            tuple(seq[i:i+n]) for i in range(len(seq) - n + 1)
        )

    def _vectorise(self, ngrams: Counter) -> np.ndarray:
        """Stable hash-based vectorisation (no vocabulary needed)."""
        vec = np.zeros(self.N_FEATURES, dtype=np.float32)
        total = sum(ngrams.values()) or 1
        for gram, count in ngrams.items():
            idx = int(hashlib.md5('_'.join(gram).encode()).hexdigest(), 16) % self.N_FEATURES
            vec[idx] += count / total
        return vec


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — API CALL SEQUENCE SCORER
# Dangerous API calls have characteristic sequence patterns in malware
# vs legitimate apps — scored using learned sequence weights
# ══════════════════════════════════════════════════════════════════════════════
class APISequenceScorer:
    """
    Extracts ordered API call sequences from APK strings.
    Scores sequences against known malicious patterns using bigram transition
    probabilities derived from a synthetic training corpus.
    """

    # Suspicious API transition pairs (A → B indicates malicious intent)
    MALICIOUS_TRANSITIONS = {
        ("getSubscriberId",      "sendTextMessage")       : 0.95,
        ("getMessageBody",       "HttpPost")              : 0.92,
        ("getRunningTasks",      "addView")               : 0.90,
        ("onAccessibilityEvent", "performAction")         : 0.95,
        ("AudioRecord",          "FileOutputStream")      : 0.88,
        ("getContactsUri",       "sendTextMessage")       : 0.85,
        ("DexClassLoader",       "loadClass")             : 0.90,
        ("Runtime.exec",         "waitFor")               : 0.93,
        ("getDeviceId",          "HttpPost")              : 0.80,
        ("Camera.open",          "FileOutputStream")      : 0.88,
        ("ClipboardManager",     "sendTextMessage")       : 0.87,
        ("requestAdminForDevice","lockNow")               : 0.98,
        ("setComponentEnabled",  "BOOT_COMPLETED")        : 0.82,
        ("SmsManager",           "sendTextMessage")       : 0.85,
        ("ContentResolver",      "HttpPost")              : 0.78,
        ("PackageInstaller",     "DexClassLoader")        : 0.95,
        ("getWindow",            "addView")               : 0.85,
        ("InputMethodService",   "getUnicodeChar")        : 0.90,
    }

    # Benign transitions (lower the overall score)
    BENIGN_TRANSITIONS = {
        ("setContentView",       "findViewById")          : -0.3,
        ("onCreate",             "setContentView")        : -0.2,
        ("SharedPreferences",    "getString")             : -0.1,
        ("Retrofit",             "enqueue")               : -0.3,
        ("Room",                 "runInTransaction")      : -0.3,
    }

    API_KEYWORDS = [
        "getSubscriberId","getDeviceId","sendTextMessage","getMessageBody",
        "onAccessibilityEvent","performAction","dispatchGesture",
        "DexClassLoader","loadClass","Runtime.exec","ProcessBuilder",
        "AudioRecord","startRecording","Camera","open","FileOutputStream",
        "HttpPost","HttpClient","getRunningTasks","addView","OVERLAY",
        "requestAdminForDevice","lockNow","getContactsUri","ClipboardManager",
        "PackageInstaller","setComponentEnabled","BOOT_COMPLETED",
        "SmsManager","ContentResolver","InputMethodService","getUnicodeChar",
        "setContentView","onCreate","SharedPreferences","Retrofit","Room",
        "MediaRecorder","getExternalStorage","WebView","JavaScript",
    ]

    def score(self, apk_path: str) -> dict:
        sequence = self._extract_sequence(apk_path)
        if not sequence:
            return {"sequence_score": 0.0, "malicious_transitions": [],
                    "sequence_length": 0}

        total_score  = 0.0
        found_mal    = []
        found_benign = []

        # Score consecutive pairs
        for i in range(len(sequence) - 1):
            pair = (sequence[i], sequence[i+1])
            rev  = (sequence[i+1], sequence[i])

            for key, weight in self.MALICIOUS_TRANSITIONS.items():
                if key[0] in pair[0] and key[1] in pair[1]:
                    total_score += weight
                    found_mal.append(f"{pair[0]}→{pair[1]}")
                    break
                if key[0] in pair[1] and key[1] in pair[0]:
                    total_score += weight * 0.7  # reversed = less confident
                    break

            for key, weight in self.BENIGN_TRANSITIONS.items():
                if key[0] in pair[0] and key[1] in pair[1]:
                    total_score += weight

        normalised = min(total_score / max(len(sequence), 1) * 20, 100)
        return {
            "sequence_score"        : round(normalised, 1),
            "sequence_length"       : len(sequence),
            "malicious_transitions" : list(set(found_mal))[:10],
            "confidence"            : "HIGH" if normalised > 60 else
                                      "MEDIUM" if normalised > 30 else "LOW",
        }

    def _extract_sequence(self, apk_path: str) -> list[str]:
        found = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        data    = zf.read(name)
                        strings = re.findall(b'[\x20-\x7e]{6,}', data)
                        for s in strings:
                            decoded = s.decode('ascii', errors='ignore')
                            for kw in self.API_KEYWORDS:
                                if kw in decoded and kw not in found:
                                    found.append(kw)
        except Exception:
            pass
        return found


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — SEMANTIC CODE SIMILARITY
# Compares APK's code signature against known malware family signatures
# using TF-IDF weighted bag-of-identifiers similarity
# ══════════════════════════════════════════════════════════════════════════════
class SemanticSimilarityEngine:
    """
    Builds a TF-IDF bag-of-identifiers representation of APK code,
    then computes cosine similarity against known malware family signatures.
    Works without a GPU — purely CPU-based sklearn vectoriser.
    """

    # Known malware family code signatures (representative identifier sets)
    FAMILY_SIGNATURES = {
        "BankBot": [
            "smsmessage getmessagebody smsmanager sendtextmessage",
            "system_alert_window addview type_application_overlay",
            "getrunningtasks foreground banking credential",
            "onreceive smsreceived abortbroadcast",
        ],
        "Cerberus": [
            "onaccessibilityevent performaction dispatchgesture",
            "accessibilitynodeinfo getpackagename banking",
            "keylogg inputmethod getunicodechar",
            "grabscreen screenshot mediaprojetion",
        ],
        "Anubis": [
            "mediaprojetion screencapture virtualscreen",
            "deviceadmin lockdevice resetpassword",
            "toast maketext overlay transparent",
        ],
        "Drinik": [
            "incometax efiling aadhaar pancard",
            "system_alert_window receive_sms otp",
            "credential harvest banking india",
        ],
        "SpyNote_RAT": [
            "audiorecord startrecording voicecommunication",
            "camera open surfacetexture captureimage",
            "location requestlocationupdates gps tracking",
            "fileoutputstream upload http exfil",
        ],
        "APT36_Transparent_Tribe": [
            "crimsonrat drdo army defence military",
            "location contacts calllog sms record",
            "dexclassloader payload decrypt execute",
            "rat remote_access_trojan command control",
        ],
        "Dropper": [
            "dexclassloader pathclassloader inmemory",
            "assets decrypt aes payload execute",
            "request_install_packages packageinstaller apk",
            "download http loadclass invoke",
        ],
        "Ransomware": [
            "deviceadmin lockdevice resetpassword lockscreen",
            "encrypt aes files sdcard storage",
            "bitcoin ransom payment decrypt key",
        ],
        "CryptoMiner": [
            "stratum mining pool hashrate monero xmr",
            "cpu wakelock background persistent service",
        ],
    }

    def __init__(self):
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
            self.TfidfVectorizer  = TfidfVectorizer
            self.cosine_similarity = cosine_similarity
            self.available = True
        except ImportError:
            self.available = False

    def analyse(self, apk_path: str) -> dict:
        if not self.available:
            return {"available": False, "error": "scikit-learn not installed"}

        apk_text = self._extract_code_text(apk_path)
        if not apk_text:
            return {"available": True, "similarities": {}, "top_match": None}

        # Flatten all signatures into a corpus + APK doc
        corpus = []
        labels = []
        for family, sigs in self.FAMILY_SIGNATURES.items():
            for sig in sigs:
                corpus.append(sig)
                labels.append(family)

        all_docs = corpus + [apk_text]

        try:
            vec = self.TfidfVectorizer(
                analyzer    = 'word',
                ngram_range = (1, 2),
                min_df      = 1,
                max_features= 2000,
                sublinear_tf= True,
            ).fit_transform(all_docs)

            # Cosine similarity between APK and each family
            apk_vec     = vec[-1]
            family_vecs = vec[:-1]
            sims        = self.cosine_similarity(apk_vec, family_vecs)[0]

            # Average similarity per family
            family_scores: dict[str, float] = {}
            label_counts:  dict[str, int]   = Counter(labels)
            label_sums:    dict[str, float] = {}

            for label, score in zip(labels, sims):
                label_sums[label] = label_sums.get(label, 0.0) + float(score)

            for family, total in label_sums.items():
                family_scores[family] = round(total / label_counts[family], 4)

            sorted_sims = sorted(
                family_scores.items(), key=lambda x: x[1], reverse=True
            )
            top_match = sorted_sims[0] if sorted_sims else None

            return {
                "available"   : True,
                "similarities": dict(sorted_sims),
                "top_match"   : {
                    "family"    : top_match[0],
                    "similarity": top_match[1],
                    "confidence": "HIGH"   if top_match[1] > 0.35
                                  else "MEDIUM" if top_match[1] > 0.15
                                  else "LOW",
                } if top_match else None,
                "strong_matches": [
                    {"family": f, "score": s}
                    for f, s in sorted_sims if s > 0.15
                ][:5],
            }
        except Exception as e:
            return {"available": True, "error": str(e)}

    def _extract_code_text(self, apk_path: str) -> str:
        """Extract and normalise all identifier-like strings from DEX."""
        tokens = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        data    = zf.read(name)
                        strings = re.findall(b'[A-Za-z_][A-Za-z0-9_]{3,}', data)
                        tokens.extend(
                            s.decode('ascii', errors='ignore').lower()
                            for s in strings
                        )
        except Exception:
            pass
        return ' '.join(tokens[:5000])


# ══════════════════════════════════════════════════════════════════════════════
# ENSEMBLE COMBINER — fuses all three ML signals into final verdict
# ══════════════════════════════════════════════════════════════════════════════
class MLEnsemble:
    """
    Combines Opcode N-gram + API Sequence + Semantic Similarity
    into a single ensemble ML score with per-signal attribution.
    """

    WEIGHTS = {
        "ngram"    : 0.30,
        "sequence" : 0.40,
        "semantic" : 0.30,
    }

    def __init__(self):
        self.ngram    = OpcodeNgramExtractor()
        self.sequence = APISequenceScorer()
        self.semantic = SemanticSimilarityEngine()

    def analyse(self, apk_path: str,
                case_id: str = "") -> dict:
        from core.event_bus import emit, EventType

        results = {}

        # --- N-gram features (used for anomaly scoring) ---
        ngram_vec  = self.ngram.extract(apk_path)
        # Anomaly: high variance in opcode distribution = suspicious
        ngram_score = float(np.clip(np.std(ngram_vec) * 800, 0, 100))
        results["ngram"] = {
            "score"         : round(ngram_score, 1),
            "feature_dim"   : len(ngram_vec),
            "nonzero_feats" : int(np.count_nonzero(ngram_vec)),
        }
        if case_id:
            emit(EventType.STATIC_FINDING, case_id, {
                "engine" : "ML-NGRAM",
                "title"  : "Opcode N-gram Analysis",
                "score"  : round(ngram_score, 1),
                "detail" : f"{int(np.count_nonzero(ngram_vec))} distinct opcode patterns",
            })

        # --- API Sequence scoring ---
        seq_result = self.sequence.score(apk_path)
        results["sequence"] = seq_result
        if case_id and seq_result.get("malicious_transitions"):
            emit(EventType.STATIC_FINDING, case_id, {
                "engine" : "ML-SEQUENCE",
                "title"  : "API Call Sequence Anomaly",
                "score"  : seq_result["sequence_score"],
                "detail" : f"Malicious transitions: {', '.join(seq_result['malicious_transitions'][:3])}",
            }, severity="HIGH")

        # --- Semantic similarity ---
        sem_result = self.semantic.analyse(apk_path)
        results["semantic"] = sem_result
        top = sem_result.get("top_match")
        sem_score = (top["similarity"] * 100 if top else 0)
        if case_id and top and top["similarity"] > 0.15:
            emit(EventType.YARA_MATCH, case_id, {
                "engine" : "ML-SEMANTIC",
                "family" : top["family"],
                "score"  : round(sem_score, 1),
                "detail" : f"Semantic similarity: {top['similarity']:.3f} ({top['confidence']})",
            }, severity="HIGH")

        # --- Ensemble score ---
        ensemble = (
            ngram_score    * self.WEIGHTS["ngram"]    +
            seq_result.get("sequence_score", 0) * self.WEIGHTS["sequence"] +
            sem_score      * self.WEIGHTS["semantic"]
        )
        ensemble = round(min(ensemble, 100), 1)

        if case_id:
            emit(EventType.SCORE_UPDATE, case_id, {
                "dimension"   : "ml_ensemble",
                "raw"         : ensemble,
                "contribution": round(ensemble * 0.15, 2),
            })

        return {
            "ensemble_score"    : ensemble,
            "ngram_score"       : round(ngram_score, 1),
            "sequence_score"    : round(seq_result.get("sequence_score", 0), 1),
            "semantic_score"    : round(sem_score, 1),
            "top_family_match"  : top["family"] if top else "Unknown",
            "family_similarity" : round(top["similarity"], 3) if top else 0,
            "strong_matches"    : sem_result.get("strong_matches", []),
            "malicious_api_chains": seq_result.get("malicious_transitions", []),
            "ml_verdict"        : "MALICIOUS" if ensemble > 60
                                   else "SUSPICIOUS" if ensemble > 30
                                   else "LIKELY_CLEAN",
            "weights_used"      : self.WEIGHTS,
        }
