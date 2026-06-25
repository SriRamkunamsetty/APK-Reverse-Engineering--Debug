"""
RAKSHAK — Database Layer
SQLite-based persistent case storage with full audit trail
"""

import sqlite3, json, os
from pathlib import Path
from datetime import datetime
from config import BASE_DIR

DB_PATH = BASE_DIR / "database" / "rakshak.db"
DB_PATH.parent.mkdir(exist_ok=True)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id       TEXT PRIMARY KEY,
        apk_name      TEXT NOT NULL,
        sha256        TEXT,
        risk_score    INTEGER,
        severity      TEXT,
        primary_family TEXT,
        apt_detected  INTEGER DEFAULT 0,
        status        TEXT DEFAULT 'PENDING',
        analyst       TEXT,
        submitted_at  TEXT,
        completed_at  TEXT,
        duration_sec  REAL,
        result_json   TEXT
    );

    CREATE TABLE IF NOT EXISTS iocs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    TEXT,
        ioc_type   TEXT,
        value      TEXT,
        risk       TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    TEXT,
        event      TEXT,
        detail     TEXT,
        timestamp  TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cases_severity  ON cases(severity);
    CREATE INDEX IF NOT EXISTS idx_cases_sha256    ON cases(sha256);
    CREATE INDEX IF NOT EXISTS idx_iocs_value      ON iocs(value);
    """)
    conn.commit()
    conn.close()
    print(f"[DB] Initialized: {DB_PATH}")


def save_case(result: dict):
    conn = get_conn()
    rs  = result.get("risk_score", {})
    h   = result.get("hashes", {})
    try:
        conn.execute("""
        INSERT OR REPLACE INTO cases
            (case_id, apk_name, sha256, risk_score, severity, primary_family,
             apt_detected, status, analyst, submitted_at, completed_at,
             duration_sec, result_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            result.get("case_id"),
            result.get("apk_name"),
            h.get("sha256"),
            rs.get("final_score"),
            rs.get("severity"),
            rs.get("primary_family"),
            1 if rs.get("apt_detected") else 0,
            result.get("status"),
            result.get("analyst"),
            result.get("analysis_start"),
            result.get("analysis_end"),
            result.get("duration_sec"),
            json.dumps(result, default=str),
        ))

        # Save IOCs
        strings = result.get("strings", {})
        case_id = result.get("case_id")
        for url in strings.get("urls", [])[:30]:
            conn.execute("INSERT INTO iocs (case_id,ioc_type,value,risk) VALUES (?,?,?,?)",
                         (case_id, "URL", url.get("url","")[:500], url.get("risk","")))
        for ip in strings.get("ips", [])[:20]:
            conn.execute("INSERT INTO iocs (case_id,ioc_type,value,risk) VALUES (?,?,?,?)",
                         (case_id, "IP", ip.get("ip",""), "HIGH"))

        conn.execute("INSERT INTO audit_log (case_id,event,detail) VALUES (?,?,?)",
                     (case_id, "ANALYSIS_COMPLETE",
                      f"Score={rs.get('final_score')}, Severity={rs.get('severity')}"))
        conn.commit()
    finally:
        conn.close()


def get_case(case_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT result_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
    conn.close()
    if row:
        return json.loads(row["result_json"])
    return None


def list_cases(limit: int = 50) -> list[dict]:
    conn = get_conn()
    rows = conn.execute("""
        SELECT case_id, apk_name, sha256, risk_score, severity,
               primary_family, apt_detected, status, analyst, submitted_at, duration_sec
        FROM cases ORDER BY submitted_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def search_ioc(value: str) -> list[dict]:
    conn = get_conn()
    rows = conn.execute("""
        SELECT i.*, c.apk_name, c.risk_score, c.severity
        FROM iocs i JOIN cases c ON i.case_id=c.case_id
        WHERE i.value LIKE ?
        ORDER BY i.created_at DESC LIMIT 20
    """, (f"%{value}%",)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = get_conn()
    total     = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    critical  = conn.execute("SELECT COUNT(*) FROM cases WHERE severity='CRITICAL'").fetchone()[0]
    apt_count = conn.execute("SELECT COUNT(*) FROM cases WHERE apt_detected=1").fetchone()[0]
    ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    conn.close()
    return {
        "total_cases"   : total,
        "critical_cases": critical,
        "apt_cases"     : apt_count,
        "total_iocs"    : ioc_count,
    }


# Initialize on import
init_db()
