import sqlite3
import os
import datetime
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "audit.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

_lock = threading.Lock()


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                session_id TEXT,
                full_name TEXT,
                drfo_code TEXT,
                edrpou_code TEXT,
                ip_address TEXT,
                action TEXT NOT NULL,
                path TEXT,
                file_name TEXT,
                user_agent TEXT,
                result TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()


def log_event(session_id, full_name, drfo_code, edrpou_code,
              ip_address, action, path, file_name, user_agent, result):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO audit_log
                (ts, session_id, full_name, drfo_code, edrpou_code,
                 ip_address, action, path, file_name, user_agent, result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, session_id, full_name, drfo_code, edrpou_code,
             ip_address, action, path, file_name, user_agent, result),
        )
        conn.commit()
        conn.close()


def fetch_recent(limit=100):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT ts, full_name, drfo_code, ip_address, action, path, file_name, result "
        "FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows
