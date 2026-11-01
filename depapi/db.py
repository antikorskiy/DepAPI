from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

DB_PATH = os.getenv("DS_DB", "data/server.db")
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    previous_key_hash TEXT,
    previous_key_expires_at TEXT,
    rps INTEGER DEFAULT 5,
    daily INTEGER DEFAULT 1000,
    active INTEGER DEFAULT 1,
    external_id TEXT,
    metadata TEXT,
    notes TEXT,
    expires_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_clients_external ON clients(external_id);

CREATE TABLE IF NOT EXISTS admin_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    expires_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS deepseek_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    auth_token TEXT NOT NULL,
    label TEXT,
    active INTEGER DEFAULT 1,
    error_count INTEGER DEFAULT 0,
    cooldown_until REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    session_key TEXT NOT NULL,
    deepseek_token_id INTEGER NOT NULL,
    ds_chat_session_id TEXT,
    ds_parent_message_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    UNIQUE(client_id, session_key),
    FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY(deepseek_token_id) REFERENCES deepseek_tokens(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(client_id, session_key);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(deepseek_token_id);

CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    endpoint TEXT,
    status INTEGER,
    latency_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_usage_client_ts ON usage_log(client_id, ts);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_log(ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_triggered_at TEXT,
    last_status INTEGER
);

CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    pattern TEXT NOT NULL,
    reason TEXT,
    notes TEXT,
    active INTEGER DEFAULT 1,
    expires_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_bans_kind ON bans(kind, active);
CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);
"""


def _migrate(conn: sqlite3.Connection):
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(clients)").fetchall()}
    for col, ddl in [
        ("previous_key_hash",       "TEXT"),
        ("previous_key_expires_at", "TEXT"),
        ("external_id",             "TEXT"),
        ("metadata",                "TEXT"),
        ("notes",                   "TEXT"),
        ("expires_at",              "TEXT"),
    ]:
        if col not in cols:
            conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {ddl}")

    scols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "deepseek_token_id" not in scols:
        conn.execute("ALTER TABLE sessions ADD COLUMN deepseek_token_id INTEGER")
        first = conn.execute(
            "SELECT id FROM deepseek_tokens WHERE active=1 ORDER BY id LIMIT 1"
        ).fetchone()
        if first:
            conn.execute(
                "UPDATE sessions SET deepseek_token_id=? WHERE deepseek_token_id IS NULL",
                (first["id"],),
            )
    conn.commit()


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    return conn


_DB = init_db()
_DB_LOCK = threading.Lock()


@contextmanager
def db():
    with _DB_LOCK:
        yield _DB


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def gen_client_key() -> str:
    return "sk-local-" + secrets.token_urlsafe(24)


def gen_admin_key() -> str:
    return "adm-" + secrets.token_urlsafe(32)


def gen_webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def log_usage(client_id: int, endpoint: str, status: int, latency_ms: int):
    with db() as conn:
        conn.execute(
            "INSERT INTO usage_log (client_id, endpoint, status, latency_ms) VALUES (?,?,?,?)",
            (client_id, endpoint, status, latency_ms),
        )
        conn.commit()