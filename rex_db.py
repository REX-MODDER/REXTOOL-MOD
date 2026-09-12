"""
REX-MOD Database Engine
Owner: REX-MOD
All rights reserved — not ankit, not anyone else.
"""

import sqlite3
import os
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = os.environ.get("REX_DB_PATH", "rex_users.db")


# ═══════════════════════════════════════════════════════════════
# INIT
# ═══════════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key         TEXT PRIMARY KEY,
            hwid        TEXT,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            is_active   INTEGER DEFAULT 1,
            is_banned   INTEGER DEFAULT 0,
            note        TEXT DEFAULT ''
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            hwid        TEXT PRIMARY KEY,
            name_match  TEXT DEFAULT '',
            reason      TEXT DEFAULT 'Fraud',
            banned_at   TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS name_blacklist (
            name_pattern TEXT PRIMARY KEY,
            reason       TEXT DEFAULT 'Fraud',
            added_at     TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key         TEXT,
            hwid        TEXT,
            ip          TEXT,
            timestamp   TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════
# KEY GENERATION
# ═══════════════════════════════════════════════════════════════

def _gen_key() -> str:
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(random.choices(chars, k=4)) for _ in range(4)]
    return "REX-" + "-".join(parts)


def create_key(days: int, note: str = "") -> str:
    """Generate a new license key valid for `days` days."""
    key = _gen_key()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.utcnow()
    exp = now + timedelta(days=days)
    c.execute(
        "INSERT INTO keys (key, created_at, expires_at, note) VALUES (?, ?, ?, ?)",
        (key, now.isoformat(), exp.isoformat(), note)
    )
    conn.commit()
    conn.close()
    return key


# ═══════════════════════════════════════════════════════════════
# VERIFICATION  (called on every /verify and /heartbeat)
# ═══════════════════════════════════════════════════════════════

def verify_key(key: str, hwid: str, ip: str = "") -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Blacklist check ──────────────────────────────────────────
    c.execute("SELECT reason FROM blacklist WHERE hwid=?", (hwid.upper(),))
    bl = c.fetchone()
    if bl:
        conn.close()
        return {"valid": False, "reason": f"HWID blacklisted: {bl[0]}"}

    # ── Key lookup ───────────────────────────────────────────────
    c.execute(
        "SELECT hwid, expires_at, is_active, is_banned FROM keys WHERE key=?",
        (key,)
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return {"valid": False, "reason": "Invalid key"}

    db_hwid, expires_at, is_active, is_banned = row

    if is_banned:
        conn.close()
        return {"valid": False, "reason": "Key is banned"}

    if not is_active:
        conn.close()
        return {"valid": False, "reason": "Key deactivated"}

    # ── Expiry ───────────────────────────────────────────────────
    if datetime.utcnow() > datetime.fromisoformat(expires_at):
        conn.close()
        return {"valid": False, "reason": "Key expired"}

    # ── HWID binding ────────────────────────────────────────────
    if db_hwid and db_hwid.upper() != hwid.upper():
        conn.close()
        return {"valid": False, "reason": "HWID mismatch — key bound to another device"}

    if not db_hwid:
        c.execute("UPDATE keys SET hwid=? WHERE key=?", (hwid.upper(), key))

    # ── Log ──────────────────────────────────────────────────────
    c.execute(
        "INSERT INTO login_log (key, hwid, ip, timestamp) VALUES (?,?,?,?)",
        (key, hwid.upper(), ip, datetime.utcnow().isoformat())
    )

    conn.commit()
    conn.close()

    exp_dt = datetime.fromisoformat(expires_at)
    days_left = max(0, (exp_dt - datetime.utcnow()).days)

    return {
        "valid": True,
        "expires_at": expires_at[:10],
        "days_left": days_left
    }


# ═══════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def ban_key(key: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE keys SET is_banned=1 WHERE key=?", (key,))
    ok = c.rowcount > 0
    conn.commit(); conn.close()
    return ok


def unban_key(key: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE keys SET is_banned=0 WHERE key=?", (key,))
    ok = c.rowcount > 0
    conn.commit(); conn.close()
    return ok


def revoke_key(key: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE keys SET is_active=0 WHERE key=?", (key,))
    ok = c.rowcount > 0
    conn.commit(); conn.close()
    return ok


def reset_hwid(key: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE keys SET hwid=NULL WHERE key=?", (key,))
    ok = c.rowcount > 0
    conn.commit(); conn.close()
    return ok


def get_key_info(key: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, hwid, created_at, expires_at, is_active, is_banned, note FROM keys WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    return {
        "key": row[0],
        "hwid": row[1] or "Not bound",
        "created_at": row[2][:10],
        "expires_at": row[3][:10],
        "is_active": bool(row[4]),
        "is_banned": bool(row[5]),
        "note": row[6] or ""
    }


def get_all_keys(limit: int = 25) -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT key, hwid, expires_at, is_active, is_banned, note "
        "FROM keys ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return rows


# ═══════════════════════════════════════════════════════════════
# HWID BLACKLIST
# ═══════════════════════════════════════════════════════════════

def blacklist_hwid(hwid: str, reason: str = "Fraud") -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT OR REPLACE INTO blacklist (hwid, reason, banned_at) VALUES (?,?,?)",
            (hwid.upper(), reason, datetime.utcnow().isoformat())
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def unblacklist_hwid(hwid: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE hwid=?", (hwid.upper(),))
    ok = c.rowcount > 0
    conn.commit(); conn.close()
    return ok


def get_blacklist_payload() -> dict:
    """Returns JSON payload matching what rexmod_tool.py already reads."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hwid FROM blacklist")
    hwids = [r[0] for r in c.fetchall()]
    c.execute("SELECT name_pattern FROM name_blacklist")
    names = [r[0] for r in c.fetchall()]
    conn.close()
    return {"hwids": hwids, "names": names}


def blacklist_name(pattern: str, reason: str = "Fraud") -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT OR REPLACE INTO name_blacklist (name_pattern, reason, added_at) VALUES (?,?,?)",
            (pattern.lower(), reason, datetime.utcnow().isoformat())
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════════

def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM keys")
    total = c.fetchone()[0]
    c.execute(
        "SELECT COUNT(*) FROM keys WHERE is_banned=0 AND is_active=1 AND expires_at > ?",
        (datetime.utcnow().isoformat(),)
    )
    active = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM blacklist")
    bl_hwids = c.fetchone()[0]
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    c.execute("SELECT COUNT(*) FROM login_log WHERE timestamp > ?", (cutoff,))
    logins_24h = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM keys WHERE is_banned=1")
    banned = c.fetchone()[0]
    conn.close()
    return {
        "total_keys": total,
        "active_keys": active,
        "banned_keys": banned,
        "blacklisted_hwids": bl_hwids,
        "logins_24h": logins_24h,
    }


# ── auto-init on import ──────────────────────────────────────────
init_db()
