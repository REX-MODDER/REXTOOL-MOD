"""
REX-MOD API Server
Owner: REX-MOD
Endpoints consumed by rexmod_tool.py (existing + new)
"""

import os
from flask import Flask, request, jsonify
from rex_db import (
    verify_key, get_blacklist_payload,
    blacklist_hwid, ban_key
)

app = Flask(__name__)

# ── Only the Telegram bot can call admin endpoints ───────────────
BOT_SECRET = os.environ.get("BOT_SECRET", "CHANGE_THIS_SECRET_NOW")


def _is_bot(req) -> bool:
    return req.headers.get("X-Bot-Secret") == BOT_SECRET


# ═══════════════════════════════════════════════════════════════
# PUBLIC ENDPOINTS  (called by rexmod_tool.py)
# ═══════════════════════════════════════════════════════════════

@app.route("/verify", methods=["POST"])
def ep_verify():
    """
    Body: {"key": "REX-XXXX-...", "hwid": "ABCD1234..."}
    Returns: {"valid": true/false, "expires_at": "...", "days_left": N, "reason": "..."}
    """
    data = request.get_json(silent=True) or {}
    key  = str(data.get("key",  "")).strip()
    hwid = str(data.get("hwid", "")).strip()
    if not key or not hwid:
        return jsonify({"valid": False, "reason": "Missing key or hwid"}), 400
    result = verify_key(key, hwid, request.remote_addr or "")
    return jsonify(result)


@app.route("/heartbeat", methods=["GET", "POST"])
def ep_heartbeat():
    """
    GET  → simple alive ping (existing tool behaviour)
    POST → per-user alive check with key + hwid

    The existing tool does:
        resp = requests.get(_HEARTBEAT_URL, timeout=8)
        if data.get("alive") is False: kill
    After patching the tool does:
        resp = requests.post(_HEARTBEAT_URL, json={key, hwid})
    Both shapes are supported here.
    """
    if request.method == "GET":
        # Legacy: just confirm server is up
        return jsonify({"alive": True})

    data = request.get_json(silent=True) or {}
    key  = str(data.get("key",  "")).strip()
    hwid = str(data.get("hwid", "")).strip()
    if not key or not hwid:
        return jsonify({"alive": True})   # no creds → don't kill, just ping
    result = verify_key(key, hwid, request.remote_addr or "")
    return jsonify({"alive": result["valid"]})


@app.route("/blacklist", methods=["GET"])
def ep_blacklist():
    """
    Returns the blacklist JSON that rexmod_tool.py already reads:
        {"hwids": [...], "names": [...]}
    """
    return jsonify(get_blacklist_payload())


@app.route("/report_fraud", methods=["POST"])
def ep_report_fraud():
    """
    Client-side fraud trap reports here → auto-ban.
    Body: {"hwid": "...", "key": "...", "reason": "..."}
    """
    data = request.get_json(silent=True) or {}
    hwid   = str(data.get("hwid",   "")).strip()
    key    = str(data.get("key",    "")).strip()
    reason = str(data.get("reason", "Client-side fraud trap")).strip()
    if hwid:
        blacklist_hwid(hwid, reason)
    if key:
        ban_key(key)
    return jsonify({"reported": True})


# ═══════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
@app.route("/", methods=["GET"])
def ep_health():
    return jsonify({"status": "REX-MOD Server Online", "owner": "REX-MOD"})


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[REX-MOD] Server starting on port {port}")
    app.run(host="0.0.0.0", port=port)
