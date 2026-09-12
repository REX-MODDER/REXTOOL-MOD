"""
REX-MOD Telegram Control Bot
Owner: REX-MOD — only your Telegram ID has access.
"""

import os
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from rex_db import (
    create_key, ban_key, unban_key, revoke_key, reset_hwid,
    get_key_info, get_all_keys, get_stats,
    blacklist_hwid, unblacklist_hwid, blacklist_name
)

# ── Secrets (set as env vars, never hardcode) ────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")          # from BotFather
OWNER_ID  = int(os.environ.get("OWNER_ID", "0"))     # your Telegram user ID


# ═══════════════════════════════════════════════════════════════
# GUARD: Only YOU can use this bot
# ═══════════════════════════════════════════════════════════════

def owner_only(fn):
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if update.effective_user.id != OWNER_ID:
            await update.message.reply_text("🔒 Access denied.")
            return
        return await fn(update, ctx)
    wrapper.__name__ = fn.__name__
    return wrapper


# ═══════════════════════════════════════════════════════════════
# /start  /help
# ═══════════════════════════════════════════════════════════════

@owner_only
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = (
        "🔥 *REX-MOD Control Panel*\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "*Key Management*\n"
        "`/genkey <days> [note]` — Generate key\n"
        "`/keyinfo <key>` — Key details\n"
        "`/ban <key>` — Ban key\n"
        "`/unban <key>` — Unban key\n"
        "`/revoke <key>` — Deactivate key\n"
        "`/resethwid <key>` — Reset device binding\n"
        "`/listkeys` — Last 25 keys\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "*Device Blacklist*\n"
        "`/blackhwid <hwid> [reason]` — Ban device\n"
        "`/unblackhwid <hwid>` — Unban device\n"
        "`/blackname <pattern> [reason]` — Ban username pattern\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "*Info*\n"
        "`/stats` — Usage statistics\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════
# KEY COMMANDS
# ═══════════════════════════════════════════════════════════════

@owner_only
async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/genkey <days> [note]`", parse_mode="Markdown")
        return
    try:
        days = int(ctx.args[0])
        if days <= 0:
            raise ValueError
    except ValueError:
        await update.message.reply_text("❌ Days must be a positive number.")
        return
    note = " ".join(ctx.args[1:]) if len(ctx.args) > 1 else ""
    key  = create_key(days, note)
    msg = (
        f"✅ *Key Generated — REX-MOD*\n\n"
        f"`{key}`\n\n"
        f"⏳ Valid: *{days} day(s)*\n"
        f"📝 Note: {note or '—'}"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


@owner_only
async def cmd_keyinfo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/keyinfo <key>`", parse_mode="Markdown")
        return
    info = get_key_info(ctx.args[0])
    if not info:
        await update.message.reply_text("❌ Key not found.")
        return
    status = "🔴 BANNED" if info["is_banned"] else ("✅ ACTIVE" if info["is_active"] else "⚫ REVOKED")
    msg = (
        f"🔑 *Key Info*\n\n"
        f"Key     : `{info['key']}`\n"
        f"HWID    : `{info['hwid']}`\n"
        f"Created : `{info['created_at']}`\n"
        f"Expires : `{info['expires_at']}`\n"
        f"Status  : {status}\n"
        f"Note    : {info['note'] or '—'}"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


@owner_only
async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/ban <key>`", parse_mode="Markdown")
        return
    key = ctx.args[0]
    if ban_key(key):
        await update.message.reply_text(f"🔴 Key `{key}` *BANNED*.", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Key not found.")


@owner_only
async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/unban <key>`", parse_mode="Markdown")
        return
    key = ctx.args[0]
    if unban_key(key):
        await update.message.reply_text(f"🟢 Key `{key}` *UNBANNED*.", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Key not found.")


@owner_only
async def cmd_revoke(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/revoke <key>`", parse_mode="Markdown")
        return
    key = ctx.args[0]
    if revoke_key(key):
        await update.message.reply_text(f"🚫 Key `{key}` *REVOKED* (permanently inactive).", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Key not found.")


@owner_only
async def cmd_resethwid(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/resethwid <key>`", parse_mode="Markdown")
        return
    key = ctx.args[0]
    if reset_hwid(key):
        await update.message.reply_text(
            f"🔄 HWID for key `{key}` *RESET*.\nUser can now log in from a new device.",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Key not found.")


@owner_only
async def cmd_listkeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    rows = get_all_keys(25)
    if not rows:
        await update.message.reply_text("No keys found.")
        return
    lines = ["🔑 *Last 25 Keys*\n"]
    for r in rows:
        key, hwid, exp, active, banned, note = r
        if banned:
            icon = "🔴"
        elif not active:
            icon = "⚫"
        else:
            icon = "✅"
        lines.append(f"{icon} `{key}` | exp `{str(exp)[:10]}` | {note or '—'}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════
# BLACKLIST COMMANDS
# ═══════════════════════════════════════════════════════════════

@owner_only
async def cmd_blackhwid(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/blackhwid <hwid> [reason]`", parse_mode="Markdown")
        return
    hwid   = ctx.args[0]
    reason = " ".join(ctx.args[1:]) if len(ctx.args) > 1 else "Fraud"
    if blacklist_hwid(hwid, reason):
        await update.message.reply_text(
            f"⛔ HWID `{hwid}` *BLACKLISTED*\nReason: {reason}",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Failed.")


@owner_only
async def cmd_unblackhwid(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/unblackhwid <hwid>`", parse_mode="Markdown")
        return
    hwid = ctx.args[0]
    if unblacklist_hwid(hwid):
        await update.message.reply_text(f"✅ HWID `{hwid}` removed from blacklist.", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ HWID not found in blacklist.")


@owner_only
async def cmd_blackname(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/blackname <pattern> [reason]`", parse_mode="Markdown")
        return
    pattern = ctx.args[0].lower()
    reason  = " ".join(ctx.args[1:]) if len(ctx.args) > 1 else "Fraud"
    if blacklist_name(pattern, reason):
        await update.message.reply_text(
            f"⛔ Name pattern `{pattern}` *BLACKLISTED*\nReason: {reason}",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Failed.")


# ═══════════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════════

@owner_only
async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    s = get_stats()
    msg = (
        f"📊 *REX-MOD Stats*\n\n"
        f"Total Keys       : `{s['total_keys']}`\n"
        f"Active Keys      : `{s['active_keys']}`\n"
        f"Banned Keys      : `{s['banned_keys']}`\n"
        f"Blacklisted HWIDs: `{s['blacklisted_hwids']}`\n"
        f"Logins (24h)     : `{s['logins_24h']}`"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN env var not set!")
    if OWNER_ID == 0:
        raise RuntimeError("OWNER_ID env var not set!")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",        cmd_start))
    app.add_handler(CommandHandler("help",         cmd_start))
    app.add_handler(CommandHandler("genkey",       cmd_genkey))
    app.add_handler(CommandHandler("keyinfo",      cmd_keyinfo))
    app.add_handler(CommandHandler("ban",          cmd_ban))
    app.add_handler(CommandHandler("unban",        cmd_unban))
    app.add_handler(CommandHandler("revoke",       cmd_revoke))
    app.add_handler(CommandHandler("resethwid",    cmd_resethwid))
    app.add_handler(CommandHandler("listkeys",     cmd_listkeys))
    app.add_handler(CommandHandler("blackhwid",    cmd_blackhwid))
    app.add_handler(CommandHandler("unblackhwid",  cmd_unblackhwid))
    app.add_handler(CommandHandler("blackname",    cmd_blackname))
    app.add_handler(CommandHandler("stats",        cmd_stats))

    print("[REX-MOD Bot] Running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
