#!/usr/bin/env python3
"""CLI for DepAPI: manage clients, tokens, admin keys, audit."""
import os
import sqlite3
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from depapi.db import DB_PATH, gen_admin_key, gen_client_key, hash_key, init_db  # noqa: E402
from depapi.auth import ALL_SCOPES, ROLE_PRESETS  # noqa: E402

DEFAULT_RPS = int(os.getenv("DS_DEFAULT_RPS", "5"))
DEFAULT_DAILY = int(os.getenv("DS_DEFAULT_DAILY", "1000"))

conn = init_db()


def _flag(args, name):
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            return args[i + 1]
    return None


def cmd_init(args):
    print(f"DB ready at {DB_PATH}")


def cmd_keygen(args):
    name = _flag(args, "--name") or f"client-{os.urandom(3).hex()}"
    rps = int(_flag(args, "--rps") or DEFAULT_RPS)
    daily = int(_flag(args, "--daily") or DEFAULT_DAILY)
    raw = gen_client_key()
    try:
        with conn:
            conn.execute(
                "INSERT INTO clients (name, key_hash, key_prefix, rps, daily) VALUES (?,?,?,?,?)",
                (name, hash_key(raw), raw[:12], rps, daily),
            )
    except sqlite3.IntegrityError:
        print(f"ERROR: name {name!r} already exists")
        sys.exit(1)
    print(f"name: {name}\nkey:  {raw}\n\nSave it now; it cannot be recovered.")


def cmd_keys(args):
    rows = conn.execute(
        "SELECT id, name, key_prefix, rps, daily, active, last_used_at FROM clients ORDER BY id"
    ).fetchall()
    print(f"{'ID':>3}  {'NAME':<20} {'KEY':<15} {'RPS':>4} {'DAILY':>6} {'ACTIVE':>6}  LAST_USED")
    for r in rows:
        print(f"{r['id']:>3}  {r['name']:<20} {r['key_prefix']:<15} "
              f"{r['rps']:>4} {r['daily']:>6} {r['active']:>6}  {r['last_used_at'] or '-'}")


def cmd_revoke(args):
    if not args:
        print("usage: manage.py revoke <name-or-id> [--purge-sessions]")
        sys.exit(1)
    target = args[0]
    purge = "--purge-sessions" in args
    with conn:
        if target.isdigit():
            cid = int(target)
            cur = conn.execute("UPDATE clients SET active=0 WHERE id=?", (cid,))
        else:
            row = conn.execute("SELECT id FROM clients WHERE name=?", (target,)).fetchone()
            if not row:
                print("not found")
                sys.exit(1)
            cid = row["id"]
            cur = conn.execute("UPDATE clients SET active=0 WHERE id=?", (cid,))
        if cur.rowcount == 0:
            print("not found")
            sys.exit(1)
        if purge:
            conn.execute("DELETE FROM sessions WHERE client_id=?", (cid,))
    print(f"revoked{' (sessions purged)' if purge else ''}")


def cmd_add_token(args):
    if len(args) < 2:
        print("usage: manage.py add-token <session_id> <bearer_token> [--label L]")
        sys.exit(1)
    sid, tok = args[0], args[1]
    if not tok.lower().startswith("bearer "):
        tok = "Bearer " + tok
    label = _flag(args, "--label") or ""
    try:
        with conn:
            conn.execute(
                "INSERT INTO deepseek_tokens (session_id, auth_token, label) VALUES (?,?,?)",
                (sid, tok, label),
            )
    except sqlite3.IntegrityError:
        print("ERROR: session_id already exists")
        sys.exit(1)
    print("added")


def cmd_tokens(args):
    import time
    rows = conn.execute(
        "SELECT id, session_id, label, active, error_count, cooldown_until FROM deepseek_tokens ORDER BY id"
    ).fetchall()
    print(f"{'ID':>3}  {'SESSION':<24} {'LABEL':<16} {'ACTIVE':>6} {'ERR':>4} {'COOLDOWN':>10}")
    for r in rows:
        cd = ""
        if r["cooldown_until"] and r["cooldown_until"] > 0:
            left = int(r["cooldown_until"] - time.time())
            if left > 0:
                cd = f"{left}s"
        print(f"{r['id']:>3}  {r['session_id']:<24} {r['label'] or '':<16} "
              f"{r['active']:>6} {r['error_count']:>4} {cd:>10}")


def cmd_rm_token(args):
    if not args:
        print("usage: manage.py rm-token <session_id> [--force]")
        sys.exit(1)
    sid = args[0]
    row = conn.execute("SELECT id FROM deepseek_tokens WHERE session_id=?", (sid,)).fetchone()
    if not row:
        print("not found")
        sys.exit(1)
    tid = row["id"]
    using = conn.execute("SELECT COUNT(*) FROM sessions WHERE deepseek_token_id=?", (tid,)).fetchone()[0]
    if using > 0:
        if "--force" in args:
            with conn:
                conn.execute("UPDATE deepseek_tokens SET active=0 WHERE id=?", (tid,))
            print(f"deactivated (still used by {using} session(s))")
        else:
            print(f"ERROR: token {tid} used by {using} session(s). Use --force to deactivate.")
            sys.exit(1)
        return
    with conn:
        conn.execute("DELETE FROM deepseek_tokens WHERE id=?", (tid,))
    print("removed")


def cmd_usage(args):
    days = int(_flag(args, "--days") or 7)
    rows = conn.execute(
        """SELECT c.name, COUNT(*) n,
                  SUM(CASE WHEN u.status=200 THEN 1 ELSE 0 END) ok
           FROM usage_log u JOIN clients c ON c.id=u.client_id
           WHERE u.ts >= datetime('now', ?)
           GROUP BY c.id ORDER BY n DESC""",
        (f"-{days} days",),
    ).fetchall()
    print(f"{'CLIENT':<20} {'TOTAL':>8} {'OK':>8} {'FAIL':>8}")
    for r in rows:
        fail = r["n"] - (r["ok"] or 0)
        print(f"{r['name']:<20} {r['n']:>8} {r['ok'] or 0:>8} {fail:>8}")


def cmd_sessions(args):
    rows = conn.execute(
        """SELECT c.name owner, s.session_key, s.deepseek_token_id,
                  s.ds_parent_message_id, s.last_used_at
           FROM sessions s JOIN clients c ON c.id=s.client_id
           ORDER BY s.last_used_at DESC LIMIT 50"""
    ).fetchall()
    print(f"{'OWNER':<20} {'SESSION_KEY':<20} {'TOKEN':>5} {'HAS_CTX':>7}  LAST_USED")
    for r in rows:
        print(f"{r['owner']:<20} {r['session_key']:<20} {r['deepseek_token_id']:>5} "
              f"{'yes' if r['ds_parent_message_id'] else 'no':>7}  {r['last_used_at'] or '-'}")


def cmd_admin_keygen(args):
    import json as _json
    name = _flag(args, "--name") or f"adm-{os.urandom(3).hex()}"
    role = _flag(args, "--role")
    scopes_arg = _flag(args, "--scopes")
    expires = _flag(args, "--expires")

    if role:
        if role not in ROLE_PRESETS:
            print(f"ERROR: unknown role {role!r}. Known: {', '.join(ROLE_PRESETS)}")
            sys.exit(1)
        scopes = sorted(ROLE_PRESETS[role])
    elif scopes_arg:
        scopes = [s.strip() for s in scopes_arg.split(",") if s.strip()]
        unknown = set(scopes) - ALL_SCOPES
        if unknown:
            print(f"ERROR: unknown scopes: {sorted(unknown)}")
            sys.exit(1)
    else:
        scopes = sorted(ROLE_PRESETS["readonly"])

    raw = gen_admin_key()
    h = hash_key(raw)
    try:
        with conn:
            conn.execute(
                "INSERT INTO admin_keys (name, key_hash, key_prefix, scopes, expires_at) VALUES (?,?,?,?,?)",
                (name, h, raw[:12], _json.dumps(scopes), expires),
            )
    except sqlite3.IntegrityError:
        print(f"ERROR: name {name!r} already exists")
        sys.exit(1)

    print(f"name:   {name}")
    print(f"key:    {raw}")
    print(f"scopes: {', '.join(scopes)}")
    if expires:
        print(f"expires: {expires}")
    print("\nSave it now; it cannot be recovered.")


def cmd_admin_keys(args):
    rows = conn.execute(
        "SELECT id, name, key_prefix, scopes, active, expires_at, last_used_at FROM admin_keys ORDER BY id"
    ).fetchall()
    print(f"{'ID':>3}  {'NAME':<20} {'KEY':<15} {'ACTIVE':>6}  SCOPES")
    for r in rows:
        print(f"{r['id']:>3}  {r['name']:<20} {r['key_prefix']:<15} "
              f"{r['active']:>6}  {r['scopes']}")


def cmd_admin_revoke(args):
    if not args:
        print("usage: manage.py admin-revoke <name-or-id>")
        sys.exit(1)
    target = args[0]
    with conn:
        if target.isdigit():
            cur = conn.execute("UPDATE admin_keys SET active=0 WHERE id=?", (int(target),))
        else:
            cur = conn.execute("UPDATE admin_keys SET active=0 WHERE name=?", (target,))
        if cur.rowcount == 0:
            print("not found")
            sys.exit(1)
    print("revoked")


def cmd_audit(args):
    since = _flag(args, "--since")
    actor = _flag(args, "--actor")
    action = _flag(args, "--action")
    limit = int(_flag(args, "--limit") or 50)

    sql = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if actor:
        sql += " AND actor=?"; params.append(actor)
    if action:
        sql += " AND action=?"; params.append(action)
    if since:
        sql += " AND ts >= ?"; params.append(since)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    print(f"{'TS':<20} {'ACTOR':<20} {'ACTION':<25} {'TARGET':<20} DETAILS")
    for r in rows:
        d = (r["details"] or "")[:60]
        print(f"{r['ts']:<20} {r['actor']:<20} {r['action']:<25} "
              f"{(r['target'] or ''):<20} {d}")


def cmd_ban_ip(args):
    from depapi.bans import create_ban
    if not args:
        print("usage: manage.py ban-ip <ip|cidr|glob> [--reason TEXT] [--hours N]")
        sys.exit(1)
    pattern = args[0]
    reason = _flag(args, "--reason") or ""
    hours = int(_flag(args, "--hours") or 0)
    expires = None
    if hours > 0:
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b = create_ban("ip", pattern, reason=reason, expires_at=expires, created_by="cli")
    print(f"banned ip {pattern} (id={b.id}){', expires '+expires if expires else ''}")


def cmd_ban_ua(args):
    from depapi.bans import create_ban
    if not args:
        print("usage: manage.py ban-ua <substring|glob> [--reason TEXT] [--hours N]")
        sys.exit(1)
    pattern = args[0]
    reason = _flag(args, "--reason") or ""
    hours = int(_flag(args, "--hours") or 0)
    expires = None
    if hours > 0:
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b = create_ban("ua", pattern, reason=reason, expires_at=expires, created_by="cli")
    print(f"banned ua {pattern!r} (id={b.id}){', expires '+expires if expires else ''}")


def cmd_bans(args):
    from depapi.bans import list_bans
    active = None
    if "--active" in args:
        active = True
    if "--inactive" in args:
        active = False
    items = list_bans(active=active)
    print(f"{'ID':>4}  {'KIND':<4} {'ACTIVE':>6} {'EXPIRES':<20} {'PATTERN':<32} REASON")
    for b in items:
        exp = b.expires_at.strftime("%Y-%m-%d %H:%M") if b.expires_at else "never"
        print(f"{b.id:>4}  {b.kind:<4} {('yes' if b.active else 'no'):>6} {exp:<20} {b.pattern[:32]:<32} {b.reason}")


def cmd_unban(args):
    from depapi.bans import delete_ban, get_ban
    if not args:
        print("usage: manage.py unban <id>")
        sys.exit(1)
    try:
        bid = int(args[0])
    except ValueError:
        print("id must be a number")
        sys.exit(1)
    if not get_ban(bid):
        print("not found")
        sys.exit(1)
    delete_ban(bid)
    print(f"deleted ban #{bid}")

    
def main():
    commands = {
        "init":         cmd_init,
        "keygen":       cmd_keygen,
        "keys":         cmd_keys,
        "revoke":       cmd_revoke,
        "add-token":    cmd_add_token,
        "tokens":       cmd_tokens,
        "rm-token":     cmd_rm_token,
        "usage":        cmd_usage,
        "sessions":     cmd_sessions,
        "admin-keygen": cmd_admin_keygen,
        "admin-keys":   cmd_admin_keys,
        "admin-revoke": cmd_admin_revoke,
        "audit":        cmd_audit,
        "ban-ip":       cmd_ban_ip,
        "ban-ua":       cmd_ban_ua,
        "bans":         cmd_bans,
        "unban":        cmd_unban,
    }
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print(__doc__)
        print("Commands:")
        for c in commands:
            print(f"  {c}")
        sys.exit(1)
    commands[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()