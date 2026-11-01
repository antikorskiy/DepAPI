"""Admin API: clients, tokens, sessions, admin keys, audit, webhooks."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .audit import audit
from .auth import (
    ALL_SCOPES, ROLE_PRESETS, AdminContext, admin_auth_dep, require_scope,
)
from .db import db, gen_admin_key, gen_client_key, gen_webhook_secret, hash_key
from .webhooks import EVENTS, dispatch

router = APIRouter(prefix="/admin", tags=["admin"])


def _client_ip(r: Request) -> str:
    return (r.client.host if r.client else "") or ""


def _parse_iso(s: Optional[str]) -> Optional[str]:
    """Accept None, "", "null", "none" as "no value"; otherwise parse ISO."""
    if s is None:
        return None
    if not isinstance(s, str):
        raise HTTPException(400, f"invalid ISO date: {s}")
    s = s.strip()
    if s == "" or s.lower() in ("null", "none"):
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        raise HTTPException(400, f"invalid ISO date: {s}")


def _client_dict(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "key_prefix": row["key_prefix"],
        "rps": row["rps"],
        "daily": row["daily"],
        "active": bool(row["active"]),
        "external_id": row["external_id"],
        "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
        "notes": row["notes"],
        "expires_at": row["expires_at"],
        "has_grace_period": bool(
            row["previous_key_hash"] and row["previous_key_expires_at"]
        ),
        "grace_expires_at": row["previous_key_expires_at"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
    }


def _admin_key_dict(row) -> dict:
    try:
        scopes = json.loads(row["scopes"] or "[]")
    except Exception:
        scopes = []
    return {
        "id": row["id"],
        "name": row["name"],
        "key_prefix": row["key_prefix"],
        "scopes": scopes,
        "active": bool(row["active"]),
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
    }


def _webhook_dict(row, *, include_secret: bool = False) -> dict:
    out = {
        "id": row["id"],
        "name": row["name"],
        "url": row["url"],
        "events": json.loads(row["events"] or "[]"),
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "last_triggered_at": row["last_triggered_at"],
        "last_status": row["last_status"],
    }
    if include_secret:
        out["secret"] = row["secret"]
    return out



@router.get("/info")
def admin_info(ctx: AdminContext = Depends(admin_auth_dep)):
    with db() as conn:
        counts = {
            "clients":     conn.execute("SELECT COUNT(*) FROM clients WHERE active=1").fetchone()[0],
            "clients_all": conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
            "tokens":      conn.execute("SELECT COUNT(*) FROM deepseek_tokens WHERE active=1").fetchone()[0],
            "sessions":    conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
            "admin_keys":  conn.execute("SELECT COUNT(*) FROM admin_keys WHERE active=1").fetchone()[0],
            "webhooks":    conn.execute("SELECT COUNT(*) FROM webhooks WHERE active=1").fetchone()[0],
            "bans":        conn.execute("SELECT COUNT(*) FROM bans WHERE active=1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)").fetchone()[0],
        }
    return {
        "name": "DepAPI",
        "version": "1.1.0",
        "actor": ctx.actor,
        "scopes": sorted(ctx.scopes),
        "counts": counts,
        "events": sorted(EVENTS),
        "scopes_available": sorted(ALL_SCOPES),
        "role_presets": {k: sorted(v) for k, v in ROLE_PRESETS.items()},
    }



class ClientCreate(BaseModel):
    name: str
    rps: Optional[int] = None
    daily: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict] = None
    notes: Optional[str] = None
    expires_at: Optional[str] = None


class ClientUpdate(BaseModel):
    rps: Optional[int] = None
    daily: Optional[int] = None
    active: Optional[bool] = None
    external_id: Optional[str] = None
    metadata: Optional[dict] = None
    notes: Optional[str] = None
    expires_at: Optional[str] = None


class BulkCreate(BaseModel):
    clients: list[ClientCreate]


class RotateRequest(BaseModel):
    grace_hours: int = 0


@router.get("/clients", dependencies=[Depends(require_scope("clients:read"))])
def admin_list_clients(
    active: Optional[bool] = None,
    q: Optional[str] = Query(None, description="search by name or external_id"),
    limit: int = 100, offset: int = 0,
):
    sql = "SELECT * FROM clients WHERE 1=1"
    params: list = []
    if active is not None:
        sql += " AND active=?"
        params.append(1 if active else 0)
    if q:
        sql += " AND (name LIKE ? OR external_id LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY id LIMIT ? OFFSET ?"
    params += [limit, offset]
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"clients": [_client_dict(r) for r in rows]}


@router.get("/clients/{cid}", dependencies=[Depends(require_scope("clients:read"))])
def admin_get_client(cid: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not row:
        raise HTTPException(404, "client not found")
    return _client_dict(row)


@router.get("/clients/by-name/{name}",
            dependencies=[Depends(require_scope("clients:read"))])
def admin_get_client_by_name(name: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE name=?", (name,)).fetchone()
    if not row:
        raise HTTPException(404, "client not found")
    return _client_dict(row)


@router.get("/clients/by-external/{ext_id}",
            dependencies=[Depends(require_scope("clients:read"))])
def admin_get_client_by_external(ext_id: str):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE external_id=?", (ext_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "client not found")
    return _client_dict(row)


@router.post("/clients")
def admin_create_client(req: ClientCreate, r: Request,
                        ctx: AdminContext = Depends(require_scope("clients:write"))):
    raw_key = gen_client_key()
    h = hash_key(raw_key)
    expires = _parse_iso(req.expires_at)
    meta = json.dumps(req.metadata, ensure_ascii=False) if req.metadata else None
    with db() as conn:
        try:
            cur = conn.execute(
                """INSERT INTO clients
                     (name, key_hash, key_prefix, rps, daily,
                      external_id, metadata, notes, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (req.name, h, raw_key[:12],
                 req.rps or 5, req.daily or 1000,
                 req.external_id, meta, req.notes, expires),
            )
            cid = cur.lastrowid
            row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, "name or external_id already exists")
            raise HTTPException(500, str(e))

    audit(ctx.actor, "client.create", f"client:{cid}",
          {"name": req.name, "external_id": req.external_id}, _client_ip(r))
    dispatch("client.created", _client_dict(row) | {"key": raw_key})
    return _client_dict(row) | {"key": raw_key}


@router.post("/clients/bulk")
def admin_bulk_create(req: BulkCreate, r: Request,
                      ctx: AdminContext = Depends(require_scope("clients:write"))):
    created, errors = [], []
    for c in req.clients:
        try:
            raw_key = gen_client_key()
            h = hash_key(raw_key)
            expires = _parse_iso(c.expires_at)
            meta = json.dumps(c.metadata, ensure_ascii=False) if c.metadata else None
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO clients
                         (name, key_hash, key_prefix, rps, daily,
                          external_id, metadata, notes, expires_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (c.name, h, raw_key[:12],
                     c.rps or 5, c.daily or 1000,
                     c.external_id, meta, c.notes, expires),
                )
                cid = cur.lastrowid
                row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
                conn.commit()
            created.append(_client_dict(row) | {"key": raw_key})
            dispatch("client.created", _client_dict(row) | {"key": raw_key})
        except Exception as e:
            errors.append({"name": c.name, "error": str(e)})

    audit(ctx.actor, "client.bulk_create", "",
          {"created": len(created), "errors": len(errors)}, _client_ip(r))
    return {"created": created, "errors": errors}


@router.patch("/clients/{cid}")
def admin_update_client(cid: int, req: ClientUpdate, r: Request,
                        ctx: AdminContext = Depends(require_scope("clients:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "client not found")

        updates, params = [], []
        if req.rps is not None:
            updates.append("rps=?"); params.append(req.rps)
        if req.daily is not None:
            updates.append("daily=?"); params.append(req.daily)
        if req.active is not None:
            updates.append("active=?"); params.append(1 if req.active else 0)
        if req.external_id is not None:
            updates.append("external_id=?"); params.append(req.external_id or None)
        if req.metadata is not None:
            updates.append("metadata=?")
            params.append(json.dumps(req.metadata, ensure_ascii=False)
                          if req.metadata else None)
        if req.notes is not None:
            updates.append("notes=?"); params.append(req.notes or None)
        if req.expires_at is not None:
            updates.append("expires_at=?")
            params.append(_parse_iso(req.expires_at) if req.expires_at else None)

        if not updates:
            raise HTTPException(400, "no fields to update")

        params.append(cid)
        conn.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
        new_row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()

    audit(ctx.actor, "client.update", f"client:{cid}",
          {k: v for k, v in req.model_dump(exclude_none=True).items()}, _client_ip(r))
    dispatch("client.updated", _client_dict(new_row))
    return _client_dict(new_row)


@router.delete("/clients/{cid}")
def admin_delete_client(cid: int, r: Request, purge_sessions: bool = False,
                        ctx: AdminContext = Depends(require_scope("clients:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "client not found")
        conn.execute("UPDATE clients SET active=0 WHERE id=?", (cid,))
        if purge_sessions:
            conn.execute("DELETE FROM sessions WHERE client_id=?", (cid,))
        conn.commit()

    audit(ctx.actor, "client.deactivate", f"client:{cid}",
          {"purge_sessions": purge_sessions}, _client_ip(r))
    dispatch("client.deactivated", {"id": cid, "purge_sessions": purge_sessions})
    return {"status": "deactivated", "sessions_purged": purge_sessions}


@router.post("/clients/{cid}/rotate")
def admin_rotate_client(cid: int, req: RotateRequest, r: Request,
                        ctx: AdminContext = Depends(require_scope("clients:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "client not found")

        new_key = gen_client_key()
        new_hash = hash_key(new_key)

        if req.grace_hours > 0:
            grace_until = (datetime.now(timezone.utc)
                           + timedelta(hours=req.grace_hours)
                           ).strftime("%Y-%m-%dT%H:%M:%SZ")
            conn.execute(
                """UPDATE clients
                   SET key_hash=?, key_prefix=?,
                       previous_key_hash=?, previous_key_expires_at=?
                   WHERE id=?""",
                (new_hash, new_key[:12],
                 row["key_hash"], grace_until, cid),
            )
        else:
            conn.execute(
                """UPDATE clients
                   SET key_hash=?, key_prefix=?,
                       previous_key_hash=NULL, previous_key_expires_at=NULL
                   WHERE id=?""",
                (new_hash, new_key[:12], cid),
            )
        conn.commit()
        new_row = conn.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()

    audit(ctx.actor, "client.rotated", f"client:{cid}",
          {"grace_hours": req.grace_hours}, _client_ip(r))
    dispatch("client.rotated", {"id": cid, "grace_hours": req.grace_hours})
    return _client_dict(new_row) | {"key": new_key}


@router.get("/clients/{cid}/usage",
            dependencies=[Depends(require_scope("clients:read"))])
def admin_client_usage(cid: int, days: int = 7):
    with db() as conn:
        rows = conn.execute(
            """SELECT date(ts) AS day, COUNT(*) AS n,
                      SUM(CASE WHEN status=200 THEN 1 ELSE 0 END) AS ok
               FROM usage_log
               WHERE client_id=? AND ts >= datetime('now', ?)
               GROUP BY day ORDER BY day DESC""",
            (cid, f"-{days} days"),
        ).fetchall()
    return {"client_id": cid, "days": days,
            "usage": [dict(r) for r in rows]}


@router.get("/clients/{cid}/sessions",
            dependencies=[Depends(require_scope("clients:read"))])
def admin_client_sessions(cid: int):
    with db() as conn:
        rows = conn.execute(
            """SELECT id, session_key, deepseek_token_id,
                      ds_chat_session_id, ds_parent_message_id,
                      created_at, last_used_at
               FROM sessions WHERE client_id=? ORDER BY last_used_at DESC""",
            (cid,),
        ).fetchall()
    return {"client_id": cid, "sessions": [dict(r) for r in rows]}



class TokenAdd(BaseModel):
    session_id: str
    auth_token: str
    label: Optional[str] = None


class TokenUpdate(BaseModel):
    label: Optional[str] = None
    active: Optional[bool] = None


@router.get("/tokens", dependencies=[Depends(require_scope("tokens:read"))])
def admin_list_tokens(active: Optional[bool] = None):
    sql = "SELECT * FROM deepseek_tokens WHERE 1=1"
    params: list = []
    if active is not None:
        sql += " AND active=?"
        params.append(1 if active else 0)
    sql += " ORDER BY id"
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"tokens": [dict(r) for r in rows]}


@router.get("/tokens/{tid}", dependencies=[Depends(require_scope("tokens:read"))])
def admin_get_token(tid: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM deepseek_tokens WHERE id=?", (tid,)).fetchone()
    if not row:
        raise HTTPException(404, "token not found")
    return dict(row)


@router.post("/tokens")
def admin_add_token(req: TokenAdd, r: Request,
                    ctx: AdminContext = Depends(require_scope("tokens:write"))):
    tok = req.auth_token if req.auth_token.startswith("Bearer ") else "Bearer " + req.auth_token
    with db() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO deepseek_tokens (session_id, auth_token, label) VALUES (?,?,?)",
                (req.session_id, tok, req.label),
            )
            tid = cur.lastrowid
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, "session_id already exists")
            raise HTTPException(500, str(e))

    audit(ctx.actor, "token.add", f"token:{tid}",
          {"session_id": req.session_id, "label": req.label}, _client_ip(r))
    dispatch("token.added", {"id": tid, "label": req.label})
    return {"id": tid, "status": "added"}


@router.patch("/tokens/{tid}")
def admin_update_token(tid: int, req: TokenUpdate, r: Request,
                       ctx: AdminContext = Depends(require_scope("tokens:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM deepseek_tokens WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(404, "token not found")
        updates, params = [], []
        if req.label is not None:
            updates.append("label=?"); params.append(req.label)
        if req.active is not None:
            updates.append("active=?"); params.append(1 if req.active else 0)
        if not updates:
            raise HTTPException(400, "no fields to update")
        params.append(tid)
        conn.execute(f"UPDATE deepseek_tokens SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
        new_row = conn.execute("SELECT * FROM deepseek_tokens WHERE id=?", (tid,)).fetchone()

    audit(ctx.actor, "token.update", f"token:{tid}",
          req.model_dump(exclude_none=True), _client_ip(r))
    dispatch("token.updated", {"id": tid, **req.model_dump(exclude_none=True)})
    return dict(new_row)


@router.delete("/tokens/{tid}")
def admin_delete_token(tid: int, r: Request,
                       ctx: AdminContext = Depends(require_scope("tokens:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM deepseek_tokens WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(404, "token not found")
        using = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE deepseek_token_id=?", (tid,)
        ).fetchone()[0]
        if using > 0:
            raise HTTPException(
                409,
                f"token {tid} is used by {using} session(s). "
                f"Deactivate it or delete those sessions first.",
            )
        conn.execute("DELETE FROM deepseek_tokens WHERE id=?", (tid,))
        conn.commit()

    audit(ctx.actor, "token.delete", f"token:{tid}",
          {"session_id": row["session_id"]}, _client_ip(r))
    dispatch("token.deleted", {"id": tid})
    return {"status": "deleted"}


class CooldownRequest(BaseModel):
    seconds: int = 3600


@router.post("/tokens/{tid}/cooldown")
def admin_token_cooldown(tid: int, req: CooldownRequest, r: Request,
                         ctx: AdminContext = Depends(require_scope("tokens:write"))):
    until = (datetime.now(timezone.utc)
             + timedelta(seconds=req.seconds)).timestamp()
    with db() as conn:
        cur = conn.execute(
            "UPDATE deepseek_tokens SET cooldown_until=? WHERE id=?", (until, tid)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "token not found")
    audit(ctx.actor, "token.cooldown", f"token:{tid}",
          {"seconds": req.seconds}, _client_ip(r))
    dispatch("token.cooldown", {"id": tid, "seconds": req.seconds})
    return {"status": "cooldown set", "until_unix": until}


@router.post("/tokens/{tid}/reset-errors")
def admin_token_reset_errors(tid: int, r: Request,
                             ctx: AdminContext = Depends(require_scope("tokens:write"))):
    with db() as conn:
        cur = conn.execute(
            "UPDATE deepseek_tokens SET error_count=0, cooldown_until=0 WHERE id=?",
            (tid,),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "token not found")
    audit(ctx.actor, "token.reset_errors", f"token:{tid}", {}, _client_ip(r))
    return {"status": "reset"}



@router.get("/sessions", dependencies=[Depends(require_scope("sessions:read"))])
def admin_list_sessions(client_id: Optional[int] = None, limit: int = 200):
    sql = """SELECT s.id, s.client_id, c.name AS owner, c.key_prefix AS owner_key,
                    s.session_key, s.deepseek_token_id, t.label AS token_label,
                    t.active AS token_active,
                    s.ds_chat_session_id, s.ds_parent_message_id,
                    s.created_at, s.last_used_at
             FROM sessions s
             JOIN clients c ON c.id = s.client_id
             LEFT JOIN deepseek_tokens t ON t.id = s.deepseek_token_id"""
    params: list = []
    if client_id is not None:
        sql += " WHERE s.client_id=?"
        params.append(client_id)
    sql += " ORDER BY s.last_used_at DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"sessions": [dict(r) for r in rows]}


@router.delete("/sessions/{sid}")
def admin_delete_session(sid: int, r: Request,
                         ctx: AdminContext = Depends(require_scope("sessions:write"))):
    from .pool import reset_session
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not row:
        raise HTTPException(404, "session not found")
    reset_session(row["client_id"], row["session_key"])
    audit(ctx.actor, "session.reset", f"session:{sid}",
          {"client_id": row["client_id"], "key": row["session_key"]},
          _client_ip(r))
    dispatch("session.reset", {"id": sid, "client_id": row["client_id"]})
    return {"status": "reset"}



class AdminKeyCreate(BaseModel):
    name: str
    role: Optional[str] = None
    scopes: Optional[list[str]] = None
    expires_at: Optional[str] = None


@router.get("/keys", dependencies=[Depends(require_scope("admin_keys:read"))])
def admin_list_keys():
    with db() as conn:
        rows = conn.execute("SELECT * FROM admin_keys ORDER BY id").fetchall()
    return {"keys": [_admin_key_dict(r) for r in rows]}


@router.post("/keys")
def admin_create_key(req: AdminKeyCreate, r: Request,
                     ctx: AdminContext = Depends(require_scope("admin_keys:write"))):
    if req.role and req.role not in ROLE_PRESETS:
        raise HTTPException(400, f"unknown role: {req.role}")
    if req.role:
        scopes = set(ROLE_PRESETS[req.role])
    elif req.scopes:
        unknown = set(req.scopes) - ALL_SCOPES
        if unknown:
            raise HTTPException(400, f"unknown scopes: {sorted(unknown)}")
        scopes = set(req.scopes)
    else:
        scopes = set(ROLE_PRESETS["readonly"])

    raw = gen_admin_key()
    h = hash_key(raw)
    expires = _parse_iso(req.expires_at)
    with db() as conn:
        try:
            cur = conn.execute(
                """INSERT INTO admin_keys (name, key_hash, key_prefix, scopes, expires_at)
                   VALUES (?,?,?,?,?)""",
                (req.name, h, raw[:12],
                 json.dumps(sorted(scopes)), expires),
            )
            kid = cur.lastrowid
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, "name already exists")
            raise HTTPException(500, str(e))

    audit(ctx.actor, "admin_key.create", f"admin_key:{kid}",
          {"name": req.name, "scopes": sorted(scopes)}, _client_ip(r))
    dispatch("admin_key.created", {"id": kid, "name": req.name, "scopes": sorted(scopes)})
    return {"id": kid, "name": req.name, "key": raw,
            "scopes": sorted(scopes), "expires_at": expires}


@router.delete("/keys/{kid}")
def admin_delete_key(kid: int, r: Request,
                     ctx: AdminContext = Depends(require_scope("admin_keys:write"))):
    with db() as conn:
        cur = conn.execute("UPDATE admin_keys SET active=0 WHERE id=?", (kid,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "admin key not found")
    audit(ctx.actor, "admin_key.delete", f"admin_key:{kid}", {}, _client_ip(r))
    dispatch("admin_key.deleted", {"id": kid})
    return {"status": "deactivated"}



@router.get("/audit", dependencies=[Depends(require_scope("audit:read"))])
def admin_audit(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
):
    sql = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if actor:
        sql += " AND actor=?"
        params.append(actor)
    if action:
        sql += " AND action=?"
        params.append(action)
    if since:
        sql += " AND ts >= ?"
        params.append(_parse_iso(since))
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"audit": [dict(r) for r in rows]}



class WebhookCreate(BaseModel):
    name: str
    url: str
    events: list[str] = Field(default_factory=lambda: ["*"])


@router.get("/webhooks", dependencies=[Depends(require_scope("webhooks:read"))])
def admin_list_webhooks():
    with db() as conn:
        rows = conn.execute("SELECT * FROM webhooks ORDER BY id").fetchall()
    return {"webhooks": [_webhook_dict(r) for r in rows]}


@router.get("/webhooks/{wid}", dependencies=[Depends(require_scope("webhooks:read"))])
def admin_get_webhook(wid: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
    if not row:
        raise HTTPException(404, "webhook not found")
    return _webhook_dict(row)


@router.post("/webhooks")
def admin_create_webhook(req: WebhookCreate, r: Request,
                         ctx: AdminContext = Depends(require_scope("webhooks:write"))):
    unknown = set(req.events) - EVENTS - {"*"}
    if unknown:
        raise HTTPException(400, f"unknown events: {sorted(unknown)}")
    secret = gen_webhook_secret()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO webhooks (name, url, secret, events) VALUES (?,?,?,?)",
            (req.name, req.url, secret, json.dumps(req.events)),
        )
        wid = cur.lastrowid
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
        conn.commit()

    audit(ctx.actor, "webhook.create", f"webhook:{wid}",
          {"name": req.name, "url": req.url, "events": req.events}, _client_ip(r))
    return _webhook_dict(row, include_secret=True)


@router.delete("/webhooks/{wid}")
def admin_delete_webhook(wid: int, r: Request,
                         ctx: AdminContext = Depends(require_scope("webhooks:write"))):
    with db() as conn:
        cur = conn.execute("DELETE FROM webhooks WHERE id=?", (wid,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "webhook not found")
    audit(ctx.actor, "webhook.delete", f"webhook:{wid}", {}, _client_ip(r))
    return {"status": "deleted"}


@router.post("/webhooks/{wid}/test")
def admin_test_webhook(wid: int, r: Request,
                       ctx: AdminContext = Depends(require_scope("webhooks:write"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM webhooks WHERE id=?", (wid,)).fetchone()
    if not row:
        raise HTTPException(404, "webhook not found")
    dispatch("test.ping", {"message": "DepAPI test event", "webhook_id": wid})
    return {"status": "sent"}


from .bans import (
    BAN_CACHE, Ban as BanModel, create_ban, delete_ban, get_ban,
    list_bans, update_ban,
)


class BanCreate(BaseModel):
    kind: str
    pattern: str
    reason: Optional[str] = None
    notes: Optional[str] = None
    expires_at: Optional[str] = None


class BanUpdate(BaseModel):
    active: Optional[bool] = None
    expires_at: Optional[str] = None
    reason: Optional[str] = None
    notes: Optional[str] = None


@router.get("/bans", dependencies=[Depends(require_scope("bans:read"))])
def admin_list_bans(
    kind: Optional[str] = None,
    active: Optional[bool] = None,
    limit: int = 500,
):
    items = list_bans(kind=kind, active=active, limit=limit)
    return {"bans": [b.to_dict() for b in items]}


@router.get("/bans/{bid}", dependencies=[Depends(require_scope("bans:read"))])
def admin_get_ban(bid: int):
    b = get_ban(bid)
    if not b:
        raise HTTPException(404, "ban not found")
    return b.to_dict()


@router.get("/bans/check", dependencies=[Depends(require_scope("bans:read"))])
def admin_check_ban(
    ip: str = Query("", description="client IP to test"),
    ua: str = Query("", description="user-agent to test"),
):
    from .bans import check_request
    b = check_request(ip, ua)
    return {
        "ip": ip, "ua": ua,
        "banned": b is not None,
        "matched_ban": b.to_dict() if b else None,
    }


@router.post("/bans")
def admin_create_ban(req: BanCreate, r: Request,
                     ctx: AdminContext = Depends(require_scope("bans:write"))):
    if req.kind not in ("ip", "ua"):
        raise HTTPException(400, "kind must be 'ip' or 'ua'")
    if not req.pattern and req.kind == "ip":
        raise HTTPException(400, "pattern is required for kind='ip'")

    expires = _parse_iso(req.expires_at)
    try:
        b = create_ban(
            kind=req.kind, pattern=req.pattern,
            reason=req.reason or "", expires_at=expires,
            notes=req.notes or "", created_by=ctx.actor,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    audit(ctx.actor, "ban.create", f"ban:{b.id}",
          {"kind": b.kind, "pattern": b.pattern}, _client_ip(r))
    dispatch("ban.created", b.to_dict())
    return b.to_dict()


@router.patch("/bans/{bid}")
def admin_update_ban(bid: int, req: BanUpdate, r: Request,
                     ctx: AdminContext = Depends(require_scope("bans:write"))):
    fields: dict = {}
    if req.active is not None:
        fields["active"] = req.active
    if req.expires_at is not None:
        fields["expires_at"] = _parse_iso(req.expires_at)
    if req.reason is not None:
        fields["reason"] = req.reason
    if req.notes is not None:
        fields["notes"] = req.notes

    if not fields:
        raise HTTPException(400, "no fields to update")

    b = update_ban(bid, **fields)
    if not b:
        raise HTTPException(404, "ban not found")

    audit(ctx.actor, "ban.update", f"ban:{bid}", fields, _client_ip(r))
    dispatch("ban.updated", b.to_dict())
    return b.to_dict()


@router.delete("/bans/{bid}")
def admin_delete_ban(bid: int, r: Request,
                     ctx: AdminContext = Depends(require_scope("bans:write"))):
    b = get_ban(bid)
    if not b:
        raise HTTPException(404, "ban not found")
    delete_ban(bid)
    audit(ctx.actor, "ban.delete", f"ban:{bid}",
          {"kind": b.kind, "pattern": b.pattern}, _client_ip(r))
    dispatch("ban.deleted", {"id": bid})
    return {"status": "deleted"}