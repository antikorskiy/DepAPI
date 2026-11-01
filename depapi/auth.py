"""Auth + rate-limit + scoped admin auth."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException

from .db import db, hash_key

ADMIN_TOKEN = os.getenv("DS_ADMIN_TOKEN", "")

ALL_SCOPES = {
    "clients:read", "clients:write",
    "tokens:read", "tokens:write",
    "sessions:read", "sessions:write",
    "audit:read",
    "bans:read", "bans:write", 
    "webhooks:read", "webhooks:write",
    "admin_keys:read", "admin_keys:write",
    "admin:all",
}

ROLE_PRESETS = {
    "root":     set(ALL_SCOPES),
    "admin":    set(ALL_SCOPES) - {"admin_keys:write"},
    "readonly": {s for s in ALL_SCOPES if s.endswith(":read")},
}


class Client:
    __slots__ = ("id", "name", "rps", "daily", "key_prefix")

    def __init__(self, row):
        self.id = row["id"]
        self.name = row["name"]
        self.rps = row["rps"]
        self.daily = row["daily"]
        self.key_prefix = row["key_prefix"]


def _is_expired(ts: Optional[str]) -> bool:
    if not ts:
        return False
    try:
        exp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)
    except Exception:
        return False


def auth_dep(authorization: Optional[str] = Header(None)) -> Client:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing Bearer token")
    raw = authorization[7:].strip()
    h = hash_key(raw)

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM clients WHERE key_hash=? AND active=1", (h,)
        ).fetchone()
        if not row:
            row = conn.execute(
                """SELECT * FROM clients
                   WHERE previous_key_hash=? AND active=1
                     AND previous_key_expires_at > CURRENT_TIMESTAMP""",
                (h,),
            ).fetchone()
        if not row:
            raise HTTPException(401, "invalid token")
        if _is_expired(row["expires_at"]):
            raise HTTPException(401, "client key expired")
        conn.execute(
            "UPDATE clients SET last_used_at=CURRENT_TIMESTAMP WHERE id=?",
            (row["id"],),
        )
        conn.commit()
    return Client(row)


class AdminContext:
    def __init__(self, actor: str, scopes: set[str]):
        self.actor = actor
        self.scopes = scopes

    def require(self, scope: str) -> None:
        if "admin:all" in self.scopes or scope in self.scopes:
            return
        raise HTTPException(403, f"missing scope: {scope}")


def admin_auth_dep(
    x_admin_token: Optional[str] = Header(None),
    x_admin_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> AdminContext:
    """
    Priority:
      1. X-Admin-Token = DS_ADMIN_TOKEN -> root (all scopes)
      2. X-Admin-Key   = adm-...        -> looked up in admin_keys
      3. Authorization: Bearer adm-...   -> same as above
    """
    if x_admin_token and ADMIN_TOKEN and secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        return AdminContext(actor="root", scopes=ROLE_PRESETS["root"])

    raw = x_admin_key or (
        authorization[7:].strip()
        if authorization and authorization.startswith("Bearer ")
        else None
    )
    if raw:
        h = hash_key(raw)
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM admin_keys WHERE key_hash=? AND active=1", (h,)
            ).fetchone()
            if row:
                if _is_expired(row["expires_at"]):
                    raise HTTPException(401, "admin key expired")
                try:
                    scopes = set(json.loads(row["scopes"] or "[]"))
                except Exception:
                    scopes = set()
                conn.execute(
                    "UPDATE admin_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?",
                    (row["id"],),
                )
                conn.commit()
                return AdminContext(actor=f"key:{row['name']}", scopes=scopes)

    raise HTTPException(401, "admin token or key required")


def require_scope(scope: str):
    def _dep(ctx: AdminContext = Depends(admin_auth_dep)) -> AdminContext:
        ctx.require(scope)
        return ctx
    return _dep


class _Bucket:
    __slots__ = ("rps", "daily", "tokens", "last", "daily_count", "daily_reset")

    def __init__(self, rps: int, daily: int):
        self.rps = max(rps, 1)
        self.daily = max(daily, 1)
        self.tokens = float(self.rps)
        self.last = time.monotonic()
        self.daily_count = 0
        self.daily_reset = time.time() + 86400

    def try_consume(self) -> tuple[bool, float]:
        now_m = time.monotonic()
        now_w = time.time()
        elapsed = now_m - self.last
        self.tokens = min(float(self.rps), self.tokens + elapsed * self.rps)
        self.last = now_m
        if now_w > self.daily_reset:
            self.daily_count = 0
            self.daily_reset = now_w + 86400
        if self.daily_count >= self.daily:
            return False, self.daily_reset - now_w
        if self.tokens < 1:
            return False, (1 - self.tokens) / self.rps
        self.tokens -= 1
        self.daily_count += 1
        return True, 0.0


_BUCKETS: dict[int, _Bucket] = {}
_BUCKETS_LOCK = threading.Lock()


def rate_limit(client: Client):
    with _BUCKETS_LOCK:
        b = _BUCKETS.get(client.id)
        if not b or b.rps != client.rps or b.daily != client.daily:
            b = _Bucket(client.rps, client.daily)
            _BUCKETS[client.id] = b
    ok, retry = b.try_consume()
    if not ok:
        raise HTTPException(
            429,
            f"rate limit: retry after {retry:.0f}s",
            headers={"Retry-After": str(int(retry) + 1)},
        )