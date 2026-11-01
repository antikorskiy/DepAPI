"""IP/User-Agent ban list: model, matchers, cache, middleware."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from .db import db

LOOPBACKS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}



class Ban:
    __slots__ = ("id", "kind", "pattern", "reason", "notes",
                 "active", "expires_at", "created_at", "created_by")

    def __init__(self, row):
        self.id = row["id"]
        self.kind = row["kind"]
        self.pattern = row["pattern"]
        self.reason = row["reason"] or ""
        self.notes = row["notes"] or ""
        self.active = bool(row["active"])
        self.expires_at = _parse_dt(row["expires_at"])
        self.created_at = row["created_at"]
        self.created_by = row["created_by"] or ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "pattern": self.pattern,
            "reason": self.reason,
            "notes": self.notes,
            "active": self.active,
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z")
                          if self.expires_at else None,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        return self.expires_at <= now


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None



def normalize_ip(ip: str) -> str:
    if not ip:
        return ""
    ip = ip.strip()
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def match_ip(client_ip: str, pattern: str) -> bool:
    """Match IP against exact IP, CIDR (10.0.0.0/8), or glob (192.168.*.*)."""
    if not client_ip or not pattern:
        return False
    client_ip = normalize_ip(client_ip)

    if client_ip == normalize_ip(pattern):
        return True

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return addr in net
        except ValueError:
            pass

    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(client_ip, pattern)

    return False


def match_ua(user_agent: str, pattern: str) -> bool:
    """Empty pattern matches only empty UA. Otherwise substring or glob."""
    ua = (user_agent or "").strip()

    if pattern == "":
        return ua == ""

    if not ua:
        return False

    ua_l = ua.lower()
    pat_l = pattern.lower()

    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(ua_l, pat_l)

    return pat_l in ua_l


def match_ban(ban: Ban, ip: str, ua: str) -> bool:
    if ban.is_expired():
        return False
    if ban.kind == "ip":
        return match_ip(ip, ban.pattern)
    if ban.kind == "ua":
        return match_ua(ua, ban.pattern)
    return False



class BanCache:
    def __init__(self, ttl: float = 5.0):
        self._bans: list[Ban] = []
        self._next_reload = 0.0
        self._ttl = ttl
        self._lock = threading.Lock()

    def _reload(self):
        with db() as conn:
            rows = conn.execute(
                "SELECT * FROM bans WHERE active=1 ORDER BY id"
            ).fetchall()
        self._bans = [Ban(r) for r in rows]

    def get(self) -> list[Ban]:
        now = time.monotonic()
        with self._lock:
            if now >= self._next_reload:
                self._reload()
                self._next_reload = now + self._ttl
            return list(self._bans)

    def invalidate(self):
        with self._lock:
            self._next_reload = 0.0


BAN_CACHE = BanCache()


def check_request(ip: str, ua: str) -> Optional[Ban]:
    """Return matching ban, or None."""
    for ban in BAN_CACHE.get():
        if match_ban(ban, ip, ua):
            return ban
    return None



def extract_client_ip(request: Request, trust_proxy: bool = False) -> str:
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return normalize_ip(xff.split(",")[0].strip())
        xri = request.headers.get("x-real-ip", "")
        if xri:
            return normalize_ip(xri.strip())
    if request.client and request.client.host:
        return normalize_ip(request.client.host)
    return ""



def make_ban_middleware(trust_proxy: bool):
    async def ban_middleware(request: Request, call_next):
        ip = extract_client_ip(request, trust_proxy)

        if ip in LOOPBACKS:
            return await call_next(request)

        ua = request.headers.get("user-agent", "")
        ban = check_request(ip, ua)
        if ban is None:
            return await call_next(request)

        reason = ban.reason or f"banned by rule #{ban.id}"
        return JSONResponse(
            {"detail": f"banned: {reason}"},
            status_code=403,
            headers={
                "X-Ban-Id": str(ban.id),
                "X-Ban-Kind": ban.kind,
            },
        )

    return ban_middleware



def create_ban(kind: str, pattern: str, reason: str = "",
               expires_at: Optional[str] = None,
               notes: str = "", created_by: str = "") -> Ban:
    if kind not in ("ip", "ua"):
        raise ValueError("kind must be 'ip' or 'ua'")
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO bans
                 (kind, pattern, reason, notes, expires_at, created_by)
               VALUES (?,?,?,?,?,?)""",
            (kind, pattern, reason, notes, expires_at, created_by),
        )
        bid = cur.lastrowid
        conn.commit()
        row = conn.execute("SELECT * FROM bans WHERE id=?", (bid,)).fetchone()
    BAN_CACHE.invalidate()
    return Ban(row)


def delete_ban(ban_id: int) -> bool:
    with db() as conn:
        cur = conn.execute("DELETE FROM bans WHERE id=?", (ban_id,))
        conn.commit()
    BAN_CACHE.invalidate()
    return cur.rowcount > 0


def update_ban(ban_id: int, **fields) -> Optional[Ban]:
    allowed = {"active", "expires_at", "reason", "notes"}
    sets, params = [], []
    for k, v in fields.items():
        if k not in allowed:
            continue
        sets.append(f"{k}=?")
        if k == "active":
            params.append(1 if v else 0)
        else:
            params.append(v)
    if not sets:
        with db() as conn:
            row = conn.execute("SELECT * FROM bans WHERE id=?", (ban_id,)).fetchone()
        return Ban(row) if row else None

    params.append(ban_id)
    with db() as conn:
        cur = conn.execute(f"UPDATE bans SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()
        if cur.rowcount == 0:
            return None
        row = conn.execute("SELECT * FROM bans WHERE id=?", (ban_id,)).fetchone()
    BAN_CACHE.invalidate()
    return Ban(row)


def list_bans(kind: Optional[str] = None, active: Optional[bool] = None,
              limit: int = 500) -> list[Ban]:
    sql = "SELECT * FROM bans WHERE 1=1"
    params: list = []
    if kind:
        sql += " AND kind=?"
        params.append(kind)
    if active is not None:
        sql += " AND active=?"
        params.append(1 if active else 0)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [Ban(r) for r in rows]


def get_ban(ban_id: int) -> Optional[Ban]:
    with db() as conn:
        row = conn.execute("SELECT * FROM bans WHERE id=?", (ban_id,)).fetchone()
    return Ban(row) if row else None