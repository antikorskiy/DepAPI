"""Webhook dispatcher — async, HMAC-signed."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time

import requests

from .db import db

EVENTS = {
    "client.created", "client.updated", "client.deactivated",
    "client.rotated", "client.expired",
    "token.added", "token.updated", "token.deleted", "token.cooldown",
    "session.reset",
    "ban.created", "ban.updated", "ban.deleted", "ban.triggered",
    "admin_key.created", "admin_key.deleted",
    "usage.threshold",
}


def dispatch(event: str, payload: dict) -> None:
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT id, url, secret, events FROM webhooks WHERE active=1"
            ).fetchall()
    except Exception:
        return

    for row in rows:
        try:
            events = json.loads(row["events"] or "[]")
        except Exception:
            continue
        if event not in events and "*" not in events:
            continue
        threading.Thread(
            target=_send,
            args=(row["id"], row["url"], row["secret"], event, payload),
            daemon=True,
        ).start()


def _send(webhook_id: int, url: str, secret: str,
          event: str, payload: dict) -> None:
    body = json.dumps(
        {"event": event, "ts": int(time.time()), "data": payload},
        separators=(",", ":"), ensure_ascii=False,
    )
    sig = hmac.new(
        secret.encode(), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    status = 0
    try:
        r = requests.post(
            url, data=body.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DepAPI-Webhook/1.1",
                "X-DepAPI-Event": event,
                "X-DepAPI-Signature": f"sha256={sig}",
                "X-DepAPI-Webhook-Id": str(webhook_id),
            },
            timeout=10,
        )
        status = r.status_code
    except Exception:
        status = 0

    try:
        with db() as conn:
            conn.execute(
                "UPDATE webhooks SET last_triggered_at=CURRENT_TIMESTAMP, last_status=? WHERE id=?",
                (status, webhook_id),
            )
            conn.commit()
    except Exception:
        pass


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[7:])