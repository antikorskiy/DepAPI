"""Audit log helper."""
from __future__ import annotations

import json
from typing import Optional

from .db import db


def audit(actor: str, action: str, target: str = "",
          details: Optional[dict] = None, ip: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, details, ip) VALUES (?,?,?,?,?)",
            (actor, action, target,
             json.dumps(details or {}, ensure_ascii=False), ip or ""),
        )
        conn.commit()