from __future__ import annotations

import threading
import time

from fastapi import HTTPException

from DeepSeekAPI.streamer import DeepSeekStreamer, _normalise_parent

from .db import db

_POOL: dict[tuple[int, str], DeepSeekStreamer] = {}
_POOL_LOCK = threading.Lock()


def acquire_session(client_id: int, session_key: str) -> DeepSeekStreamer:
    key = (client_id, session_key)
    with _POOL_LOCK:
        if key in _POOL:
            return _POOL[key]

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE client_id=? AND session_key=?",
            (client_id, session_key),
        ).fetchone()

        if row:
            tok = conn.execute(
                "SELECT * FROM deepseek_tokens WHERE id=?",
                (row["deepseek_token_id"],),
            ).fetchone()
            if not tok:
                raise HTTPException(
                    410,
                    f"session '{session_key}' is orphaned: its DeepSeek token was deleted. "
                    f"Call DELETE /v1/sessions/{session_key} to start over.",
                )
            if not tok["active"]:
                raise HTTPException(
                    410,
                    f"session '{session_key}' was created with a deactivated DeepSeek token. "
                    f"Call DELETE /v1/sessions/{session_key} to start a fresh one.",
                )
            token_row = tok
        else:
            tok = conn.execute(
                """SELECT * FROM deepseek_tokens
                   WHERE active=1 AND cooldown_until<=?
                   ORDER BY id LIMIT 1""",
                (time.time(),),
            ).fetchone()
            if not tok:
                raise HTTPException(503, "no deepseek tokens available")
            token_row = tok

        sess = DeepSeekStreamer(
            ds_session_id=token_row["session_id"],
            auth_token=token_row["auth_token"],
            chat_session_id=row["ds_chat_session_id"] if row else None,
            parent_message_id=_normalise_parent(row["ds_parent_message_id"]) if row else None,
        )
        sess.pinned_token_id = token_row["id"]

        conn.execute(
            "UPDATE deepseek_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?",
            (token_row["id"],),
        )
        conn.commit()

    with _POOL_LOCK:
        _POOL[key] = sess
    return sess


def save_session_state(client_id: int, session_key: str, sess: DeepSeekStreamer):
    token_id = getattr(sess, "pinned_token_id", None)
    if token_id is None:
        return
    parent = sess.parent_message_id
    parent_str = None if parent is None else str(parent)
    with db() as conn:
        conn.execute(
            """INSERT INTO sessions
                 (client_id, session_key, deepseek_token_id,
                  ds_chat_session_id, ds_parent_message_id, last_used_at)
               VALUES (?,?,?,?,?, CURRENT_TIMESTAMP)
               ON CONFLICT(client_id, session_key)
               DO UPDATE SET ds_chat_session_id  = excluded.ds_chat_session_id,
                             ds_parent_message_id= excluded.ds_parent_message_id,
                             last_used_at        = CURRENT_TIMESTAMP""",
            (client_id, session_key, token_id,
             sess.chat_session_id, parent_str),
        )
        conn.commit()


def reset_session(client_id: int, session_key: str):
    with _POOL_LOCK:
        _POOL.pop((client_id, session_key), None)
    with db() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE client_id=? AND session_key=?",
            (client_id, session_key),
        )
        conn.commit()