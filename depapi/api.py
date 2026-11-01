from __future__ import annotations

import json
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .admin import router as admin_router
from .admin_ui import router as admin_ui_router
from .auth import Client, auth_dep, rate_limit
from .db import db, log_usage
from .pool import acquire_session, reset_session, save_session_state
from .bans import make_ban_middleware

app = FastAPI(title="DepAPI", version="1.1")
app.include_router(admin_router)
app.include_router(admin_ui_router)

_cors = os.getenv("DS_CORS_ORIGINS", "").strip()
if _cors:
    from fastapi.middleware.cors import CORSMiddleware
    origins = ["*"] if _cors == "*" else [o.strip() for o in _cors.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.middleware("http")(make_ban_middleware(
    trust_proxy=os.getenv("DS_TRUST_PROXY", "0").lower() in ("1", "true", "yes")
))

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "deepseek-default"
    messages: list[ChatMessage] = Field(default_factory=list)
    prompt: Optional[str] = None
    stream: bool = False
    session_key: str = "default"


class ResetRequest(BaseModel):
    session_key: str = "default"


def _extract_prompt(req: ChatRequest) -> str:
    if req.prompt:
        return req.prompt
    for m in reversed(req.messages):
        if m.role == "user":
            return m.content
    return ""


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _model_flags(model: str) -> tuple[str, bool]:
    m = (model or "").lower()
    model_type = "expert" if ("v4" in m or "r4" in m or "expert" in m) else "default"
    thinking = ("r1" in m or "r4" in m or "reasoning" in m or "reasoner" in m)
    return model_type, thinking


def _stream_generator(client: Client, session_key: str, prompt: str,
                      model_type: str, thinking: bool):
    t0 = time.monotonic()
    status = 500
    sess = None
    try:
        sess = acquire_session(client.id, session_key)
        for kind, text in sess.stream(prompt, thinking_enabled=thinking,
                                       model_type=model_type):
            if kind == "response":
                yield _sse({"choices": [{"delta": {"content": text}}]})
            elif kind == "error":
                yield _sse({"error": text})
                status = 502
                return
        yield "data: [DONE]\n\n"
        status = 200
    except HTTPException as e:
        yield _sse({"error": e.detail})
        status = e.status_code
    except Exception as e:
        yield _sse({"error": str(e)})
        status = 500
    finally:
        if sess is not None and status == 200:
            try:
                save_session_state(client.id, session_key, sess)
            except Exception:
                pass
        log_usage(client.id, "/v1/chat/completions", status,
                  int((time.monotonic() - t0) * 1000))


@app.get("/")
def root():
    return {
        "name": "DepAPI",
        "version": "1.1.0",
        "docs": "/docs",
        "admin_ui": "/admin/ui",
        "openapi": "/openapi.json",
        "health": "/health",
    }


@app.get("/health")
def health():
    with db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM deepseek_tokens WHERE active=1"
        ).fetchone()[0]
    return {"status": "ok", "tokens_active": n}


@app.get("/v1/models")
def models(client: Client = Depends(auth_dep)):
    return {
        "object": "list",
        "data": [
            {"id": "deepseek-default", "object": "model", "owned_by": "deepseek"},
            {"id": "deepseek-reasoner", "object": "model", "owned_by": "deepseek"},
            {"id": "deepseek-expert", "object": "model", "owned_by": "deepseek"},
            {"id": "deepseek-expert-reasoner", "object": "model", "owned_by": "deepseek"},
        ],
    }


@app.get("/v1/me")
def me(client: Client = Depends(auth_dep)):
    return {
        "id": client.id,
        "name": client.name,
        "rps": client.rps,
        "daily": client.daily,
        "key_prefix": client.key_prefix,
    }


@app.post("/v1/chat/completions")
def chat_completions(req: ChatRequest, client: Client = Depends(auth_dep)):
    rate_limit(client)
    prompt = _extract_prompt(req)
    if not prompt:
        raise HTTPException(400, "empty prompt")
    session_key = req.session_key or "default"
    model_type, thinking = _model_flags(req.model)

    if req.stream:
        return StreamingResponse(
            _stream_generator(client, session_key, prompt, model_type, thinking),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    t0 = time.monotonic()
    status = 500
    sess = None
    try:
        sess = acquire_session(client.id, session_key)
        parts: list[str] = []
        for kind, text in sess.stream(prompt, thinking_enabled=thinking,
                                       model_type=model_type):
            if kind == "response":
                parts.append(text)
            elif kind == "error":
                raise HTTPException(502, text)
        content = "".join(parts)
        save_session_state(client.id, session_key, sess)
        status = 200
        return {
            "id": f"chatcmpl-{int(time.time()*1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
        }
    finally:
        log_usage(client.id, "/v1/chat/completions", status,
                  int((time.monotonic() - t0) * 1000))


@app.get("/v1/sessions")
def list_my_sessions(client: Client = Depends(auth_dep)):
    with db() as conn:
        rows = conn.execute(
            """SELECT session_key, ds_chat_session_id, ds_parent_message_id,
                      created_at, last_used_at
               FROM sessions WHERE client_id=?
               ORDER BY last_used_at DESC""",
            (client.id,),
        ).fetchall()
    return {
        "client": client.name,
        "sessions": [
            {
                "session_key": r["session_key"],
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
                "has_context": bool(r["ds_parent_message_id"]),
            }
            for r in rows
        ],
    }


@app.get("/v1/sessions/{session_key}")
def get_my_session(session_key: str, client: Client = Depends(auth_dep)):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE client_id=? AND session_key=?",
            (client.id, session_key),
        ).fetchone()
    if not row:
        raise HTTPException(404, "session not found")
    return {
        "session_key": row["session_key"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "has_context": bool(row["ds_parent_message_id"]),
    }


@app.delete("/v1/sessions/{session_key}")
def delete_my_session(session_key: str, client: Client = Depends(auth_dep)):
    reset_session(client.id, session_key)
    return {"status": "reset"}


@app.post("/v1/session/reset")
def session_reset(req: ResetRequest, client: Client = Depends(auth_dep)):
    reset_session(client.id, req.session_key or "default")
    return {"status": "reset"}