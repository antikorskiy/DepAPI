#!/usr/bin/env python3

from __future__ import annotations

import json
import threading
from typing import Generator, Optional

import requests

from .DeepSeekChat.DeepSeekWASM.wasmsolver import solve_wasm

BASE_URL = "https://chat.deepseek.com"

_WASM_LOCK = threading.Lock()


def _solve_pow(challenge: dict) -> tuple[Optional[int], str]:
    with _WASM_LOCK:
        return solve_wasm(
            challenge["algorithm"],
            challenge["challenge"],
            challenge["salt"],
            challenge["expire_at"],
            challenge["difficulty"],
            challenge["signature"],
            challenge["target_path"],
        )


def _normalise_parent(value):
    """DeepSeek /completion expects parent_message_id as u32 or null.
    DB stores it as TEXT; coerce numeric strings to int."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s == "" or s.lower() == "null":
            return None
        try:
            return int(s)
        except (ValueError, TypeError):
            return s
    return value


class DeepSeekStreamer:

    def __init__(
        self,
        ds_session_id: str,
        auth_token: str,
        chat_session_id: Optional[str] = None,
        parent_message_id: Optional[object] = None,
    ):
        self.ds_session_id = ds_session_id
        self.auth_token = (
            auth_token if auth_token.startswith("Bearer ") else "Bearer " + auth_token
        )
        self.chat_session_id = chat_session_id
        self.parent_message_id = _normalise_parent(parent_message_id)

        self._http = requests.Session()
        self._http.cookies.set("ds_session_id", ds_session_id)
        self._headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9,ru;q=0.8,zh-CN;q=0.5",
            "authorization": self.auth_token,
            "content-type": "application/json",
            "priority": "u=1, i",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-app-version": "20241129.1",
            "x-client-locale": "zh_CN",
            "x-client-platform": "web",
            "x-client-version": "1.5.0",
            "x-debug-lite-model-channel": "prod",
            "x-debug-model-channel": "prod",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/142.0",
        }

    def reset(self):
        self.chat_session_id = None
        self.parent_message_id = None

    def _ensure_chat_session(self):
        if self.chat_session_id:
            return
        r = self._http.post(
            f"{BASE_URL}/api/v0/chat_session/create",
            headers=self._headers, data="{}", timeout=30,
        )
        if r.status_code != 200:
            raise RuntimeError(f"create_session HTTP {r.status_code}: {r.text[:200]}")
        j = r.json()
        if j.get("code") != 0:
            raise RuntimeError(f"create_session code {j.get('code')}: {j.get('msg')}")
        data = j.get("data") or {}
        biz = data.get("biz_data") or {}
        cid = (
            biz.get("id")
            or (biz.get("chat_session") or {}).get("id")
            or biz.get("chat_session_id")
            or data.get("id")
            or data.get("chat_session_id")
            or (data.get("chat_session") or {}).get("id")
        )
        if not cid:
            snippet = json.dumps(j, ensure_ascii=False)
            if len(snippet) > 2000:
                snippet = snippet[:2000] + "..."
            raise RuntimeError(f"create_session no id. Response: {snippet}")
        self.chat_session_id = cid

    def _create_pow_challenge(self) -> dict:
        r = self._http.post(
            f"{BASE_URL}/api/v0/chat/create_pow_challenge",
            headers=self._headers,
            data=json.dumps({"target_path": "/api/v0/chat/completion"}),
            timeout=30,
        )
        if r.status_code != 200:
            raise RuntimeError(f"pow_challenge HTTP {r.status_code}")
        j = r.json()
        if j.get("code") != 0:
            raise RuntimeError(f"pow_challenge code {j.get('code')}")
        return (j.get("data") or {}).get("biz_data", {}).get("challenge") or {}

    def stream(
        self,
        prompt: str,
        thinking_enabled: bool = True,
        model_type: str = "default",
        timeout: int = 180,
    ) -> Generator[tuple[str, str], None, None]:
        try:
            self._ensure_chat_session()
            challenge = self._create_pow_challenge()
            if not challenge:
                yield ("error", "no pow challenge")
                return
            _, pow_response = _solve_pow(challenge)
            if not pow_response:
                yield ("error", "pow solve failed")
                return
        except Exception as e:
            yield ("error", f"setup: {e}")
            return

        headers = dict(self._headers)
        headers["x-ds-pow-response"] = pow_response
        headers["accept"] = "text/event-stream"
        headers["referer"] = f"{BASE_URL}/a/chat/s/{self.chat_session_id}"

        body = {
            "chat_session_id": self.chat_session_id,
            "parent_message_id": self.parent_message_id,
            "model_type": model_type,
            "prompt": prompt,
            "ref_file_ids": [],
            "thinking_enabled": thinking_enabled,
            "search_enabled": False,
            "action": None,
            "preempt": False,
        }

        try:
            r = self._http.post(
                f"{BASE_URL}/api/v0/chat/completion",
                headers=headers, data=json.dumps(body),
                stream=True, timeout=timeout,
            )
        except Exception as e:
            yield ("error", f"request: {e}")
            return

        if r.status_code != 200:
            yield ("error", f"completion HTTP {r.status_code}: {r.text[:300]}")
            return

        mode = "THINK" if thinking_enabled else "RESPONSE"
        msg_id: Optional[object] = None
        saw_event = False

        def walk(v):
            nonlocal mode, msg_id
            if isinstance(v, list):
                for e in v:
                    yield from walk(e)
                return
            if isinstance(v, str):
                if mode == "THINK":
                    yield ("think", v)
                elif mode == "RESPONSE":
                    yield ("response", v)
                return
            if not isinstance(v, dict):
                return
            typ = v.get("type")
            if isinstance(typ, str) and typ:
                mode = typ
                if "content" in v:
                    yield from walk(v["content"])
                return
            p = v.get("p")
            if isinstance(p, str):
                tail = p.rsplit("/", 1)[-1]
                if tail == "fragments":
                    arr = v.get("v") or []
                    if arr:
                        last = arr[-1]
                        if isinstance(last, dict):
                            if last.get("type"):
                                mode = last["type"]
                            if "content" in last:
                                yield from walk(last["content"])
                elif tail in ("response", "content", "fragment", "results"):
                    yield from walk(v.get("v"))
                return
            if "message_id" in v and msg_id is None:
                mid = v["message_id"]
                if mid is not None:
                    msg_id = mid
            if "v" in v:
                yield from walk(v["v"])
                return
            if "response" in v:
                yield from walk(v["response"])
                return
            if "thought" in v:
                prev = mode
                mode = "THINK"
                yield from walk(v["thought"])
                mode = prev
                return

        try:
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                saw_event = True
                if line.startswith("event: "):
                    continue
                if not line.startswith("data: "):
                    continue
                try:
                    v = json.loads(line[6:])
                except Exception:
                    continue
                yield from walk(v)
        except Exception as e:
            yield ("error", f"stream: {e}")
            return

        if msg_id is not None:
            self.parent_message_id = _normalise_parent(msg_id)
        if not saw_event:
            yield ("error", "no SSE events")
            return
        yield ("done", "")