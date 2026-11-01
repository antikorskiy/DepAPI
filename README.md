# DepAPI

An unofficial DeepSeek API gateway. DepAPI reverse-engineers the DeepSeek web interface and exposes it through an OpenAI-compatible HTTP API, with multi-tenant client keys, rate limiting, session pooling, an admin API/UI, audit logging, webhooks and IP/User-Agent bans.

The project has two layers:

- `DeepSeekAPI/` -- the reverse-engineered client library (talks directly to `chat.deepseek.com`, solves the proof-of-work challenge via WASM, streams responses).
- `depapi/` -- the FastAPI + SQLite gateway that turns that client into a multi-tenant, authenticated HTTP service.

> This project is unofficial and not affiliated with DeepSeek. Use it in accordance with DeepSeek's terms of service and all applicable laws. You are responsible for how you use it.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Running the server](#running-the-server)
- [Client API](#client-api)
- [Admin API](#admin-api)
- [Admin UI](#admin-ui)
- [CLI (`manage.py`)](#cli-managepy)
- [Scopes and roles](#scopes-and-roles)
- [Webhooks](#webhooks)
- [Bans](#bans)
- [The `DeepSeekAPI` library](#the-deepseekapi-library)
- [Self-test](#self-test)
- [Project layout](#project-layout)
- [Security notes](#security-notes)
- [License](#license)

---

## Features

- **OpenAI-compatible chat endpoint** -- `POST /v1/chat/completions` with `messages` or `prompt`, streaming (SSE) or buffered.
- **Multi-tenant client keys** -- issue, rotate (with grace period), deactivate per-client keys.
- **Per-client rate limiting** -- token-bucket RPS plus a rolling daily quota.
- **Session pooling** -- each `(client, session_key)` keeps its own DeepSeek conversation context (`chat_session_id` / `parent_message_id`).
- **DeepSeek token pool** -- rotate multiple `session_id` + `auth_token` pairs; automatic cooldown on errors.
- **Scoped admin keys** -- granular scopes plus `root` / `admin` / `readonly` role presets.
- **Admin REST API + single-page web UI** at `/admin/ui`.
- **Audit log** of every mutating admin action.
- **Webhooks** -- HMAC-SHA256 signed event delivery.
- **Bans** -- match clients by IP (exact / CIDR / glob) or User-Agent (substring / glob).
- **Usage logging** per client per endpoint.

---

## Requirements

- Python **3.8+**
- Dependencies in `requirements.txt` (FastAPI, Uvicorn, Pydantic v2, `requests`, `wasmtime`, `pygments`, `pylatexenc`, `appdirs`, `term-image`, `wcwidth`, `toml`, `python-dotenv`).

```
pip install -r requirements.txt
```

`wasmtime` is required to run the proof-of-work solver (`DeepSeekAPI/DeepSeekChat/DeepSeekWASM/wasm.wasm`).

---

## Quick start

1. **Install dependencies**

   ```
   pip install -r requirements.txt
   ```

2. **Create your `.env`**

   ```
   copy .env.example .env      # Windows
   # or: cp .env.example .env  # POSIX
   ```

   Generate a strong root admin token and put it in `.env`:

   ```
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   ```
   DS_ADMIN_TOKEN=<the value you just generated>
   ```

3. **Add at least one DeepSeek token** (see below for how to obtain one), then start the server.

4. **Run the server**

   ```
   python server.py
   ```

   Then open:

   - API docs: `http://127.0.0.1:8787/docs`
   - Admin UI: `http://127.0.0.1:8787/admin/ui`
   - Health:   `http://127.0.0.1:8787/health`

5. **Create a client key** and call the API (see [Client API](#client-api)).

### Obtaining a DeepSeek token

DepAPI drives the DeepSeek **web** app, so it needs a browser session, not an API key.

1. Log in to <https://chat.deepseek.com> in your browser.
2. Open DevTools and read two values:
   - the `ds_session_id` cookie value,
   - the `Authorization` request header (a `Bearer ...` token).
3. Register them with DepAPI (either via the CLI or the admin API):

   ```
   python manage.py add-token <ds_session_id> "Bearer <authorization_token>" --label main
   ```

> Treat these values like passwords. They grant full access to that DeepSeek account. Never commit them. `tokens` and `.env` are gitignored.

---

## Configuration

Configuration is read from environment variables, typically via a `.env` file (see `.env.example`).

| Variable | Default | Description |
|---|---|---|
| `DS_HOST` | `127.0.0.1` | Bind address. `0.0.0.0` exposes all interfaces -- put it behind TLS. |
| `DS_PORT` | `8787` | HTTP port. |
| `DS_DB` | `data/server.db` | SQLite database path. Parent directory is created automatically. |
| `DS_ADMIN_TOKEN` | *(required)* | Root admin token for `/admin/*`. Send as `X-Admin-Token`. Must be non-empty. |
| `DS_DEFAULT_RPS` | `5` | Default requests-per-second for new clients. |
| `DS_DEFAULT_DAILY` | `1000` | Default daily request quota for new clients. |
| `DS_CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins, or `*`. Empty disables CORS middleware. |
| `DS_TRUST_PROXY` | `0` | If `1`/`true`, trust `X-Forwarded-For` / `X-Real-IP`. Enable **only** behind a trusted reverse proxy. |

The server refuses to start if `DS_ADMIN_TOKEN` is empty.

---

## Running the server

```
python server.py                          # defaults: 127.0.0.1:8787
python server.py --host 0.0.0.0 --port 8080
python server.py --reload                 # dev auto-reload
```

`server.py` is a thin wrapper around `uvicorn.run("depapi.api:app", ...)`. You can also run Uvicorn directly:

```
uvicorn depapi.api:app --host 127.0.0.1 --port 8787
```

---

## Client API

All client endpoints require an API key in the standard OpenAI header:

```
Authorization: Bearer sk-local-...
```

### `GET /v1/models`

Lists the pseudo-models understood by the gateway:

- `deepseek-default` -- default chat model
- `deepseek-reasoner` -- thinking enabled
- `deepseek-expert` -- expert model
- `deepseek-expert-reasoner` -- expert model with thinking

The model string is interpreted heuristically: `v4`/`r4`/`expert` select the expert model, and `r1`/`r4`/`reasoning`/`reasoner` enable thinking.

### `GET /v1/me`

Returns the calling client's id, name, limits and key prefix.

### `POST /v1/chat/completions`

OpenAI-compatible chat completion.

Request body:

```json
{
  "model": "deepseek-default",
  "messages": [{"role": "user", "content": "Hello"}],
  "stream": false,
  "session_key": "default"
}
```

- Provide either `messages` (the last `user` message is used) or a `prompt` string directly.
- `stream: true` returns `text/event-stream` with OpenAI-style `data: {"choices":[{"delta":{"content":"..."}}]}` chunks, terminated by `data: [DONE]`.
- `session_key` selects a conversation context; different keys keep independent histories.

Buffered response:

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "deepseek-default",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "..."},
    "finish_reason": "stop"
  }]
}
```

### Sessions

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/sessions` | List this client's sessions. |
| `GET` | `/v1/sessions/{session_key}` | Get one session. |
| `DELETE` | `/v1/sessions/{session_key}` | Reset (drop) a session and its context. |
| `POST` | `/v1/session/reset` | Reset a session by body `{"session_key": "..."}`. |

A `410 Gone` on chat means the session is orphaned (its DeepSeek token was deleted or deactivated); reset the session to start fresh.

---

## Admin API

All admin endpoints live under `/admin`. Authenticate with **either**:

- `X-Admin-Token: <DS_ADMIN_TOKEN>` -- root, all scopes, or
- `X-Admin-Key: adm-...` (or `Authorization: Bearer adm-...`) -- a scoped admin key.

### Info

- `GET /admin/info` -- counts, your actor and scopes, available events/scopes/role presets.

### Clients

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/clients` | `clients:read` | List (filters: `active`, `q`, `limit`, `offset`). |
| `GET` | `/admin/clients/{id}` | `clients:read` | Get by id. |
| `GET` | `/admin/clients/by-name/{name}` | `clients:read` | Get by name. |
| `GET` | `/admin/clients/by-external/{ext}` | `clients:read` | Get by external id. |
| `POST` | `/admin/clients` | `clients:write` | Create; returns the plaintext key once. |
| `POST` | `/admin/clients/bulk` | `clients:write` | Bulk create. |
| `PATCH` | `/admin/clients/{id}` | `clients:write` | Update limits/flags/metadata/expiry. |
| `DELETE` | `/admin/clients/{id}` | `clients:write` | Deactivate (optionally `?purge_sessions=true`). |
| `POST` | `/admin/clients/{id}/rotate` | `clients:write` | Rotate key; `grace_hours` keeps the old key valid. |
| `GET` | `/admin/clients/{id}/usage` | `clients:read` | Per-day usage. |
| `GET` | `/admin/clients/{id}/sessions` | `clients:read` | Sessions of a client. |

### DeepSeek tokens

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/tokens` | `tokens:read` | List tokens. |
| `GET` | `/admin/tokens/{id}` | `tokens:read` | Get token. |
| `POST` | `/admin/tokens` | `tokens:write` | Add `{session_id, auth_token, label}`. |
| `PATCH` | `/admin/tokens/{id}` | `tokens:write` | Update label / active. |
| `DELETE` | `/admin/tokens/{id}` | `tokens:write` | Delete (409 if in use). |
| `POST` | `/admin/tokens/{id}/cooldown` | `tokens:write` | Put on cooldown for `seconds`. |
| `POST` | `/admin/tokens/{id}/reset-errors` | `tokens:write` | Clear error count and cooldown. |

### Sessions

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/sessions` | `sessions:read` | List sessions (filter `client_id`). |
| `DELETE` | `/admin/sessions/{id}` | `sessions:write` | Reset a session. |

### Admin keys

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/keys` | `admin_keys:read` | List admin keys. |
| `POST` | `/admin/keys` | `admin_keys:write` | Create `{name, role? | scopes?, expires_at?}`. |
| `DELETE` | `/admin/keys/{id}` | `admin_keys:write` | Deactivate. |

### Audit

- `GET /admin/audit` -- `audit:read`. Filters: `actor`, `action`, `since`, `limit`.

### Webhooks

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/webhooks` | `webhooks:read` | List. |
| `GET` | `/admin/webhooks/{id}` | `webhooks:read` | Get. |
| `POST` | `/admin/webhooks` | `webhooks:write` | Create `{name, url, events}`; returns the secret once. |
| `DELETE` | `/admin/webhooks/{id}` | `webhooks:write` | Delete. |
| `POST` | `/admin/webhooks/{id}/test` | `webhooks:write` | Send a `test.ping`. |

### Bans

| Method | Path | Scope | Description |
|---|---|---|---|
| `GET` | `/admin/bans` | `bans:read` | List (filters `kind`, `active`). |
| `GET` | `/admin/bans/{id}` | `bans:read` | Get. |
| `GET` | `/admin/bans/check` | `bans:read` | Test `?ip=` / `?ua=`. |
| `POST` | `/admin/bans` | `bans:write` | Create `{kind: "ip"|"ua", pattern, reason?, expires_at?}`. |
| `PATCH` | `/admin/bans/{id}` | `bans:write` | Update. |
| `DELETE` | `/admin/bans/{id}` | `bans:write` | Delete. |

---

## Admin UI

A single-page web UI is served at `GET /admin/ui` (source: `depapi/static/admin.html`). Paste an admin token or key; it stores it in `localStorage` and calls the admin API above. It is a convenience front-end over the same endpoints -- nothing is available there that is not in the API.

---

## CLI (`manage.py`)

`manage.py` operates directly on the SQLite database. It does **not** require the server to be running, but the server must be restarted (or use the API) for in-memory caches to refresh.

```
python manage.py <command> [args]
```

| Command | Description |
|---|---|
| `init` | Create/verify the database schema. |
| `keygen [--name N] [--rps R] [--daily D]` | Create a client and print its key once. |
| `keys` | List clients. |
| `revoke <name-or-id> [--purge-sessions]` | Deactivate a client. |
| `add-token <session_id> <token> [--label L]` | Add a DeepSeek token. |
| `tokens` | List DeepSeek tokens and cooldowns. |
| `rm-token <session_id> [--force]` | Remove/deactivate a DeepSeek token. |
| `usage [--days N]` | Per-client usage summary. |
| `sessions` | Recent sessions. |
| `admin-keygen [--name N] [--role R \| --scopes a,b] [--expires ISO]` | Create an admin key. |
| `admin-keys` | List admin keys. |
| `admin-revoke <name-or-id>` | Deactivate an admin key. |
| `audit [--actor A] [--action X] [--since ISO] [--limit N]` | Tail the audit log. |
| `ban-ip <ip\|cidr\|glob> [--reason T] [--hours N]` | Add an IP ban. |
| `ban-ua <substring\|glob> [--reason T] [--hours N]` | Add a User-Agent ban. |
| `bans [--active\|--inactive]` | List bans. |
| `unban <id>` | Delete a ban. |

---

## Scopes and roles

Available scopes:

```
clients:read   clients:write
tokens:read    tokens:write
sessions:read  sessions:write
audit:read
bans:read      bans:write
webhooks:read  webhooks:write
admin_keys:read admin_keys:write
admin:all
```

Role presets:

- `root` -- all scopes.
- `admin` -- all scopes except `admin_keys:write`.
- `readonly` -- every `*:read` scope.

`admin:all` satisfies any scope check. The root `X-Admin-Token` always has all scopes.

---

## Webhooks

Create a webhook with a list of events (`*` for all). On a matching event DepAPI POSTs a JSON body to your URL and signs it.

Events: `client.created`, `client.updated`, `client.deactivated`, `client.rotated`, `client.expired`, `token.added`, `token.updated`, `token.deleted`, `token.cooldown`, `session.reset`, `ban.created`, `ban.updated`, `ban.deleted`, `ban.triggered`, `admin_key.created`, `admin_key.deleted`, `usage.threshold`, plus `test.ping`.

Request headers:

```
Content-Type: application/json
User-Agent: DepAPI-Webhook/1.1
X-DepAPI-Event: <event>
X-DepAPI-Webhook-Id: <id>
X-DepAPI-Signature: sha256=<hex hmac>
```

Body:

```json
{"event": "client.created", "ts": 1700000000, "data": { ... }}
```

The signature is `HMAC-SHA256(secret, raw_body)` in hex. Verify it against the exact bytes you received before trusting the payload. The secret is returned only once, at webhook creation.

---

## Bans

Bans are checked by HTTP middleware on every request (loopback addresses are always allowed).

- **IP** -- matches an exact IP, a CIDR block (`10.0.0.0/8`) or a glob (`192.168.*.*`).
- **User-Agent** -- case-insensitive substring match, or glob if the pattern contains `*`/`?`. An empty pattern matches only an empty UA.

A banned request receives `403` with `X-Ban-Id` and `X-Ban-Kind` headers. Bans may have an `expires_at`; expired bans stop matching. The active-ban list is cached for a few seconds and invalidated on change.

---

## The `DeepSeekAPI` library

The `DeepSeekAPI` package can be used standalone, without the gateway.

```python
from DeepSeekAPI import DeepSeekChat

chat = DeepSeekChat(ds_session_id, "Bearer <token>")
print(chat.send_message("Hello", thinking_enabled=True))
```

Lower-level streaming lives in `DeepSeekAPI/streamer.py` (`DeepSeekStreamer.stream(...)`), which yields `(kind, text)` tuples where `kind` is `think`, `response`, `error` or `done`. It handles session creation, the WASM proof-of-work challenge and the SSE stream from `chat.deepseek.com`.

`main.py` is a minimal interactive example:

```
python main.py     # reads two lines from ./tokens, then prompts for a message
```

`DeepSeekAPI/streamdown/` is a vendored terminal markdown/ANSI renderer used by the `STREAMDOWN` I/O mode.

---

## Self-test

```
python selftest.py                 # offline checks: python, deps, tokens, imports
python selftest.py --live          # also send a real message
python selftest.py --live --message "ping"
```

Exit code is `0` on success. Tokens are read from `./tokens` (two lines) or from `DS_SESSION_ID` / `AUTHORIZATION_TOKEN` environment variables.

---

## Project layout

```
server.py                 Entry point: Uvicorn launcher for depapi.api:app
manage.py                 DB-admin CLI
selftest.py               Environment / live self-test
main.py                   Minimal standalone example
requirements.txt
.env.example              Configuration template

depapi/
  api.py                  FastAPI app: client endpoints, middleware wiring
  auth.py                 Client auth, admin auth, scopes, rate limiter
  admin.py                Admin REST API
  admin_ui.py             Serves depapi/static/admin.html
  static/admin.html       Single-page admin UI
  db.py                   SQLite schema, migrations, key generation, usage log
  pool.py                 Session pool over DeepSeekStreamer
  bans.py                 Ban model, matchers, cache, middleware
  webhooks.py             HMAC webhook dispatcher
  audit.py                Audit log helper

DeepSeekAPI/
  __init__.py             Public exports: DeepSeekChat, DeepSeekChatExample, IOMethods
  wrapper.py              IOMethods (PRINT / RETURN / STREAMDOWN) and example runner
  streamer.py             Streaming DeepSeek client used by the gateway
  DeepSeekChat/main.py    Blocking DeepSeekChat client
  DeepSeekChat/DeepSeekWASM/
    wasmsolver.py         Proof-of-work solver
    wasm.wasm             WASM module used by the solver
  streamdown/             Terminal markdown renderer
```

---

## Security notes

- **`.env` and `tokens` are secrets.** They are gitignored. Never commit them or paste their contents into issues.
- **Client and admin keys are stored hashed** (SHA-256); plaintext is shown only once at creation.
- **Run behind TLS** if you bind to anything other than `127.0.0.1`. Set `DS_TRUST_PROXY=1` only when a trusted reverse proxy terminates TLS and sets `X-Forwarded-For`.
- **CORS is off by default.** Only set `DS_CORS_ORIGINS` if you have browser clients and understand the implications.
- **The root admin token bypasses scope checks.** Keep it out of clients and rotate any admin key you suspect is leaked.
- **DeepSeek tokens grant full account access.** A leaked token is as sensitive as the account password.
- The database (`data/server.db`) contains hashed keys, DeepSeek tokens and the audit log -- protect it like any credential store.

---

## License

Released under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). See `LICENSE` for the full text.

Copyright (C) 2025 smkttl.
