#!/usr/bin/env python3
"""
DepAPI - HTTP server (FastAPI + SQLite) for DeepSeek web API.

Run:
    python -m server
    python -m server --host 0.0.0.0 --port 8080
    python -m server --reload
"""
import argparse
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

if not os.getenv("DS_ADMIN_TOKEN"):
    sys.stderr.write(
        "ERROR: DS_ADMIN_TOKEN not set.\n"
        "  Copy .env.example to .env and set DS_ADMIN_TOKEN.\n"
        "  Generate one: python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
    )
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="DepAPI - DeepSeek Gateway")
    ap.add_argument("--host", default=os.getenv("DS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.getenv("DS_PORT", "8787")))
    ap.add_argument("--reload", action="store_true", help="dev auto-reload")
    args = ap.parse_args()

    import uvicorn
    print(f"DepAPI on http://{args.host}:{args.port}")
    print(f"  docs:   http://{args.host}:{args.port}/docs")
    print(f"  admin:  http://{args.host}:{args.port}/admin/ui")
    print(f"  health: http://{args.host}:{args.port}/health")
    uvicorn.run(
        "depapi.api:app",
        host=args.host, port=args.port,
        reload=args.reload, log_level="info",
    )


if __name__ == "__main__":
    main()