"""Serve the admin UI (single HTML file)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter(tags=["admin-ui"])

_STATIC = Path(__file__).parent / "static" / "admin.html"


@router.get("/admin/ui", response_class=HTMLResponse, include_in_schema=False)
def admin_ui():
    if not _STATIC.exists():
        return HTMLResponse(
            "<h1>Admin UI not installed</h1>"
            "<p>Missing <code>depapi/static/admin.html</code></p>",
            status_code=500,
        )
    return HTMLResponse(_STATIC.read_text(encoding="utf-8"))


@router.get("/admin/ui/", include_in_schema=False)
def admin_ui_slash():
    return RedirectResponse("/admin/ui", status_code=307)