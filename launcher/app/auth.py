"""users.json login gate for the OpnAgent web entry point.

A passkey stored as 64 hex characters is treated as its SHA-256 hash;
anything else is compared in plaintext (as specified in the config format).
Sessions are HMAC-signed, expiring cookies — no server-side state.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
import time

from .config import OpnConfig

COOKIE_NAME = "opnagent_session"
SESSION_TTL = 8 * 3600

_SECRET = os.environ.get("OPN_SESSION_SECRET") or secrets.token_hex(32)

LOGIN_HTML = """<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpnAgent 登入</title>
<style>
 body{font-family:system-ui,sans-serif;background:#101418;color:#e6e6e6;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 .box{background:#1b2128;padding:2.2rem;border-radius:12px;width:22rem}
 h1{font-size:1.2rem;margin:0 0 1.2rem}
 label{display:block;font-size:.85rem;margin:.7rem 0 .2rem;color:#9fb0bf}
 input{width:100%;padding:.55rem;border-radius:6px;border:1px solid #34404d;
       background:#12171d;color:#eee;font-size:.95rem}
 button{margin-top:1.3rem;width:100%;padding:.6rem;border:0;border-radius:6px;
        background:#3d7efd;color:#fff;font-size:1rem;cursor:pointer}
 .err{color:#ff7b72;font-size:.85rem;margin-top:.8rem}
</style></head><body>
<form class="box" method="post" action="/login">
 <h1>OpnAgent</h1>
 <label for="u">使用者</label><input id="u" name="username" autocomplete="username" required>
 <label for="p">Passkey</label><input id="p" name="passkey" type="password" autocomplete="current-password" required>
 <button type="submit">登入</button>
 {error}
</form></body></html>
"""


def _sign(payload: str) -> str:
    return hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_token(username: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{username}.{exp}"
    return f"{payload}.{_sign(payload)}"


def verify_token(token: str) -> str | None:
    try:
        username, exp, sig = token.rsplit(".", 2)
    except ValueError:
        return None
    payload = f"{username}.{exp}"
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    if int(exp) < time.time():
        return None
    return username


def role_for(cfg: OpnConfig, username: str) -> str | None:
    """Current role of a (session) username, or None if no longer present —
    None also fences out users removed via the web console mid-session."""
    for u in cfg.users:
        if u.username == username:
            return u.role
    return None


def check_credentials(cfg: OpnConfig, username: str, passkey: str) -> bool:
    for u in cfg.users:
        if u.username != username:
            continue
        stored = u.passkey
        if len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower()):
            return hmac.compare_digest(
                stored.lower(), hashlib.sha256(passkey.encode()).hexdigest())
        return hmac.compare_digest(stored, passkey)
    return False


def login_page(error: str | None = None) -> str:
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return LOGIN_HTML.replace("{error}", err)
