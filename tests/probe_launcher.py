#!/usr/bin/env python3
"""Black-box probe of the launcher web app over a real socket.

Boots `uvicorn app.main:app` as a subprocess pointed at the repo's config/
dir, then asserts the entry-point behaviour that does not need a gateway:
/status shape, login page, credential check, session cookie, and the
not-ready 503 (bootstrap cannot finish on a dev box without openshell).

Run from anywhere:  python tests/probe_launcher.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = int(os.environ.get("OPN_PROBE_PORT", "8011"))
BASE = f"http://127.0.0.1:{PORT}"

FAILED = []


def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), name, extra if not cond else "")
    if not cond:
        FAILED.append(name)


def main():
    # PREPEND our PYTHONPATH: a harness-set value (e.g. a sitecustomize
    # stubbing websockets to emulate the bare-uvicorn bug) must survive.
    env = {**os.environ,
           "OPN_CONFIG_DIR": os.path.join(ROOT, "config"),
           "PYTHONPATH": os.pathsep.join(
               filter(None, [os.path.join(ROOT, "launcher"),
                             os.environ.get("PYTHONPATH", "")]))}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=os.path.join(ROOT, "launcher"), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        ok = False
        for _ in range(80):  # up to ~16 s
            time.sleep(0.2)
            try:
                httpx.get(f"{BASE}/status", timeout=1)
                ok = True
                break
            except httpx.HTTPError:
                continue
        if not ok:
            proc.terminate()
            out = proc.stdout.read().decode(errors="replace")
            print("server never came up; uvicorn output:\n" + out[-3000:])
            sys.exit(1)

        # /status stays informative even while bootstrap fails (no
        # openshell binary on a dev box -> error text, ready:false).
        # Bootstrap runs in the background; give it a moment to load the
        # config (auth_required flips once cfg is in).
        j = {}
        for _ in range(50):
            j = httpx.get(f"{BASE}/status").json()
            if j.get("auth_required"):
                break
            time.sleep(0.2)
        check("/status 200 + shape",
              j.get("ready") is False
              and isinstance(j.get("error"), (str, type(None)))
              and j.get("auth_required") is True, str(j))

        r = httpx.get(f"{BASE}/login")
        check("/login renders form",
              r.status_code == 200 and "passkey" in r.text
              and "OpnAgent" in r.text)

        r = httpx.post(f"{BASE}/login",
                       data={"username": "admin", "passkey": "WRONG"})
        check("wrong passkey -> 401 + error shown",
              r.status_code == 401 and "錯誤" in r.text)

        c = httpx.Client(base_url=BASE, follow_redirects=False)
        r = c.post("/login", data={"username": "admin", "passkey": "change-me"})
        # login_post redirects by ROLE (main.py): admin -> /admin, else /.
        # Derive the expectation from the same users.json the server loaded
        # instead of hardcoding a path (a stale "/" here failed the probe
        # once the admin redirect shipped).
        with open(os.path.join(ROOT, "config", "users.json"),
                  encoding="utf-8") as f:
            users = json.load(f)["user-list"]
        home = next(("/admin" if u.get("role") == "admin" else "/")
                    for u in users if u.get("username") == "admin")
        check("correct passkey -> 302 + cookie",
              r.status_code == 302 and r.headers["location"] == home
              and "opnagent_session" in r.headers.get("set-cookie", ""),
              str(dict(r.headers)))
        check("session cookie is httponly",
              "httponly" in r.headers.get("set-cookie", "").lower())

        r = c.get("/")
        check("proxy before ready -> 503 with reason",
              r.status_code == 503 and "not ready" in r.text.lower(), r.text[:200])

        r = c.get("/logout")
        check("logout -> 302 back to /login",
              r.status_code == 302 and r.headers["location"] == "/login")

        # FastAPI's own docs/openapi routes disabled: those paths must fall
        # through to the proxy (503 while not ready), not be served — and
        # /openapi.json must reach hermes once ready, not shadow its API.
        r = httpx.get(f"{BASE}/docs")
        r2 = httpx.get(f"{BASE}/openapi.json")
        check("docs/openapi fall through to proxy",
              r.status_code == 503 and r2.status_code == 503
              and "Swagger" not in r.text, f"{r.status_code} {r2.status_code}")

        # --- live WS upgrade against the REAL uvicorn ------------------------
        # The container bug this catches: bare `uvicorn` (no [standard]) has no
        # ws library and silently re-routes upgrades to plain GETs — the
        # handshake then "succeeds" against our 503 not-ready page. With ws
        # support, a not-ready close is a proper rejection (403 pre-accept).
        import asyncio

        import aiohttp

        async def _ws_probe():
            to = aiohttp.ClientTimeout(total=8)
            try:
                async with aiohttp.ClientSession(timeout=to) as s:
                    async with s.ws_connect(f"{BASE}/api/pty") as w:
                        return "opened", None
            except aiohttp.WSServerHandshakeError as e:
                return "handshake", e.status
            except asyncio.TimeoutError:
                # ws-supporting uvicorn stalled on our pre-accept close();
                # still proves it spoke the WebSocket protocol layer
                return "timeout", None
            except Exception as e:  # noqa: BLE001
                return "error", repr(e)
        kind, code = asyncio.run(_ws_probe())
        # Bare uvicorn (no ws library) re-serves upgrades as plain GETs, so
        # the handshake answer is our own 503 page verbatim — that exact
        # signature fails; anything else means uvicorn spoke WebSocket.
        check("uvicorn speaks WebSocket (uvicorn[standard])",
              kind in ("timeout", "opened")
              or (kind == "handshake" and code != 503),
              f"{kind} {code}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)
    print("launcher probe: all passed")


if __name__ == "__main__":
    main()
