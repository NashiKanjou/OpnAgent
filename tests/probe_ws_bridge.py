"""Live WebSocket bridge probe (no Docker needed).

browser-role (TestClient) ── /hermes/rt?x=1, subprotocol "chat" ──>
app websocket route ── Reverse.handle_ws ──> real aiohttp echo server.

Asserts what the VM deploy actually broke on / what must now hold:
  * ANY ws path is bridged (hermes' socket is not under /ws)
  * the upstream sees the vhost Host header, not the launcher's
  * subprotocol negotiation survives (bridge accepts() only after the
    upstream 101) and messages flow both ways

Run:  python tests/probe_ws_bridge.py
"""

import asyncio
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "launcher"))

import aiohttp
from aiohttp import web
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

from app.proxy import Reverse

UP_PORT = 8799
VHOST = "default--opnagent.openshell.localhost:8080"
seen: dict = {}


async def _handler(request: web.Request) -> web.WebSocketResponse:
    seen["path"] = request.path
    seen["host"] = request.headers.get("Host")
    wanted = (request.headers.get("Sec-WebSocket-Protocol") or "").split(",")
    kw = {}
    if "chat" in [w.strip() for w in wanted]:
        try:  # aiohttp >= 3.14 takes plain strings
            ws = web.WebSocketResponse(protocols=["chat"])
        except TypeError:  # old aiohttp
            from aiohttp.web import Subprotocol
            ws = web.WebSocketResponse(subprotocols=[Subprotocol("chat")])
    else:
        ws = web.WebSocketResponse()
    await ws.prepare(request)
    # hermes-style keepalive: servers ping right away, and a bridge that
    # treats a PING as a disconnect answers the FIRST message with a
    # hang-up (the live 1006 "Reconnecting..." loop).
    await ws.ping()
    await asyncio.sleep(0.3)
    await ws.ping()
    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            await ws.send_str("echo:" + msg.data)
    return ws


def _upstream_thread() -> None:
    async def _main():
        app = web.Application()
        app.add_routes([web.route("*", "/{p:.*}", _handler)])
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", UP_PORT).start()
        while True:
            await asyncio.sleep(3600)
    asyncio.run(_main())


def main() -> None:
    threading.Thread(target=_upstream_thread, daemon=True).start()
    for _ in range(50):
        try:
            import socket
            socket.create_connection(("127.0.0.1", UP_PORT), 0.5).close()
            break
        except OSError:
            time.sleep(0.1)

    app = FastAPI()
    rev = Reverse(f"http://127.0.0.1:{UP_PORT}", vhost=VHOST)

    @app.websocket("/{path:path}")
    async def anyws(ws: WebSocket, path: str) -> None:  # pragma: noqa
        await rev.handle_ws(ws)

    def _watchdog():
        time.sleep(10)
        print("FAIL: no reply within 10s — bridge died on the keepalive ping?")
        os._exit(2)
    threading.Thread(target=_watchdog, daemon=True).start()

    with TestClient(app) as c:
        with c.websocket_connect("/hermes/rt?x=1", subprotocols=["chat"]) as wc:
            wc.send_text("hi")
            got = wc.receive_text()
            assert got == "echo:hi", f"bridge mangled reply: {got!r}"
            wc.send_text("again")
            assert wc.receive_text() == "echo:again"

    assert seen.get("path") == "/hermes/rt", f"path not passed through: {seen}"
    assert seen.get("host") == VHOST, f"vhost not pinned: {seen}"
    print("PASS ws path passthrough, vhost Host pinning, subprotocol handshake")
    print("PASS bidirectional frames across the bridge")
    print("\nws bridge probe: all passed")


if __name__ == "__main__":
    main()
