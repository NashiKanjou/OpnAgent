"""Reverse proxy from the launcher to the sandbox's exposed hermes service.

Everything under / (except /login etc.) is streamed to the OpenShell
service URL. SSE / chunked responses pass through block by block, and
WebSocket sessions are bridged with aiohttp.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time

import aiohttp
import httpx
from fastapi import Request, WebSocket
from fastapi.responses import StreamingResponse

log = logging.getLogger("opnagent")

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

# aiohttp rewrote its WS client in 3.14: `protocols=["chat"]` replaced
# `subprotocols=[web.Subprotocol("chat")]`. requirements.txt is >=3.9, so
# adapt to whichever the installed version offers.
_HAS_PLAIN_PROTOCOLS = "protocols" in inspect.signature(
    aiohttp.ClientSession.ws_connect).parameters


class Reverse:
    def __init__(self, base_url: str, vhost: str | None = None):
        self.base = base_url.rstrip("/")
        # Gateway service URLs are vhost-routed: dial the gateway origin but
        # pin Host to the CLI-printed authority (see main._service_target).
        self.vhost = vhost
        # Bounded pool with an EXPLICIT pool timeout: default httpx queues
        # forever when the pool is exhausted, which turned one leaked
        # streaming connection into a silent app-wide stall. Now
        # exhaustion surfaces as a logged PoolTimeout after `pool` secs.
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(None, connect=15.0, write=30.0, pool=10.0),
            limits=httpx.Limits(max_connections=32,
                                max_keepalive_connections=8,
                                keepalive_expiry=15.0),
            follow_redirects=False,
            http2=False,
        )
        self.active = 0          # in-flight upstream exchanges (diag)

    def _url(self, request: Request) -> str:
        path = request.url.path.lstrip("/")
        url = f"{self.base}/{path}" if path else self.base + "/"
        if request.url.query:
            url += "?" + request.url.query
        return url

    async def handle_http(self, request: Request) -> StreamingResponse:
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() not in
                   ("host", "x-forwarded-host", "x-real-host")}
        if self.vhost:
            headers["host"] = self.vhost
        # hermes-webui's CSRF gate compares the browser Origin against the
        # Host it sees — and we just pinned Host to the gateway vhost, so
        # every browser POST would 403 "Cross-origin mismatch". With
        # HERMES_WEBUI_TRUST_FORWARDED_HOST=1 (set by the sandbox
        # entrypoint) it also accepts X-Forwarded-Host, so carry the
        # browser's real authority there. Stale client-sent copies are
        # stripped above and only the launcher's own value survives.
        fwd = request.headers.get("host", "")
        if fwd:
            headers["x-forwarded-host"] = fwd
        req = self.client.build_request(
            request.method, self._url(request),
            headers=headers, content=request.stream())
        t0 = time.monotonic()
        self.active += 1
        try:
            resp = await self.client.send(req, stream=True)
        except Exception as exc:  # noqa: BLE001
            self.active -= 1
            log.warning("proxy %s %s UPSTREAM FAIL after %.1fs (active=%d): %r",
                        request.method, request.url.path,
                        time.monotonic() - t0, self.active, exc)
            return StreamingResponse(
                iter([(b'{"detail":"upstream unreachable"}')]),
                status_code=502,
                headers={"content-type": "application/json"})
        log.info("proxy %s %s -> %s t=%.2fs active=%d",
                 request.method, request.url.path, resp.status_code,
                 time.monotonic() - t0, self.active)

        out_headers = {k: v for k, v in resp.headers.items()
                       if k.lower() not in HOP_BY_HOP | {"content-length"}
                       }

        async def aiterate():
            nbytes = 0
            why = "eof"
            try:
                async for chunk in resp.aiter_raw():
                    nbytes += len(chunk)
                    yield chunk
            except (asyncio.CancelledError, GeneratorExit):
                # client went away mid-stream (tab closed / SPA route
                # change). Loud on purpose: silent here was the zombie-
                # connection leak that starved the httpx pool.
                why = "client-gone"
                raise
            except Exception as exc:  # noqa: BLE001
                why = f"upstream-error {exc!r}"
                raise
            finally:
                await resp.aclose()
                self.active -= 1
                if nbytes > 4096 or why != "eof" or time.monotonic() - t0 > 30:
                    log.info("proxy stream end %s: %s %dB %.1fs active=%d",
                             why, request.url.path, nbytes,
                             time.monotonic() - t0, self.active)

        return StreamingResponse(
            aiterate(), status_code=resp.status_code, headers=out_headers)

    async def handle_ws(self, ws: WebSocket) -> None:
        url = self._url_from_ws(ws)
        headers = {}
        if self.vhost:
            headers["Host"] = self.vhost
        fwd = ws.headers.get("host", "")
        if fwd:
            headers["X-Forwarded-Host"] = fwd
        cookie = ws.headers.get("cookie", "")
        if cookie:
            headers["Cookie"] = cookie
        # Subprotocol negotiation must survive the hop: if the client
        # requested one (and the app accepts it), Starlette has to echo it
        # in the 101, which means we cannot accept() until the upstream
        # handshake is through.
        requested = ws.scope.get("subprotocols") or []
        ws_kwargs: dict = {"headers": headers or None, "receive_timeout": None}
        if requested:
            if _HAS_PLAIN_PROTOCOLS:
                ws_kwargs["protocols"] = list(requested)
            else:  # aiohttp < 3.14
                from aiohttp.web import Subprotocol
                ws_kwargs["subprotocols"] = [Subprotocol(s) for s in requested]
        async with aiohttp.ClientSession() as session:
            try:
                remote = await session.ws_connect(url, **ws_kwargs)
            except Exception as exc:  # noqa: BLE001
                await ws.close(code=1011, reason=str(exc)[:80])
                return
            resp = getattr(remote, "_resp", None)  # private in some versions
            negotiated = (resp.headers.get("sec-websocket-protocol")
                          if resp is not None else None)
            await ws.accept(subprotocol=negotiated)
            t_ws = time.monotonic()
            log.info("ws bridge open %s", ws.url.path)

            # First-frames trace: the /api/events channel closing every
            # few seconds was the sessions page never leaving "loading";
            # who closes and what frames (if any) flow is the answer.
            traced = [0, 0]

            async def client_to_remote():
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        log.info("ws bridge: client closed %s code=%s",
                                 ws.url.path, msg.get("code"))
                        break
                    if msg.get("bytes") is not None:
                        if traced[0] < 5:
                            traced[0] += 1
                            log.info("ws C>S %s bin %dB", ws.url.path,
                                     len(msg["bytes"]))
                        await remote.send_bytes(msg["bytes"])
                    elif msg.get("text") is not None:
                        if traced[0] < 5:
                            traced[0] += 1
                            log.info("ws C>S %s txt %r", ws.url.path,
                                     msg["text"][:80])
                        await remote.send_str(msg["text"])

            async def remote_to_client():
                async for m in remote:
                    if m.type == aiohttp.WSMsgType.TEXT:
                        if traced[1] < 5:
                            traced[1] += 1
                            log.info("ws S>C %s txt %r", ws.url.path,
                                     m.data[:80])
                        await ws.send_text(m.data)
                    elif m.type == aiohttp.WSMsgType.BINARY:
                        if traced[1] < 5:
                            traced[1] += 1
                            log.info("ws S>C %s bin %dB", ws.url.path,
                                     len(m.data))
                        await ws.send_bytes(m.data)
                    elif m.type in (aiohttp.WSMsgType.PING,
                                    aiohttp.WSMsgType.PONG):
                        # Keepalive, answered at the aiohttp protocol layer
                        # (autoping). Killing the bridge here was the 1006
                        # "Reconnecting..." loop: hermes pings, we treated
                        # it as a disconnect.
                        continue
                    else:  # CLOSED / ERROR
                        log.info("ws bridge: upstream %s (%s)",
                                 getattr(m, "type", "?"),
                                 getattr(m, "data", ""))
                        break

            tasks = [asyncio.create_task(client_to_remote()),
                     asyncio.create_task(remote_to_client())]
            try:
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
            finally:
                log.info("ws bridge end %s after %.1fs",
                         ws.url.path, time.monotonic() - t_ws)
                await remote.close()
                try:
                    await ws.close()
                except Exception:  # noqa: BLE001
                    pass

    def _url_from_ws(self, ws: WebSocket) -> str:
        base = self.base
        if base.startswith("https://"):
            base = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            base = "ws://" + base[len("http://"):]
        path = ws.url.path.lstrip("/")
        url = f"{base}/{path}" if path else base
        if ws.url.query:
            url += "?" + ws.url.query
        return url
