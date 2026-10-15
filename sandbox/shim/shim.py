#!/usr/bin/env python3
"""opn-shim: loopback LLM reverse proxy inside the OpenShell sandbox.

For each entry in "LLM_Porting_Map.json" the launcher starts one shim:

    python3 shim.py --listen 127.0.0.1:18001 \
                    --upstream https://api.openai.com/v1 \
                    --inner-key fake-key-local-0 \
                    --cred-env OPNL_0

Agents inside the sandbox are configured with
    OPENAI_BASE_URL = http://127.0.0.1:18001/v1
    OPENAI_API_KEY  = fake-key-local-0          (the *fake* key)

The shim verifies the fake key — presented either as
``Authorization: Bearer <fake>`` (OpenAI-protocol clients, hermes
chat_completions) or as ``x-api-key: <fake>`` (Anthropic-protocol clients:
hermes' anthropic_messages transport sends x-api-key for any non-
anthropic.com base_url) — then rewrites the Authorization header to
the OpenShell credential placeholder that OpenShell injects into the
environment variable named by --cred-env. The OpenShell supervisor replaces
the placeholder with the real API key only at the profile-approved upstream
endpoint, so the real key never exists inside the sandbox.

Streaming (SSE / chunked) responses are passed through block by block.
Standard library only — no pip install needed inside the sandbox.
"""

import argparse
import base64
import http.client
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# Hop-by-hop / connection-managed headers we must not copy verbatim.
# "x-api-key": Anthropic-protocol clients authenticate to US with it; it is
# the client's proof of the fake key, never forwarded upstream (the egress
# credential carrier is the single Authorization: Bearer <placeholder>).
_SKIP_REQ = {"host", "authorization", "x-api-key", "connection", "keep-alive",
             "proxy-authenticate", "proxy-authorization", "te", "trailers",
             "transfer-encoding", "upgrade", "content-length"}
_SKIP_RESP = {"connection", "keep-alive", "proxy-authenticate",
              "proxy-authorization", "te", "trailers", "transfer-encoding",
              "upgrade", "content-length", "content-encoding"}

CHUNK = 16384


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pre-resolved IP but keeps TLS SNI and
    certificate verification bound to the real hostname (self.host).

    Why: under the OpenShell network supervisor, every fresh
    getaddrinfo can stall for tens of seconds (resolver/AAAA retry
    cascades through the intercepted DNS path), and the openai SDK's
    httpx pool drops idle connections after ~5 s — so without a DNS
    cache every chat turn pays that stall again."""

    def __init__(self, ip, host, port, ctx, timeout):
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class Shim:
    def __init__(self, upstream, inner_key, cred_env):
        parts = urlsplit(upstream)
        if parts.scheme not in ("https", "http"):
            raise SystemExit(f"opn-shim: upstream must be http(s): {upstream}")
        self.secure = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.secure else 80)
        self.prefix = parts.path.rstrip("/")          # e.g. "/v1"
        self.inner_key = inner_key
        self.cred_env = cred_env
        # Plain http upstream is allowed (self-hosted/inference servers) but
        # the supervisor injects the REAL key at egress, so that leg is
        # cleartext — config.load_config() warns about this.
        self.ctx = ssl.create_default_context() if self.secure else None
        # Optional custom CA bundle (corporate TLS-terminating proxies,
        # test rigs). Standard OpenSSL env var; honored on all platforms.
        ca = os.environ.get("OPN_SHIM_CA") or os.environ.get("SSL_CERT_FILE")
        if self.secure and ca and os.path.exists(ca):
            self.ctx.load_verify_locations(cafile=ca)
        # Per-thread keep-alive connection. One hermes turn fires several
        # sequential calls (chat, title-gen, tool follow-ups); a fresh
        # TCP+TLS handshake per call adds RTTs to every one of them.
        # threading.local keeps this lock-free; a connection that ever
        # raised is dropped, never reused.
        self._local = threading.local()
        # Resolved-IP cache (see _PinnedHTTPSConnection): one getaddrinfo
        # per TTL instead of one per connection. Lock only on refetch.
        self._dns_lock = threading.Lock()
        self._dns_ip = None
        self._dns_at = 0.0

    DNS_TTL = 300.0

    def resolve(self):
        now = time.monotonic()
        with self._dns_lock:
            if self._dns_ip and now - self._dns_at < self.DNS_TTL:
                return self._dns_ip
            try:
                infos = socket.getaddrinfo(self.host, self.port,
                                           0, socket.SOCK_STREAM)
            except OSError:
                if self._dns_ip:          # stale beats dead
                    return self._dns_ip
                raise
            ip = next((sa[0] for fam, _, _, _, sa in infos
                       if fam == socket.AF_INET), infos[0][4][0])
            self._dns_ip, self._dns_at = ip, now
            return ip

    def invalidate_dns(self):
        # A connect error may mean the CDN rotated IPs; force a refetch
        # on the next connection rather than retrying a dead address.
        with self._dns_lock:
            self._dns_at = 0.0

    def _new_conn(self):
        ip = self.resolve()
        if self.secure:
            return _PinnedHTTPSConnection(
                ip, self.host, self.port, self.ctx, 600)
        # Host header is set explicitly in _proxy, so dialing by IP is
        # still protocol-correct on the plain-http leg.
        return http.client.HTTPConnection(ip, self.port, timeout=600)

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._new_conn()
            self._local.conn = c
        return c

    def drop_conn(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            except OSError:
                pass
            self._local.conn = None
            self.invalidate_dns()

    def credential(self):
        # OpenShell replaces the provider's env var value with an opaque
        # placeholder token at process start. Never log this value.
        return os.environ.get(self.cred_env, "")


class Handler(BaseHTTPRequestHandler):
    shim: Shim  # assigned in main() — one shim per process
    protocol_version = "HTTP/1.1"
    # SSE frames arrive in small writes; Nagle + delayed-ACK interaction
    # adds up to ~40 ms per chunk of perceived token lag.
    disable_nagle_algorithm = True

    def log_message(self, fmt, *args):  # keep sandbox logs quiet
        sys.stderr.write("opn-shim: %s\n" % (fmt % args))

    # -- helpers ----------------------------------------------------------
    def _denied(self, code, msg):
        # Drain any unread request body first: under our HTTP/1.1
        # keep-alive, bytes left in the socket buffer get parsed as the
        # NEXT request line (live test: an early 403 poisoned the
        # connection — next request line read "{}POST /v1/x..." -> 501).
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > 8 << 20:
            self.close_connection = True   # too big to eat; drop the conn
        else:
            while n > 0:
                blk = self.rfile.read(min(n, 65536))
                if not blk:
                    break
                n -= len(blk)
        body = json.dumps({"error": {"message": msg, "type": "opn_shim"}}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_key(self):
        auth = self.headers.get("Authorization", "")
        bearer = auth.removeprefix("Bearer ").removeprefix("bearer ")
        if bearer and bearer == self.shim.inner_key:
            return True
        # Anthropic-protocol clients (hermes anthropic_messages, claude-code
        # with ANTHROPIC_API_KEY) present the fake key in x-api-key instead.
        return self.headers.get("x-api-key", "") == self.shim.inner_key

    def _proxy(self, method):
        if not self._check_key():
            return self._denied(403, "invalid api key for this local endpoint")
        cred = self.shim.credential()
        if not cred:
            return self._denied(
                503,
                f"credential placeholder missing in env {self.shim.cred_env}; "
                "is the provider attached to this sandbox?",
            )

        # Local path -> upstream path. Agents usually point OPENAI_BASE_URL
        # at the shim including the upstream prefix (e.g. .../v1), in which
        # case the request path arrives as /v1/chat/completions; strip the
        # duplicated prefix if present, then re-add it once.
        path = self.path
        prefix = self.shim.prefix
        if prefix and path.startswith(prefix + "/") or path == prefix:
            rel = path[len(prefix):]
        else:
            rel = path
        target = (prefix + rel) or "/"

        t0 = time.monotonic()
        try:
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in _SKIP_REQ}
            headers["Host"] = self.shim.host
            headers["Authorization"] = f"Bearer {cred}"
            # Keep the placeholder in a Content-Type-sibling header too? No:
            # exactly one credential carrier (the supervisor swaps Bearer).
            length = self.headers.get("Content-Length")
            body = self.rfile.read(int(length)) if length else None
            # Large/streaming request bodies are not expected from LLM
            # clients; refuse rather than buffer silently.

            # Per-thread keep-alive upstream connection. A stale idle
            # connection (peer timed it out) shows up as the request dying
            # before ANY response byte — safe to reconnect and resend once
            # (body is buffered above); anything else poisons the slot.
            attempt = 0
            while True:
                conn = self.shim.conn()
                try:
                    conn.request(method, target, body=body, headers=headers)
                    resp = conn.getresponse()
                    break
                except (OSError, http.client.HTTPException) as exc:
                    self.shim.drop_conn()
                    if attempt == 0 and isinstance(
                            exc, (http.client.BadStatusLine,
                                  http.client.RemoteDisconnected)):
                        attempt += 1
                        continue
                    raise
            ttfb = time.monotonic() - t0

            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() in _SKIP_RESP:
                    continue
                self.send_header(k, v)

            # We always strip upstream Transfer-Encoding and re-frame from
            # the DECODED body http.client gives us: any response without a
            # Content-Length becomes chunked on our side, terminated below.
            # Without this, SSE clients would never see end-of-body.
            #
            # LIVE-BUG: _SKIP_RESP drops the upstream Content-Length for
            # re-framing — it MUST be echoed back on the has_len branch,
            # or a keep-alive client (openai SDK / httpx) waits forever
            # for an EOF that never comes: the non-streaming response
            # looks "hung/slow". (Early tests passed only because urllib
            # sends Connection: close, so EOF accidentally framed it.)
            has_len = resp.headers.get("Content-Length")
            if has_len is not None:
                self.send_header("Content-Length", has_len)
                self.end_headers()
                write = self.wfile.write                  # noqa: E731
            else:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                write = lambda b: self.wfile.write(       # noqa: E731
                    b"%X\r\n" % len(b) + b + b"\r\n")

            while True:
                block = resp.read(CHUNK)                  # per-SSE-event yields
                if not block:
                    break
                write(block)
                self.wfile.flush()
            if not has_len:
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            # Only a fully drained, keep-alive-worthy connection goes back
            # into the thread's slot.
            if getattr(resp, "will_close", True):
                self.shim.drop_conn()
            # Wall-clock stamp so log lines can be correlated with the
            # moment the user pressed Enter (bisect webui-side stall vs
            # shim/upstream stall).
            self.log_message("%s %s %s -> %s ttfb=%.2fs total=%.2fs",
                             time.strftime("%H:%M:%S"),
                             method, self.path.split("?")[0], resp.status,
                             ttfb, time.monotonic() - t0)
        except (OSError, http.client.HTTPException) as exc:
            # Client may have disconnected mid-stream; that is normal.
            self.shim.drop_conn()
            self.log_message("upstream error on %s: %s", self.path, exc)
            try:
                self._denied(502, f"upstream error: {exc}")
            except OSError:
                pass

    # -- verbs -------------------------------------------------------------
    def do_GET(self):    self._proxy("GET")
    def do_POST(self):   self._proxy("POST")
    def do_PATCH(self):  self._proxy("PATCH")
    def do_PUT(self):    self._proxy("PUT")
    def do_DELETE(self): self._proxy("DELETE")
    def do_HEAD(self):   self._proxy("HEAD")

    def do_OPTIONS(self):
        # CORS preflight answered locally; upstream is not involved.
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                         "Authorization, Content-Type, Stripe-Billing-Origin")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", required=True, help="127.0.0.1:PORT")
    ap.add_argument("--upstream", required=True, help="https://host/prefix")
    ap.add_argument("--inner-key", required=True,
                    help="fake key clients must present (or 'any')")
    ap.add_argument("--cred-env", required=True,
                    help="env var holding the OpenShell placeholder token")
    ap.add_argument("--spec-b64", help=argparse.SUPPRESS)  # unused, reserved
    a = ap.parse_args()

    host, _, port = a.listen.rpartition(":")
    shim = Shim(a.upstream, a.inner_key, a.cred_env)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = Server((host or "127.0.0.1", int(port)), Handler)
    Handler.shim = shim
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(
        target=srv.shutdown).start())
    sys.stderr.write(
        f"opn-shim: listening {a.listen} -> {a.upstream} "
        f"(cred env {a.cred_env} = "
        f"{'set' if shim.credential() else 'EMPTY'})\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
