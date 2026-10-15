#!/usr/bin/env python3
"""Live shim test: dummy HTTPS upstream + real shim process over loopback.

Verifies the three behaviors that matter:
 1. wrong inner key -> 403 (never touches upstream)
 2. correct inner key -> upstream sees the placeholder, NOT the fake key
 3. chunked/SSE response streams through

Run from the repo root:  python tests/test_shim_live.py
(Windows: run `bash` git shell with openssl available, or pre-place
 cert.pem/key.pem next to this file.)
"""
import http.client
import http.server
import os
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIM = os.path.join(ROOT, "sandbox", "shim", "shim.py")
CERT = os.path.join(HERE, "cert.pem")
KEY = os.path.join(HERE, "key.pem")

# Deliberately high ports: Windows/Docker-Desktop reserve dynamic ranges
# (netsh int ipv4 show excludedportrange) that can make low binds fail.
UPSTREAM_PORT = 28643
SHIM_PORT = 28644
FAKE_KEY = "fake key with spaces"     # must survive quoting
PLACEHOLDER = "openshell:resolve:env:OPNL_0"

SEEN = {}


def ensure_cert():
    # ALWAYS regenerate: the cert is issued with -days 1, and reusing a
    # checked-in/stale one fails the shim's TLS verify with
    # "certificate has expired" the day after it was minted.
    for p in (CERT, KEY):
        if os.path.exists(p):
            os.unlink(p)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", KEY, "-out", CERT, "-days", "1", "-subj", "/CN=localhost",
    ], check=True, capture_output=True)


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        SEEN["auth"] = self.headers.get("Authorization", "")
        SEEN["path"] = self.path
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        SEEN["body"] = body
        # No Content-Length, no manual chunking: HTTP/1.0 close-on-EOF
        # semantics. The shim must detect the unknown length and re-frame
        # the stream to its client as proper chunks (SSE-style increments).
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: chunk{i}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.15)

    def log_message(self, *a):
        pass


def main():
    print(f"upstream :{UPSTREAM_PORT}, shim :{SHIM_PORT}", flush=True)
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    up = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    up.socket = ctx.wrap_socket(up.socket, server_side=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    env = {**os.environ, "OPNL_0": PLACEHOLDER, "SSL_CERT_FILE": CERT}
    shim_log = open(os.path.join(HERE, "shim-live.log"), "w")
    proc = subprocess.Popen(
        [sys.executable, SHIM,
         "--listen", f"127.0.0.1:{SHIM_PORT}",
         "--upstream", f"https://localhost:{UPSTREAM_PORT}/v1",
         "--inner-key", FAKE_KEY,
         "--cred-env", "OPNL_0"],
        env=env, stderr=shim_log, stdout=shim_log)
    try:
        up_ok = False
        for _ in range(100):
            try:
                http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=2).request("GET", "/")
                up_ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not up_ok:
            shim_log.flush()
            print("shim never came up; shim log:")
            print(open(os.path.join(HERE, "shim-live.log")).read())
            sys.exit(1)

        fails = []

        # 1. wrong key -> 403
        c = http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=5)
        c.request("POST", "/v1/chat/completions",
                  headers={"Authorization": "Bearer wrong"}, body=b"{}")
        r = c.getresponse(); r.read()
        if r.status != 403:
            fails.append(f"wrong key expected 403 got {r.status}")

        # 2. correct key (with spaces) -> upstream sees placeholder
        c = http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=5)
        c.request("POST", "/v1/chat/completions",
                  headers={"Authorization": f"Bearer {FAKE_KEY}",
                           "Content-Type": "application/json"},
                  body=b'{"ping":1}')
        r = c.getresponse()
        body = b""
        while True:
            blk = r.read(4096)
            if not blk:
                break
            body += blk
        if SEEN.get("auth") != f"Bearer {PLACEHOLDER}":
            fails.append(f"upstream saw auth={SEEN.get('auth')!r}")
        if SEEN.get("path") != "/v1/chat/completions":
            fails.append(f"upstream saw path={SEEN.get('path')!r}")
        if b"chunk0" not in body or b"chunk2" not in body:
            fails.append(f"stream body wrong: {body!r}")
        # 3. path without prefix should also mount /v1 once
        c = http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=5)
        c.request("POST", "/chat/completions",
                  headers={"Authorization": f"Bearer {FAKE_KEY}",
                           "Content-Length": "0"})
        r = c.getresponse(); r.read()
        if SEEN.get("path") != "/v1/chat/completions":
            fails.append(f"prefix remount wrong: {SEEN.get('path')!r}")

        if fails:
            print("FAIL")
            for f in fails:
                print(" -", f)
            sys.exit(1)
        print("shim live test: all passed")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
