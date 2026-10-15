#!/usr/bin/env python3
"""Extended shim regression: the frame-level behaviors keep-alive clients
(openai SDK / httpx) depend on, which test_shim_live's SSE case cannot see.

 1. single client connection, 3 sequential NON-STREAM (Content-Length)
    responses — the live "hung/slow reply" bug was exactly this path
    (upstream Content-Length stripped by _SKIP_RESP and never echoed, so
    a keep-alive client waited forever for an EOF that never came)
 2. a 403 (undrained request body!) mid-connection, then a GOOD request
    on the same connection — if _denied does not drain the body, the
    next request line parses as `{}POST /v1/...` -> 501
 3. 4 concurrent threads on separate connections (per-thread keep-alive
    pool + pinned-DNS connections)

Run from the repo root:  python tests/test_shim_ext.py
Requires tests/cert.pem + key.pem (minted by test_shim_live's ensure_cert;
we regenerate here too so this file is self-sufficient).
"""
import http.client
import http.server
import json
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

# Distinct from test_shim_live's 28643/28644 so the two suites can coexist.
UPSTREAM_PORT = 28651
SHIM_PORT = 28652


def ensure_cert():
    # Always mint: -days 1 certs go stale overnight (live test failure:
    # reusing a two-day-old cert made the shim reject with "expired").
    for p in (CERT, KEY):
        if os.path.exists(p):
            os.unlink(p)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", KEY, "-out", CERT, "-days", "1", "-subj", "/CN=localhost",
    ], check=True, capture_output=True)


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # keep-alive like the real API

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        payload = json.loads(body or b"{}")
        # Echo the auth headers the shim forwarded: the egress leg must
        # carry ONLY Authorization: Bearer <placeholder>, never the fake
        # key (x-api-key from Anthropic-protocol clients must not leak).
        out = json.dumps({"echo": payload,
                          "auth": self.headers.get("authorization"),
                          "xapikey": self.headers.get("x-api-key")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def main():
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    up = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    up.socket = ctx.wrap_socket(up.socket, server_side=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    env = {**os.environ, "OPNL_0": "openshell:resolve:env:OPNL_0",
           "SSL_CERT_FILE": CERT}   # dummy upstream is self-signed
    shim_log = open(os.path.join(HERE, "shim-ext.log"), "w")
    proc = subprocess.Popen(
        [sys.executable, SHIM,
         "--listen", f"127.0.0.1:{SHIM_PORT}",
         "--upstream", f"https://localhost:{UPSTREAM_PORT}/v1",
         "--inner-key", "fk", "--cred-env", "OPNL_0"],
        env=env, stderr=shim_log, stdout=shim_log)
    fails = []
    try:
        for _ in range(100):
            try:
                http.client.HTTPConnection(
                    "127.0.0.1", SHIM_PORT, timeout=2).request("GET", "/")
                break
            except OSError:
                time.sleep(0.1)
        else:
            print("shim never came up; log:\n" +
                  open(os.path.join(HERE, "shim-ext.log")).read())
            sys.exit(1)

        # 1. three sequential non-stream responses on ONE connection
        c = http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=10)
        for i in range(3):
            c.request("POST", "/v1/chat/completions",
                      body=json.dumps({"i": i}).encode(),
                      headers={"Authorization": "Bearer fk",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            d = r.read()
            if r.status != 200 or json.loads(d)["echo"].get("i") != i:
                fails.append(f"seq{i}: {r.status} {d!r}")

        # 2. denied request mid-connection, then a good one on the SAME
        #    connection (catches an undrained body in _denied)
        c.request("POST", "/v1/x", body=b"{}",
                  headers={"Authorization": "Bearer wrong"})
        r = c.getresponse()
        r.read()
        if r.status != 403:
            fails.append(f"denied: expected 403 got {r.status}")
        c.request("POST", "/v1/chat/completions", body=b'{"k":9}',
                  headers={"Authorization": "Bearer fk"})
        r = c.getresponse()
        d = r.read()
        if r.status != 200 or json.loads(d)["echo"].get("k") != 9:
            fails.append(f"post-403 reuse: {r.status} {d!r}")

        # 4. Anthropic-protocol inner leg: fake key in x-api-key (hermes'
        #    anthropic_messages sends x-api-key for non-anthropic.com
        #    base_urls). Must be accepted, must NOT be forwarded, and the
        #    egress credential must arrive as Authorization: Bearer <cred>.
        c4 = http.client.HTTPConnection("127.0.0.1", SHIM_PORT, timeout=10)
        c4.request("POST", "/v1/messages", body=json.dumps({"m": 1}).encode(),
                   headers={"x-api-key": "fk",
                            "Content-Type": "application/json"})
        r = c4.getresponse()
        d = json.loads(r.read())
        if r.status != 200 or d["echo"].get("m") != 1:
            fails.append(f"x-api-key accept: {r.status} {d!r}")
        if d.get("auth") != "Bearer openshell:resolve:env:OPNL_0":
            fails.append(f"x-api-key egress bearer: {d.get('auth')!r}")
        if d.get("xapikey") is not None:
            fails.append(f"fake x-api-key leaked upstream: {d!r}")
        c4.request("POST", "/v1/messages", body=b"{}",
                   headers={"x-api-key": "wrong"})
        r = c4.getresponse()
        r.read()
        if r.status != 403:
            fails.append(f"x-api-key wrong: expected 403 got {r.status}")
        c4.request("POST", "/v1/messages", body=b'{"k":3}',
                   headers={"Authorization": "Bearer fk"})
        r = c4.getresponse()
        d = r.read()
        if r.status != 200 or json.loads(d)["echo"].get("k") != 3:
            fails.append(f"post-xapikey-403 reuse: {r.status} {d!r}")

        # 3. concurrency: 4 threads, own connection each
        lock = threading.Lock()

        def worker(n):
            try:
                cc = http.client.HTTPConnection("127.0.0.1", SHIM_PORT,
                                                timeout=15)
                cc.request("POST", "/v1/chat/completions",
                           body=json.dumps({"t": n}).encode(),
                           headers={"Authorization": "Bearer fk"})
                rr = cc.getresponse()
                dd = rr.read()
                if rr.status != 200 or json.loads(dd)["echo"].get("t") != n:
                    raise AssertionError(f"thread{n}: {rr.status} {dd!r}")
            except Exception as exc:                       # noqa: BLE001
                with lock:
                    fails.append(f"thread{n}: {exc!r}")

        ts = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
    finally:
        # ALWAYS reap: an orphaned shim holding the port makes the next
        # run talk to the OLD process (Windows SO_REUSEADDR double-bind),
        # which once masqueraded as a certificate bug.
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if fails:
        print("FAIL")
        for f in fails:
            print(" -", f)
        sys.exit(1)
    print("shim ext test: all passed")


if __name__ == "__main__":
    main()
