#!/usr/bin/env python3
"""Fake-key acceptance + 403 diagnostics regression (the auth-mismatch
incident: a stale key persisted in the sandbox's ~/.hermes made every
turn 403 "invalid api key for this local endpoint" while webui's
self-heal kept re-serving it — the shim's own log was silent about WHY).

Cases (two shim processes on a plain-HTTP local upstream):
 1. correct key via Authorization: Bearer        -> 200
 2. correct key via x-api-key (anthropic client) -> 200
 3. wrong key / missing key                      -> 403
 4. every 403 appends a "403 key mismatch" line to the shim's stderr
    (redirected to a log file, mirroring the sandbox's /tmp/opn-shim-N.log)
    carrying bearer/x-api-key/expected FINGERPRINTS — and the presented
    key value must never appear in full in that log
 5. --inner-key any accepts anything (advertised by argparse, previously
    unimplemented — _check_key only ever did an equality compare)

Run from the repo root:  python tests/test_shim_keycheck.py
"""
import http.server
import json
import os
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHIM = os.path.join(ROOT, "sandbox", "shim", "shim.py")

# Distinct from the other suites (28643/4 live, 28651/2 ext).
UPSTREAM_PORT = 28661
SHIM_KEYED = 28662
SHIM_ANY = 28663
FAKE_KEY = "fk-keycheck-0123456789"
WRONG_KEY = "sk-REAL-looking-9876543210"   # stands in for an operator's
                                           # real key leaked via a client
                                           # settings page


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *a):  # noqa: A002 — match base signature
        pass


def call(port, headers):
    """GET through the shim; returns (status, error_body_str)."""
    req = Request(f"http://127.0.0.1:{port}/v1/models", headers=headers)
    try:
        with urlopen(req, timeout=10) as r:
            return r.status, ""
    except HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def read_log(path, needle, timeout=5.0):
    """Poll the shim's stderr log until `needle` appears (stderr is
    line-buffered, but the write races the HTTP response)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            txt = open(path, encoding="utf-8", errors="replace").read()
        except FileNotFoundError:
            txt = ""
        if needle in txt:
            return txt
        time.sleep(0.05)
    return open(path, encoding="utf-8", errors="replace").read() \
        if os.path.exists(path) else ""


def start_shim(port, inner_key, log_path):
    fh = open(log_path, "w")
    p = subprocess.Popen(
        [sys.executable, SHIM, "--listen", f"127.0.0.1:{port}",
         "--upstream", f"http://127.0.0.1:{UPSTREAM_PORT}/v1",
         "--inner-key", inner_key, "--cred-env", "OPN_TEST_CRED"],
        stdout=fh, stderr=fh)
    import socket
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        s = socket.socket()
        s.settimeout(0.3)
        ok = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
        if ok:
            return p
        time.sleep(0.1)
    p.kill()
    raise RuntimeError(f"shim #{port} never listened")


def main():
    failed = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failed.append(name)

    # The shim needs a real credential placeholder in env for the PROXY
    # path (403 fires before the cred check, but 200 cases need it).
    os.environ["OPN_TEST_CRED"] = "openshell:resolve:env:OPN_TEST_CRED"

    up = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT),
                                         Upstream)
    up.daemon_threads = True
    import threading
    threading.Thread(target=up.serve_forever, daemon=True).start()

    log_keyed = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                             "opn-shim-keycheck.log")
    log_any = log_keyed + ".any"
    a = start_shim(SHIM_KEYED, FAKE_KEY, log_keyed)
    b = start_shim(SHIM_ANY, "any", log_any)
    try:
        # 1/2 — the two legitimate presentations of the fake key
        check("correct Bearer accepted",
              call(SHIM_KEYED, {"Authorization": f"Bearer {FAKE_KEY}"})[0] == 200)
        check("correct x-api-key accepted (anthropic client)",
              call(SHIM_KEYED, {"x-api-key": FAKE_KEY})[0] == 200)

        # 3 — rejections
        s, body = call(SHIM_KEYED, {"Authorization": f"Bearer {WRONG_KEY}"})
        check("wrong Bearer -> 403 opn_shim",
              s == 403 and '"opn_shim"' in body)
        s, _ = call(SHIM_KEYED, {"x-api-key": WRONG_KEY})
        check("wrong x-api-key -> 403", s == 403)
        s, _ = call(SHIM_KEYED, {})
        check("missing key -> 403", s == 403)

        # 4 — diagnostics: fingerprint only, never the full presented key
        txt = read_log(log_keyed, "403 key mismatch")
        check("403 logged a key-mismatch line", "403 key mismatch" in txt)
        check("log carries fingerprints of presented + expected",
              f"{WRONG_KEY[:4]}(len {len(WRONG_KEY)})" in txt
              and f"{FAKE_KEY[:4]}(len {len(FAKE_KEY)})" in txt
              and "bearer=(absent)" in txt)
        check("log NEVER contains the full presented key",
              WRONG_KEY not in txt and FAKE_KEY not in txt)

        # 5 — 'any' sentinel (advertised by --inner-key help)
        check("inner-key=any: arbitrary key accepted",
              call(SHIM_ANY, {"Authorization": f"Bearer {WRONG_KEY}"})[0] == 200)
        check("inner-key=any: no header accepted",
              call(SHIM_ANY, {})[0] == 200)
        check("inner-key=any: correct key still accepted",
              call(SHIM_ANY, {"x-api-key": FAKE_KEY})[0] == 200)
    finally:
        for p in (a, b):
            p.terminate()
        up.shutdown()

    print()
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("all shim keycheck tests passed")


if __name__ == "__main__":
    main()
