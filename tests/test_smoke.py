#!/usr/bin/env python3
"""Offline smoke tests for the OpnAgent launcher modules (no Docker needed).

Run from the repo root:  python tests/test_smoke.py
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "launcher"))
os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

from app import (adminui, auth, config, hermesfs, policy, providers,  # noqa: E402
                 reload as hotreload)

FAILED = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        FAILED.append(name)


def main():
    cfg = config.load_config()

    # --- config -----------------------------------------------------------
    check("llm entries parsed", len(cfg.llm_map) == 2)
    e0 = cfg.llm_map[0]
    check("host/port/path", (e0.host, e0.port, e0.path_prefix) ==
          ("api.openai-compatible.com", 443, "/v1"))
    check("bare second entry has empty path", cfg.llm_map[1].path_prefix == "")
    check("cred env naming", e0.cred_env == "OPNL_0" and
          cfg.llm_map[1].cred_env == "OPNL_1")

    # duplicate inner-port must be rejected
    import json, tempfile
    bad = {"https://a.com": {"key": "k", "inner-port": 18001, "inner-key": "f"},
           "https://b.com": {"key": "k", "inner-port": 18001, "inner-key": "g"}}
    d = tempfile.mkdtemp()
    with open(os.path.join(d, config.F_LLM_MAP), "w") as fh:
        json.dump(bad, fh)
    for opt in (config.F_URL_WL, config.F_URL_BL, config.F_PKG_WL,
                config.F_PKG_BL, config.F_USERS):
        try:
            with open(os.path.join(os.environ["OPN_CONFIG_DIR"], opt), "rb") as s, \
                 open(os.path.join(d, opt), "wb") as t:
                t.write(s.read())
        except FileNotFoundError:
            pass
    os.environ["OPN_CONFIG_DIR"] = d
    try:
        config.load_config()
        check("duplicate inner-port rejected", False)
    except config.ConfigError:
        check("duplicate inner-port rejected", True)
    os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    # --- providers --------------------------------------------------------
    p = providers.profile_yaml(e0)
    check("profile has env var", "OPNL_0" in p)
    check("profile paths", "/v1/**" in p and "/v1" in p)
    check("profile binaries", policy.BIN_PY_PATH in p)
    check("profile bearer", "auth_style: bearer" in p)

    # --- policy ------------------------------------------------------------
    y = policy.policy_yaml(cfg)
    check("policy version", "version: 1" in y)
    check("pypi hosts", "pypi.org" in y and "files.pythonhosted.org" in y)
    check("packages glob", "/packages/**" in y)
    # sample lists disabled -> no /simple path rules, no deny
    check("lists disabled = open pypi simple", "/simple/" not in y)
    # schema: a rest endpoint needs access OR rules, and access is only
    # valid when there are no rules ("cannot be combined")
    check("default mode uses access preset", "access: read-only" in y)

    # whitelist pkg mode
    cfg2 = config.load_config()
    cfg2.pkg_wl.enabled = True
    cfg2.pkg_wl.items = ["requests"]
    y2 = policy.policy_yaml(cfg2)
    check("pkg wl /simple path", "/simple/requests/**" in y2)
    check("pkg wl drops access", "access" not in y2)

    # whitelist+blacklist combined: deny_rules sit on top of allow rules
    cfg2b = config.load_config()
    cfg2b.pkg_wl.enabled = True
    cfg2b.pkg_wl.items = ["requests"]
    cfg2b.pkg_bl.enabled = True
    cfg2b.pkg_bl.items = ["requests"]
    y2b = policy.policy_yaml(cfg2b)
    check("wl+bl keeps both rule kinds",
          "deny_rules" in y2b and "/simple/requests/**" in y2b)

    # empty enabled whitelist -> sentinel, still valid (no access+rules clash)
    cfg2c = config.load_config()
    cfg2c.pkg_wl.enabled = True
    cfg2c.pkg_wl.items = []
    y2c = policy.policy_yaml(cfg2c)
    check("empty wl uses sentinel", "__opn_no_packages__" in y2c
          and "access" not in y2c)

    # blacklist pkg mode
    cfg3 = config.load_config()
    cfg3.pkg_bl.enabled = True
    cfg3.pkg_bl.items = ["cryptominer"]
    y3 = policy.policy_yaml(cfg3)
    check("pkg bl deny_rules", "deny_rules" in y3 and "/simple/cryptominer/**" in y3)

    # url white+black trimming
    cfg4 = config.load_config()
    cfg4.url_wl.enabled = True
    cfg4.url_wl.items = ["ok.example.com", "evil.example.com"]
    cfg4.url_bl.enabled = True
    cfg4.url_bl.items = ["evil.example.com"]
    y4 = policy.policy_yaml(cfg4)
    check("url wl includes ok", "ok.example.com" in y4)
    check("blacklist trims white", "evil.example.com" not in y4)

    # alias-bomb regression: PyYAML anchors shared collection objects and
    # the deployed OpenShell parser REJECTS aliased policy docs
    # ("alias_anchor_ratio heuristic tripped: 11 aliases / 2 anchors > 5"
    # — live on a box with ~11 whitelist hosts; shared BIN_PY/URL_BINARIES
    # were the cause). Many-host policies must serialize alias-free.
    cfg4b = config.load_config()
    cfg4b.url_wl.enabled = True
    cfg4b.url_wl.items = [f"h{i:02d}.example.com" for i in range(12)]
    y4b = policy.policy_yaml(cfg4b)
    check("many-host policy is anchor/alias-free",
          "&id" not in y4b and "*id" not in y4b
          and y4b.count("url-allow-") == 12
          and y4b.count(policy.BIN_PY_PATH) >= 12)

    # --- auth ---------------------------------------------------------------
    t = auth.make_token("admin")
    check("session roundtrip", auth.verify_token(t) == "admin")
    check("tampered rejected", auth.verify_token(t[:-4] + "ffff") is None)
    check("plaintext passkey ok",
          auth.check_credentials(cfg, "admin", "change-me"))
    check("wrong passkey rejected",
          not auth.check_credentials(cfg, "admin", "nope"))
    cfg5 = config.load_config()
    cfg5.users[0].passkey = hashlib.sha256(b"s3cret").hexdigest()
    check("sha256 passkey ok", auth.check_credentials(cfg5, "admin", "s3cret"))
    check("unknown user rejected",
          not auth.check_credentials(cfg, "ghost", "change-me"))

    # --- shim import + auth logic (no sockets) ------------------------------
    sys.path.insert(0, os.path.join(ROOT, "sandbox", "shim"))
    import shim as shimmod
    s = shimmod.Shim("https://api.openai.com/v1", "fk", "OPNL_0")
    check("shim upstream parse", s.host == "api.openai.com" and s.prefix == "/v1")
    sh = shimmod.Shim("http://114.33.193.52/v1", "fk", "OPNL_0")
    check("shim http upstream ok", sh.secure is False and sh.port == 80
          and sh.ctx is None)
    try:
        shimmod.Shim("ftp://nope.example/v1", "fk", "OPNL_0")
        check("shim rejects non-http scheme", False)
    except SystemExit:
        check("shim rejects non-http scheme", True)

    # http LLM map entry: accepted, port defaults to 80, warning recorded
    d2 = tempfile.mkdtemp()
    with open(os.path.join(d2, config.F_LLM_MAP), "w") as fh:
        json.dump({"http://114.33.193.52/v1":
                   {"key": "k", "inner-port": 18101, "inner-key": "f"}}, fh)
    os.environ["OPN_CONFIG_DIR"] = d2
    cfg6 = config.load_config()
    os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")
    check("http entry parsed", len(cfg6.llm_map) == 1
          and cfg6.llm_map[0].port == 80 and not cfg6.llm_map[0].secure)
    check("http entry warns", any("plain http" in w for w in cfg6.warnings))

    # --- listen.json (entry point bind) --------------------------------------
    check("listen default loopback",
          (cfg.listen_host, cfg.listen_port) == ("127.0.0.1", 8000))

    def _listen_cfg(listen_value, users_enabled=True):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w") as fh:
            json.dump({"https://a.com/v1":
                       {"key": "k", "inner-port": 18001, "inner-key": "f"}}, fh)
        with open(os.path.join(dd, config.F_USERS), "w") as fh:
            json.dump({"enabled": users_enabled,
                       "user-list": [{"username": "a", "passkey": "b"}]}, fh)
        if listen_value is not None:
            with open(os.path.join(dd, config.F_LISTEN), "w") as fh:
                json.dump({"listen_url": listen_value}, fh)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    c = _listen_cfg("0.0.0.0:8000")
    check("listen 0.0.0.0 parsed", (c.listen_host, c.listen_port) == ("0.0.0.0", 8000))
    check("listen public warns", any("cleartext" in w for w in c.warnings))
    c = _listen_cfg("http://192.168.1.50")
    check("listen scheme+default port",
          (c.listen_host, c.listen_port) == ("192.168.1.50", 8000))
    c = _listen_cfg(None, users_enabled=True)
    check("listen absent -> loopback",
          (c.listen_host, c.listen_port) == ("127.0.0.1", 8000))
    try:
        _listen_cfg("0.0.0.0:99999")
        check("listen bad port rejected", False)
    except config.ConfigError:
        check("listen bad port rejected", True)
    try:
        _listen_cfg("0.0.0.0:8000", users_enabled=False)
        check("public bind needs login", False)
    except config.ConfigError:
        check("public bind needs login", True)

    # --- hot list reload -----------------------------------------------------
    # gateway-stored base policy: fs section is enriched at sandbox start
    # (bigger than build_policy's), reload must keep it byte-for-byte and
    # only swap network_policies.
    base = {"version": 1,
            "filesystem_policy": {"include_workdir": True,
                                  "read_only": ["/usr", "/lib", "/etc"],
                                  "read_write": ["/home/opn", "/tmp"]},
            "some_future_key": {"kept": True}}
    cfg7 = config.load_config()
    cfg7.url_wl.enabled = True
    cfg7.url_wl.items = ["hot.example.com"]
    m = hotreload.merge_network(base, cfg7)
    check("merge swaps network",
          "hot.example.com" in str(m["network_policies"]))
    check("merge keeps version", m["version"] == 1)
    check("merge keeps fs section",
          m["filesystem_policy"] == base["filesystem_policy"])
    check("merge keeps unknown keys",
          m.get("some_future_key") == {"kept": True})
    check("merge leaves input base untouched",
          "network_policies" not in base)

    fp = hotreload.guard_fingerprint(cfg)
    c = config.load_config()
    c.url_wl.enabled = True
    c.url_wl.items = ["new.example.com"]
    c.pkg_bl.enabled = True
    c.pkg_bl.items = ["evilpkg"]
    check("fingerprint ignores lists",
          hotreload.guard_fingerprint(c) == fp)
    c = config.load_config()
    c.llm_map[0].model = "other-model"
    check("fingerprint sees llm map",
          hotreload.guard_fingerprint(c) != fp)
    c = config.load_config()
    c.llm_map[0].context_length = 131072  # feeds config.yaml -> restart-only
    check("fingerprint sees context_length",
          hotreload.guard_fingerprint(c) != fp)
    c = config.load_config()
    c.users[0].passkey = "rotated"
    check("fingerprint sees users",
          hotreload.guard_fingerprint(c) != fp)
    c = config.load_config()
    c.listen_port = 8001
    check("fingerprint sees listen",
          hotreload.guard_fingerprint(c) != fp)

    # --- users.json roles + console user management --------------------------
    def _users_cfg(user_list, enabled=True):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w") as fh:
            json.dump({"https://a.com/v1":
                       {"key": "k", "inner-port": 18001, "inner-key": "f"}}, fh)
        with open(os.path.join(dd, config.F_USERS), "w") as fh:
            json.dump({"enabled": enabled, "user-list": user_list}, fh)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    c = _users_cfg([{"username": "a", "passkey": "b"}])
    check("role default admin", c.users[0].role == "admin")
    c = _users_cfg([{"username": "a", "passkey": "b", "role": "user"}])
    check("role user parsed", c.users[0].role == "user")
    try:
        _users_cfg([{"username": "a", "passkey": "b", "role": "root"}])
        check("bad role rejected", False)
    except config.ConfigError:
        check("bad role rejected", True)
    try:
        _users_cfg([{"username": "a", "passkey": "b"},
                    {"username": "a", "passkey": "c"}])
        check("duplicate username rejected", False)
    except config.ConfigError:
        check("duplicate username rejected", True)
    c = _users_cfg([{"username": "a", "passkey": "b", "role": "user"}])
    check("no-admin warns", any("no account has role" in w for w in c.warnings))

    # auth role lookup
    c = _users_cfg([{"username": "a", "passkey": "b"},
                    {"username": "u1", "passkey": "p", "role": "user"}])
    check("role_for admin", auth.role_for(c, "a") == "admin")
    check("role_for user", auth.role_for(c, "u1") == "user")
    check("role_for gone", auth.role_for(c, "ghost") is None)

    # pure user-management ops over UserEntry lists
    base_u = [config.UserEntry(username="boss", passkey="x", role="admin")]
    out = adminui.user_add(base_u, "newbie", "pw")
    check("user_add appends role user",
          len(out) == 2 and out[1].role == "user")
    try:
        adminui.user_add(out, "newbie", "pw2")
        check("user_add dup rejected", False)
    except ValueError:
        check("user_add dup rejected", True)
    out2 = adminui.user_set_passkey(out, "boss", "y")
    boss = [u for u in out2 if u.username == "boss"][0]
    check("set_passkey keeps role", boss.role == "admin")
    check("set_passkey changes key", boss.passkey == "y")
    try:
        adminui.user_remove(out2, "boss")
        check("last admin protected", False)
    except ValueError:
        check("last admin protected", True)
    check("plain user removable",
          len(adminui.user_remove(out2, "newbie")) == 1)
    pl = adminui.users_payload(out2, True)
    check("payload keeps role+enabled",
          pl["enabled"] is True and
          {e["username"]: e["role"] for e in pl["user-list"]} ==
          {"boss": "admin", "newbie": "user"})

    # list-file validator (what POST /admin/lists runs before writing)
    def _rejects(name, text):
        try:
            adminui.validate_list_text(name, text)
            return False
        except ValueError:
            return True

    check("validate url wl ok", not _rejects(
        config.F_URL_WL, json.dumps({"enabled": True, "list": ["a.example.com"]})))
    check("validate bad host", _rejects(
        config.F_URL_WL, json.dumps({"enabled": True, "list": ["a;rm -rf"]})))
    check("validate bad json", _rejects(config.F_URL_WL, "{oops"))
    check("validate non-dict", _rejects(config.F_URL_WL, "[1,2]"))
    check("validate url wl host:port ok", not _rejects(
        config.F_URL_WL, json.dumps({"enabled": True,
                                     "list": ["10.0.0.5:22"]})))
    check("validate url wl bad port rejected", _rejects(
        config.F_URL_WL, json.dumps({"enabled": True,
                                     "list": ["10.0.0.5:99999"]})))
    check("validate url bl still host-only", _rejects(
        config.F_URL_BL, json.dumps({"enabled": True,
                                     "list": ["a.example.com:22"]})))
    check("validate bad pkg", _rejects(
        config.F_PKG_WL, json.dumps({"enabled": True, "list": ["bad pkg!"]})))
    check("validate unknown file", _rejects(config.F_LLM_MAP, "{}"))

    # --- hermes file browser (pure: path guard, scripts, exec parsing) ----
    def _path_rejects(p):
        try:
            hermesfs.normalize_rel(p)
            return False
        except ValueError:
            return True

    def _raises_path(fn, p):
        try:
            fn(p)
            return False
        except ValueError:
            return True

    check("hrel root", hermesfs.normalize_rel("") == ""
          and hermesfs.normalize_rel("/") == "")
    check("hrel cleans slashes/dots",
          hermesfs.normalize_rel("/a//b/") == "a/b")
    check("hrel dotdot rejected",
          _path_rejects("a/../..") and _path_rejects("..")
          and _path_rejects("a/./b") and _path_rejects("a//") is False)
    check("hrel traversal words ok (not segments)",
          hermesfs.normalize_rel("notes/..readme") == "notes/..readme")
    for badp in ('a"b', "a'b", "a`b", "a$b", "a\\b", "a\nb", "a\x00b"):
        check(f"hrel rejects {badp!r}", _path_rejects(badp))
    check("hrel spaces+cjk+dotfiles ok",
          hermesfs.normalize_rel(".hermes/sessions/我的 對話 1")
          == ".hermes/sessions/我的 對話 1")
    ls = hermesfs.script_ls('a b/.hermes')
    # bare code for `-- python3 -c <body>`; a bundled "python3 -c '...'"
    # wrapper made the CLI quote the whole line as one command word (rc=127)
    check("ls script is bare python", not ls.startswith("python3")
          and ls.lstrip().startswith("import os,json"))
    check("ls script carries rel+sentinel",
          'rel="a b/.hermes"' in ls and hermesfs.SENTINEL in ls)
    check("mkdir empty rejected", _raises_path(hermesfs.script_mkdir, ""))
    check("delete home rejected", _raises_path(hermesfs.script_delete, ""))
    check("delete script recursive for dirs", "rmtree" in hermesfs.script_delete("x"))

    def _zip(p="a b/我的", stamp="20261011-120000", cap=123):
        return hermesfs.script_zip_dir(p, stamp, cap)

    check("zip home rejected", _raises_path(
        lambda p: _zip(p=p), ""))
    check("zip staging dir rejected", _raises_path(
        lambda p: _zip(p=p), hermesfs.DOWNLOADS_DIR))
    check("zip bad stamp rejected", _raises_path(
        lambda s: _zip(stamp=s), "2026-10-11"))
    check("zip bad stamp rejected 2", _raises_path(
        lambda s: _zip(stamp=s), '2026"x"-120000'))
    zd = _zip()
    check("zip script is bare python", not zd.startswith("python3")
          and zd.lstrip().startswith("import os,json")
          and "import time,zipfile,fnmatch" in zd)
    check("zip script carries rel/stamp/sentinel",
          'rel="a b/我的"' in zd and "20261011-120000" in zd
          and hermesfs.SENTINEL in zd and "ZipFile" in zd)
    check("zip script sweeps stale, caps size, stages in DLDIR",
          str(hermesfs.STALE_SECONDS) in zd
          and '"' + hermesfs.DOWNLOADS_DIR + '"' in zd and "123" in zd)
    check("zip exclude patterns validated (quoting-safe, relative)",
          _raises_path(lambda p: hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=[p]), "a;b")
          and _raises_path(lambda p: hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=[p]), "a$b")
          and _raises_path(lambda p: hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=[p]), 'a"b')
          and _raises_path(lambda p: hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=[p]), "../x")
          and _raises_path(lambda p: hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=[p]), "/abs")
          and "profiles/*/cache" in hermesfs.script_zip_dir(
              "x", "20261011-120000", 10, exclude=["profiles/*/cache"]))
    try:
        compile(zd, "<zip>", "exec")
        check("zip script compiles", True)
    except SyntaxError as exc:
        check(f"zip script compiles: {exc}", False)

    # chunked range reads (the transfer primitive: sandbox download is
    # dead in this deployment — bytes ride the exec channel)
    rr = hermesfs.script_read_range("a b/f.bin", 1048576, 2097152)
    check("range script is bare python", not rr.startswith("python3")
          and rr.lstrip().startswith("import os,json") and "base64" in rr)
    check("range script inlines ints+rel", "fh.seek(1048576)" in rr
          and "fh.read(2097152)" in rr and 'rel="a b/f.bin"' in rr)
    check("range rejects home", _raises_path(
        lambda p: hermesfs.script_read_range(p, 0, 10), ""))
    check("range rejects bad ints",
          _raises_path(lambda v: hermesfs.script_read_range("f", v, 10), -1)
          and _raises_path(lambda v: hermesfs.script_read_range("f", 0, v), 0)
          and _raises_path(lambda v: hermesfs.script_read_range(
              "f", 0, v), 20 * 1024 * 1024))
    try:
        compile(rr, "<range>", "exec")
        check("range script compiles", True)
    except SyntaxError as exc:
        check(f"range script compiles: {exc}", False)

    # chunked uploads over the exec channel (sandbox upload is as dead
    # as sandbox download — bytes ride in as separate argv)
    staging = hermesfs.UPLOADS_DIR + "/123-4-abcdef0123456789"
    us = hermesfs.script_upload_start(staging)
    check("upload start sweeps+stages",
          "os.makedirs(dl,exist_ok=True)" in us and "scandir" in us
          and str(hermesfs.STALE_SECONDS) in us)
    ua = hermesfs.script_upload_append(staging, 4096, 24576)
    check("upload append reads stdin, offset+length guarded",
          "sys.stdin.buffer.read()" in ua and "b64decode" in ua
          and "at!=4096" in ua and 'out["at"]=at' in ua
          and "len(data)!=24576" in ua and 'out["short"]' in ua)
    check("append rejects bad offset/want",
          _raises_path(lambda v: hermesfs.script_upload_append(staging, v,
                                                               10), -1)
          and _raises_path(lambda v: hermesfs.script_upload_append(
              staging, 0, v), 0)
          and _raises_path(lambda v: hermesfs.script_upload_append(
              staging, 0, v), 17 * 1024 * 1024))
    ss = hermesfs.script_stat_size("notes/x.txt")
    check("stat_size reports size, compiles",
          "os.path.getsize(root)" in ss and '"size"' in ss)
    try:
        compile(ss, "<stat>", "exec")
        check("stat script compiles", True)
    except SyntaxError as exc:
        check(f"stat script compiles: {exc}", False)
    check("stat rejects home",
          _raises_path(lambda p: hermesfs.script_stat_size(p), ""))
    up = hermesfs.script_promote(staging, "notes/x y.txt", 12345)
    check("promote verifies size and replaces",
          "os.replace(root,dst)" in up and "!=12345" in up
          and 'os.path.join(home,"notes/x y.txt")' in up)
    for nm, scr in (("start", us), ("append", ua), ("promote", up)):
        try:
            compile(scr, f"<{nm}>", "exec")
            check(f"upload {nm} script compiles", True)
        except SyntaxError as exc:
            check(f"upload {nm} script compiles: {exc}", False)
    check("staging paths fenced to UPLOADS_DIR",
          _raises_path(lambda p: hermesfs.script_upload_start(p),
                       "notes/evil")
          and _raises_path(lambda p: hermesfs.script_promote(p, "a", 1),
                           "evil-123")
          and _raises_path(lambda p: hermesfs.script_upload_append(p, 0,
                                                                   10),
                           ""))
    check("promote rejects empty dst and bad size",
          _raises_path(lambda s: hermesfs.script_promote(staging, s, 1), "")
          and _raises_path(lambda s: hermesfs.script_promote(
              staging, "a", s), -5))
    check("upload chunk sizes sane (stdin channel, floor fits one argv)",
          0 < hermesfs.UPLOAD_CHUNK_RAW < hermesfs.UPLOAD_STDIN_CHUNK_RAW
          <= 16 * 1024 * 1024
          and (hermesfs.UPLOAD_CHUNK_RAW + 2) // 3 * 4 < 32768)
    # restore-side unzip (sandbox-rebuild backup/restore): the staged zip
    # must live in UPLOADS_DIR, skip entries obey path discipline, and the
    # body carries zip-slip containment + ratio guard + skip list
    uz = hermesfs.script_unzip(staging,
                               [".hermes/config.yaml", ".hermes/.env"],
                               2000000000)
    check("unzip staged-zip path + skip + cap enforced",
          _raises_path(lambda p: hermesfs.script_unzip(p, [], 10),
                       "elsewhere/x.zip")
          and _raises_path(lambda s: hermesfs.script_unzip(staging, s, 10),
                           ["../escape"])
          and _raises_path(lambda s: hermesfs.script_unzip(staging, [], s), 0)
          and _raises_path(lambda s: hermesfs.script_unzip(staging, s, 10), [""]))
    check("unzip guards: ZipFile + normpath containment + .. + ratio cap",
          "ZipFile" in uz and "normpath" in uz and '"."' in uz
          and "file_size" in uz and "2000000000" in uz)
    check("unzip inlines skip list + staging rel",
          ".hermes/config.yaml" in uz and ".hermes/.env" in uz
          and 'rel="' + staging + '"' in uz and hermesfs.SENTINEL in uz)

    # script_unzip EXECUTED sandbox-style (python -c body in a fake HOME,
    # same harness as the entrypoint generator test)
    import subprocess as _sp
    import zipfile as _zipf
    home2 = tempfile.mkdtemp()
    os.makedirs(os.path.join(home2, hermesfs.UPLOADS_DIR))
    env2 = {**os.environ, "HOME": home2, "USERPROFILE": home2}
    with _zipf.ZipFile(os.path.join(home2, hermesfs.UPLOADS_DIR, "b.zip"),
                       "w") as zf:
        zf.writestr(".hermes/config.yaml", "stale")
        zf.writestr(".hermes/sessions/s1.json", "{}")
        zf.writestr("workspace/a.txt", "hello")
        zf.writestr("workspace/../evil.txt", "nope")
        zf.writestr("/abs.txt", "nope")

    def _run_unzip(skip):
        r = _sp.run([sys.executable, "-c",
                     hermesfs.script_unzip(hermesfs.UPLOADS_DIR + "/b.zip",
                                           skip, 10 ** 9)],
                    capture_output=True, text=True, env=env2)
        lines = [l for l in r.stdout.splitlines()
                 if l.startswith(hermesfs.SENTINEL)]
        return (json.loads(lines[0][len(hermesfs.SENTINEL):])
                if lines else {"error": "no sentinel: " + r.stdout[:200]})

    d = _run_unzip([".hermes/config.yaml"])
    check("unzip aborts on zip-slip members",
          d.get("n") == -1 and "跳出 home" in (d.get("error") or "")
          or ("非法" in (d.get("error") or "")))
    # drop the hostile members, then the legit restore must land
    os.remove(os.path.join(home2, hermesfs.UPLOADS_DIR, "b.zip"))
    with _zipf.ZipFile(os.path.join(home2, hermesfs.UPLOADS_DIR, "b.zip"),
                       "w") as zf:
        zf.writestr(".hermes/config.yaml", "stale")
        zf.writestr(".hermes/sessions/s1.json", "{}")
        zf.writestr("workspace/a.txt", "hello")
    d = _run_unzip([".hermes/config.yaml"])
    check("unzip restores files, skips entrypoint-owned",
          d.get("n") == 2
          and open(os.path.join(home2, "workspace", "a.txt")).read()
          == "hello"
          and os.path.isfile(os.path.join(home2, ".hermes", "sessions",
                                          "s1.json"))
          and not os.path.exists(os.path.join(home2, ".hermes",
                                              "config.yaml")))

    # script_zip_dir EXECUTED with exclude (the sandbox-rebuild backup
    # leg): exclude globs prune regenerable subtrees without descending,
    # and the dir members zipfile writes (trailing slash) must survive
    # the round trip back through script_unzip.
    import shutil as _sh
    home3 = tempfile.mkdtemp()
    env3 = {**os.environ, "HOME": home3, "USERPROFILE": home3}

    def _mk(*rel, content="x"):
        p = os.path.join(home3, *rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    _mk(".hermes", "profiles", "kenny", "cache", "tools", "sdk.tar")
    _mk(".hermes", "profiles", "kenny", "home", "dotnet", "sdk.dll")
    _mk(".hermes", "profiles", "kenny", "home", ".cache", "junk")
    _mk(".hermes", "cache", "junk2")
    _mk(".hermes", "webui", "sessions", "s1.json")
    os.makedirs(os.path.join(home3, ".hermes", "profiles", "kenny",
                             "home", "empty-dir"))
    rz = _sp.run([sys.executable, "-c", hermesfs.script_zip_dir(
        ".hermes", "20261015-000000", 10 ** 9,
        exclude=["cache", "profiles/*/cache", "profiles/*/home/.cache"])],
        capture_output=True, text=True, env=env3)
    zl = [l for l in rz.stdout.splitlines()
          if l.startswith(hermesfs.SENTINEL)]
    zo = (json.loads(zl[0][len(hermesfs.SENTINEL):]) if zl
          else {"error": (rz.stdout + rz.stderr)[:200]})
    names = []
    if zo.get("zip"):
        with _zipf.ZipFile(os.path.join(home3, zo["zip"])) as zf:
            names = zf.namelist()
    check("zip exclude prunes caches, keeps SDKs/sessions/empty dirs",
          zo.get("error") is None and zo.get("n") == 2
          and any(n.endswith("home/dotnet/sdk.dll") for n in names)
          and any(n.endswith("webui/sessions/s1.json") for n in names)
          and any(n.endswith("home/empty-dir/") for n in names)
          and not any("kenny/cache" in n or "junk" in n for n in names))
    home4 = tempfile.mkdtemp()
    env4 = {**os.environ, "HOME": home4, "USERPROFILE": home4}
    os.makedirs(os.path.join(home4, hermesfs.UPLOADS_DIR))
    _sh.copy(os.path.join(home3, zo["zip"]),
             os.path.join(home4, hermesfs.UPLOADS_DIR, "b.zip"))
    r2 = _sp.run([sys.executable, "-c", hermesfs.script_unzip(
        hermesfs.UPLOADS_DIR + "/b.zip", [], 10 ** 9)],
        capture_output=True, text=True, env=env4)
    z2 = [l for l in r2.stdout.splitlines()
          if l.startswith(hermesfs.SENTINEL)]
    d2 = (json.loads(z2[0][len(hermesfs.SENTINEL):]) if z2
          else {"error": (r2.stdout + r2.stderr)[:200]})
    check("zip→unzip roundtrip: dir members restore, exclude stayed out",
          d2.get("n") == 2
          and os.path.isfile(os.path.join(
              home4, ".hermes", "profiles", "kenny", "home",
              "dotnet", "sdk.dll"))
          and os.path.isdir(os.path.join(
              home4, ".hermes", "profiles", "kenny", "home", "empty-dir"))
          and not os.path.exists(os.path.join(
              home4, ".hermes", "profiles", "kenny", "cache")))

    noise = "motd junk\n" + hermesfs.SENTINEL + '{"path":"","entries":[{"name":"a","dir":false}]}'
    check("parse skips profile noise",
          hermesfs.parse_exec_output(noise)["entries"][0]["name"] == "a")
    try:
        hermesfs.parse_exec_output("no sentinel here")
        check("parse rejects missing sentinel", False)
    except ValueError:
        check("parse rejects missing sentinel", True)
    c = _listen_cfg("localhost:8000")
    check("listen localhost stays quiet",
          (c.listen_host, c.listen_port) == ("localhost", 8000)
          and not any("cleartext" in w for w in c.warnings))

    # optional "model" per map entry (feeds hermes default_model)
    d3 = tempfile.mkdtemp()
    with open(os.path.join(d3, config.F_LLM_MAP), "w") as fh:
        json.dump({"https://a.example/v1": {"key": "k", "inner-port": 18111,
                                            "inner-key": "f",
                                            "model": "glm-4.6"}}, fh)
    os.environ["OPN_CONFIG_DIR"] = d3
    cfg7 = config.load_config()
    os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")
    check("optional model parsed", cfg7.llm_map[0].model == "glm-4.6")
    check("context_length defaults 0 when absent",
          cfg7.llm_map[0].context_length == 0)

    def _ctx_cfg(value):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w") as fh:
            json.dump({"https://a.example/v1": {"key": "k", "inner-port": 18112,
                                                "inner-key": "f",
                                                "context-length": value}}, fh)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    check("context-length parsed (string coerced)",
          _ctx_cfg("262144").llm_map[0].context_length == 262144)
    for bad in ("128k", 512, 0, True, 1.5):
        try:
            _ctx_cfg(bad)
            check(f"bad context-length {bad!r} rejected", False)
        except config.ConfigError:
            check(f"bad context-length {bad!r} rejected", True)

    # optional catalog-provider (metadata lookups only; feeds providers.opnN)
    def _map_cfg(extra):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w") as fh:
            json.dump({"https://a.example/v1": {"key": "k", "inner-port": 18113,
                                                "inner-key": "f", **extra}}, fh)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    def _wl_bl(wl, bl):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w") as fh:
            json.dump({"https://a.example/v1": {"key": "k", "inner-port": 18001,
                                                "inner-key": "f"}}, fh)
        if wl is not None:
            with open(os.path.join(dd, config.F_URL_WL), "w") as fh:
                json.dump({"enabled": True, "list": wl}, fh)
        if bl is not None:
            with open(os.path.join(dd, config.F_URL_BL), "w") as fh:
                json.dump({"enabled": True, "list": bl}, fh)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    # blacklist vs whitelist WILDCARDS: raw allows can't be denied per-host,
    # so a covered entry must fail loudly (fail-closed), never pass silently
    check("non-covering whitelist wildcard passes",
          _wl_bl(["safe.example.com", "*.open.example.com"],
                 ["evil.example.com"]) is not None)
    try:
        _wl_bl(["*.example.com"], ["evil.example.com"])
        check("blacklist covered by whitelist wildcard rejected", False)
    except config.ConfigError:
        check("blacklist covered by whitelist wildcard rejected", True)
    check("blacklist-only mode warns fully-closed",
          any("FULLY CLOSED" in w
              for w in _wl_bl(None, ["evil.example.com"]).warnings))

    # --- url whitelist host[:port]: arbitrary TCP ports (native TCP) -------
    cport = _wl_bl(["lan.example.com:22", "plain.example.com",
                    "exact.example.com:443"], None)
    pol_port = {r["endpoints"][0]["host"]: r
                for k, r in policy.build_policy(cport)["network_policies"].items()
                if k.startswith("url-allow-")}
    check("bare host still 80+443",
          pol_port["plain.example.com"]["endpoints"][0]
          == {"host": "plain.example.com", "ports": [80, 443]})
    check("bare host rule lacks LAN clients",
          "/usr/bin/ssh" not in [b["path"]
                                 for b in pol_port["plain.example.com"]["binaries"]])
    check("explicit :443 = exact port only",
          pol_port["exact.example.com"]["endpoints"][0]
          == {"host": "exact.example.com", "port": 443})
    check("custom port = native tcp (tls skip, no protocol)",
          pol_port["lan.example.com"]["endpoints"][0]
          == {"host": "lan.example.com", "port": 22, "tls": "skip"})
    check("tcp rule binds ssh/telnet/nc binaries",
          {b["path"] for b in pol_port["lan.example.com"]["binaries"]}
          >= {policy.BIN_PY_PATH, "/usr/bin/curl", "/usr/bin/git",
              "/usr/bin/ssh", "/usr/bin/telnet", "/usr/bin/nc"})
    # blacklist trims a :port entry on the bare host
    yport = policy.policy_yaml(_wl_bl(["evil.example.com:22",
                                       "ok.example.com:8080"],
                                      ["evil.example.com"]))
    check("blacklist trims host:port entry",
          "evil.example.com" not in yport and "ok.example.com" in yport)
    # the wildcard-coverage trap sees through the port suffix too
    try:
        _wl_bl(["*.example.com:22"], ["evil.example.com"])
        check("wildcard-with-port coverage rejected", False)
    except config.ConfigError:
        check("wildcard-with-port coverage rejected", True)
    for bad_e in ("h:0", "h:99999", "h:abc", "h:22:33", "h:", ":22"):
        try:
            _wl_bl([bad_e], None)
            check(f"bad wl entry {bad_e!r} rejected", False)
        except config.ConfigError:
            check(f"bad wl entry {bad_e!r} rejected", True)
    # alias regression across tcp rules (fresh-dict discipline of _tcp_binaries)
    ymix = policy.policy_yaml(_wl_bl(
        [f"h{i:02d}.example.com:{2000 + i}" for i in range(12)], None))
    check("many tcp-port rules are anchor/alias-free",
          "&id" not in ymix and "*id" not in ymix
          and ymix.count("tls: skip") == 12)

    check("catalog-provider parsed",
          _map_cfg({"catalog-provider": "openai"}).llm_map[0].catalog_provider == "openai")
    check("catalog-provider absent = empty",
          _map_cfg({}).llm_map[0].catalog_provider == "")
    for bad in ("open ai", "x" * 65, "../evil"):
        try:
            _map_cfg({"catalog-provider": bad})
            check(f"bad catalog-provider {bad!r} rejected", False)
        except config.ConfigError:
            check(f"bad catalog-provider {bad!r} rejected", True)

    # optional "protocol": "anthropic" selects hermes' Messages transport
    check("protocol anthropic parsed",
          _map_cfg({"protocol": "anthropic"}).llm_map[0].protocol == "anthropic")
    check("protocol absent defaults to openai",
          _map_cfg({}).llm_map[0].protocol == "openai")
    check("protocol trimmed/case-insensitive",
          _map_cfg({"protocol": " Anthropic "}).llm_map[0].protocol == "anthropic")
    for bad in ("messages", "anthropic-messages", "bedrock", True, 5):
        try:
            _map_cfg({"protocol": bad})
            check(f"bad protocol {bad!r} rejected", False)
        except config.ConfigError:
            check(f"bad protocol {bad!r} rejected", True)

    # --- array form: ONE service mapped under BOTH protocols ------------------
    # (classic trap: {url: e} written twice collapses to the LAST entry under
    # json.load — duplicate keys must fail loudly, array form is the fix.)
    def _raw_map(text):
        dd = tempfile.mkdtemp()
        with open(os.path.join(dd, config.F_LLM_MAP), "w", encoding="utf-8") as fh:
            fh.write(text)
        os.environ["OPN_CONFIG_DIR"] = dd
        try:
            return config.load_config()
        finally:
            os.environ["OPN_CONFIG_DIR"] = os.path.join(ROOT, "config")

    acfg = _raw_map(
        '[{"url": "http://192.0.2.7:8000/v1", "key": "k", "inner-port": 18121,'
        ' "inner-key": "a", "protocol": "openai"},'
        ' {"url": "http://192.0.2.7:8000/v1", "key": "k", "inner-port": 18122,'
        ' "inner-key": "b", "protocol": "anthropic", "provider": "OpnAgentAPI0"}]')
    check("array form maps ONE url twice",
          len(acfg.llm_map) == 2 and acfg.llm_map[0].url == acfg.llm_map[1].url
          and acfg.llm_map[0].protocol == "openai"
          and acfg.llm_map[1].protocol == "anthropic"
          and providers.profile_id(acfg.llm_map[0]) != providers.profile_id(acfg.llm_map[1]))
    check("array entry 'provider' ignored WITH warning (name is generated)",
          any("'provider' is ignored" in w for w in acfg.warnings))
    try:
        _raw_map('{"http://192.0.2.7:8000/v1": {"key":"k","inner-port":18123,'
                 '"inner-key":"a"},'
                 '"http://192.0.2.7:8000/v1": {"key":"k","inner-port":18124,'
                 '"inner-key":"b"}}')
        check("duplicate url keys rejected loudly", False)
    except config.ConfigError as exc:
        check("duplicate url keys rejected loudly",
              "duplicate JSON key" in str(exc) and "array form" in str(exc))
    try:
        _raw_map('[{"key":"k","inner-port":18125,"inner-key":"a"}]')
        check("array entry without 'url' rejected", False)
    except config.ConfigError as exc:
        check("array entry without 'url' rejected", "'url'" in str(exc))

    # --- entrypoint's ~/.hermes/config.yaml generator -------------------------
    import re as _re
    import subprocess
    sh_src = open(os.path.join(ROOT, "sandbox", "entrypoint.sh"),
                  encoding="utf-8").read()
    m = _re.search(r"if python3 - <<'PY'\n(.*?)\nPY\n", sh_src, _re.S)
    check("entrypoint embeds config.yaml generator", m is not None)
    tmp_home = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp_home, ".hermes"))
    env = {**os.environ, "HOME": tmp_home, "USERPROFILE": tmp_home,
           "_SPEC": json.dumps([
               {"listen": "127.0.0.1:18001",
                "upstream": "http://114.33.193.52/v1",
                "inner_key": "fk-0", "cred_env": "OPNL_0",
                "model": "glm-4.6", "context_length": 262144,
                "catalog_provider": "openai", "provider": "OpnAgentAPI0"},
               {"listen": "127.0.0.1:18002",
                "upstream": "https://api.openai.com/v1",
                "inner_key": "fk/1", "cred_env": "OPNL_1", "model": ""},
               {"listen": "127.0.0.1:18003",
                "upstream": "https://api.anthropic.com/v1",
                "inner_key": "fk-2", "cred_env": "OPNL_2",
                "model": "claude-sonnet-4-5", "protocol": "anthropic",
                "provider": "OpnAgentAPI2"}])}
    r = subprocess.run([sys.executable, "-c", m.group(1)],
                       capture_output=True, text=True, env=env)
    check("config.yaml generator runs", r.returncode == 0)
    import yaml as _yaml
    gen = _yaml.safe_load(open(os.path.join(tmp_home, ".hermes",
                                            "config.yaml"), encoding="utf-8"))
    check("hermes default binds by NAMED provider (never bare custom)",
          gen["model"] == {"provider": "OpnAgentAPI0",
                           "base_url": "http://127.0.0.1:18001/v1",
                           "api_key": "fk-0", "model": "glm-4.6",
                           "context_length": 262144})
    # spec-provided name (OpnAgentAPI0) on entry 0; spec WITHOUT a
    # "provider" key still falls back to opn<N> (entry 1)
    check("opn0 entry carries context_length + catalog_provider",
          gen["providers"]["OpnAgentAPI0"].get("context_length") == 262144
          and gen["providers"]["OpnAgentAPI0"].get("catalog_provider") == "openai")
    check("provider name absent falls back to opn<N>",
          "opn1" in gen["providers"])
    # without an explicit models: map the webui picker falls back to hermes'
    # static catalog (gpt-5.1-codex etc.) instead of the operator's model
    check("models: list pins the picker to the configured model",
          gen["providers"]["OpnAgentAPI0"].get("models") == {"glm-4.6": {}}
          and "models" not in gen["providers"]["opn1"])
    check("bare entry carries neither",
          "context_length" not in gen["providers"]["opn1"]
          and "catalog_provider" not in gen["providers"]["opn1"])
    check("named providers keyed to fake keys",
          gen["providers"]["OpnAgentAPI0"]["api_key"] == "fk-0"
          and gen["providers"]["OpnAgentAPI0"]["default_model"] == "glm-4.6"
          and gen["providers"]["opn1"]["api"] == "http://127.0.0.1:18002/v1"
          and gen["providers"]["opn1"]["api_key"] == "fk/1"
          and "default_model" not in gen["providers"]["opn1"])
    # map "protocol" drives the hermes transport: anthropic entries get
    # the canonical anthropic_messages name (verified against the pinned
    # hermes source's _API_MODE_ALIASES), everything else stays
    # chat_completions — a Messages relay 404s on /chat/completions.
    check("openai entries keep transport chat_completions",
          gen["providers"]["OpnAgentAPI0"].get("transport") == "chat_completions"
          and gen["providers"]["opn1"].get("transport") == "chat_completions")
    check("protocol=anthropic emits transport: anthropic_messages",
          gen["providers"]["OpnAgentAPI2"].get("transport")
          == "anthropic_messages"
          and gen["providers"]["OpnAgentAPI2"]["api"]
          == "http://127.0.0.1:18003/v1"
          and gen["providers"]["OpnAgentAPI2"]["api_key"] == "fk-2")
    # hermes finds a non-default provider's key via <NAME>_API_KEY env
    # (live deploy: "no API key was found. Set the OPN0_API_KEY ..." on
    # profile switch) — the shim loop must export it per entry.
    check("entrypoint exports <NAME>_API_KEY per provider",
          '${pname^^}_API_KEY=$inner_key' in sh_src)
    check("launcher names hermes providers OpnAgentAPI<N>",
          providers.hermes_provider_name(cfg.llm_map[0]) == "OpnAgentAPI0"
          and providers.hermes_provider_name(cfg.llm_map[1]) == "OpnAgentAPI1")
    env_txt = open(os.path.join(tmp_home, ".hermes", ".env"),
                   encoding="utf-8").read()
    # OPENAI_* in .env/process env would re-register the fake key + shim URL
    # under the "openai" provider (webui key manager + runtime route match).
    check(".env carries no OPENAI_* (no openai-provider shadowing)",
          "OPENAI_API_KEY" not in env_txt
          and "OPENAI_BASE_URL" not in env_txt)
    api_srv = (gen.get("platforms") or {}).get("api_server") or {}
    check("gateway api_server enabled on loopback 8642",
          api_srv.get("enabled") is True
          and api_srv.get("extra", {}).get("host") == "127.0.0.1"
          and api_srv.get("extra", {}).get("port") == 8642
          and len(api_srv.get("extra", {}).get("key", "")) >= 16)
    check("hermes .env carries API_SERVER_KEY",
          "API_SERVER_KEY=" in env_txt)
    # Live deploy: switching to a non-default profile failed with
    # "no API key was found. Set the OPNAGENTAPI0_API_KEY environment
    # variable" even though the shim loop EXPORTED it — the resolver reads
    # ~/.hermes/.env (dotenv), so the named-provider keys must be there too.
    check("hermes .env carries <NAME>_API_KEY per provider (fake keys)",
          "OPNAGENTAPI0_API_KEY=fk-0" in env_txt
          and "OPN1_API_KEY=fk/1" in env_txt
          and "OPNAGENTAPI2_API_KEY=fk-2" in env_txt)

    print()
    if FAILED:
        print("FAILED:", FAILED)
        sys.exit(1)
    print("all smoke tests passed")


if __name__ == "__main__":
    main()
