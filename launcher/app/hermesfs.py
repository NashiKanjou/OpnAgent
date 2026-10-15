"""Pure helpers behind the /admin hermes file browser (offline-testable).

Everything runs INSIDE the sandbox through the OpenShell CLI: a validated
python3 one-liner per action via `sandbox exec` — including file bytes,
which come out base64-chunked through the same channel (live deploy:
`sandbox download`/`sandbox upload` fail on every source, even
image-baked paths, so nothing may depend on them). UI paths are
HOME-relative (the exec login shell's HOME, which OpenShell overrides —
it is NOT the image's ENV HOME) and must survive normalize_rel() before
they reach any command string.

Defense in depth:
- normalize_rel refuses absolute paths, '.'/'..' segments, and any
  character with bash- or python-string- meaning (quotes, backslash, $,
  backtick, NUL, control chars). Unicode names (e.g. Chinese) are fine.
- The action scripts go to the CLI as separate argv (`-- python3 -c
  <body>`); the CLI quotes each argument itself, and bodies use only
  double-quoted python literals — a validated path inlined between
  double quotes cannot break out of either quoting layer.
- The CLI itself separately refuses sources that escape the working dir.
"""

from __future__ import annotations

import json
import re

# Sentinel prefix on the python script's stdout line: `sandbox exec` runs
# through a login shell, so profile/motd noise may precede our payload.
SENTINEL = "@@OPNFS@@"

# Everything the quoting layers hate. Deliberately NOT a charset
# whitelist: filenames are operator/hermes-created (CJK included), so we
# only ban what could terminate a single-quoted bash word or a
# double-quoted python string — plus control characters.
_BAD_CHARS = re.compile(r"[\"'`$\\\x00-\x1f]")


class PathError(ValueError):
    """UI-supplied path rejected before it reaches any CLI command."""


def validate_basename(name: str) -> str:
    """Validate an uploaded file's chosen name as a SINGLE path segment
    (browsers can submit anything in filename; keep it out of directories
    and out of the quoting layers). Returns the stripped name."""
    n = (name or "").strip()
    if not n or n in (".", "..") or "/" in n:
        raise PathError(f"上傳檔名無效: {name!r}")
    if _BAD_CHARS.search(n) or n != name:
        raise PathError(f"上傳檔名含非法字元: {name!r}")
    return n


# Editor cap: past this the file is offered for download only.
EDIT_MAX_BYTES = 2 * 1024 * 1024

# Folder downloads are zipped into this HOME-relative staging dir inside
# the sandbox: never inside the zipped folder itself (zipping home is
# refused anyway), disposable, and the only place the stale sweep looks.
DOWNLOADS_DIR = ".opn_downloads"

# Orphan staging lifetime: a request that dies between "staged" and
# "consumed" leaves its file behind; the sweep baked into each staging
# script unlinks anything older than this (zips AND upload fragments).
STALE_SECONDS = 7 * 24 * 3600

# Upload staging dir (sibling of DOWNLOADS_DIR): chunked writes land
# here under a random name, get size-verified, then os.replace onto the
# target. `sandbox upload` is as dead as `sandbox download` (live
# probe: ENOENT with explicit dest too), so bytes ride the exec channel
# — as the command's STDIN, not argv (see below).
UPLOADS_DIR = ".opn_uploads"

# Why stdin and not argv: argv died twice on live deploy — the exec
# channel's own 32768-byte per-arg limit ("command argument 3 exceeds
# 32768 byte limit"), then a DETERMINISTIC "exec relay closed" when the
# total command string reached ~450 KB (16 x 28 KB base64 args; small
# execs in the same second worked fine). Piped stdin is the CLI's
# documented input path (refdocs overview.mdx: echo | exec -- cat) and
# sidesteps the command string entirely. UPLOAD_STDIN_CHUNK_RAW is the
# starting batch size; the launcher halves it on repeated channel deaths
# down to UPLOAD_CHUNK_RAW (which also stays safely under the per-arg
# limit, so a whole batch still fits ONE argv if ever needed).
UPLOAD_STDIN_CHUNK_RAW = 1024 * 1024
UPLOAD_CHUNK_RAW = 21 * 1024


# Exclude-glob alphabet for script_zip_dir: fnmatch patterns are inlined
# into the generated body's double-quoted literals, so keep them to
# ASCII glob characters (no quotes/backslash/$ that could break quoting).
_EXCLUDE_PAT = re.compile(r"[\w.\-\[\]?*/]+")


def script_zip_dir(rel: str, stamp: str, max_bytes: int,
                   exclude: list[str] | None = None) -> str:
    """Zip `root` (a folder) into DOWNLOADS_DIR as
    '<basename>-<stamp>.zip', first sweeping zips older than
    STALE_SECONDS. On success out['zip'] carries the HOME-relative
    zip path for `sandbox download`. `stamp` is launcher-generated
    (never user-derived) so names stay collision-free per click;
    max_bytes refuses to hand back an archive nobody asked to hold.

    `exclude` is a launcher-generated list of fnmatch globs matched
    against each entry's path RELATIVE TO `root` ('profiles/*/cache');
    a matching directory is pruned without descending, so regenerable
    trees (hermes tool caches) never ride the exec channel (see
    main.BACKUP_EXCLUDE). Walking instead of shutil.make_archive also
    lets us skip symlinks (make_archive dereferenced them). Directory
    members keep zipfile's trailing slash; script_unzip accepts them."""
    if not rel:
        raise PathError("請指定資料夾(不可為 home 本身)")
    if rel == DOWNLOADS_DIR:
        raise PathError("那是壓縮暫存目錄,不能壓縮自己")
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}", stamp):
        raise PathError(f"無效的壓縮時間戳: {stamp!r}")
    exc: list[str] = []
    for pat in (exclude or []):
        if (not _EXCLUDE_PAT.fullmatch(pat) or "/" in pat[:1]
                or ".." in pat.split("/")):
            raise PathError(f"無效的排除樣式: {pat!r}")
        exc.append(pat)
    return _finish("""import time,zipfile,fnmatch
DLDIR="__DL__"
EXC=__EXC__
dl=os.path.join(home,DLDIR)
def _hit(rp):
    for pat in EXC:
        if fnmatch.fnmatchcase(rp,pat):
            return True
    return False
try:
    os.makedirs(dl,exist_ok=True)
    now=time.time()
    for e in os.scandir(dl):
        if e.name.endswith(".zip"):
            try:
                if now-e.stat(follow_symlinks=False).st_mtime>__STALE__:
                    os.remove(e.path)
            except OSError:
                pass
    if not os.path.isdir(root):
        out["error"]="這不是資料夾,請直接用檔案下載"
    else:
        base=os.path.basename(root)
        zp=os.path.join(dl,base+"-__STAMP__.zip")
        nfile=0
        with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED) as zf:
            # Directory entries via writestr(from_file(...)), never
            # zf.write(): ZipFile.write recurses into directories on
            # python 3.13+ (would double-add children and defeat the
            # pruning below). Files go through zf.write() — no
            # recursion for non-dirs, no whole-file buffering.
            zf.writestr(zipfile.ZipInfo.from_file(root,base),b"")
            for dirpath,dirnames,filenames in os.walk(root,followlinks=False):
                keep=[]
                for dn in sorted(dirnames):
                    full=os.path.join(dirpath,dn)
                    if os.path.islink(full):
                        continue
                    rp=os.path.relpath(full,root).replace(os.sep,"/")
                    if _hit(rp):
                        continue
                    keep.append(dn)
                    zf.writestr(
                        zipfile.ZipInfo.from_file(full,base+"/"+rp),b"")
                dirnames[:]=keep
                for fn in sorted(filenames):
                    full=os.path.join(dirpath,fn)
                    if os.path.islink(full):
                        continue
                    rp=os.path.relpath(full,root).replace(os.sep,"/")
                    if _hit(rp):
                        continue
                    try:
                        zf.write(full,base+"/"+rp)
                        nfile+=1
                    except OSError:
                        pass
        size=os.path.getsize(zp)
        if size>__MAX__:
            os.remove(zp)
            out["error"]=("壓縮檔過大("+str(size)+" bytes,上限 "
                          +str(__MAX__)+" bytes)")
        else:
            out["zip"]=DLDIR+"/"+base+"-__STAMP__.zip"
            out["size"]=size
            out["n"]=nfile
except Exception as ex:
    out["error"]="壓縮失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL)
                   .replace("__DL__", DOWNLOADS_DIR)
                   .replace("__STALE__", str(STALE_SECONDS))
                   .replace("__MAX__", str(int(max_bytes)))
                   .replace("__EXC__", json.dumps(exc))
                   .replace("__STAMP__", stamp), rel)


def script_read(rel: str) -> str:
    """Read a file for the web editor. Bytes travel as base64 inside the
    sentinel JSON — keeps the payload ASCII-safe end to end and lets the
    browser TextDecoder do the UTF-8 decode in one place."""
    return _finish(f"""import base64
MAX={EDIT_MAX_BYTES}
try:
    if os.path.isdir(root):
        out["error"]="這是資料夾"
    else:
        with open(root,"rb") as fh:
            data=fh.read(MAX+1)
        if len(data)>MAX:
            out["error"]="檔案過大(編輯上限 "+str(MAX)+" bytes),請改用下載"
        else:
            out["b64"]=base64.b64encode(data).decode("ascii")
except OSError as ex:
    out["error"]="讀取失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL), rel)


def normalize_rel(path: str) -> str:
    """Validate a UI path as HOME-relative; returns the cleaned '/'-joined
    path ('' = home itself). Raises PathError (-> HTTP 400)."""
    p = (path or "").strip().strip("/")
    while "//" in p:
        p = p.replace("//", "/")
    if not p:
        return ""
    segs = p.split("/")
    for s in segs:
        if not s or s in (".", ".."):
            raise PathError(f"無效路徑(不可含 . / .. / 空段): {path!r}")
        if _BAD_CHARS.search(s) or s != s.strip():
            raise PathError(f"路徑段含非法字元(引號/反斜線/$/`/控制字元): "
                            f"{s!r}")
    return "/".join(segs)


def _script(body: str) -> str:
    """Return the action body (a python snippet using `root`, printing a
    JSON payload) as the CODE argument of `-- python3 -c <body>`.

    Live deploy caught the other shape — one argv element carrying the
    whole `python3 -c '...'` line — failing with rc=127: the CLI quotes
    each argv itself before joining them into the sandbox login shell's
    command string, so the bundled wrapper became a single (unfindable)
    COMMAND WORD. Passing python3/-c/body as three separate arguments
    lets the CLI's own quoting do the work."""
    return body


# json.dumps stays ensure_ascii (default True) on purpose: the exec
# session may run under a POSIX/C locale, where printing Chinese names
# as raw UTF-8 through a non-UTF-8 stdout would raise UnicodeEncodeError.
# \uXXXX escapes survive any code page.
_HEAD = """import os,json
rel="__REL__"
home=os.path.expanduser("~")
root=home if not rel else os.path.join(home,rel)
out={"path":rel}
"""


def _finish(body: str, rel: str) -> str:
    assert "'" not in rel  # normalize_rel strips them; belt and braces
    return _script((_HEAD + body).replace("__REL__", rel))


def script_ls(rel: str) -> str:
    return _finish("""try:
    with os.scandir(root) as it:
        for e in it:
            try:
                st=e.stat(follow_symlinks=False)
            except OSError:
                continue
            out["entries"]=out.get("entries",[])
            out["entries"].append({"name":e.name,
                "dir":e.is_dir(follow_symlinks=False),
                "size":st.st_size,"mtime":st.st_mtime})
except OSError as ex:
    out["error"]="無法列出 "+root+": "+str(ex)
out.setdefault("entries",[])
out["entries"].sort(key=lambda x:(not x["dir"],x["name"].lower()))
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL), rel)


def script_read_range(rel: str, offset: int, length: int) -> str:
    """Read [offset, offset+length) of a file as base64 — the chunked
    pull behind folder/zip downloads. offset/length are launcher-side
    ints (inlined after validation), never UI input. Live deploy:
    `sandbox download` ENOENTs on EVERY source (even image-baked
    files), so file bytes ride the proven exec channel instead."""
    if not rel:
        raise PathError("請指定檔案(不可為 home 本身)")
    if not isinstance(offset, int) or offset < 0:
        raise PathError(f"無效的位移: {offset!r}")
    if not isinstance(length, int) or not 0 < length <= 16 * 1024 * 1024:
        raise PathError(f"無效的塊大小: {length!r}")
    return _finish("""import base64
try:
    with open(root,"rb") as fh:
        fh.seek(__OFF__)
        data=fh.read(__LEN__)
    out["n"]=len(data)
    if data:
        out["b64"]=base64.b64encode(data).decode("ascii")
except OSError as ex:
    out["error"]="讀取失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL)
                   .replace("__OFF__", str(offset))
                   .replace("__LEN__", str(length)), rel)


def _check_staging_rel(rel: str) -> str:
    """Upload staging paths are launcher-generated; re-assert they are
    HOME-relative and inside UPLOADS_DIR before any script touches them."""
    clean = normalize_rel(rel)
    if not clean.startswith(UPLOADS_DIR + "/"):
        raise PathError(f"上傳暫存路徑必須在 {UPLOADS_DIR}/ 下: {rel!r}")
    return clean


def script_upload_start(rel_tmp: str) -> str:
    """Create the (empty) staging file and sweep orphaned fragments from
    requests that died mid-chunk (same STALE_SECONDS net as zip orphans).
    Runs on the first chunk of every upload, so the sweep needs no timer
    of its own."""
    rel = _check_staging_rel(rel_tmp)
    return _finish("""import time
dl=os.path.dirname(root)
try:
    os.makedirs(dl,exist_ok=True)
    now=time.time()
    for e in os.scandir(dl):
        try:
            if now-e.stat(follow_symlinks=False).st_mtime>__STALE__:
                os.remove(e.path)
        except OSError:
            pass
    with open(root,"wb"):
        pass
    out["ok"]=True
except OSError as ex:
    out["error"]="建立暫存檔失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL).replace("__STALE__", str(STALE_SECONDS)),
               rel)


def script_upload_append(rel_tmp: str, offset: int, want: int) -> str:
    """Append one base64 batch that arrives on the command's STDIN
    (the launcher pipes it; see the UPLOAD_STDIN_CHUNK_RAW note for why
    not argv), but ONLY while the staging file is exactly `offset` bytes
    long, and only if the batch decodes to exactly `want` bytes.

    Both guards exist because a relay death ("exec relay closed before
    the command reported an exit status") is an UNKNOWN outcome: the
    batch may or may not have landed, and a truncated stdin must never
    append as if it were whole. Outcomes the launcher reasons over:
    n=want            batch landed (or a lost reply for it: at=off+want);
    n=0 + at=off      never landed — replay the batch;
    n=0 + short=<k>   stdin arrived truncated/corrupt — never written,
                      replay (and treat as a channel-unstable signal);
    n=0 + other at    file is somewhere else — real corruption, abort.

    sys.stdin stays unread when the guard refuses, but stdin is drained
    FIRST so a half-delivered pipe is always observable (short) instead
    of leaving the CLI blocked on a pipe nobody reads."""
    rel = _check_staging_rel(rel_tmp)
    if not isinstance(offset, int) or offset < 0:
        raise PathError(f"無效的位移: {offset!r}")
    if not isinstance(want, int) or not 0 < want <= 16 * 1024 * 1024:
        raise PathError(f"無效的區塊大小: {want!r}")
    return _finish("""import base64,sys
try:
    blob=sys.stdin.buffer.read()
    try:
        data=base64.b64decode(blob)
    except Exception:
        data=b""
    at=os.path.getsize(root)
    if at!=__OFF__:
        out["at"]=at
        out["n"]=0
    elif len(data)!=__WANT__:
        out["n"]=0
        out["short"]=len(data)
    else:
        with open(root,"ab") as fh:
            fh.write(data)
        out["n"]=len(data)
except Exception as ex:
    out["error"]="寫入區塊失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL)
                   .replace("__OFF__", str(offset))
                   .replace("__WANT__", str(want)), rel)


def script_stat_size(rel: str) -> str:
    """Size of a HOME-relative file (-1 when absent) — the witness the
    launcher queries when an exec's RESPONSE was lost but the command
    may have run (relay blips), to decide what actually landed."""
    if not rel:
        raise PathError("請指定檔案(不可為 home 本身)")
    return _finish("""try:
    out["size"]=os.path.getsize(root) if os.path.isfile(root) else -1
except OSError:
    out["size"]=-1
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL), rel)


def script_promote(rel_tmp: str, rel_dst: str, expected_size: int) -> str:
    """Atomically move the verified staging file onto its target. The
    size check runs sandbox-side so a lost/duffed chunk batch can never
    masquerade as a complete upload; os.replace clobbers in one step
    (the CLI upload's clobber-refusal + delete/retry dance is gone)."""
    rel = _check_staging_rel(rel_tmp)
    dst = normalize_rel(rel_dst)
    if not dst:
        raise PathError("上傳目標不可為 home 本身")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise PathError(f"無效的預期大小: {expected_size!r}")
    return _finish("""try:
    if not os.path.isfile(root):
        out["error"]="暫存檔不存在(區塊遺失?)"
    else:
        size=os.path.getsize(root)
        if size!=__SIZE__:
            out["error"]="大小不符: 暫存 "+str(size)+" 期望 "+str(__SIZE__)
        else:
            dst=os.path.join(home,"__DST__")
            os.makedirs(os.path.dirname(dst),exist_ok=True)
            os.replace(root,dst)
            out["ok"]=True
except OSError as ex:
    out["error"]="換名失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL)
                   .replace("__SIZE__", str(int(expected_size)))
                   .replace("__DST__", dst), rel)


def script_unzip(rel_tmp: str, skip: list[str], max_total: int) -> str:
    """Unpack a BACKUP zip (staged under UPLOADS_DIR by
    _sandbox_put_bytes) into HOME — the restore leg of the sandbox
    rebuild backup/restore (see main.backup_hermes_data). Entries look
    like '<dir>/...' (shape of script_zip_dir's make_archive), so the
    extract root is home itself.

    Guards: member paths must be plain relative segments (no absolute,
    drive letters, '~', empty/'.'/'..' segments) and must normpath under
    home (zip-slip); summed uncompressed size must stay under max_total
    (ratio guard against planted/duffed archives). `skip` is a
    launcher-generated list of HOME-relative paths never restored —
    entrypoint-owned files (config.yaml/.env/gateway_state.json) whose
    fresh boot-time values must not be clobbered by stale ones.
    mtime is restored from the zip so session listings keep their order.
    out['n'] = files unpacked (-1 on abort, out['error'] set)."""
    rel = _check_staging_rel(rel_tmp)
    clean_skip = []
    for s in skip:
        c = normalize_rel(s)
        if not c:
            raise PathError(f"跳過項不可為 home 本身: {s!r}")
        clean_skip.append(c)
    if not isinstance(max_total, int) or max_total <= 0:
        raise PathError(f"無效的大小上限: {max_total!r}")
    return _finish("""import zipfile,shutil,calendar
SKIP=__SKIP__
def _parts(name):
    if chr(92) in name:                          # backslash = win-style path
        return None
    if name.endswith("/"):
        name=name[:-1]   # dir member: zipfile writes them slash-suffixed
    if name.startswith("/") or ":" in name:
        return None
    parts=name.split("/")
    if any(p in ("",".","..") or p.startswith("~") for p in parts):
        return None
    return parts
n=0
try:
    zf=zipfile.ZipFile(root)
    with zf:
        if sum(m.file_size for m in zf.infolist())>__MAX__:
            out["error"]="解壓總量超過上限 "+str(__MAX__)
        else:
            for m in zf.infolist():
                parts=_parts(m.filename)
                if parts is None:
                    out["error"]="非法 zip 條目: "+repr(m.filename); n=-1; break
                if "/".join(parts) in SKIP:
                    continue
                target=os.path.normpath(os.path.join(home,*parts))
                if target!=home and not target.startswith(home+os.sep):
                    out["error"]="條目跳出 home: "+repr(m.filename); n=-1; break
                if m.is_dir():
                    os.makedirs(target,exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target),exist_ok=True)
                with zf.open(m) as src, open(target,"wb") as dst:
                    shutil.copyfileobj(src,dst,1048576)
                mode=(m.external_attr>>16)&0o7777
                if mode:
                    try: os.chmod(target,mode)
                    except OSError: pass
                try:
                    mt=calendar.timegm(m.date_time+(0,0,-1))
                    os.utime(target,(mt,mt))
                except Exception: pass
                n+=1
except (OSError,zipfile.BadZipFile) as ex:
    out["error"]="解壓失敗: "+str(ex); n=-1
out["n"]=n
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL)
                   .replace("__SKIP__", json.dumps(clean_skip))
                   .replace("__MAX__", str(int(max_total))), rel)


def script_mkdir(rel: str) -> str:
    if not rel:
        raise PathError("請輸入資料夾名稱")
    return _finish("""try:
    os.mkdir(root)
    out["ok"]=True
except OSError as ex:
    out["error"]="建立失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL), rel)


def script_delete(rel: str) -> str:
    if not rel:
        raise PathError("不可刪除 home 本身")
    return _finish("""import shutil
try:
    if os.path.isdir(root) and not os.path.islink(root):
        shutil.rmtree(root)
    else:
        os.remove(root)
    out["ok"]=True
except OSError as ex:
    out["error"]="刪除失敗: "+str(ex)
print("__SENT__"+json.dumps(out))
""".replace("__SENT__", SENTINEL), rel)


def parse_exec_output(out: str) -> dict:
    """Pull the sentinel JSON line out of `sandbox exec` stdout (login
    shell motd/profile noise precedes it). Raises ValueError -> 400 with
    the raw output head, so CLI drift stays debuggable from the console."""
    for line in reversed(out.splitlines()):
        if line.startswith(SENTINEL):
            try:
                return json.loads(line[len(SENTINEL):])
            except json.JSONDecodeError:
                break
    raise ValueError(f"sandbox 指令未回傳結果;原始輸出開頭: {out[:300]!r}")
