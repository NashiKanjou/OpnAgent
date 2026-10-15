"""Launcher web console (/admin), admin-role only.

The page is launcher-owned (hermes never sees it): status line, hot
reload button, list-JSON editors, user management. Vanilla JS + fetch,
carrying the same session cookie the entry point uses.

User-management helpers here are PURE functions over list[UserEntry]
(offline-testable); main.py wires them to routes and writes the file.
Roles are two-tier: "admin" reaches this console, "user" goes straight
to hermes and is fenced out of every /admin* route.
"""

from __future__ import annotations

import json

from . import config
from .config import ConfigError, UserEntry

# The only files the web editor may touch (fixed mapping — names are
# looked up, never joined from user input, so no path traversal).
# LLM_Porting_Map (real keys) and listen.json (needs a container
# recreate anyway) deliberately stay file-only.
LIST_FILES = {config.F_URL_WL: "host", config.F_URL_BL: "host",
              config.F_PKG_WL: "pkg", config.F_PKG_BL: "pkg"}

_PKG_RE = r"[A-Za-z0-9._\-]+"


def validate_list_text(name: str, text: str) -> None:
    """Raise ValueError (-> HTTP 400, file untouched) unless `text` is a
    valid list-config of `name`'s kind."""
    if name not in LIST_FILES:
        raise ValueError(f"not an editable file: {name!r}")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name}: invalid JSON: {exc}") from None
    try:
        nl = config._list_cfg(raw, name)
    except ConfigError as exc:
        raise ValueError(str(exc)) from None
    if LIST_FILES[name] == "host":
        bad = [i for i in nl.items if not config._safe_host_or_pkg(i)]
    else:
        import re
        bad = [i for i in nl.items if not re.fullmatch(_PKG_RE, i)]
    if bad:
        raise ValueError(f"{name}: invalid {LIST_FILES[name]} entries: {bad}")


# --- user management (pure; ValueError -> 400) -----------------------------

def user_add(users: list[UserEntry], username: str, passkey: str):
    username, passkey = username.strip(), passkey.strip()
    if not username or not passkey:
        raise ValueError("username 與 passkey 皆不可為空")
    if any(u.username == username for u in users):
        raise ValueError(f"帳號 {username!r} 已存在")
    # Web-created accounts are always plain users; roles are not mintable
    # or changeable through the console (file-only, by design).
    return [*users, UserEntry(username=username, passkey=passkey, role="user")]


def user_set_passkey(users: list[UserEntry], username: str, passkey: str):
    passkey = passkey.strip()
    if not passkey:
        raise ValueError("passkey 不可為空")
    if not any(u.username == username for u in users):
        raise ValueError(f"帳號 {username!r} 不存在")
    return [u if u.username != username
            else UserEntry(username=u.username, passkey=passkey, role=u.role)
            for u in users]


def user_remove(users: list[UserEntry], username: str):
    hit = [u for u in users if u.username == username]
    if not hit:
        raise ValueError(f"帳號 {username!r} 不存在")
    if hit[0].role == "admin" and sum(1 for u in users if u.role == "admin") == 1:
        raise ValueError("不可刪除最後一個管理員(會鎖死 /admin;請先於檔案中保留至少一個)")
    return [u for u in users if u.username != username]


def users_payload(users: list[UserEntry], enabled: bool) -> dict:
    """Serialize back to users.json format, keeping the enabled flag and
    each entry's role (never rewritten through the web path)."""
    return {"enabled": bool(enabled),
            "user-list": [{"username": u.username, "passkey": u.passkey,
                           "role": u.role} for u in users]}


# --- the console page -------------------------------------------------------

ADMIN_HTML = """<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpnAgent 主控台</title>
<style>
 body{font-family:system-ui,sans-serif;background:#101418;color:#e6e6e6;
      margin:0;padding:1.4rem 2rem;max-width:60rem}
 h1{font-size:1.2rem;margin:.2rem 0 .8rem} h2{font-size:.95rem;color:#9fb0bf;margin:1.4rem 0 .4rem}
 .row{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
 button{padding:.5rem .9rem;border:0;border-radius:6px;background:#3d7efd;
        color:#fff;font-size:.9rem;cursor:pointer}
 button:disabled{opacity:.5;cursor:default}
 button.ghost{background:#2a333d;color:#cfd8e3}
 pre{background:#1b2128;border-radius:8px;padding:.8rem;font-size:.8rem;
      white-space:pre-wrap;word-break:break-all;margin:.4rem 0}
 textarea{width:100%;height:20rem;background:#12171d;color:#dfe;
      border:1px solid #34404d;border-radius:8px;padding:.7rem;
      font:13px/1.5 ui-monospace,monospace;box-sizing:border-box}
 table{border-collapse:collapse;margin:.4rem 0}
 td,th{padding:.35rem .8rem;border-bottom:1px solid #2a333d;font-size:.9rem;text-align:left}
 input{padding:.45rem;border-radius:6px;border:1px solid #34404d;background:#12171d;color:#eee}
 .tab{background:#2a333d;color:#cfd8e3}.tab.on{background:#3d7efd;color:#fff}
 .ok{color:#7ee787}.bad{color:#ff7b72}
</style></head><body>
<h1>OpnAgent 主控台</h1>
<pre id="status">讀取中…</pre>
<div class="row">
 <button onclick="location.href='/'">進入 Hermes</button>
 <button onclick="reloadLists(this)">熱更新名單</button>
</div>
<h2>名單 JSON(儲存 = 驗證 → 寫檔 → 立即熱套;會切斷沙箱舊長連線)</h2>
<div class="row" id="tabs"></div>
<textarea id="ed" spellcheck="false"></textarea>
<div class="row">
 <button class="ghost" onclick="saveList(this,false)">只儲存(不套用)</button>
 <button onclick="saveList(this,true)">儲存並套用</button>
</div>
<pre id="out"></pre>
<h2>使用者(新增帳號固定為「使用者」角色;角色僅能於檔案中調整)</h2>
<table id="users"><thead><tr><th>帳號</th><th>角色</th><th>新 passkey</th><th></th></tr></thead><tbody></tbody></table>
<div class="row">
 <input id="nu" placeholder="新帳號" autocomplete="off">
 <input id="np" placeholder="passkey" type="password">
 <button onclick="addUser(this)">新增使用者</button>
</div>
<pre id="uout"></pre>
<h2>Hermes 檔案管理(沙箱 home;~/.hermes、~/workspace…)</h2>
<div class="row">
 <button class="ghost" onclick="hUp()">⬆ 上一層</button>
 <span id="hpath" style="font-family:ui-monospace,monospace"></span>
 <button class="ghost" onclick="$('hup').click()">上傳到這裡</button>
 <input type="file" id="hup" multiple style="display:none" onchange="hUpload(this)">
</div>
<table id="hfiles"><thead><tr><th>名稱</th><th>大小</th><th>修改時間</th><th></th></tr></thead><tbody></tbody></table>
<div class="row" id="heditrow" style="display:none">
 <span id="heditname"></span>
 <button onclick="hSave(this)">儲存</button>
 <button class="ghost" onclick="hCloseEdit()">收起編輯</button>
</div>
<textarea id="hed" spellcheck="false" style="display:none"></textarea>
<div class="row">
 <input id="nf" placeholder="新資料夾名稱" autocomplete="off">
 <button onclick="hMkdir(this)">建立資料夾</button>
</div>
<pre id="hout"></pre>
<script>
const FILES=["url_whitelist.json","url_blacklist.json",
             "python_pkg_whitelist.json","python_pkg_blacklist.json"];
let cur=FILES[0], lists={};
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const show=(el,msg,ok)=>{el.textContent=msg;el.className=ok?"ok":"bad"};
async function j(url,opt){const r=await fetch(url,Object.assign({credentials:"same-origin"},opt));
 const d=await r.json().catch(()=>({detail:r.status}));
 if(!r.ok) throw new Error(d.detail||JSON.stringify(d));return d;}
async function boot(){
 try{const s=await j("/status");
  $("status").textContent=`ready: ${s.ready}${s.error?" | error: "+esc(s.error):""}`
   +` | 上次熱更新: ${(s.last_reload&&s.last_reload.time)||"从未"}`
   +(s.warnings&&s.warnings.length?"\\n警告: "+s.warnings.map(esc).join("\\n"):"");
 }catch(e){$("status").textContent=e.message}
 lists=await j("/admin/lists");
 $("tabs").innerHTML=FILES.map(f=>`<button class="tab${f===cur?" on":""}" onclick="pick('${f}')">${f}</button>`).join("");
 pick(cur); renderUsers(); renderH();}
function pick(f){cur=f;$("ed").value=lists[f]||"";
 [...$("tabs").children].forEach(b=>b.classList.toggle("on",b.textContent===f));}
async function reloadLists(btn){btn.disabled=true;
 try{const d=await j("/admin/reload",{method:"POST"});
  show($("out"),"已套用:\\n"+JSON.stringify(d,null,1),true);boot();}
 catch(e){show($("out"),"失敗: "+e.message,false)}btn.disabled=false;}
async function saveList(btn,apply){
 // only this button is disabled; a concurrent second apply is answered
 // server-side ("另一個熱更新還在跑"), it never queues silently
 btn.disabled=true;
 const el0=Date.now();let timer=null;
 if(apply)timer=setInterval(async()=>{
  try{const s=await j("/admin/reload/status");
   if(s.busy)show($("out"),"套用中:"+s.phase+"(已 "+s.elapsed_s+" 秒,兩步各有 120s 上限)\\n"+
     "若超過 240 秒仍卡在同一階段,開另一終端機查:"+
     "docker logs opnagent-launcher --since 5m",false);}
  catch(e){}},1500);
 const done=()=>{btn.disabled=false;if(timer){clearInterval(timer);timer=null;}};
 try{const d=await j("/admin/lists",{method:"POST",headers:{"content-type":"application/json"},
   body:JSON.stringify({name:cur,content:$("ed").value,apply:apply})});
  const secs=Math.round((Date.now()-el0)/1000);
  if(d.applied){lists=await j("/admin/lists");$("ed").value=lists[cur];
   show($("out"),"已儲存並套用("+secs+" 秒):\\n"+JSON.stringify(d.result,null,1),true);boot();}
  else if(apply)show($("out"),"檔案已儲存,但政策未套用("+secs+" 秒):\\n"+(d.error||""),false);
  else show($("out"),"已儲存(尚未套用)。可繼續改其他檔,完成後按【熱更新名單】。",true);}
 catch(e){show($("out"),"錯誤(可能未寫檔,重新整理確認): "+e.message,false)}
 done();}
async function renderUsers(){let us=[];
 try{us=await j("/admin/users")}catch(e){show($("uout"),e.message,false);return}
 const tb=$("users").tBodies[0];tb.innerHTML="";
 us.forEach(u=>{const tr=document.createElement("tr");
  tr.innerHTML=`<td>${esc(u.username)}</td><td>${esc(u.role)}</td>`+
   `<td><input data-k type="password" placeholder="(不變更)"></td>`;
  const td=document.createElement("td");
  const mk=(label,fn)=>{const b=document.createElement("button");
   b.className="ghost";b.textContent=label;b.onclick=fn;return b};
  td.append(
   mk("改 passkey",async()=>{const v=tr.querySelector("[data-k]").value;
     if(!v)return;
     try{await j("/admin/users/update",{method:"POST",headers:{"content-type":"application/json"},
       body:JSON.stringify({username:u.username,passkey:v})});
      show($("uout"),u.username+" passkey 已更新(舊工作階段仍有效,下次登入用新值)",true);renderUsers();}
     catch(e){show($("uout"),e.message,false)}}),
   mk("刪除",async()=>{if(!confirm("刪除 "+u.username+" ?"))return;
     try{await j("/admin/users/remove",{method:"POST",headers:{"content-type":"application/json"},
       body:JSON.stringify({username:u.username})});renderUsers();}
     catch(e){show($("uout"),e.message,false)}}));
  tr.append(td);tb.append(tr);});}
async function addUser(btn){btn.disabled=true;
 try{await j("/admin/users/add",{method:"POST",headers:{"content-type":"application/json"},
   body:JSON.stringify({username:$("nu").value.trim(),passkey:$("np").value})});
  $("nu").value=$("np").value="";show($("uout"),"已新增(角色: user)",true);renderUsers();}
 catch(e){show($("uout"),e.message,false)}btn.disabled=false;}
// --- hermes file browser ----------------------------------------------------
let hpath="";
const hfull=n=>hpath?hpath+"/"+n:n;
const fmtB=n=>n==null?"-":n<1024?n+" B":n<1048576?(n/1024).toFixed(1)+" KB"
                       :(n/1048576).toFixed(1)+" MB";
async function renderH(){let d;
 try{d=await j("/admin/hermes/ls?path="+encodeURIComponent(hpath))}
 catch(e){show($("hout"),"列出失敗: "+e.message,false);return}
 $("hpath").textContent=hpath?"~/"+hpath:"~(home)";
 const tb=$("hfiles").tBodies[0];tb.innerHTML="";
 (d.entries||[]).forEach(en=>{const tr=document.createElement("tr");
  const nm=document.createElement("td");
  if(en.dir){const a=document.createElement("a");a.href="#";a.textContent=en.name+"/";
   a.style.color="#7cb7ff";a.onclick=ev=>{ev.preventDefault();hpath=hfull(en.name);renderH()};nm.append(a)}
  else nm.textContent=en.name;
  const sz=document.createElement("td");sz.textContent=en.dir?"-":fmtB(en.size);
  const mt=document.createElement("td");mt.textContent=en.mtime?new Date(en.mtime*1000).toLocaleString():"";
  const td=document.createElement("td");
  const mk=(label,fn)=>{const b=document.createElement("button");
   b.className="ghost";b.textContent=label;b.onclick=fn;b.style.marginLeft=".4rem";return b};
  if(en.dir){
   // fetch+blob (not location.href): the server compresses first, which
   // can take minutes — the button must show that, a navigation can't.
   const go=async()=>{b.disabled=true;
    show($("hout"),en.name+": 壓縮中(大資料夾需要一些時間)…",true);
    try{
     const r=await fetch("/admin/hermes/download_dir?path="
      +encodeURIComponent(hfull(en.name)),{credentials:"same-origin"});
     if(!r.ok){let d;try{d=await r.json()}catch(e){d=null}
      throw new Error((d&&d.detail)||("HTTP "+r.status))}
     const blob=await r.blob();
     const m=(r.headers.get("content-disposition")||"")
      .match(/filename\\*=UTF-8''([^;]+)/);
     const a=document.createElement("a");
     a.href=URL.createObjectURL(blob);
     a.download=m?decodeURIComponent(m[1]):(en.name+".zip");
     document.body.append(a);a.click();a.remove();
     show($("hout"),en.name+": 壓縮下載完成("+fmtB(blob.size)+
      ");沙箱端暫存檔隨後自動清理(殘留最長 7 天)",true);}
    catch(e){show($("hout"),en.name+" 壓縮下載失敗: "+e.message,false)}
    b.disabled=false;};
   const b=mk("下載(zip)",go);td.append(b);
  }else{
   td.append(mk("編輯",()=>hOpenEdit(en.name)));
   td.append(mk("下載",()=>{location.href="/admin/hermes/download?path="
    +encodeURIComponent(hfull(en.name))}));
  }
  td.append(mk("刪除",async()=>{
   if(!confirm((en.dir?"遞歸刪除資料夾(含所有內容):":"刪除檔案:")+en.name+" ?"))return;
   try{await j("/admin/hermes/delete",{method:"POST",headers:{"content-type":"application/json"},
     body:JSON.stringify({path:hfull(en.name)})});renderH();}
   catch(e){show($("hout"),e.message,false)}}));
  tr.append(nm,sz,mt,td);tb.append(tr);});}
function hUp(){const i=hpath.lastIndexOf("/");hpath=i<0?"":hpath.slice(0,i);renderH()}
async function hMkdir(btn){const v=$("nf").value.trim();btn.disabled=true;
 if(!v){show($("hout"),"請輸入資料夾名稱",false);btn.disabled=false;return}
 try{await j("/admin/hermes/mkdir",{method:"POST",headers:{"content-type":"application/json"},
   body:JSON.stringify({path:hfull(v)})});
  $("nf").value="";show($("hout"),"已建立資料夾 "+v,true);renderH();}
 catch(e){show($("hout"),e.message,false)}btn.disabled=false;}
async function hUpload(inp){const files=[...inp.files];inp.value="";
 const done=[],fail=[];
 for(const f of files){const fd=new FormData();
  fd.append("path",hpath);fd.append("file",f,f.name);
  try{await j("/admin/hermes/upload",{method:"POST",body:fd});done.push(f.name)}
  catch(e){fail.push(f.name+": "+e.message)}}
 renderH();
 if(fail.length)show($("hout"),"完成 "+done.length+" 個,失敗 "+fail.length+" 個:\\n"
   +fail.join("\\n"),false);
 else show($("hout"),"已上傳 "+done.length+" 個檔案到 "+(hpath||"home"),true);}
let hedit=null;
function hOpenEdit(name){hedit=name;
 j("/admin/hermes/read?path="+encodeURIComponent(hfull(name))).then(d=>{
   $("heditrow").style.display="flex";$("hed").style.display="block";
   $("heditname").textContent="編輯: ~/"+hfull(name);
   $("hed").value=new TextDecoder().decode(
     Uint8Array.from(atob(d.b64),c=>c.charCodeAt(0)));
  }).catch(e=>show($("hout"),e.message,false));}
function hCloseEdit(){hedit=null;
 $("heditrow").style.display="none";$("hed").style.display="none";}
async function hSave(btn){if(!hedit)return;btn.disabled=true;
 try{await j("/admin/hermes/save",{method:"POST",headers:{"content-type":"application/json"},
   body:JSON.stringify({path:hfull(hedit),content:$("hed").value})});
  show($("hout"),"已儲存 "+hedit,true);renderH();}
 catch(e){show($("hout"),e.message,false)}btn.disabled=false;}
boot();
</script></body></html>
"""
