# OpnAgent
環境配置(測試環境):
作業系統: Linux (Ubuntu Server)
前置軟體: Docker

部屬方法:
1. apt update / upgrade (更新所有系統套件)
2. git clone 此repo
3. 根據需求修改config內設定
4. bash deploy/bootstrap.sh
5. docker compose -f deploy/docker-compose.yml up -d --build



以下部分為LLM生成 待整理
__________________________________________________________________________________
把 [hermes-agent](https://github.com/NousResearch/hermes-agent)(Nous Research)跑在
[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) 的政策沙箱裡,由一組 JSON
設定檔驅動,docker compose 部署。

```
瀏覽器 ─> launcher:8000(users.json 登入 + 反向代理)
              │
              v
         gateway:8080(ghcr.io/nvidia/openshell/gateway,掛宿主 /var/run/docker.sock)
              │  --expose 服務 URL(kernel 政策邊界 + 憑證代理)
              v
   sandbox 容器(opnagent-sandbox:latest,Ubuntu 26.04 + hermes, network=none)
     shim :1800x(收 fake key → 換 OpenShell placeholder)→ hermes-webui :9119
```

## 安全模型(重點)

- **`LLM_Porting_Map.json` 的幾組 LLM API 在沙箱內可直接調用**;每組映射在沙箱內只暴露
  `https?://127.0.0.1:{inner-port}` + `inner-key`(fake key)。
- **真實金鑰只存在 gateway 的 credential store**。OpenShell 在沙箱啟動時把 provider
  對應環境變數換成不透明 placeholder;請求经政策與端點綁定驗證通過,supervisor 才在出口
  換回真 key。fake key/placeholder 拿到別處一律無效(錯 host → 403)。
- 網路出口採 **allow-list-only**:政策未核准的連線一律拒絕(kernel 層 Landlock/seccomp 邊界)。
- 政策把網路規則綁定到執行程式(readlink 解析後的 binary;腳本算它的直譯器,即
  沙箱基底的系統直譯器,目前 ubuntu:26.04 為 `/usr/bin/python3.14`;可在 launcher
  以 `OPN_SANDBOX_PYTHON` 環境變數覆蓋,見 `launcher/app/policy.py` `BIN_PY_PATH`),
  未在規則 `binaries` 清單中的程式完全無法上網(fail-closed:綁定不符時 shim
  出口連線直接 EACCES,LLM 測試表現為 502 `upstream error: [Errno 13] Permission denied`)。

## 宿主需求

| 項目 | 需求 |
|---|---|
| OS | Linux(部署/執行都要;Windows 開發機只能寫碼不能跑) |
| Kernel | **≥ 6.2**(Landlock ABI 3,OpenShell 邊界會 fail-closed 偵測) |
| Docker | **≥ 28.0**,daemon 可訪問 |
| 磁碟 | 映像約 2–3 GB(ubuntu + hermes + gateway) |

## 部署

```bash
# 1) 宿主前置檢查 + 抽取 supervisor binary + build sandbox image + 產生 deploy/.env
bash deploy/bootstrap.sh

# 2) 設定(見下表;LLM_Porting_Map.json 內含真 key,請 chmod 600 config/)
vi config/*.json

# 3) 起 gateway + launcher(launcher 自動 register profile/provider、
#    產生政策、建立 hermes 沙箱、發布 web 入口)
docker compose -f deploy/docker-compose.yml up -d --build

# 4) 驗證
curl http://127.0.0.1:8000/status     # {"ready": true, ...}
# 瀏覽器 http://127.0.0.1:8000 → 登入(admin → 主控台 /admin;user → 直達 hermes)
```

## 設定檔(`config/`,掛載進 launcher,檔名固定)

| 檔案 | 格式 | 效果 |
|---|---|---|
| `LLM_Porting_Map.json` | `{"<http(s)://url>": {"key","inner-port","inner-key"[,"model"][,"context-length"][,"catalog-provider"][,"protocol"]}}` | 每組生成 provider profile + 沙箱內 shim;真 key 進 gateway,沙箱只有 inner-port + fake key(不可重複 port)。建議 https;http 可用但真 key 在 supervisor→上游段為明文(啟動時會警告)。選填 `model`=該端點的模型 id,會預配置進沙箱 hermes(見下);選填 `context-length`(整數 tokens)=寫進 hermes config.yaml **兩處**(model.context_length + 該組 providers.opnN 條目),hermes 直接採用作 step 0、**跳過網路 probe**,消除「Could not determine/fallback 256,000」訊息,`/model` 切組也適用;選填 `catalog-provider`=上游轉售的真實厂商 id(如 `openai`),讓 hermes 用 models.dev 目錄查 metadata/context(僅 metadata,不影響路由);選填 `protocol`=`openai`(預設)/`anthropic`——`anthropic` 表示該組走 Anthropic Messages 線格式(`/v1/messages`,適合 Anthropic 官方或转售 relay),該組 hermes 改用 `transport: anthropic_messages`(hermes 真源码 `_API_MODE_ALIASES` 規範名),fake key 由客户端改放 `x-api-key` header,shim 兩種(Bearer/x-api-key)都驗;出口**仍統一** `Authorization: Bearer <placeholder>`(Anthropic 原生與多數 relay 亦收 Bearer),尚未接 OpenShell 對 `x-api-key` 的出口注入(只收 `x-api-key` 的 relay 需先驗證 profile `auth_style`/`header_name` 支援)。改動要重啟 launcher(進 fingerprint) |
| `url_whitelist.json` | `{"enabled":bool,"list":["host",...]}` | 逐 host 網路 allow(支援 `*.example.com` 萬用字元,至少三段);自動附加 pypi。**改後 `/admin/reload` 免重啟**(見下) |
| `url_blacklist.json` | 同上 | **語意四象限**:白T黑T=白名單減黑名單(黑名單剔除同名白名單條目);白T黑F=只準白名單;白F黑T=**全關閉**(見下,非「全開放」);白F黑F=全關閉(僅 pypi+LLM 映射)。**防呆**:黑名單條目落在白名單萬用字元涵蓋範圍 → **啟動直接報錯**(無法逐 host 擋,拒絕靜默放行,請把該萬用字元改列明確 host)。**`/admin/reload`** |
| `python_pkg_whitelist.json` | `{"enabled":bool,"list":["pkg",...]}` | 僅 allow `pypi.org/simple/<pkg>/`;其他套件 pip 無法解析(強制)。**`/admin/reload`** |
| `python_pkg_blacklist.json` | 同上 | `deny_rules` 擋 `/simple/<pkg>/`、`/json/<pkg>`(deny 勝 allow)。**`/admin/reload`** |
| `users.json` | `{"enabled":bool,"user-list":[{"username","passkey"[,"role"]}]}` | launcher 登入頁 + 8 小時簽名 cookie;passkey 為 64 位 hex 時視為 SHA-256 hash,否則明文。選填 `role`=`admin`/`user`(缺省 `admin`,相容舊檔):admin 登入落 `/admin` 主控台(熱更新名單/編輯名單 JSON/管理使用者),`user` 登入直達 hermes、進不去 `/admin`。Web 上新增的帳號固定 `user`,**role 僅能直接在檔案裡改**;web 管理可新增/改 passkey/刪除,但不可刪最後一個 admin。改檔要重啟,經主控台改則即時生效 |
| `listen.json` | `{"listen_url":"<host>[:port]"}` | web 入口的宿主綁定(預設 `127.0.0.1:8000`,走 ssh -L)。改成 `0.0.0.0:8000` 或內網 IP(如 `192.168.1.50:8000`)即可讓其他電腦直接連、免 ssh。**生效要重跑 `bash deploy/bootstrap.sh`**(把值鏡像進 `deploy/.env`,compose 的 host 綁定從那讀,`up -d launcher` 重建容器;改動只 restart 不會換綁定)。防線:users.json 登入未啟用時,launcher 直接拒起非 loopback 綁定;http 明文本質不變,長期給群組用仍建議 TLS reverse proxy。gateway :8080 不受影響,永遠 127.0.0.1 |

**Web 主控台 `/admin`(admin 角色限定)**:admin 登入後落地此頁(一般
`user` 直達 hermes、進不來)。四個功能:**進入 Hermes**、**熱更新名單**、
**名單 JSON 編輯器**(四份名單檔;驗證 → 寫檔;【只儲存】可先批量改多檔、
最後一次【熱更新名單】,【儲存並套用】則一步生效)、
**使用者管理**(新增帳號固定 `user` 角色;改 passkey 後舊 session cookie
仍有效,下次登入才用新值)、
**Hermes 檔案管理**(瀏覽沙箱 home——`~/.hermes`、`~/workspace` 皆可進去;
檔案【下載】/【編輯】/【刪除】、【上傳】(多檔,到目前目錄)、文字檔編輯後
【儲存】(≤2MB,經 upload 覆寫)、資料夾【建立】/【刪除】(遞歸,UI 先
confirm)。實作走 `openshell sandbox exec` 的驗證過 python3 腳本與
`sandbox upload/download`;路徑一律 home 相對、拒 `..`/絕對路徑/引號類字元,
CLI 本身另有 working-dir 範圍防護。对应 API:
`GET /admin/hermes/ls|read|download?path=`、`POST /admin/hermes/mkdir|delete`
(body `{"path":...}`)、`POST /admin/hermes/save`(body `{"path","content"}`)、
`POST /admin/hermes/upload`(multipart,欄位 `path`+`file`),皆 admin only)。套用期間頁面每 1.5 秒輪詢 `GET /admin/reload/status`
顯示目前階段與秒數(`policy get` 與 `policy set --wait` 各有 120s 上限,超過
4 分鐘必回錯,不會無限卡死;鎖被佔用時新請求直接早退並提示稍後再按,不再無聲
排隊)。為讓 launcher 寫回檔案,`/config` 在 compose
以 **rw** 掛載(真 key 仍靠宿主 `chmod 600 config/` 保護);
LLM_Porting_Map(真 key)與 listen.json **永不進瀏覽器**、不可線上改。
注意主控台與 passkey/名單都走站內 http——入口預設僅 loopback,開放內網
前請置入 TLS reverse proxy。

**名單四檔免重啟**(url 白/黑 + python_pkg 白/黑):主控台內儲存即套用;
在宿主手動改檔後按【熱更新名單】,或
`curl -b "<admin cookie>" -X POST http://127.0.0.1:8000/admin/reload`
——launcher 取回沙箱 **base policy**、只替換 `network_policies` 段,再以
`openshell policy set --wait` 熱套用,沙箱與 hermes **不重啟**。注意:新規則
載入時,舊規則下開著的長連線(keep-alive / WebSocket / LLM stream)會被關閉,
客戶端下次請求自行重連;結果記錄在 `/status` 的 `last_reload`。LLM_Porting_Map
/ listen 改動仍要重啟(喂 provider、shim、host 綁定,非熱更新範圍,端點會回
400 拒絕);users.json **走檔案**改動同样要重啟——帳號相關請直接用主控台。

其余設定檔改動後:`docker compose -f deploy/docker-compose.yml restart launcher`
(profile/provider 冪等重試)。改 launcher **程式碼**則要
`up -d --build launcher`(restart 不會重 build 映像)。`listen.json` 是例外,
见上表要重跑 bootstrap + `up -d launcher`。

**沙箱重建的 hermes 資料保護**(LLM_Porting_Map 等 create 期欄位改動必須重建
沙箱——`OPN_SHIM_SPEC` 是 create 時注入的 env,跑著的沙箱改不了;而
`sandbox delete` 連 compute 帶 workspace 一併清除):
- **spec 沒變就不重建**:launcher 每次啟動比對「镜像+shim spec+providers+policy」
  雜湊(存宿主 `backups/applied-spec.json`)與目前運行中的沙箱,相同 → 原地保留,
  零中斷。改 launcher 程式碼重啟、重跑 `up -d` 都走這條。
- **要重建就自動搬**:刪除前經 exec 通道把 `~/.hermes`(對話/會話)+ `~/workspace`
  壓縮拉回宿主 `backups/<沙箱>-時間戳/`(保留最近 5 組,`OPN_BACKUP_SETS_KEPT`
  可調),新沙箱起來後解壓回 home;entrypoint 自己生成的
  `config.yaml`/`.env`/`gateway_state.json` **不覆壞**(API_SERVER_KEY 是每次
  開機重鑰的)。**備份失敗 → 中止重建**,原沙箱原封不動(fail-closed);
  還原失敗不中止(沙箱已重建),備份保留在 `backups/` 可人工復原,
  `/status` 的 `hermes_restore` 會顯示結果。
- **可重生的快取不入備份**:`profiles/*/cache`、`profiles/*/home/.cache`、
  `.hermes/cache`(hermes 工具下載快取 + scratch,實測佔 2.9 GB 裡的 2.0 GB)
  由 `BACKUP_EXCLUDE` 排除,新沙箱要用時 hermes 自己會重抓;agent 裝好的
  SDK(`profiles/*/home/dotnet`、`.local`)留著,慢線環境重抓太貴。
  上調大小上限 `OPN_BACKUP_MAX_BYTES`(compose 已放 5 GiB)並可把保留組數
  調小省宿主磁碟;要改排除清單用 `OPN_BACKUP_EXCLUDE`(JSON)。
- **重建 sandbox 映像要走 `bash deploy/bootstrap.sh`**——它除了 `docker build`
  還會失效雜湊,下次重啟便自動走「備份→重建→還原」;直接手 build 不會觸發重建。
- 注意:map 的 `key`(真 API 金鑰)**不在**雜湊內——改 key 不會重建沙箱,且
  provider create 對已存在者跳過;輪換真鑰仍需 gateway 端刪建 provider。

**hermes 模型設定(webui 不需要 `hermes model`)**:沙箱 entrypoint 每次啟動
都依 LLM_Porting_Map 自動產生 `~/.hermes/config.yaml`——每組映射都是命名條目
`providers.OpnAgentAPI<N>`(fake key inline 在條目內),`model.provider:
OpnAgentAPI<預設索引>` 直接綁定;entrypoint 同時為每條導出
`OPNAGENTAPI<N>_API_KEY`(hermes 對「非預設」命名 provider 的金鑰契約,缺它
切換會報 "no API key was found. Set the ..._API_KEY";實測只有 process-env
導出會被解析器忽略,故**同時**導出 env 並寫進 `~/.hermes/.env`——後者是
webui 讀 `API_SERVER_KEY` 的同一條有效路徑)。**不再用匿名
`provider: custom` + `OPENAI_API_KEY`/`OPENAI_BASE_URL`
env**——那對變數名是 openai provider 的憑證契約(webui 金鑰頁會把 fake key
顯示成 openai 的金鑰,runtime 也會把 base_url==OPENAI_BASE_URL 的路由判成
openai),命名條目才能让 fake key/URL 只出現在自己的 provider slug 下。對話中
用 `/model OpnAgentAPI<N>:<model>` 選擇/切換;不寫 `model` 欄位時由 hermes 自行探索
端點的模型清單。在沙箱內手跑
`hermes model` 可以,但沙箱重建時會被覆蓋(entrypoint 註解有標)。
**web 介面 = [hermes-webui](https://github.com/nesquena/hermes-webui)(非 hermes 內建
dashboard)**:映像 build 期 `git clone` 到 `/opt/hermes-webui`(純 Python+vanilla JS,
無 build step;依賴只有 pyyaml+cryptography,pip 進 hermes venv),entrypoint 用
`/opt/hermes-venv/bin/python server.py` 起在 :9119(policy 把該 checkout 掛唯讀,
state 寫 HOME/.hermes/webui)。它以 **in-process 方式跑 hermes agent、直接讀上面那份
config.yaml**,fake key/shim 接線完全沿用。換版:`--build-arg HERMES_WEBUI_REF=<tag>`
(目前 v0.52.458)。排程(cron)的 tick 由 **`hermes gateway run` daemon** 驅動
(webui 本身不排程,官方 docker.md 有載),entrypoint 以背景程序拉起,日誌
`/tmp/opn-gateway.log`;webui 讀 `~/.hermes/gateway_state.json` 顯示狀態。
另:手動 "Run now" 走 multiprocessing spawn 子進程,`sem_open()` 需要
`/dev/shm` 可寫(政策已加)。hermes 內建 dashboard/TUI 仍燒在映像裡,僅作 server.py 缺席時的
fallback 與沙箱內手動 CLI 用。
舊 webui 內嵌 chat 是 Node TUI(0.21 起 `node --expose-gc /opt/hermes/ui-tui/dist/entry.js`,
由映像 build 期跑 npm/vite 預組,`HERMES_TUI_DIR`/`HERMES_WEB_DIST` 指向預組產物),
沙箱映像已預燒 Node 26(`/usr/local/node` + PATH symlink),
故 **nodejs.org 不需要進 url 白名單**;缺 node 時 chat 會報
`Chat unavailable: 1`(`_make_tui_argv` sys.exit(1))。

**SQLite(pin 版)**:ubuntu 基底附帶的 libsqlite3 太舊(24.04 時代是
3.45.1)有 WAL-reset corruption bug(hermes 啟動會警告並把 state db 降為
`journal_mode=DELETE`)。
Dockerfile 從源碼 build **固定版** `SQLITE_VER=3.53.4`(tarball 在
`sqlite.org/<SQLITE_YEAR>/`,升版兩個 ARG 一起改)裝進 `/usr/local`,
ldconfig 讓系統 python3 的 stdlib sqlite3 載到新庫;build 最後一行 assert
会在 pin 與實際載入版本不符時直接失敗,不會靜默漂移。

**hermes 版本**:0.20 起 PyPI 不再是發布管道(wheel 拒 build、資產改 runtime
解析),沙箱映像改從 GitHub 日期標籤 `git clone` 來源Checkout(/opt/hermes,
政策上唯讀)+ `pip install -e`。換版:`docker build -t opnagent-sandbox:latest
--build-arg HERMES_REF=<tag> sandbox` 後重啟 launcher(目前 v0.22.2;
版本標籤與日期標籤皆可,`git ls-remote --tags` 可查)。

## 驗證清單

```bash
docker ps                                        # gateway + launcher(+ 執行期 sandbox/supervisor 兄弟容器)
curl -s http://127.0.0.1:8000/status
OPENSHELL="docker exec -it opnagent-launcher openshell"   # gateway 映像 distroless,CLI 只在 launcher
openshell sandbox get opnagent                   # Ready?
openshell logs opnagent --tail
# 政策生效:
openshell sandbox exec -n opnagent -- curl -s https://example.com   # 未白名單 → 拒絕
openshell sandbox exec -n opnagent -- pip install <黑名單pkg>        # 失敗
# 真 key 不外洩:
openshell sandbox exec -n opnagent -- env | grep -i OPNL_          # 只有 placeholder
```

## 已知限制(老實說)

1. **「全開放 + 黑名單減除」在 OpenShell 无法实现(已查官方文件定案)** —
   連線層是 allow-list-only,而政策語言**表達不出「allow 一切」**:萬用字元
   host 至少三段(`example.com` 這種兩段網域無法用萬用字元涵蓋)、hostless
   端點只能靠 allowed_ips 且 0.0.0.0/0 因涵蓋 loopback 等被拒;
   `deny_rules` 必須綁「 inspected 協議」的端點,`protocol: tcp` 不收任何規則;
   官方文件明載 supervisor middleware「只看到政策已允許的流量」(只能加擋、
   不能放行)。所以白名單 disabled 時一律**全關閉**(fail-closed),黑名單僅在
   白名單開啟且條目**同名完全相符**時剔除;黑名單被白名單萬用字元涵蓋會
   **啟動報錯**而非靜默放行(python 套件黑名單不受影響,走 pypi deny_rules
   有效)。真需要「大範圍放行+少量黑名單」:把白名單寫成明確列舉(可大量),
   黑名單減同名條目;更進階只能走自寫 supervisor middleware(gRPC)扩大
   過濾面——`gateway.toml.example` 留有位置,但它改的是「已允許流量再擋」,
   「全開放」本身仍表達不了。
2. **command 黑白名單本輪未實作**(OpenShell 無 exec 白名單機制;已與需求方確認取消)。
3. `files.pythonhosted.org` 的 wheel URL 是內容 hash,無法按套件名過濾——
   套件級管制生效點在 `pypi.org/simple/<pkg>`(pip 解析必經)。直接知道 URL 的
   下載只能靠白名單模式全擋。
4. 沙箱內任何程式都能用注入的 placeholder 呼叫「已映射」的 LLM 組(內部直接調用=
   設計目標);防線是真 key 不出 gateway。組間配額隔離不在 v1。
5. Gateway 以 `OPENSHELL_DISABLE_TLS=true` 跑在 compose 私網,宿主只綁
   `127.0.0.1:8080/:8000`。因無 TLS 也無客戶端憑證,`deploy/gateway.toml`
   開啟官方文件所載的開發用逃生口
   (`[openshell.gateway.auth] allow_unauthenticated_users = true`,否則
   docker 驅動拒絕 `sandbox create`);防線是 127.0.0.1 綁定 + launcher
   登入頁,**絕不可**把 8080 暴露到任何網路。要給群組/外部用,請置于
   TLS reverse proxy 後,或依官方文件啟用 mTLS(`generate-certs`)。
6a. **plugin_compat 警告(已修)**:`tools.approval.
   reset_current_session_key moved to tools.approval_context…` 過去來自
   hermes-webui 自己的舊路徑 import(streaming.py;hermes 對 external plugin
   保留 shim,故僅警告)。webui 自 v0.52.458 起改走 `api/agent_compat.py`
   的 `agent_attr()`:先看舊模組自己的 namespace(不含 PEP 562 `__getattr__`
   指標),再導向新模組 `tools.approval_context`,因此同時相容拆分前/後的
   hermes 且**不再觸發**該警告。**升 `HERMES_REF` 前仍要確認 webui 版有
   `agent_attr` 這層**(缺它 approval/session-key 鏈會 ImportError);
   不要用 sed 補 webui checkout(破壞映像=乾淨 tag 的溯源原則)。
6. 介面鏈為 hermes-webui → (server.py 缺席時)hermes `dashboard` → `hermes serve`,
   entrypoint 已內含偵測。hermes-webui 的串流走 SSE(非 WS),launcher proxy 逐塊
   直通;若某版改回 WS,launcher 的 catch-all WS 路由(`/{path:path}`)已覆蓋。
   另注意 hermes-webui 與 hermes-agent 是獨立版本管道(in-process 匯入 agent),
   升 hermes 後若 webui 報 import/API 錯,先試 `HERMES_WEBUI_REF` 較新 tag。
7. 換 LLM 真 key 或改動端點/路徑後重啟 launcher:已存在的 provider 憑證不會自動
   覆蓋、已 import 的 profile 也不會被新版本替換(lint/import 只容忍「已存在」)
   — 請先在 gateway 端刪除舊 provider 與 profile 再重啟 launcher。

## 開發除錯

- 離線測試(不需要 Docker/Linux,任何機器可跑):
  ```bash
  pip install -r launcher/requirements.txt
  python tests/test_smoke.py        # 設定解析 / profile & policy 生成 / auth / shim 邏輯 / 名單熱更新
  python tests/test_shim_live.py    # shim 實戰:假 key 拒絕、placeholder 改寫、SSE 串流
  python tests/probe_launcher.py    # launcher web 實跑:登入/cookie/503 未就緒/路由不遮蔽 hermes
  ```
- `refdocs/` 是官方文件快照:**OpenShell v0.1.4**(政策/provider/容器部署,
  `refdocs/how-it-works|about|extensibility/`)與 **hermes-agent v0.22.2**
  精選(`refdocs/hermes/`:config.yaml 契約、provider runtime、gateway
  internals、env 變數、CLI、docker 部署)。改政策生成器或 entrypoint 的
  hermes 契約生成前必讀對應快照(溯源與同步方式見 `refdocs/README.md`)。
- launcher 日誌:`docker logs -f opnagent-launcher`(`bootstrap failed: ...` 帶原因)。
- shim 日誌在沙箱內 `/tmp/opn-shim-*.log`;`openshell sandbox exec -n opnagent -- cat /tmp/opn-shim-0.log`。
- 本機(Windows)只能改碼;所有 build/測試在 Linux 宿主進行。
