# refdocs — 上游官方文件快照

本目錄是兩個上游專案官方文件的**唯讀快照**,供離線查證政策生成器
(`launcher/app/policy.py`、`providers.py`)與沙箱 entrypoint 依賴的契約。
改動這些生成器前先讀對應快照;實測與快照不符時( deployed CLI 常領先/
落後文件),以實測為準並在 README 記錄差異。

## 目前快照

| 來源 | 版本 (git tag) | 快照日期 | 對應 pin |
|---|---|---|---|
| [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) `docs/` | `v0.1.4` | 2026-10-18 | `OPENSHELL_IMAGE_TAG=0.1.4`(bootstrap.sh、launcher/Dockerfile CLI) |
| [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) `website/docs/` | `v0.22.2` | 2026-10-18 | `HERMES_REF=v0.22.2`(sandbox/Dockerfile) |

- OpenShell 部分為精選子集(about/policies/providers/gateways/sandboxes/
  supervisor-middleware 共 17 頁),非全樹;hermes 部分為 OpnAgent 依賴面
  精選 9 頁(config.yaml 契約、provider runtime、gateway internals、
  environment-variables、cli-commands、docker 部署、which-file-does-what、
  configuring-models、integrations/providers)。
- 檔案內容與上游逐位元組相同(未改寫);`refdocs/hermes/` 的下層目錄名
  (`user-guide/`、`reference/`、`developer-guide/`、`integrations/`)保留
  上游路徑便於溯源。

## 重新同步

```bash
# OpenShell(替换 <tag> 為目標版本)
git clone --depth 1 --branch <tag> https://github.com/NVIDIA/OpenShell.git
cp openshell/docs/<對應路徑>… refdocs/<對應路徑>

# hermes-agent
git clone --depth 1 --branch <tag> https://github.com/NousResearch/hermes-agent.git
cp hermes/website/docs/<對應路徑>… refdocs/hermes/<對應路徑>
```

同步後務必複查:政策 schema(`policies/schema.mdx`)、profile/provider
契約(`providers/overview.mdx`)、gateway 配置鍵(`gateways/configuration.mdx`)
與 hermes `_KNOWN_PROVIDER_KEYS`/`_API_MODE_ALIASES`
(`hermes_cli/config_providers.py`)是否仍與 policy.py / providers.py /
entrypoint.sh 的生成器一致。
