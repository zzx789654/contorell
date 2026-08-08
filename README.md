# contorell — AD 權限比對管理系統

以 **AD 使用者為權威來源**，把 AD 群組與其他系統帳號（或其他 AD 群組）拉在一起比對差異，
找出「該給沒給、該收沒收」的權限，並在自訂欄位中留下處置說明。

> **本系統為唯讀稽核工具**：只比對與記錄，**不會**修改 AD 或任何外部系統的帳號與權限。
> 這是刻意的設計決策——AD 服務帳號只需最小權限、誤操作風險趨近零。

---

## 核心概念（只有四個）

```
資料來源（Source） → 快照（Snapshot） → 比對（Comparison） → 標註（Annotation）
```

| 概念 | 說明 |
|---|---|
| **資料來源** | 帳號從哪來。三種型態共用同一個介面：**LDAP**（AD 群組）、**API**（外部系統 REST）、**檔案**（Excel/CSV） |
| **快照** | 某一時刻抓到的完整名單。保存快照才能做「這次 vs 上次」的變更追蹤 |
| **比對** | 任兩個來源的差異，分成四種狀態並判定風險等級 |
| **標註** | 管理者對每筆差異填寫的自訂欄位（處理狀態、負責人、說明） |

## 比對結果的四種狀態與風險判定

| 狀態 | 意義 | 風險 |
|---|---|---|
| **屬性不一致** | AD 已停用，但外部系統仍啟用 | 🔴 **高** — 離職者仍可登入該系統 |
| **僅存在於 B** | 外部系統有啟用帳號，AD 查無此人 | 🔴 **高** — 孤兒帳號 |
| **僅存在於 B** | 外部帳號已停用，AD 查無此人 | 🟠 中 — 應確認是否刪除 |
| **僅存在於 A** | AD 有此人，外部系統未開通 | 🟡 低 — 權限缺漏，非安全問題 |
| **相符** | 兩邊一致 | — |

---

## 選擇部署方式（先看這個）

兩種方式**功能完全相同**（同一份程式碼），差別只在「怎麼把服務跑起來、資料放哪」。
挑一個，往下看它**自己那一節**即可，不必兩節交叉讀。

| | 🐳 **Docker** | 🖥️ **本機原生（Ubuntu）** |
|---|---|---|
| 適合 | 快速試用；內含模擬 AD 測試環境 | 正式跑在一台 Ubuntu 主機、不想裝 Docker |
| 需要 | Docker Engine + Compose v2 | Python 3.12+（沒有就裝 `uv`，腳本會自帶） |
| 資料庫 | 容器內 PostgreSQL | **SQLite 單檔** 或 本機 PostgreSQL |
| 常駐方式 | `docker compose` | **systemd 服務**（開機自啟、崩潰重啟） |
| 往下看 | [**方式一：Docker**](#方式一docker) | [**方式二：本機原生**](#方式二本機原生ubuntu) |

> 兩種方式都會用到設定檔 `.env`，開始前先讀一次下面這節。

---

## 設定檔 `.env`（兩種方式共用）

**日常只需要編輯一個檔案：專案根目錄的 `.env`。** 所有連線資訊與金鑰都集中在這。

> **🔎 剛 clone 下來找不到 `.env`？這是正常的。**
> `.env` 內含金鑰與密碼，**刻意不進版控**（列在 `.gitignore`），所以 clone 下來只有範本 `.env.example`。
> **執行 `scripts/install.sh` 後 `.env` 才會出現**（從範本自動建立並填好金鑰），接著才能編輯它。

| 檔案路徑 | 版控狀態 | 需要編輯嗎 |
|---|---|---|
| **`./.env`** | 🚫 不進版控（`install.sh` 後才產生） | ✅ **要**——你唯一要編輯的設定檔 |
| `./.env.example` | ✅ clone 就有 | ❌ 唯讀範本，勿直接改 |
| `./docker-compose.yml` | ✅ clone 就有 | ⚙️ 通常不用（對外綁定改 `.env` 的 `APP_BIND` 即可） |

編輯（`install.sh` 已產生金鑰，通常只需視環境補這幾類）：

```bash
$EDITOR .env        # 或 vim / nano / code .env
```

| 欄位 | 什麼時候改 |
|---|---|
| `LDAP_HOST`／`LDAP_BASE_DN`／`LDAP_BIND_DN`／`LDAP_BIND_PASSWORD` | **接真實 AD 時必填**（唯讀服務帳號，非 Domain Admin） |
| `LDAP_VERIFY_CERT`／`LDAP_CA_CERT_FILE` | 正式環境務必 `true` 並提供企業 CA 憑證路徑 |
| `APP_BIND` | 要讓其他網段連進來時設 `0.0.0.0`（見[跨網段連線](#讓其他網段的-ip-連線到網頁)） |
| `APP_ENV` | 上正式環境時設 `production`（啟用 HSTS／secure cookie／關閉 API 文件） |
| `SECRET_KEY`／`POSTGRES_PASSWORD`／`BOOTSTRAP_ADMIN_PASSWORD` | **通常不用改**（已自動產生；要重產用 `install.sh --force`） |

> ⚠️ `.env` 內含密鑰、權限為 `600`、已列入 `.gitignore`，**絕不可提交進版控**。完整欄位說明見 [`.env.example`](.env.example) 內註解。

---

# 方式一：Docker

> 環境需求：**Docker Engine + Compose v2**。全程三個指令：安裝 → 部署 → 測試。

## 1. 安裝（Docker）

```bash
scripts/install.sh          # 產生 .env 與金鑰、build 映像（把所有套件裝進映像），並建 .venv 供本機測試
```

- **冪等**：已存在的 `.env` 不覆寫，只補仍是 `CHANGE_ME` 的欄位。
- **金鑰安全**：`SECRET_KEY`／各密碼在本機產生後直接寫入 `.env`，**不印到終端機**。
- 其他旗標：`--no-deps`（只產生 `.env`、不裝套件）、`--force`（重產所有金鑰，先備份舊 `.env`）、`--admin-user NAME`。
- 裝完若要接真實 AD，依上面[設定檔 `.env`](#設定檔-env兩種方式共用)補 `LDAP_*` 欄位。

## 2. 部署（Docker）

```bash
scripts/deploy.sh                               # 開發部署（db + 內建模擬 AD DC + app）
scripts/deploy.sh --env production --no-samba   # 正式部署（接真實 AD，執行安全關卡）
```

部署流程（五步，任一步失敗自動回滾、保留資料）：

1. **前置驗證** — `.env` 存在；`SECRET_KEY`／`POSTGRES_PASSWORD`／`BOOTSTRAP_ADMIN_PASSWORD` 不得是佔位符；`SECRET_KEY` ≥ 32 字元。
2. **正式環境安全關卡**（`--env production`）— 強制 `LDAP_VERIFY_CERT=true`、須 `--no-samba` 接真實 AD、管理員密碼 ≥ 16；**未過即拒絕**。
3. **建置並啟動** — `docker compose up -d --build`。
4. **健康檢查** — 等 app 容器 `healthy`，逾時即回滾。
5. **煙霧測試** — 驗證 `/login`、授權導向與安全標頭；失敗自動 `docker compose down` 回滾。

完成後開啟 <http://localhost:8000>（預設管理員帳號 `admin`，密碼在 `.env`）。

常用管理：

| 動作 | 指令 |
|---|---|
| 追蹤 app 即時 log | `scripts/deploy.sh --logs` |
| 停止（保留資料卷） | `scripts/deploy.sh --down` |
| 回滾（停掉這批容器） | `scripts/deploy.sh --rollback` |
| 連資料一併清除 | `docker compose down -v` |

## 3. 測試（Docker）

`install.sh` 已把 `pytest` 等裝進專案的 `.venv`，直接用 `make`（自動使用 `.venv`）：

```bash
make test          # 完整測試套件（含覆蓋率）
```

> 也可先 `source .venv/bin/activate` 再 `pytest tests/ -v`。
> 出現 `ModuleNotFoundError`？多半是沒用 `.venv`——改用 `make test`，或補跑 `scripts/install.sh`。

---

# 方式二：本機原生（Ubuntu）

> 環境需求：**Python 3.12+**（沒有就裝 `uv`，腳本會自帶）。**不需要 Docker**。
> 服務會註冊成 **systemd 常駐**（開機自啟、崩潰自動重啟、非 root、附沙箱強化）。
>
> 之所以能輕鬆脫離 Docker：本應用**執行期不寫檔**（Excel 匯出走記憶體串流）、
> 資料模型**不依賴 PostgreSQL 專屬型別**，因此原生部署只需要「venv + 資料庫 + systemd」。

## 1. 安裝（本機原生）

```bash
scripts/install.sh --mode local     # 建 .venv、自動安裝所有套件（含 uvicorn/pytest）、產生 .env 與金鑰
```

- 會在專案下建立 `.venv` 並裝齊相依；`.env` 的 `DATABASE_URL` 預設指向本機。
- 裝完若要接真實 AD，依上面[設定檔 `.env`](#設定檔-env兩種方式共用)補 `LDAP_*` 欄位。

## 2. 部署（本機原生，systemd）

資料庫二選一：

**（最簡）SQLite — 零額外服務：**

```bash
sudo scripts/deploy-native.sh --sqlite      # 用檔案型 SQLite，裝好 systemd 服務並啟動
```

**（正式）PostgreSQL — 自動安裝並設定：**

```bash
sudo scripts/deploy-native.sh --with-db     # apt 裝 PostgreSQL、用 .env 帳密建 role/db、再啟動
```

> 已有自架資料庫？在 `.env` 把 `DATABASE_URL` 指過去，然後只跑 `sudo scripts/deploy-native.sh`（不加旗標）。

部署腳本做的事（五步）：**① apt 系統相依 → ② 建 `.venv` 裝套件 → ③ 準備資料庫（資料表啟動時自動建立）→ ④ 產生 `/etc/systemd/system/contorell.service` 並 `enable --now` → ⑤ 健康檢查 + 煙霧測試（失敗印出 `journalctl` 最近 log）**。

完成後開啟 <http://127.0.0.1:8000>（預設管理員帳號 `admin`，密碼在 `.env`）。

可用旗標：

| 參數 | 用途 |
|---|---|
| `--sqlite` | 用檔案型 SQLite（不裝資料庫服務） |
| `--with-db` | 在本機 apt 安裝並設定 PostgreSQL |
| `--port 8080` | 指定監聽埠（預設 8000） |
| `--service-user contorell` | 用專屬系統帳號跑服務（預設用執行者帳號） |

管理服務：

| 動作 | 指令 |
|---|---|
| 服務狀態 | `scripts/deploy-native.sh --status`（或 `systemctl status contorell`） |
| 即時 log | `scripts/deploy-native.sh --logs`（或 `journalctl -u contorell -f`） |
| 重啟／停止 | `scripts/deploy-native.sh --restart` ／ `--stop` |
| 更新程式後重部署 | `git pull && sudo scripts/deploy-native.sh` |
| 移除服務 | `scripts/deploy-native.sh --uninstall`（保留 venv／.env／資料庫） |

> `make` 捷徑：`make deploy-native`、`make deploy-native-sqlite`、`make native-status`、`make native-logs`。

## 3. 測試（本機原生）

與 Docker 相同——`install.sh --mode local` 已把測試工具裝進 `.venv`：

```bash
make test          # 完整測試套件（含覆蓋率）
```

> 也可先 `source .venv/bin/activate` 再 `pytest tests/ -v`。

---

## 讓其他網段的 IP 連線到網頁

**預設只有執行主機自己（`127.0.0.1`）連得到**——這是刻意的安全預設。要讓別的電腦用瀏覽器連進來：

**Docker：** 在 `.env` 設 `APP_BIND=0.0.0.0`，重跑 `scripts/deploy.sh`。
**本機原生：** 在 `.env` 設 `APP_BIND=0.0.0.0`，重跑 `sudo scripts/deploy-native.sh`（或直接 `uvicorn app.main:app --host 0.0.0.0 --port 8000`）。

然後其他電腦以「**執行主機的 IP**」連線，例如 `http://192.168.1.50:8000`。

還要打通防火牆（否則封包到不了）：

```bash
# Ubuntu/Debian（ufw）— 建議只放行特定網段
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp
# RHEL/CentOS（firewalld）
sudo firewall-cmd --add-port=8000/tcp --permanent && sudo firewall-cmd --reload
# Windows Server
New-NetFirewallRule -DisplayName "contorell 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

查主機 IP：`ip addr`（Linux）／`ipconfig`（Windows）。跨網段時另需路由/NAT 可達（屬你的網路環境）。

### ⚠️ 安全提醒（務必看）

- 對外的是**明文 HTTP**，只適合**受信任的內網測試**。本系統集中儲存全公司帳號權限資料，是高價值目標。
- **正式環境不要直接對外暴露 8000**：前面架 **HTTPS 反向代理**（nginx／Caddy／Traefik），對外只開 443，`APP_BIND` 維持 `127.0.0.1`。
- `APP_ENV=production` 會啟用 **secure cookie（僅限 HTTPS）**——在正式模式下走明文 HTTP 會**登不進去**。內網測試請維持 `development`。
- 防火牆盡量**只放行需要的來源網段**，不要對整個網際網路開放。

---

## Windows Server 版本相容性

本系統支援 **Windows Server 2016 / 2019 / 2022 / 2025**。各版本的預設安全策略差異很大，
程式碼一律**自動協商**而非寫死（詳見 [`docs/SRS.md`](docs/SRS.md) 第 5.1 節）。

| 特性 | WS 2016 | WS 2019 | WS 2022 | WS 2025 |
|---|---|---|---|---|
| LDAP Signing 預設 | 未強制 | 未強制 | 未強制 | **預設要求** |
| Channel Binding | Never | Never | Never | **When Supported** |
| TLS 1.3 | ❌ | ❌ | ❌ | ✅ |
| TLS 1.2 | ✅ | ✅ | ✅ | ✅ |
| RC4 | 可用 | 可用 | 可用 | **已棄用** |
| 查詢筆數上限 | 1000 | 1000 | 1000 | 1000 |

**兩個最容易踩的坑**：

1. **WS2025 預設要求 LDAP signing** — 寫死 simple bind over 389 會直接連不上。
   本系統優先用 NTLM（協商 signing），失敗才退回 TLS 通道內的 simple bind。
2. **AD 單次查詢只回 1000 筆，且不會報錯** — 未分頁會**靜默截斷**，
   產出看起來正常但實際錯誤的稽核結論。本系統一律使用分頁查詢，
   並在 UI 顯示來源筆數供人工交叉檢查。

連線失敗時，請用**資料來源頁的「測試連線」**功能——它會顯示實際協商到的
TLS 版本、bind 方式與憑證驗證狀態，而不是只給一句 "bind failed"。

---

## 安全設計

| 面向 | 措施 |
|---|---|
| **傳輸** | 強制 LDAPS/StartTLS，明文 389 bind 被程式**直接拒絕**，不提供繞過選項 |
| **憑證儲存** | AD 密碼、API 金鑰以 Fernet 加密入庫；本地密碼以 argon2id 雜湊 |
| **AD 登入** | 以使用者帳密做 LDAP bind 驗證，**帳密絕不儲存** |
| **注入防護** | LDAP filter 一律經 RFC 4515 轉義（CWE-90）；SQL 全數參數化 |
| **SSRF** | 外部 API 目標位址阻擋 loopback／內網／雲端 metadata，重導向逐跳重驗（CWE-918） |
| **CSRF** | synchronizer token + SameSite=strict + Origin 比對（CWE-352） |
| **暴力破解** | 帳號鎖定 + 身分層級節流；帳號名正規化防大小寫變形繞過 |
| **授權** | 一律伺服器端判斷，角色每次請求從 DB 重讀（降權即時生效） |
| **匯出** | CSV/Excel 公式注入防護（CWE-1236） |
| **稽核** | 抓取、比對、標註、設定變更、登入皆留軌跡 |

### 正式環境部署檢查清單

- [ ] `APP_ENV=production`（關閉 API 文件、啟用 HSTS 與 secure cookie）
- [ ] `SECRET_KEY` 為隨機產生的高熵值，且**與開發環境不同**
- [ ] `LDAP_VERIFY_CERT=true`，並提供企業 CA 憑證（`LDAP_CA_CERT_FILE`）
- [ ] AD 服務帳號為**唯讀**權限，非 Domain Admin
- [ ] 服務置於 HTTPS 反向代理之後
- [ ] 資料庫帳號只授予必要權限；`audit_logs` 表建議設為僅可 INSERT/SELECT
- [ ] 若外部 API 皆為內網系統，設定 `allowed_hosts` 允許清單（優於開啟 `allow_private_network`）

---

## 角色與權限

| 角色 | 可執行 |
|---|---|
| **管理者（admin）** | 設定資料來源、執行比對、填寫標註、匯出、查看稽核軌跡 |
| **稽核者（auditor）** | **唯讀** — 查看比對結果、匯出、查看稽核軌跡 |

> 由 AD 登入自動建立的使用者，預設角色為**稽核者**（最小權限），需由管理者手動升級。

---

## 專案文件

| 文件 | 內容 |
|---|---|
| [`CoreMain.md`](CoreMain.md) | 專案中心思想、範圍邊界、設計原則 |
| [`docs/SRS.md`](docs/SRS.md) | 需求規格：14 條功能需求、12 條非功能需求、AD 相容性矩陣、驗收標準 |
| [`docs/UX-Design.md`](docs/UX-Design.md) | Persona、痛點、使用者旅程、資訊架構、可用性標準 |
| [`待修改.md`](待修改.md) | 開發計畫、三維度 Exit Criteria、關卡狀態、已知風險 |
| [`lessons.md`](lessons.md) | 每輪開發紀錄與可操作教訓 |

## 專案結構

```
app/
├── security/          # LDAP 轉義、加密、CSRF、SSRF 防護
├── providers/         # 三種資料來源（共用 AccountProvider 介面）
├── comparison/        # 比對引擎（不知道資料從哪來）
├── auth/              # 雙軌認證（AD bind + 本地退路）
├── db/                # 資料模型與 session
├── export/            # Excel / CSV 匯出
└── web/               # 路由、模板、靜態資源
scripts/               # 自動化安裝與部署
├── install.sh         # 一鍵安裝：產生 .env 與金鑰、自動裝套件（建 .venv）
├── deploy.sh          # Docker 部署：建置→啟動→健康檢查→煙霧測試，失敗自動回滾
├── deploy-native.sh   # 原生部署（不用 Docker）：venv + 資料庫 + systemd 服務
├── smoke-test.sh      # 部署後煙霧測試（可指向 staging/prod）
└── lib.sh             # 共用函式庫
Makefile               # 常用指令捷徑（make help 看全部）
```
