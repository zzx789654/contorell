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

## 快速開始（自動化，兩個指令）

專案內附一鍵安裝與部署腳本，把「複製 `.env` → 產生高熵金鑰 → 檢查前置條件 →
建置 → 部署 → 健康檢查 → 煙霧測試 → 失敗回滾」這串每個人都要做、又最容易做錯的步驟自動化。

```bash
scripts/install.sh      # ① 安裝：產生 .env 與所有金鑰、檢查 Docker/Python
scripts/deploy.sh       # ② 部署：建置 → 起服務 → 健康檢查 → 煙霧測試（含模擬 AD）
```

完成後開啟 <http://localhost:8000>（預設管理員帳號 `admin`，密碼由 `install.sh` 隨機產生於 `.env`）。

> 也可用 `make install && make deploy`——`Makefile` 只是這些腳本的薄封裝，`make help` 看全部指令。

環境需求：**Docker Engine + Compose v2**（Docker 模式）或 **Python 3.12+**（本機模式）。
腳本會自行偵測並在缺少時給出安裝提示。詳細用法見下方
[「自動化安裝與部署」](#自動化安裝與部署)。

### 執行測試

```bash
pytest tests/ -v                                  # 全部測試
pytest tests/ --cov=app --cov-report=term-missing # 含覆蓋率
pytest tests/ -m "not slow"                       # 跳過效能測試
```

---

## 自動化安裝與部署

四個腳本各司其職，全部可獨立執行，也可用 `Makefile` 捷徑呼叫：

| 腳本 | 對應 `make` | 做什麼 |
|---|---|---|
| [`scripts/install.sh`](scripts/install.sh) | `make install` | 產生 `.env`、以 `secrets` 模組產生高熵金鑰、同步 `DATABASE_URL`、檢查前置條件 |
| [`scripts/deploy.sh`](scripts/deploy.sh) | `make deploy` | 前置驗證 → 建置 → 啟動 → 健康檢查 → 煙霧測試，**失敗自動回滾** |
| [`scripts/smoke-test.sh`](scripts/smoke-test.sh) | `make smoke` | 部署後快速確認服務可對外服務（可指向 staging/prod URL） |
| [`scripts/lib.sh`](scripts/lib.sh) | — | 共用函式庫，不單獨執行 |

### ① 安裝：`scripts/install.sh`

```bash
scripts/install.sh                  # Docker 模式（預設，含模擬 AD）
scripts/install.sh --mode local     # 本機模式（uv + 本機 PostgreSQL）
scripts/install.sh --admin-user ops # 指定本地管理員帳號名稱
scripts/install.sh --force          # 重新產生所有金鑰（先自動備份舊 .env）
```

- **冪等**：已存在的 `.env` 預設不覆寫，只補上仍是 `CHANGE_ME` 的欄位；重跑不會換掉你已設定的值。
- **安全**：`SECRET_KEY`／各密碼在本機產生後直接寫入 `.env`，**不印到終端機**；`.env` 權限收緊為 `600`。
- 無法自動產生的欄位（真實 AD 的 `LDAP_HOST`／`LDAP_BIND_DN`／`LDAP_BIND_PASSWORD`）會逐一提示你手動填。

> ⚠️ `.env` 已列入 `.gitignore`，內含密鑰，**絕不可提交進版控**。

自動產生後仍需你視環境確認的關鍵變數：

| 變數 | 說明 |
|---|---|
| `SECRET_KEY` | session 簽章與憑證加密的主金鑰（**至少 32 字元**，已自動產生） |
| `DATABASE_URL` | PostgreSQL 連線字串（已依 `POSTGRES_*` 自動同步） |
| `LDAP_HOST` / `LDAP_BASE_DN` | AD 網域控制站與 Base DN（**接真實 AD 時必填**） |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | **唯讀**服務帳號（非 Domain Admin） |
| `BOOTSTRAP_ADMIN_PASSWORD` | 本地管理員密碼（AD 故障時的退路，已自動產生） |

### ② 部署：`scripts/deploy.sh`

```bash
scripts/deploy.sh                   # 開發部署（db + 模擬 AD DC + app）
scripts/deploy.sh --env production --no-samba   # 正式部署（接真實 AD，執行安全關卡）
scripts/deploy.sh --logs            # 只追蹤 app 即時 log（不部署）
scripts/deploy.sh --down            # 停止並移除容器（保留資料卷）
scripts/deploy.sh --rollback        # 回滾：停掉目前這批容器
```

部署流程（對應 CD 五步）與各關卡：

1. **前置驗證** — `.env` 存在；`SECRET_KEY`／`POSTGRES_PASSWORD`／`BOOTSTRAP_ADMIN_PASSWORD`
   不得仍是佔位符；`SECRET_KEY` 長度 ≥ 32。任一不符即中止並提示補救。
2. **正式環境安全關卡**（`--env production` 時強制，對齊下方[上線檢查清單](#正式環境部署檢查清單)）：
   `LDAP_VERIFY_CERT=true`、**不得啟動內建 Samba**（須 `--no-samba` 接真實 AD）、管理員密碼 ≥ 16 字元。
   **未過關即拒絕部署，不提供略過選項。**
3. **建置並啟動** — `docker compose up -d --build`；失敗時自動印出最近 log。
4. **健康檢查** — 等待 app 容器 `healthy`（沿用 Dockerfile／compose 的 `HEALTHCHECK`）；逾時即回滾。
5. **煙霧測試** — 呼叫 `smoke-test.sh` 驗證 `/login`、根路徑授權行為與安全標頭；
   **失敗會自動 `docker compose down` 回滾**，避免帶病對外服務（資料卷保留）。

### ③ 煙霧測試：`scripts/smoke-test.sh`

部署腳本會自動呼叫；也可獨立對任一環境執行：

```bash
scripts/smoke-test.sh                                   # 預設 http://localhost:8000
scripts/smoke-test.sh --url https://staging.example.com # 指向 staging/prod
scripts/smoke-test.sh --retries 20 --interval 3         # 調整等待就緒的次數/間隔
```

### 回滾與資料安全

- 本專案為**單機 Docker Compose 部署**，回滾＝把壞掉的這批容器停掉，讓服務回到乾淨的「未部署」狀態。
- `--down` 與 `--rollback` **只停容器、保留資料卷**（`pgdata` 等）；要連資料一併清除才需 `docker compose down -v`。
- 正式環境的映像版本控管，建議由 CI（`.github/workflows/ci.yml` 的 `build` job 已產出 artifact）搭配 registry tag 管理。

### 本機開發模式（不進 Docker）

若要直接在本機跑（需自備 PostgreSQL）：

```bash
scripts/install.sh --mode local     # 產生 .env 並把 DATABASE_URL 指向 localhost
uv venv && uv pip install -e ".[dev]"
uvicorn app.main:app --reload
```

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
├── install.sh         # 一鍵安裝：產生 .env 與高熵金鑰、檢查前置條件
├── deploy.sh          # 部署：建置→啟動→健康檢查→煙霧測試，失敗自動回滾
├── smoke-test.sh      # 部署後煙霧測試（可指向 staging/prod）
└── lib.sh             # 共用函式庫
Makefile               # 常用指令捷徑（make install / deploy / smoke / test …）
```
