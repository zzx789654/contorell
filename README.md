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

## 快速開始

### 1. 環境需求

- Python 3.12+
- PostgreSQL 16（或以 Docker Compose 一併啟動）
- 可連線的 AD 網域控制站（或用內附的 Samba AD DC 模擬環境）

### 2. 設定環境變數

```bash
cp .env.example .env
```

編輯 `.env`，**至少**要填：

```bash
# 產生高熵金鑰
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

| 變數 | 說明 |
|---|---|
| `SECRET_KEY` | session 簽章與憑證加密的主金鑰（**至少 32 字元**） |
| `DATABASE_URL` | PostgreSQL 連線字串 |
| `LDAP_HOST` / `LDAP_BASE_DN` | AD 網域控制站與 Base DN |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | **唯讀**服務帳號（非 Domain Admin） |
| `BOOTSTRAP_ADMIN_PASSWORD` | 本地管理員密碼（AD 故障時的退路） |

> ⚠️ `.env` 已列入 `.gitignore`，**絕不可提交進版控**。

### 3. 啟動

**Docker（含模擬 AD 測試環境）**

```bash
docker compose up -d
```

**本機開發**

```bash
uv venv && uv pip install -e ".[dev]"
uvicorn app.main:app --reload
```

開啟 http://localhost:8000

### 4. 執行測試

```bash
pytest tests/ -v                                  # 全部測試
pytest tests/ --cov=app --cov-report=term-missing # 含覆蓋率
pytest tests/ -m "not slow"                       # 跳過效能測試
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
```
