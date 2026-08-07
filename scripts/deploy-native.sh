#!/usr/bin/env bash
# contorell 原生部署腳本（不使用 Docker，直接在 Ubuntu 上以 systemd 常駐）
#
# 為什麼可以不用 Docker：本應用執行期不寫檔（Excel 匯出走記憶體串流），
# 資料模型不依賴 PostgreSQL 專屬型別（測試在 SQLite 全綠），因此原生部署很單純：
#   一個 Python venv + 一個資料庫（PostgreSQL 或 SQLite）+ 一個 systemd 服務。
#
# 這支腳本會：安裝系統相依 → 建 venv 裝套件 → 準備資料庫 → 安裝並啟動 systemd 服務
#           → 健康檢查 + 煙霧測試。服務會開機自啟、崩潰自動重啟。
#
# 用法：
#   sudo scripts/deploy-native.sh                 # 用 .env 現有 DATABASE_URL 部署
#   sudo scripts/deploy-native.sh --with-db       # 另外在本機安裝並設定 PostgreSQL
#   sudo scripts/deploy-native.sh --sqlite        # 改用檔案型 SQLite（零額外服務，最簡單）
#   sudo scripts/deploy-native.sh --port 8080     # 指定監聽埠（預設 8000）
#   sudo scripts/deploy-native.sh --service-user contorell  # 用專屬系統帳號跑服務
#   scripts/deploy-native.sh --status | --logs | --restart | --stop | --uninstall
#
# 需要 sudo（安裝套件、寫入 /etc/systemd、操作 systemctl）。非部署類動作（status/logs）不需要。
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SERVICE_NAME="contorell"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

ACTION="deploy"
WITH_DB=0
USE_SQLITE=0
PORT=8000
SERVICE_USER=""   # 空＝以呼叫者（SUDO_USER 或目前使用者）身分執行

while [ $# -gt 0 ]; do
    case "$1" in
        --with-db)      WITH_DB=1; shift ;;
        --sqlite)       USE_SQLITE=1; shift ;;
        --port)         PORT="${2:-}"; shift 2 ;;
        --port=*)       PORT="${1#*=}"; shift ;;
        --service-user) SERVICE_USER="${2:-}"; shift 2 ;;
        --service-user=*) SERVICE_USER="${1#*=}"; shift ;;
        --status)       ACTION="status"; shift ;;
        --logs)         ACTION="logs"; shift ;;
        --restart)      ACTION="restart"; shift ;;
        --stop)         ACTION="stop"; shift ;;
        --uninstall)    ACTION="uninstall"; shift ;;
        -h|--help)      sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "未知參數：$1（用 --help 看說明）" ;;
    esac
done

cd "$PROJECT_ROOT"

# ---- 非部署類動作：直接處理後退出（多數不需 sudo）----
case "$ACTION" in
    status)  exec systemctl status "$SERVICE_NAME" --no-pager ;;
    logs)    exec journalctl -u "$SERVICE_NAME" -f --no-pager ;;
    restart) exec sudo systemctl restart "$SERVICE_NAME" ;;
    stop)    exec sudo systemctl stop "$SERVICE_NAME" ;;
    uninstall)
        section "移除 systemd 服務"
        sudo systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
        sudo rm -f "$UNIT_PATH"
        sudo systemctl daemon-reload
        ok "已停止並移除服務。venv、.env、資料庫皆保留（如需清除請自行處理）。"
        exit 0
        ;;
esac

# ===============================================================
# 以下為部署流程
# ===============================================================

# --- sudo 與平台檢查 ---
command -v systemctl >/dev/null 2>&1 || die "找不到 systemctl —— 本腳本需在使用 systemd 的系統（如 Ubuntu）上執行"
command -v apt-get   >/dev/null 2>&1 || warn "找不到 apt-get（非 Debian/Ubuntu？）將略過系統套件安裝，請自行確保 python3.12 已就緒"
SUDO="sudo"
[ "$(id -u)" -eq 0 ] && SUDO=""   # 已是 root 就不需要 sudo 前綴
if [ -n "$SUDO" ] && ! sudo -n true 2>/dev/null; then
    log "部分步驟需要 sudo，過程中可能會要求輸入密碼。"
fi

# 決定服務要以哪個使用者身分執行：
#   預設 = 呼叫 sudo 的登入者（SUDO_USER），既能讀 .env（600）又非 root，最省事。
RUN_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
[ "$RUN_USER" = "root" ] && warn "服務將以 root 執行 —— 建議用 --service-user 指定非 root 帳號以符合最小權限。"

[ -f "$ENV_FILE" ] || die ".env 不存在，請先執行 scripts/install.sh 產生設定與金鑰"

# ---------------------------------------------------------------
section "步驟 1／5：系統相依套件"
# ---------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    PKGS="python3 python3-venv python3-dev"
    [ "$WITH_DB" -eq 1 ] && PKGS="$PKGS postgresql"
    log "安裝：$PKGS"
    $SUDO apt-get update -qq
    # shellcheck disable=SC2086
    $SUDO apt-get install -y -qq $PKGS
    ok "系統套件就緒"
fi

# ---------------------------------------------------------------
section "步驟 2／5：Python venv 與套件"
# ---------------------------------------------------------------
# .venv 交給 install.sh（--mode local）處理：它會用 uv 或內建 venv 裝好所有相依。
# 以 RUN_USER 身分建立，確保服務跑得起來時讀得到 .venv。
if [ ! -x "$PROJECT_ROOT/.venv/bin/uvicorn" ]; then
    log "建立 .venv 並安裝所有套件（含 uvicorn）…"
    if [ "$(id -un)" = "$RUN_USER" ]; then
        ( cd "$PROJECT_ROOT" && ./scripts/install.sh --mode local ) || die "venv 建立/套件安裝失敗"
    else
        # 以 RUN_USER 身分建立 venv，避免 root 擁有導致服務讀不到
        $SUDO -u "$RUN_USER" bash -lc "cd '$PROJECT_ROOT' && ./scripts/install.sh --mode local" || die "venv 建立/套件安裝失敗"
    fi
else
    ok ".venv 已存在（含 uvicorn），沿用"
fi

# ---------------------------------------------------------------
section "步驟 3／5：準備資料庫"
# ---------------------------------------------------------------
RW_PATH=""   # 服務需要可寫入的路徑（SQLite 檔案用）；空＝不需要（Postgres 走網路）
if [ "$USE_SQLITE" -eq 1 ]; then
    # 檔案型 SQLite：零額外服務，適合單機、少量並發的稽核用途。
    mkdir -p "$PROJECT_ROOT/data"
    chown "$RUN_USER" "$PROJECT_ROOT/data" 2>/dev/null || true
    env_set DATABASE_URL "sqlite:///${PROJECT_ROOT}/data/${SERVICE_NAME}.db"
    # SQLite 會在此目錄寫 .db/.db-wal/.db-journal，需在 systemd 沙箱中開放此路徑可寫
    RW_PATH="${PROJECT_ROOT}/data"
    ok "已改用 SQLite：data/${SERVICE_NAME}.db（DATABASE_URL 已更新）"
elif [ "$WITH_DB" -eq 1 ]; then
    # 在本機 PostgreSQL 建立 role 與 database（用 .env 裡的帳密，冪等）。
    PGUSER="$(env_get POSTGRES_USER)"; PGUSER="${PGUSER:-contorell}"
    PGPASS="$(env_get POSTGRES_PASSWORD)"
    PGDB="$(env_get POSTGRES_DB)"; PGDB="${PGDB:-contorell}"
    is_placeholder "$PGPASS" && die "POSTGRES_PASSWORD 尚未設定，請先跑 scripts/install.sh"
    log "在本機 PostgreSQL 建立角色與資料庫（若不存在）…"
    $SUDO systemctl enable --now postgresql 2>/dev/null || true
    $SUDO -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PGUSER}'" | grep -q 1 \
        || $SUDO -u postgres psql -qc "CREATE ROLE \"${PGUSER}\" LOGIN PASSWORD '${PGPASS}'"
    $SUDO -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${PGDB}'" | grep -q 1 \
        || $SUDO -u postgres createdb -O "${PGUSER}" "${PGDB}"
    # 確保 DATABASE_URL 指向本機 postgres
    env_set DATABASE_URL "postgresql+psycopg://${PGUSER}:${PGPASS}@localhost:5432/${PGDB}"
    ok "PostgreSQL 已就緒（角色 ${PGUSER} / 資料庫 ${PGDB}）"
else
    DBURL="$(env_get DATABASE_URL)"
    log "沿用 .env 的 DATABASE_URL（${DBURL%%://*}://…）。若連不上，可加 --with-db 自動裝本機 PostgreSQL，或加 --sqlite。"
fi
# 資料表由應用啟動時自動建立（app/main.py 的 lifespan → init_db），不需另跑 migration。

# ---------------------------------------------------------------
section "步驟 4／5：安裝 systemd 服務"
# ---------------------------------------------------------------
APP_BIND="$(env_get APP_BIND)"; APP_BIND="${APP_BIND:-127.0.0.1}"
UVICORN="$PROJECT_ROOT/.venv/bin/uvicorn"
[ -x "$UVICORN" ] || die "找不到 $UVICORN，venv 可能未正確建立"

log "產生 ${UNIT_PATH}（執行身分：${RUN_USER}，監聽 ${APP_BIND}:${PORT}）"
$SUDO tee "$UNIT_PATH" >/dev/null <<UNIT
[Unit]
Description=contorell — AD 權限比對管理系統（原生部署）
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${PROJECT_ROOT}
# 應用設定由 pydantic 從 WorkingDirectory 下的 .env 載入（不在此重複列出密鑰）
ExecStart=${UVICORN} app.main:app --host ${APP_BIND} --port ${PORT}
Restart=on-failure
RestartSec=3
# --- 基本強化（對齊 Dockerfile 的非 root、最小權限精神）---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ProtectControlGroups=true
ProtectKernelModules=true
${RW_PATH:+ReadWritePaths=${RW_PATH}}

[Install]
WantedBy=multi-user.target
UNIT

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
$SUDO systemctl restart "$SERVICE_NAME"
ok "服務已安裝並啟動（開機自啟、崩潰自動重啟）"

# ---------------------------------------------------------------
section "步驟 5／5：健康檢查與煙霧測試"
# ---------------------------------------------------------------
log "等待服務就緒…"
healthy=0
for i in $(seq 1 20); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/login" 2>/dev/null; then
            ok "服務就緒（/login 可存取，第 ${i} 次嘗試）"; healthy=1; break
        fi
    else
        # 服務已退出：直接把最近的 log 秀出來協助診斷
        err "服務未處於 active 狀態，最近 log："
        $SUDO journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
        die "部署失敗。修正後重跑；或用 scripts/deploy-native.sh --logs 追 log。"
    fi
    sleep 2
done
[ "$healthy" -eq 1 ] || { $SUDO journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true; die "服務在時限內未回應 /login"; }

# 用既有的煙霧測試做多一層驗證（/login、授權行為、安全標頭）
"$PROJECT_ROOT/scripts/smoke-test.sh" --url "http://127.0.0.1:${PORT}" --retries 5 --interval 2 || \
    warn "煙霧測試有項目未通過，請檢視上方輸出（服務仍在執行）。"

echo
ok "原生部署完成 🎉"
cat <<EOF

服務資訊：
  網址        ： http://127.0.0.1:${PORT}$( [ "$APP_BIND" = "0.0.0.0" ] && echo "  （已對外，其他網段用 http://<本機IP>:${PORT}）" )
  執行身分    ： ${RUN_USER}
  管理員帳號  ： $(env_get BOOTSTRAP_ADMIN_USERNAME)
  服務狀態    ： scripts/deploy-native.sh --status
  即時 log    ： scripts/deploy-native.sh --logs
  重啟／停止  ： scripts/deploy-native.sh --restart | --stop
  移除服務    ： scripts/deploy-native.sh --uninstall

要讓其他網段連線：在 .env 設 APP_BIND=0.0.0.0，重跑本腳本，並放行防火牆 ${PORT} 埠。
⚠️ 對外是明文 HTTP，正式環境請置於 HTTPS 反向代理之後（見 README）。
EOF
exit 0
