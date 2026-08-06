#!/usr/bin/env bash
# contorell 一鍵安裝腳本
#
# 目的：把「複製 .env → 產生高熵金鑰 → 檢查前置條件」這段每個人都會做、
#       又最容易做錯（用弱金鑰、把 CHANGE_ME 帶上線）的手動步驟自動化。
#
# 特性：
# - 冪等：已存在的 .env 預設不覆寫，只補上仍是佔位符的密鑰
# - 安全：金鑰以 secrets 模組於本機產生，不印到終端機，只回報「已產生」
# - 不做危險假設：正式環境相關的驗證留給 deploy.sh，install 只負責「能跑起來」
#
# 用法：
#   scripts/install.sh                 # docker 模式（預設）
#   scripts/install.sh --mode local    # 本機開發模式（uv + 本機 Postgres）
#   scripts/install.sh --force         # 重新產生所有金鑰（會先備份舊 .env）
#   scripts/install.sh --admin-user ops
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="docker"
FORCE=0
ADMIN_USER=""

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)       MODE="${2:-}"; shift 2 ;;
        --mode=*)     MODE="${1#*=}"; shift ;;
        --force)      FORCE=1; shift ;;
        --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
        --admin-user=*) ADMIN_USER="${1#*=}"; shift ;;
        -h|--help)    usage 0 ;;
        *) die "未知參數：$1（用 --help 看說明）" ;;
    esac
done

case "$MODE" in
    docker|local) ;;
    *) die "--mode 只接受 docker 或 local，收到：$MODE" ;;
esac

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------
section "步驟 1／3：檢查前置條件（模式：$MODE）"
# ---------------------------------------------------------------
require_cmd python3 "請安裝 Python 3.12+（金鑰產生需要）" || exit 1
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info[:2] >= (3,12) else 0)')
[ "$PY_OK" = "1" ] || warn "偵測到的 Python 低於 3.12；金鑰產生仍可運作，但本機模式需要 3.12+"

if [ "$MODE" = "docker" ]; then
    require_cmd docker "請安裝 Docker Engine：https://docs.docker.com/engine/install/" || exit 1
    COMPOSE="$(detect_compose)" || die "找不到 docker compose（v2）或 docker-compose（v1），請先安裝"
    ok "Docker 與 Compose 就緒（$COMPOSE）"
else
    if command -v uv >/dev/null 2>&1; then
        ok "偵測到 uv（本機模式建議用它建立虛擬環境）"
    else
        warn "未偵測到 uv；本機模式可改用內建 venv：python3 -m venv .venv && pip install -e '.[dev]'"
    fi
    require_cmd python3 || exit 1
fi
ok "前置條件檢查完成"

# ---------------------------------------------------------------
section "步驟 2／3：準備 .env 設定檔"
# ---------------------------------------------------------------
[ -f "$ENV_EXAMPLE" ] || die "找不到範本 .env.example，無法產生設定檔"

if [ -f "$ENV_FILE" ] && [ "$FORCE" -eq 1 ]; then
    backup="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$ENV_FILE" "$backup"
    warn "--force：已將現有 .env 備份為 $(basename "$backup")，並將重新產生所有金鑰"
    rm -f "$ENV_FILE"
fi

if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    ok "已從 .env.example 建立 .env"
else
    log ".env 已存在，只補上仍為佔位符的欄位（不覆寫既有值）"
fi

# 需要高熵金鑰的欄位：只在仍是佔位符時才填，已設定的尊重使用者的值
maybe_fill_secret() {
    local key="$1" generator="$2"
    local current
    current="$(env_get "$key")"
    if is_placeholder "$current"; then
        env_set "$key" "$($generator)"
        ok "已產生並寫入 ${key}（值不顯示於畫面）"
    else
        log "${key} 已有值，保留不動"
    fi
}

maybe_fill_secret SECRET_KEY              gen_secret
maybe_fill_secret POSTGRES_PASSWORD       gen_password
maybe_fill_secret BOOTSTRAP_ADMIN_PASSWORD gen_password
maybe_fill_secret SAMBA_ADMIN_PASSWORD    gen_password

# DATABASE_URL 需與 POSTGRES_* 一致，否則本機模式連不上（docker 模式由 compose 覆寫）
PG_USER="$(env_get POSTGRES_USER)"; PG_USER="${PG_USER:-contorell}"
PG_PASS="$(env_get POSTGRES_PASSWORD)"
PG_DB="$(env_get POSTGRES_DB)"; PG_DB="${PG_DB:-contorell}"
if [ "$MODE" = "docker" ]; then
    DB_HOST="db"
else
    DB_HOST="localhost"
fi
if ! is_placeholder "$PG_PASS"; then
    env_set DATABASE_URL "postgresql+psycopg://${PG_USER}:${PG_PASS}@${DB_HOST}:5432/${PG_DB}"
    ok "已同步 DATABASE_URL（主機：${DB_HOST}）"
fi

# 管理員帳號名稱（可選）
if [ -n "$ADMIN_USER" ]; then
    env_set BOOTSTRAP_ADMIN_USERNAME "$ADMIN_USER"
    ok "本地管理員帳號設為：${ADMIN_USER}"
fi

# .env 權限收緊，避免同機其他使用者讀到密鑰
chmod 600 "$ENV_FILE" 2>/dev/null || true

# ---------------------------------------------------------------
section "步驟 3／3：檢查剩餘待填欄位"
# ---------------------------------------------------------------
# 這些欄位無法自動產生（要看使用者的實際 AD 環境），逐一提示
pending=0
check_manual() {
    local key="$1" note="$2"
    local val; val="$(env_get "$key")"
    if is_placeholder "$val"; then
        warn "尚未設定 ${key} — ${note}"
        pending=$((pending + 1))
    fi
}
if [ "$MODE" = "docker" ]; then
    log "Docker 模式內建 Samba AD 模擬環境，可先不接真實 AD 直接啟動"
else
    check_manual LDAP_HOST      "本機模式需指向可連線的 AD 網域控制站"
    check_manual LDAP_BIND_DN   "AD 唯讀服務帳號 DN"
    check_manual LDAP_BIND_PASSWORD "AD 唯讀服務帳號密碼"
fi

echo
ok "安裝完成 🎉"
cat <<EOF

下一步：
  1. （選填）編輯 .env 填入真實 AD 連線資訊：\$EDITOR .env
  2. 啟動並部署：
$( [ "$MODE" = "docker" ] \
    && echo "       scripts/deploy.sh                  # 開發環境（含模擬 AD）" \
    || echo "       uvicorn app.main:app --reload      # 本機開發伺服器" )
  3. 開啟 http://localhost:8000  （預設管理員帳號：$(env_get BOOTSTRAP_ADMIN_USERNAME)）

提醒：.env 內含密鑰，已設為 600 權限且列入 .gitignore，切勿提交進版控。
EOF

[ "$pending" -gt 0 ] && warn "仍有 ${pending} 個欄位需你手動填入才能連上真實 AD。"
exit 0
