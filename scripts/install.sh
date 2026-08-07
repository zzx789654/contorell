#!/usr/bin/env bash
# contorell 一鍵安裝腳本
#
# 目的：把「複製 .env → 產生高熵金鑰 → 檢查前置條件 → 安裝所有套件」這段
#       每個人都會做、又最容易做錯（用弱金鑰、把 CHANGE_ME 帶上線、漏裝套件）的
#       手動步驟全部自動化，跑完即可直接部署。
#
# 特性：
# - 冪等：已存在的 .env 預設不覆寫，只補上仍是佔位符的密鑰
# - 安全：金鑰以 secrets 模組於本機產生，不印到終端機，只回報「已產生」
# - 自動裝套件：docker 模式 build 映像（套件裝進映像）、local 模式建 venv 並裝相依
# - 不做危險假設：正式環境相關的驗證留給 deploy.sh，install 只負責「能跑起來」
#
# 用法：
#   scripts/install.sh                 # docker 模式（預設，會 build 映像裝好所有套件）
#   scripts/install.sh --mode local    # 本機模式（建 .venv 並自動安裝所有相依套件）
#   scripts/install.sh --no-deps       # 只產生 .env，跳過套件安裝
#   scripts/install.sh --force         # 重新產生所有金鑰（會先備份舊 .env）
#   scripts/install.sh --admin-user ops
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="docker"
FORCE=0
NO_DEPS=0
ADMIN_USER=""

usage() {
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)       MODE="${2:-}"; shift 2 ;;
        --mode=*)     MODE="${1#*=}"; shift ;;
        --force)      FORCE=1; shift ;;
        --no-deps)    NO_DEPS=1; shift ;;
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
section "步驟 1／4：檢查前置條件（模式：$MODE）"
# ---------------------------------------------------------------
require_cmd python3 "請安裝 Python 3.12+（產生金鑰與 .env 需要）" || exit 1
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info[:2] >= (3,12) else 0)')
[ "$PY_OK" = "1" ] || warn "偵測到的 Python 低於 3.12；金鑰產生仍可運作，但本機模式需要 3.12+"

# 重要：前置條件缺少「套件安裝工具」時，只跳過套件安裝步驟，
# **絕不因此中止 .env 的產生**——不然使用者沒裝 Docker 就連設定檔都拿不到。
COMPOSE=""
SKIP_BUILD=0
if [ "$MODE" = "docker" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        warn "未偵測到 Docker —— 仍會照常產生 .env，但本次略過映像建置。"
        warn "裝好 Docker 後執行 scripts/deploy.sh 即可建置並啟動：https://docs.docker.com/engine/install/"
        SKIP_BUILD=1
    elif ! COMPOSE="$(detect_compose)"; then
        warn "有 Docker 但找不到 compose（v2/v1）—— 仍會產生 .env，補裝 compose 後再部署。"
        SKIP_BUILD=1
    else
        ok "Docker 與 Compose 就緒（$COMPOSE）"
    fi
else
    if command -v uv >/dev/null 2>&1; then
        ok "偵測到 uv（將用它建立 .venv 並安裝套件）"
    else
        log "未偵測到 uv，將改用 Python 內建 venv + pip 安裝套件（同樣全自動）"
    fi
fi
ok "前置條件檢查完成"

# ---------------------------------------------------------------
section "步驟 2／4：準備 .env 設定檔"
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

# 安裝本機 Python 套件到 .venv —— 這是讓 `pytest`／`ruff` 等在本機直接跑得起來的關鍵。
# 兩種模式都裝：Docker 模式的映像有自己的一份（供部署），但在「本機跑測試」時
# 用的是本機 Python，因此仍需要一份本機 .venv，否則會出現「模組沒下載、無法執行測試」。
install_local_venv() {
    # 需要 Python 3.12+；uv 可自帶 3.12，沒有 uv 時才要求系統 python3 已是 3.12+
    if ! command -v uv >/dev/null 2>&1 && [ "$PY_OK" != "1" ]; then
        if [ "$MODE" = "local" ]; then
            die "本機模式需要 Python 3.12+（或安裝 uv 由它自帶）才能安裝套件"
        fi
        warn "本機 Python 低於 3.12 且未裝 uv —— 略過本機 .venv。"
        warn "要在本機跑測試，請裝 Python 3.12+ 或 uv 後重跑；或用 'make test' 在容器內跑。"
        return 0
    fi

    if command -v uv >/dev/null 2>&1; then
        [ -d "$PROJECT_ROOT/.venv" ] || uv venv --python 3.12 "$PROJECT_ROOT/.venv"
        log "以 uv 安裝所有相依套件（含 pytest、ruff 等 dev 工具）…"
        ( cd "$PROJECT_ROOT" && uv pip install -e ".[dev]" ) && ok "本機套件安裝完成（.venv）" || _deps_failed
    else
        [ -d "$PROJECT_ROOT/.venv" ] || python3 -m venv "$PROJECT_ROOT/.venv"
        log "以 pip 安裝所有相依套件（含 pytest、ruff 等 dev 工具）…"
        "$PROJECT_ROOT/.venv/bin/python" -m pip install --quiet --upgrade pip
        "$PROJECT_ROOT/.venv/bin/pip" install -e "$PROJECT_ROOT[dev]" && ok "本機套件安裝完成（.venv）" || _deps_failed
    fi
}
_deps_failed() {
    [ "$MODE" = "local" ] && die "套件安裝失敗，請檢查上方錯誤輸出"
    warn "本機套件安裝未完成；可稍後重跑 scripts/install.sh，或在容器內跑測試（make test）。"
}

# ---------------------------------------------------------------
section "步驟 3／4：安裝所有套件"
# ---------------------------------------------------------------
if [ "$NO_DEPS" -eq 1 ]; then
    log "--no-deps：略過套件安裝"
else
    # (1) 本機 .venv —— 讓 pytest / ruff 直接在本機跑（解決「測試模組沒下載」）
    install_local_venv

    # (2) Docker 模式額外 build 映像（套件也裝進映像，供 deploy 使用）
    if [ "$MODE" = "docker" ]; then
        if [ "$SKIP_BUILD" -eq 1 ] || [ -z "$COMPOSE" ]; then
            warn "略過映像建置（Docker／compose 尚未就緒）。.env 已建立，裝好 Docker 後執行 scripts/deploy.sh 會自動 build。"
        else
            log "建置 Docker 映像（把所有套件裝進映像，首次較久）…"
            if $COMPOSE build app 2>&1 | tail -3; then
                ok "映像建置完成，所有套件已裝入映像"
            else
                warn "映像建置未完成（可能 Docker daemon 未啟動）。稍後可用 scripts/deploy.sh 重試——它會自動 build。"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------
section "步驟 4／4：檢查剩餘待填欄位"
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
ok "安裝完成 🎉（套件$( [ "$NO_DEPS" -eq 1 ] && echo "未安裝，--no-deps" || echo "已安裝" )）"
cat <<EOF

下一步：
  1. （選填）編輯 .env 填入真實 AD 連線資訊：\$EDITOR .env
  2. 啟動並部署：
$( [ "$MODE" = "docker" ] \
    && echo "       scripts/deploy.sh                  # 開發環境（含模擬 AD）" \
    || echo "       source .venv/bin/activate && uvicorn app.main:app --reload   # 本機開發伺服器" )
  3. 開啟 http://localhost:8000  （預設管理員帳號：$(env_get BOOTSTRAP_ADMIN_USERNAME)）

  想讓「其他網段的電腦」也能連進來？見 README「讓其他網段的 IP 連線」一節，
  或在 .env 設定 APP_BIND=0.0.0.0 後重新部署（Docker 模式）。

提醒：.env 內含密鑰，已設為 600 權限且列入 .gitignore，切勿提交進版控。
EOF

[ "$pending" -gt 0 ] && warn "仍有 ${pending} 個欄位需你手動填入才能連上真實 AD。"
exit 0
