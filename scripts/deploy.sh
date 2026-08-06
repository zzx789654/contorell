#!/usr/bin/env bash
# contorell 部署腳本
#
# 把 CD 流程（建置 → 部署 → 健康檢查 → 煙霧測試 → 失敗回滾）收斂成一個指令。
# 對齊 CoreMain 的「簡單順手」：這是 Docker Compose 專案，不需要 K8s/Helm，
# 一台機器上 `up -d` 即可服務；本腳本補上「上線前該擋的關卡」與「失敗自動回滾」。
#
# 用法：
#   scripts/deploy.sh                      # 開發環境部署（含模擬 AD DC）
#   scripts/deploy.sh --env production     # 正式環境（會強制執行安全檢查）
#   scripts/deploy.sh --no-samba           # 不啟動內建 Samba，接真實 AD
#   scripts/deploy.sh --logs               # 只看 app 服務 log（不部署）
#   scripts/deploy.sh --down               # 停止並移除容器（保留資料卷）
#   scripts/deploy.sh --rollback           # 回滾：停掉目前這批容器
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

APP_ENV_ARG=""
RUN_SAMBA=1
ACTION="deploy"

while [ $# -gt 0 ]; do
    case "$1" in
        --env)       APP_ENV_ARG="${2:-}"; shift 2 ;;
        --env=*)     APP_ENV_ARG="${1#*=}"; shift ;;
        --no-samba)  RUN_SAMBA=0; shift ;;
        --logs)      ACTION="logs"; shift ;;
        --down)      ACTION="down"; shift ;;
        --rollback)  ACTION="rollback"; shift ;;
        -h|--help)   sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "未知參數：$1（用 --help 看說明）" ;;
    esac
done

cd "$PROJECT_ROOT"

require_cmd docker "請安裝 Docker Engine" || exit 1
COMPOSE="$(detect_compose)" || die "找不到 docker compose / docker-compose"

# 非部署類的動作：先處理掉直接退出
case "$ACTION" in
    logs)
        exec $COMPOSE logs -f --tail=200 app
        ;;
    down)
        section "停止服務"
        $COMPOSE down
        ok "容器已停止並移除（資料卷保留）。要一併刪資料卷請執行：$COMPOSE down -v"
        exit 0
        ;;
    rollback)
        section "回滾：停止目前這批容器"
        # Compose 單機部署沒有「上一版映像」的概念，回滾＝把壞掉的版本停掉，
        # 讓服務回到「未部署」的乾淨狀態，避免帶病對外服務。
        $COMPOSE down
        ok "已停止目前部署。請修正問題後重新 scripts/deploy.sh；資料卷未受影響。"
        exit 0
        ;;
esac

# ---------------------------------------------------------------
section "步驟 1／5：前置驗證"
# ---------------------------------------------------------------
[ -f "$ENV_FILE" ] || die ".env 不存在，請先執行 scripts/install.sh"

# 決定本次部署的環境：命令列參數優先，否則沿用 .env 的 APP_ENV
APP_ENV="${APP_ENV_ARG:-$(env_get APP_ENV)}"
APP_ENV="${APP_ENV:-development}"
case "$APP_ENV" in
    development|staging|production) ;;
    *) die "APP_ENV 只能是 development / staging / production，收到：$APP_ENV" ;;
esac
log "部署環境：${C_BOLD}${APP_ENV}${C_RESET}"

# 必填密鑰不可仍是佔位符（三種環境都要）
for key in SECRET_KEY POSTGRES_PASSWORD BOOTSTRAP_ADMIN_PASSWORD; do
    val="$(env_get "$key")"
    is_placeholder "$val" && die "${key} 仍是佔位符或空值，請先執行 scripts/install.sh 產生金鑰"
done
# SECRET_KEY 長度硬性要求（對應 config.py 的 min_length=32）
sk="$(env_get SECRET_KEY)"
[ "${#sk}" -ge 32 ] || die "SECRET_KEY 長度不足 32（目前 ${#sk}），不符合設定要求"
ok "必填金鑰檢查通過"

# --- 正式環境專屬安全關卡（對齊 README 的上線檢查清單）---
if [ "$APP_ENV" = "production" ]; then
    section "正式環境安全關卡"
    fail=0
    prod_check() {  # 條件為真才算通過
        if eval "$1"; then ok "$2"; else err "$3"; fail=$((fail + 1)); fi
    }
    # 憑證驗證必須開啟（IR-06）
    prod_check '[ "$(env_get LDAP_VERIFY_CERT)" = "true" ]' \
        "LDAP_VERIFY_CERT=true（強制驗證 AD 憑證）" \
        "正式環境 LDAP_VERIFY_CERT 必須為 true（IR-06），目前為：$(env_get LDAP_VERIFY_CERT)"
    # 正式環境不應啟動內建 Samba 模擬 AD
    prod_check '[ "$RUN_SAMBA" -eq 0 ]' \
        "未啟動內建 Samba（正式環境應接真實 AD）" \
        "正式環境請加上 --no-samba，並在 .env 指向真實 AD 網域控制站"
    # 管理員密碼不應是明顯弱值
    admin_pw="$(env_get BOOTSTRAP_ADMIN_PASSWORD)"
    prod_check '[ "${#admin_pw}" -ge 16 ]' \
        "管理員退路密碼長度足夠（≥16）" \
        "正式環境 BOOTSTRAP_ADMIN_PASSWORD 建議至少 16 字元，目前 ${#admin_pw}"
    # 提醒：正式環境務必置於 HTTPS 反向代理之後（此處僅提示，不阻擋）
    warn "提醒：正式環境務必置於 HTTPS 反向代理之後，並確認資料庫帳號為最小權限"
    [ "$fail" -eq 0 ] || die "正式環境安全關卡未通過（${fail} 項），請修正後再部署。不可略過關卡放行。"
    ok "正式環境安全關卡全數通過"
fi

# ---------------------------------------------------------------
section "步驟 2／5：選擇要啟動的服務"
# ---------------------------------------------------------------
# 一律啟動 db + app；Samba 模擬 AD 只在開發/測試時需要
SERVICES=(db app)
if [ "$RUN_SAMBA" -eq 1 ]; then
    SERVICES=(db addc app)
    log "將一併啟動內建 Samba AD DC 模擬環境（測試用）"
else
    log "不啟動 Samba，app 將連線 .env 指定的真實 AD"
fi

# 把本次要用的 APP_ENV 傳給 compose（不改寫使用者 .env 中的其他設定）
export APP_ENV

# ---------------------------------------------------------------
section "步驟 3／5：建置並啟動容器"
# ---------------------------------------------------------------
log "建置映像並啟動：${SERVICES[*]}"
if ! $COMPOSE up -d --build "${SERVICES[@]}"; then
    err "容器啟動失敗"
    warn "顯示最近的 app log 以協助診斷："
    $COMPOSE logs --tail=50 app || true
    die "部署中止。修正後重試，或執行 scripts/deploy.sh --rollback 清理。"
fi
ok "容器已啟動"

# ---------------------------------------------------------------
section "步驟 4／5：健康檢查"
# ---------------------------------------------------------------
# 等 compose 回報的 health 狀態（Dockerfile / compose 已定義 healthcheck）
log "等待 app 容器健康檢查通過…"
healthy=0
for i in $(seq 1 30); do
    cid="$($COMPOSE ps -q app 2>/dev/null || true)"
    if [ -n "$cid" ]; then
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo unknown)"
        case "$status" in
            healthy) ok "app 容器健康（第 ${i} 次檢查）"; healthy=1; break ;;
            unhealthy) err "app 容器被判定為 unhealthy"; break ;;
        esac
    fi
    sleep 3
done
if [ "$healthy" -ne 1 ]; then
    err "健康檢查未在時限內通過"
    $COMPOSE logs --tail=50 app || true
    die "自動回滾中止部署。執行 scripts/deploy.sh --rollback 清理後修正問題。"
fi

# ---------------------------------------------------------------
section "步驟 5／5：煙霧測試"
# ---------------------------------------------------------------
if ! "$PROJECT_ROOT/scripts/smoke-test.sh" --url "http://localhost:8000" --retries 10 --interval 3; then
    err "煙霧測試失敗 — 服務起來了但行為不正確"
    warn "為避免帶病對外服務，執行回滾…"
    $COMPOSE down
    die "已回滾（容器停止，資料卷保留）。請看上方失敗項與 app log 後修正。"
fi

echo
ok "部署成功 🎉（環境：${APP_ENV}）"
cat <<EOF

服務資訊：
  網址        ： http://localhost:8000
  管理員帳號  ： $(env_get BOOTSTRAP_ADMIN_USERNAME)
  查看即時 log： scripts/deploy.sh --logs
  停止服務    ： scripts/deploy.sh --down
  回滾／清理  ： scripts/deploy.sh --rollback

$( [ "$APP_ENV" = "production" ] && echo "正式環境提醒：請確認已在前方掛好 HTTPS 反向代理。" )
EOF
exit 0
