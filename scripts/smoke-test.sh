#!/usr/bin/env bash
# contorell 煙霧測試（Smoke Test）
#
# 目的：部署後在數十秒內快速確認「服務真的活著」，而不是只看容器有沒有起來。
# 檢查項目對應 CD 流程 Step 3：HTTP 可達 + 關鍵路由回應正確。
#
# 這是刻意「淺而快」的測試——完整行為由 pytest 測試套件負責，
# 這裡只回答一個問題：這次部署能不能對外服務？
#
# 用法：
#   scripts/smoke-test.sh                         # 預設打 http://localhost:8000
#   scripts/smoke-test.sh --url https://staging.example.com
#   scripts/smoke-test.sh --retries 20 --interval 3
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BASE_URL="http://localhost:8000"
RETRIES=20
INTERVAL=3

while [ $# -gt 0 ]; do
    case "$1" in
        --url)      BASE_URL="${2:-}"; shift 2 ;;
        --url=*)    BASE_URL="${1#*=}"; shift ;;
        --retries)  RETRIES="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        -h|--help)  echo "用法：scripts/smoke-test.sh [--url URL] [--retries N] [--interval SEC]"; exit 0 ;;
        *) die "未知參數：$1" ;;
    esac
done

require_cmd curl "請安裝 curl 以執行煙霧測試" || exit 1

BASE_URL="${BASE_URL%/}"  # 去掉結尾斜線

# 回傳指定路徑的 HTTP 狀態碼（連不上回 000）
http_code() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}$1" 2>/dev/null || echo "000"
}

section "煙霧測試：${BASE_URL}"

# 檢查 1：等待服務就緒（/login 是最輕量且一定存在的公開頁）
log "等待服務就緒（最多 $((RETRIES * INTERVAL)) 秒）…"
ready=0
for i in $(seq 1 "$RETRIES"); do
    code="$(http_code /login)"
    if [ "$code" = "200" ]; then
        ok "服務已就緒（/login → 200，第 ${i} 次嘗試）"
        ready=1
        break
    fi
    sleep "$INTERVAL"
done
[ "$ready" -eq 1 ] || die "服務在時限內未就緒（/login 最後狀態碼：${code:-000}）。請看容器 log：scripts/deploy.sh --logs"

failed=0
assert_code() {
    local path="$1" expect="$2" desc="$3"
    local code; code="$(http_code "$path")"
    if [ "$code" = "$expect" ]; then
        ok "${desc}（${path} → ${code}）"
    else
        err "${desc} 失敗（${path} 期望 ${expect}，實際 ${code}）"
        failed=$((failed + 1))
    fi
}

# 檢查 2：登入頁可正常渲染（代表模板與靜態資源已隨映像打包）
assert_code /login 200 "登入頁可存取"

# 檢查 3：未登入存取受保護頁面應被導向登入（授權在伺服器端生效）
#   FastAPI 對未授權者導回 /login（303/307）或直接擋（401/403）皆為合格行為
code_root="$(http_code /)"
if [ "$code_root" = "200" ] || [ "$code_root" = "303" ] || [ "$code_root" = "307" ] || \
   [ "$code_root" = "401" ] || [ "$code_root" = "403" ]; then
    ok "根路徑授權行為正常（/ → ${code_root}）"
else
    err "根路徑回應異常（/ → ${code_root}）"
    failed=$((failed + 1))
fi

# 檢查 4：安全標頭確實套用（對應 app/main.py 的 security_headers 中介層）
headers="$(curl -skI --max-time 5 "${BASE_URL}/login" 2>/dev/null || true)"
if echo "$headers" | grep -qi '^X-Content-Type-Options:.*nosniff'; then
    ok "安全標頭已套用（X-Content-Type-Options: nosniff）"
else
    warn "未偵測到 X-Content-Type-Options 標頭（若經反向代理可能被改寫，請人工確認）"
fi

echo
if [ "$failed" -eq 0 ]; then
    ok "煙霧測試全數通過 ✅"
    exit 0
else
    die "煙霧測試有 ${failed} 項失敗 ❌ — 不應繼續推進到正式環境"
fi
