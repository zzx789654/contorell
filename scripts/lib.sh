#!/usr/bin/env bash
# contorell 部署腳本共用函式庫
#
# 設計原則（對齊 CoreMain 的「簡單、順手、不複雜」）：
# - 只用 bash + 專案已有的工具（python3、docker），不引入額外相依
# - 所有訊息以人看得懂的方式輸出，失敗時給「下一步怎麼做」而非只丟錯誤碼
# - 絕不把產生的密鑰印到終端機或 log（避免肩窺與 CI log 外洩）
#
# 本檔只被其他腳本 source，不單獨執行。

# 專案根目錄（scripts/ 的上一層），無論從哪裡呼叫都能定位
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"

# --- 終端機顏色（無 TTY 時自動關閉，避免污染 CI log）---
if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''
fi

log()  { printf '%s[·]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[✗]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

# 標題分隔線
section() { printf '\n%s── %s ──%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# 確認某個指令存在，否則給出安裝提示後中止
require_cmd() {
    local cmd="$1" hint="${2:-}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "找不到必要指令：${cmd}"
        [ -n "$hint" ] && printf '    %s\n' "$hint" >&2
        return 1
    fi
    return 0
}

# 偵測 docker compose：優先用 v2（docker compose），退回 v1（docker-compose）
detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        return 1
    fi
}

# 產生 URL-safe 高熵金鑰（供 SECRET_KEY 用；含 - 與 _，長度足夠）
gen_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(48))"
}

# 產生純英數密碼（供 DB / 管理員 / Samba 用）。
# 刻意排除特殊符號，避免在 DATABASE_URL 與 shell/compose 變數插值時需要跳脫。
gen_password() {
    local length="${1:-32}"
    python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range($length)))"
}

# 讀取 .env 中某個 key 的值（去掉引號），找不到回傳空字串
env_get() {
    local key="$1"
    [ -f "$ENV_FILE" ] || { echo ""; return; }
    # 取最後一個匹配（允許後面覆寫前面），去掉左側 key= 與可能的引號
    sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n1 | sed -e 's/^"//' -e 's/"$//'
}

# 在 .env 設定 key=value：存在則就地取代，不存在則附加。value 原樣寫入。
env_set() {
    local key="$1" value="$2"
    touch "$ENV_FILE"
    if grep -qE "^${key}=" "$ENV_FILE"; then
        # 用 python 做取代，避免 sed 對 value 中的 / & 等字元敏感
        python3 - "$ENV_FILE" "$key" "$value" <<'PY'
import sys, io
path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
with io.open(path, encoding="utf-8") as f:
    lines = f.readlines()
out, done = [], False
for line in lines:
    if line.startswith(key + "=") and not done:
        out.append(f"{key}={value}\n"); done = True
    else:
        out.append(line)
if not done:
    out.append(f"{key}={value}\n")
with io.open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
PY
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

# 判斷某個值是否仍是未設定的佔位符（CHANGE_ME…、空字串）
is_placeholder() {
    local value="$1"
    [ -z "$value" ] && return 0
    case "$value" in
        CHANGE_ME*) return 0 ;;
        *) return 1 ;;
    esac
}
