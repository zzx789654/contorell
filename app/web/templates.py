"""Jinja2 模板設定。

**安全紀律**：``autoescape`` 必須開啟（Jinja2Templates 預設開啟），
所有輸出到 HTML 的資料自動做輸出編碼，防 XSS。
任何 ``|safe`` 的使用都必須經過審查。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.comparison.engine import MatchStatus, RiskLevel

TEMPLATE_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

STATUS_LABELS = {
    MatchStatus.ONLY_IN_A.value: "僅存在於 A",
    MatchStatus.ONLY_IN_B.value: "僅存在於 B",
    MatchStatus.MATCHED.value: "相符",
    MatchStatus.ATTRIBUTE_MISMATCH.value: "屬性不一致",
}

# 三重編碼：顏色 + 圖示 + 文字。
# WCAG 1.4.1 要求不可單靠顏色傳達資訊（見 docs/UX-Design.md）。
STATUS_ICONS = {
    MatchStatus.ONLY_IN_A.value: "◀",
    MatchStatus.ONLY_IN_B.value: "▶",
    MatchStatus.MATCHED.value: "✓",
    MatchStatus.ATTRIBUTE_MISMATCH.value: "≠",
}

RISK_LABELS = {
    RiskLevel.HIGH.value: "高風險",
    RiskLevel.MEDIUM.value: "中風險",
    RiskLevel.LOW.value: "低風險",
    RiskLevel.NONE.value: "無風險",
}

RISK_ICONS = {
    RiskLevel.HIGH.value: "▲",
    RiskLevel.MEDIUM.value: "●",
    RiskLevel.LOW.value: "○",
    RiskLevel.NONE.value: "—",
}

ACCOUNT_STATUS_LABELS = {"enabled": "啟用", "disabled": "停用", "unknown": "未知"}

AUDIT_ACTION_LABELS = {
    "login_success": "登入成功",
    "login_failed": "登入失敗",
    "login_denied": "登入遭拒",
    "source_fetched": "抓取來源",
    "source_tested": "測試連線",
    "comparison_run": "執行比對",
    "comparison_exported": "匯出報表",
    "annotation_saved": "儲存標註",
}


def _account_status_label(value: str | None) -> str:
    if not value:
        return "（不存在）"
    return ACCOUNT_STATUS_LABELS.get(value, value)


def csrf_token(request) -> str:  # type: ignore[no-untyped-def]
    """供模板取得 CSRF token（FIND-001）。

    定義為全域函式而非依賴各路由傳入 context，
    確保任何表單都能取到 token，不會因為某個路由忘了傳而失效。

    注意：路由的 context 若也用 ``csrf_token`` 這個鍵，會遮蔽本函式並
    導致模板中的 ``csrf_token(request)`` 變成呼叫字串。因此路由一律
    **不要**傳同名變數，統一由本函式提供。
    """
    from app.security.csrf import get_or_create_token

    return get_or_create_token(request)


templates.env.globals.update(
    status_labels=STATUS_LABELS,
    status_icons=STATUS_ICONS,
    risk_labels=RISK_LABELS,
    risk_icons=RISK_ICONS,
    audit_action_labels=AUDIT_ACTION_LABELS,
    csrf_token=csrf_token,
)

templates.env.filters["account_status"] = _account_status_label
