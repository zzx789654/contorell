"""CSRF 防護 — 對應 FIND-001（CWE-352、OWASP A01:2025）。

採 **synchronizer token pattern**：伺服器端在 session 中保存一組隨機 token，
所有變更狀態的請求都必須在表單或標頭中帶回同一組 token 才放行。

為什麼 SameSite cookie 不足以單獨作為防線：
- ``SameSite=Lax`` 不阻擋頂層導覽觸發的 GET，也不涵蓋所有瀏覽器版本。
- 使用者若以舊版瀏覽器存取，SameSite 可能完全不生效。
因此採「token 為主、SameSite=strict 與 Origin 比對為輔」的縱深防禦。
"""

from __future__ import annotations

import hmac
import logging
import secrets
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

SESSION_KEY = "csrf_token"
FORM_FIELD = "csrf_token"
HEADER_NAME = "X-CSRF-Token"

# 這些方法依定義不改變狀態，不需驗證
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def get_or_create_token(request: Request) -> str:
    """取得目前 session 的 CSRF token，不存在時產生一組。"""
    token = request.session.get(SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[SESSION_KEY] = token
    return token


def rotate_token(request: Request) -> str:
    """換發 token。登入成功時呼叫，與 session 換發一併進行。"""
    token = secrets.token_urlsafe(32)
    request.session[SESSION_KEY] = token
    return token


def _origin_matches(request: Request) -> bool:
    """比對 Origin / Referer 與本站是否相符（第二道防線）。

    標頭缺失時回傳 True——某些合法情境（隱私設定、舊版瀏覽器）不會送出這些標頭，
    此時仍由 token 驗證把關，不因缺少標頭而誤擋正常使用者。
    """
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return True

    parsed = urlparse(source)
    if not parsed.netloc:
        return True

    # 與請求本身的 Host 比對
    host = request.headers.get("host", "")
    return parsed.netloc == host


async def verify_csrf(request: Request) -> None:
    """驗證 CSRF token。掛在所有變更狀態的路由上。

    Raises:
        HTTPException: token 缺失或不符時回 403。
    """
    if request.method in SAFE_METHODS:
        return

    expected = request.session.get(SESSION_KEY)
    if not expected:
        # 完全沒有 session 代表根本未建立會話。此時真正的原因是「未登入」，
        # 回 401 讓前端導向登入頁；若回 403 會讓使用者以為是權限不足，
        # 也會掩蓋掉真正的認證狀態（AC-13 要求未登入回 401）。
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="登入狀態已失效，請重新登入。",
            headers={"HX-Redirect": "/login"},
        )

    if not _origin_matches(request):
        logger.warning(
            "CSRF：Origin/Referer 與本站不符（path=%s）", request.url.path
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="請求來源不正確，已拒絕。",
        )

    # 表單欄位優先，其次是標頭（供 HTMX 使用）
    submitted = request.headers.get(HEADER_NAME, "")
    if not submitted:
        try:
            form = await request.form()
            submitted = str(form.get(FORM_FIELD, ""))
        except (AssertionError, ValueError):
            submitted = ""

    # 以常數時間比對，避免時序攻擊
    if not submitted or not hmac.compare_digest(submitted, expected):
        logger.warning("CSRF token 驗證失敗（path=%s）", request.url.path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="請求已逾期或無效，請重新整理頁面後再試。",
        )
