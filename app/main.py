"""FastAPI 應用程式進入點。

安全紀律：
- 所有授權判斷在伺服器端，不信任前端（見 app/web/deps.py）。
- 錯誤處理不洩漏堆疊與內部細節。
- 安全標頭一律套用。
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.db.session import init_db, session_scope
from app.providers.base import ProviderError
from app.web import routes
from app.web.templates import templates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時初始化資料庫與本地管理員帳號。"""
    settings = get_settings()
    init_db()

    from app.auth.service import AuthService

    with session_scope() as session:
        AuthService(session).ensure_bootstrap_admin(
            settings.bootstrap_admin_username,
            settings.bootstrap_admin_password,
        )

    logger.info("contorell 啟動完成（環境：%s）", settings.app_env)
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="contorell — 權限比對管理系統",
        description="以 AD 為基準的唯讀權限差異比對工具",
        version="0.1.0",
        lifespan=lifespan,
        # 正式環境不公開 API 文件，減少攻擊面
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
    )

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="contorell_session",
        https_only=settings.is_production,
        # strict 而非 lax：本系統無需從外部連結帶登入狀態進入，
        # 收緊可作為 CSRF token 之外的第二道防線（FIND-001）
        same_site="strict",
        max_age=8 * 60 * 60,  # 8 小時，符合一個工作天
    )

    static_dir = BASE_DIR / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    app.include_router(routes.router)

    _register_middleware(app, settings)
    _register_error_handlers(app)

    return app


def _register_middleware(app: FastAPI, settings) -> None:  # type: ignore[no-untyped-def]
    # 注意：以 @app.middleware 註冊的中介層會包在 add_middleware 註冊者的**外層**，
    # 因此此處無法存取 request.session（SessionMiddleware 尚未執行）。
    # CSRF token 的建立改由模板全域函式 csrf_token() 於渲染時按需產生。
    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        # 本應用不需要這些瀏覽器功能
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # CSP：只允許同源資源。HTMX 需要 unsafe-inline 供 hx-* 屬性使用，
        # 但不允許外部來源，仍能阻擋典型的 XSS 資料外傳。
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProviderError)
    async def provider_error_handler(request: Request, exc: ProviderError):  # type: ignore[no-untyped-def]
        """把 Provider 錯誤轉成可行動的畫面訊息（AC-01、AC-04）。"""
        logger.warning("Provider 錯誤（%s）：%s", exc.category, exc.message)

        context = {
            "request": request,
            "category": exc.category,
            "message": exc.message,
            "remediation": exc.remediation,
        }

        if request.headers.get("HX-Request"):
            return templates.TemplateResponse(
                request, "partials/error.html", context, status_code=400
            )
        return templates.TemplateResponse(request, "error.html", context, status_code=400)

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        """不洩漏堆疊與內部細節給使用者。"""
        logger.exception("未預期的錯誤：%s", exc)

        if request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse(
                {"detail": "系統發生未預期的錯誤，請聯繫管理員。"}, status_code=500
            )
        return HTMLResponse(
            "<h1>系統錯誤</h1><p>發生未預期的錯誤，請聯繫管理員。</p>", status_code=500
        )


app = create_app()
