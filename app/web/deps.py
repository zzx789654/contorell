"""FastAPI 依賴：認證與授權 — 對應 AC-13。

**安全紀律**：所有授權判斷在此集中處理，路由一律透過依賴取得使用者。
不接受前端傳來的角色資訊——那可以被竄改。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import AuditLog, User, UserRole
from app.db.session import get_session
from app.providers.ldap_provider import LdapConfig, NestingStrategy
from app.security.csrf import verify_csrf

SessionDep = Annotated[Session, Depends(get_session)]

# 所有變更狀態的路由都必須掛上此依賴（FIND-001，CWE-352）
CsrfProtected = Depends(verify_csrf)


def get_current_user(request: Request, session: SessionDep) -> User:
    """取得已登入的使用者，未登入回 401。

    角色一律**從資料庫重新讀取**，不從 session cookie 取用——
    否則管理者被降權後，舊 session 仍會保有管理者權限。
    """
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="請先登入。",
            headers={"HX-Redirect": "/login"},
        )

    user = session.get(User, user_id)
    if user is None or not user.is_active:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="登入狀態已失效，請重新登入。",
            headers={"HX-Redirect": "/login"},
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(user: CurrentUser) -> User:
    """要求管理者權限，稽核者存取時回 403。"""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="此操作需要管理者權限。您目前的角色為稽核者（唯讀）。",
        )
    return user


AdminUser = Annotated[User, Depends(require_admin)]


def get_ldap_config() -> LdapConfig | None:
    """從設定建立 AD 連線設定。未設定 host 時回 None。"""
    settings = get_settings()
    if not settings.ldap_host or not settings.ldap_base_dn:
        return None

    return LdapConfig(
        host=settings.ldap_host,
        port=settings.ldap_port,
        use_ssl=settings.ldap_use_ssl,
        base_dn=settings.ldap_base_dn,
        bind_dn=settings.ldap_bind_dn,
        bind_password=settings.ldap_bind_password,
        verify_cert=settings.ldap_verify_cert,
        ca_cert_file=settings.ldap_ca_cert_file or None,
        page_size=settings.ldap_page_size,
        nesting_strategy=NestingStrategy.RECURSIVE,
    )


LdapConfigDep = Annotated[LdapConfig | None, Depends(get_ldap_config)]


def client_ip(request: Request) -> str:
    """取得用戶端 IP。

    只有在確知服務位於受信任的反向代理之後時才採信 X-Forwarded-For，
    否則該標頭可被任意偽造，會污染稽核紀錄。
    """
    return request.client.host if request.client else ""


def record_audit(
    session: Session,
    user: User,
    action: str,
    *,
    target_type: str = "",
    target_id: str = "",
    detail: str = "",
    ip_address: str = "",
) -> None:
    """寫入稽核軌跡（FR-14、AC-14）。"""
    session.add(
        AuditLog(
            actor_username=user.username,
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            detail=detail,
            ip_address=ip_address,
        )
    )


def role_label(role: str) -> str:
    return {UserRole.ADMIN.value: "管理者", UserRole.AUDITOR.value: "稽核者"}.get(role, role)
