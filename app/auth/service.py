"""認證服務 — 對應 FR-13（AD 登入）、FR-13b（本地管理員退路）、AC-13、AC-13b。

雙軌設計：
1. **AD 登入優先**：以使用者輸入的帳密對 AD 做 LDAP bind。
   驗證成功即代表帳密正確——**帳密絕不儲存**，用完即丟。
2. **本地管理員退路**：AD 故障時仍能登入維護系統與查看歷史快照。

安全紀律：
- 兩種管道的失敗訊息**完全一致**，防止帳號列舉（AC-13b）。
- 登入失敗計數與鎖定，防暴力破解。
- 授權判斷一律在伺服器端，不信任前端。
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ldap3 import SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPExceptionError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, LoginAttempt, User, UserRole
from app.providers.ldap_provider import LdapConfig, _build_tls_config
from app.security.crypto import hash_password, needs_rehash, verify_password
from app.security.ldap_escape import build_filter

logger = logging.getLogger(__name__)

# 統一的登入失敗訊息 —— 不透露是帳號不存在還是密碼錯誤（防帳號列舉）
GENERIC_LOGIN_ERROR = "帳號或密碼錯誤。"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# 未佈建帳號的失敗計數視窗（FIND-004）。
# 針對「AD 帳號首次登入」情境——此時本地尚無使用者記錄可計數，
# 若不另外追蹤，攻擊者可對任意 AD 帳號無限次爆破。
THROTTLE_WINDOW = timedelta(minutes=15)
MAX_ATTEMPTS_PER_IDENTITY = 10


def normalize_username(username: str) -> str:
    """正規化帳號名稱供比對與計數使用（FIND-003）。

    AD 的 sAMAccountName 大小寫不敏感，但 PostgreSQL 的預設 collation 敏感。
    若不正規化，攻擊者可用 ``Admin``、``ADMIN``、``aDmin`` 等變形，
    每次都建立/命中不同的使用者記錄，使鎖定計數形同虛設。
    """
    return (username or "").strip().casefold()


class AuthenticationFailed(Exception):
    """登入失敗。訊息一律為通用文字，不洩漏內部細節。"""

    def __init__(self, message: str = GENERIC_LOGIN_ERROR) -> None:
        super().__init__(message)
        self.message = message


class AccountLocked(AuthenticationFailed):
    def __init__(self, until: datetime) -> None:
        super().__init__(
            f"帳號因連續登入失敗已暫時鎖定，請於 {until.strftime('%H:%M')} 後再試。"
        )


@dataclass(slots=True)
class AuthResult:
    user: User
    method: str


class AuthService:
    """處理登入驗證與使用者佈建。"""

    def __init__(self, session: Session, ldap_config: LdapConfig | None = None) -> None:
        self._session = session
        self._ldap_config = ldap_config

    # ------------------------------------------------------------------
    # 登入
    # ------------------------------------------------------------------

    def authenticate(
        self, username: str, password: str, *, ip_address: str = ""
    ) -> AuthResult:
        """驗證登入，AD 優先、本地帳號退路。

        Raises:
            AuthenticationFailed: 帳密錯誤或帳號停用（訊息一律通用）。
            AccountLocked: 連續失敗次數過多。
        """
        username = (username or "").strip()

        # 空值提早擋掉。注意：LDAP 的匿名 bind 在密碼為空時可能「成功」，
        # 若不擋會造成嚴重的認證繞過（CWE-287）。
        if not username or not password:
            raise AuthenticationFailed

        # 節流檢查必須在任何驗證動作之前（FIND-004）。
        # 以正規化後的帳號為鍵，防止大小寫變形繞過（FIND-003）。
        self._assert_not_throttled(username)

        user = self._find_user(username)

        if user is not None:
            self._assert_not_locked(user)
            if not user.is_active:
                self._audit(username, "login_denied", "帳號已停用", ip_address)
                raise AuthenticationFailed

        # --- 管道一：本地帳號 ---
        if user is not None and user.is_local:
            if user.password_hash and verify_password(user.password_hash, password):
                if needs_rehash(user.password_hash):
                    user.password_hash = hash_password(password)
                self._on_success(user, "local", ip_address)
                return AuthResult(user=user, method="local")

            self._on_failure(user, username, "local", ip_address)
            raise AuthenticationFailed

        # --- 管道二：AD 登入 ---
        if self._ldap_config is None:
            self._on_failure(user, username, "ad_unavailable", ip_address)
            raise AuthenticationFailed

        if self._bind_as_user(username, password):
            user = self._provision_ad_user(username, user)
            self._on_success(user, "ad", ip_address)
            return AuthResult(user=user, method="ad")

        self._on_failure(user, username, "ad", ip_address)
        raise AuthenticationFailed

    def _bind_as_user(self, username: str, password: str) -> bool:
        """以使用者自己的帳密對 AD 做 bind 驗證。

        bind 成功即代表帳密正確。**密碼用完即丟，絕不儲存**（AC-13）。
        """
        config = self._ldap_config
        if config is None:
            return False

        # 再次確認密碼非空 —— 防止匿名 bind 被誤判為驗證成功
        if not password:
            return False

        try:
            server = Server(
                host=config.host,
                port=config.port,
                use_ssl=config.use_ssl,
                tls=_build_tls_config(config),
                connect_timeout=config.receive_timeout,
            )

            # 使用者可能輸入 sAMAccountName 或 UPN，統一補成 UPN 格式
            bind_user = username if "@" in username or "\\" in username else self._to_upn(username)

            conn = Connection(
                server,
                user=bind_user,
                password=password,
                authentication=SIMPLE,
                auto_bind=False,
                receive_timeout=config.receive_timeout,
                raise_exceptions=False,
            )

            if config.use_start_tls and not config.use_ssl:
                conn.start_tls()

            bound = conn.bind()
            try:
                # ldap3 在某些設定下對空密碼會回報 bind 成功（匿名 bind），
                # 因此額外確認連線確實處於已認證狀態。
                if bound and not conn.bound:
                    bound = False
                return bool(bound)
            finally:
                conn.unbind()

        except LDAPExceptionError as exc:
            logger.info("AD bind 驗證失敗（username=%s）：%s", username, type(exc).__name__)
            return False
        except OSError as exc:
            logger.warning("AD 連線異常，無法驗證：%s", exc)
            return False

    def _to_upn(self, username: str) -> str:
        """把 sAMAccountName 轉成 UPN（user@domain.local）。"""
        config = self._ldap_config
        if config is None:
            return username
        domain = ".".join(
            part.split("=", 1)[1]
            for part in config.base_dn.split(",")
            if part.strip().lower().startswith("dc=")
        )
        return f"{username}@{domain}" if domain else username

    def _provision_ad_user(self, username: str, existing: User | None) -> User:
        """AD 登入成功後，建立或更新本地的使用者記錄。

        AD 帳號的 ``password_hash`` 一律留空 —— AD 密碼絕不儲存。
        """
        if existing is not None:
            return existing

        # 以正規化後的帳號儲存（FIND-003）：AD 帳號本身大小寫不敏感，
        # 統一存成小寫可避免 Admin/admin 建出兩筆記錄、稽核歸屬分歧。
        user = User(
            username=normalize_username(username),
            display_name=username,
            role=UserRole.AUDITOR.value,  # 安全預設：最小權限，由管理者手動升級
            is_local=False,
            # 空字串是刻意的安全設計，不是遺漏：AD 帳號的密碼一律不儲存。
            # 空的雜湊值也讓 verify_password 必定失敗，因此 AD 使用者
            # 無法繞過 AD 改走本地密碼驗證。
            password_hash="",  # noqa: S106  # nosec B106 - 見上方說明
            is_active=True,
        )
        self._session.add(user)
        self._session.flush()
        logger.info("由 AD 登入自動建立使用者：%s（預設角色：稽核者）", username)
        return user

    # ------------------------------------------------------------------
    # 失敗處理與節流
    # ------------------------------------------------------------------

    def _assert_not_locked(self, user: User) -> None:
        locked_until = _as_aware(user.locked_until)
        if locked_until and locked_until > datetime.now(UTC):
            raise AccountLocked(locked_until)

    def _assert_not_throttled(self, username: str) -> None:
        """檢查該身分是否已超過失敗次數上限（FIND-004）。

        本檢查涵蓋「本地尚無使用者記錄」的情境（AD 帳號首次登入），
        補上 ``User.failed_login_count`` 無法保護的缺口。
        """
        attempt = self._get_attempt_record(username)
        if attempt is None:
            return

        # 超過視窗即視為過期，重新計數
        last_failure = _as_aware(attempt.last_failure_at)
        if last_failure and datetime.now(UTC) - last_failure > THROTTLE_WINDOW:
            attempt.failure_count = 0
            return

        if attempt.failure_count >= MAX_ATTEMPTS_PER_IDENTITY:
            unlock_at = (last_failure or datetime.now(UTC)) + THROTTLE_WINDOW
            logger.warning(
                "身分 %s 於視窗內失敗 %d 次，暫時拒絕登入",
                username,
                attempt.failure_count,
            )
            raise AccountLocked(unlock_at)

    def _get_attempt_record(self, username: str) -> LoginAttempt | None:
        return self._session.scalar(
            select(LoginAttempt).where(
                LoginAttempt.identity_key == normalize_username(username)
            )
        )

    def _record_attempt_failure(self, username: str) -> None:
        """累加身分層級的失敗計數。"""
        now = datetime.now(UTC)
        attempt = self._get_attempt_record(username)

        if attempt is None:
            attempt = LoginAttempt(
                identity_key=normalize_username(username),
                failure_count=1,
                first_failure_at=now,
                last_failure_at=now,
            )
            self._session.add(attempt)
            return

        last_failure = _as_aware(attempt.last_failure_at)
        if last_failure and now - last_failure > THROTTLE_WINDOW:
            attempt.failure_count = 1  # 視窗已過，重新計數
            attempt.first_failure_at = now
        else:
            attempt.failure_count += 1
        attempt.last_failure_at = now

    def _on_failure(
        self, user: User | None, username: str, method: str, ip_address: str
    ) -> None:
        """記錄失敗並在超過門檻時鎖定帳號。"""
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(UTC) + LOCKOUT_DURATION
                logger.warning(
                    "帳號 %s 連續失敗 %d 次，鎖定至 %s",
                    username,
                    user.failed_login_count,
                    user.locked_until,
                )

        # 身分層級計數涵蓋尚未佈建的 AD 帳號（FIND-004）
        self._record_attempt_failure(username)

        self._audit(username, "login_failed", f"method={method}", ip_address)
        self._session.commit()

    def _on_success(self, user: User, method: str, ip_address: str) -> None:
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = datetime.now(UTC)

        # 成功登入後清除身分層級的失敗計數
        attempt = self._get_attempt_record(user.username)
        if attempt is not None:
            self._session.delete(attempt)

        self._audit(user.username, "login_success", f"method={method}", ip_address)
        self._session.commit()

    def _find_user(self, username: str) -> User | None:
        """以正規化後的帳號查詢，避免大小寫變形造成重複記錄（FIND-003）。

        AD 的 sAMAccountName 不分大小寫，若以精確比對查詢，
        ``Admin`` 與 ``admin`` 會被當成兩個不同的人，
        造成鎖定計數失效與權限歸屬分歧。
        """
        target = normalize_username(username)
        # func.lower 在資料庫端比對，可搭配函式索引；
        # casefold 與 lower 對 ASCII 帳號名結果一致。
        return self._session.scalar(
            select(User).where(func.lower(User.username) == target)
        )

    def _audit(self, username: str, action: str, detail: str, ip_address: str) -> None:
        self._session.add(
            AuditLog(
                actor_username=username,
                action=action,
                target_type="auth",
                detail=detail,
                ip_address=ip_address,
            )
        )

    # ------------------------------------------------------------------
    # 本地管理員佈建
    # ------------------------------------------------------------------

    def ensure_bootstrap_admin(self, username: str, password: str) -> User | None:
        """首次啟動時建立本地管理員（FR-13b）。

        已存在時不覆寫密碼——避免重啟服務就把管理員密碼重設回環境變數的值。
        """
        if not username or not password:
            logger.warning("未設定本地管理員帳密，跳過建立。AD 故障時將無法登入。")
            return None

        existing = self._find_user(username)
        if existing is not None:
            return existing

        admin = User(
            username=username,
            display_name="本地管理員",
            role=UserRole.ADMIN.value,
            is_local=True,
            password_hash=hash_password(password),
            is_active=True,
        )
        self._session.add(admin)
        self._session.commit()
        logger.info("已建立本地管理員帳號：%s", username)
        return admin


def _as_aware(value: datetime | None) -> datetime | None:
    """把資料庫回傳的 datetime 統一成帶時區的 UTC。

    並非所有資料庫後端都保留時區資訊（SQLite 就會回傳 naive datetime）。
    若直接與 ``datetime.now(UTC)`` 比較會拋 TypeError——
    對登入鎖定這種安全檢查而言，例外等同於檢查失效，
    因此在此統一正規化，而非在每個呼叫點各自處理。
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def generate_session_token() -> str:
    """產生高熵的 session token。"""
    return secrets.token_urlsafe(32)


def find_ad_user_attributes(
    session: Session, config: LdapConfig, username: str
) -> dict[str, str]:
    """以服務帳號查詢 AD 使用者的顯示名稱與 Email。

    登入驗證用的是使用者自己的 bind，這裡另以服務帳號查屬性，
    因為使用者帳號未必有讀取目錄的權限。
    """
    from app.providers.ldap_provider import LdapProvider

    provider = LdapProvider(
        config,
        user_filter=build_filter("(sAMAccountName={u})", u=username),
        label=f"user:{username}",
    )
    result = provider.fetch()
    if result.accounts:
        account = result.accounts[0]
        return {"display_name": account.display_name, "email": account.email}
    return {}
