"""認證測試 — 對應 FR-13、FR-13b、AC-13、AC-13b。

重點驗證安全屬性：
- 空密碼不可通過（防 LDAP 匿名 bind 造成的認證繞過，CWE-287）
- AD 密碼絕不儲存
- 帳號列舉防護（失敗訊息一致）
- 暴力破解節流
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.auth.service import (
    GENERIC_LOGIN_ERROR,
    MAX_FAILED_ATTEMPTS,
    AccountLocked,
    AuthenticationFailed,
    AuthService,
    generate_session_token,
)
from app.db.models import AuditLog, Base, User, UserRole
from app.providers.ldap_provider import LdapConfig
from app.security.crypto import hash_password, verify_password


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        yield s


@pytest.fixture
def ldap_config() -> LdapConfig:
    return LdapConfig(
        host="dc.example.local",
        base_dn="DC=example,DC=local",
        bind_dn="CN=svc,DC=example,DC=local",
        bind_password="svc-secret",  # noqa: S106
    )


def make_local_user(session: Session, username: str = "admin", password: str = "Str0ng!Pass") -> User:
    user = User(
        username=username,
        role=UserRole.ADMIN.value,
        is_local=True,
        password_hash=hash_password(password),
        is_active=True,
    )
    session.add(user)
    session.commit()
    return user


class TestLocalAuthentication:
    """FR-13b：本地管理員退路。"""

    def test_correct_password_succeeds(self, session):
        make_local_user(session, "admin", "Str0ng!Pass")
        service = AuthService(session)

        result = service.authenticate("admin", "Str0ng!Pass")

        assert result.method == "local"
        assert result.user.username == "admin"
        assert result.user.is_admin

    def test_wrong_password_fails(self, session):
        make_local_user(session, "admin", "Str0ng!Pass")
        service = AuthService(session)

        with pytest.raises(AuthenticationFailed):
            service.authenticate("admin", "WrongPassword")

    def test_password_stored_as_hash_not_plaintext(self, session):
        """AC-13b：本地密碼必須以 argon2 雜湊儲存。"""
        password = "Str0ng!Pass"
        user = make_local_user(session, "admin", password)

        assert password not in user.password_hash
        assert user.password_hash.startswith("$argon2")
        assert verify_password(user.password_hash, password)

    def test_successful_login_resets_failure_count(self, session):
        user = make_local_user(session, "admin", "Str0ng!Pass")
        user.failed_login_count = 3
        session.commit()

        AuthService(session).authenticate("admin", "Str0ng!Pass")

        assert user.failed_login_count == 0
        assert user.last_login_at is not None


class TestEmptyCredentialRejection:
    """CWE-287：空密碼必須被擋下。

    LDAP 的匿名 bind 在密碼為空時可能回報成功，
    若不擋會造成任意帳號都能免密碼登入的嚴重漏洞。
    """

    @pytest.mark.parametrize(
        ("username", "password"),
        [
            ("admin", ""),
            ("", "password"),
            ("", ""),
            ("admin", None),
            (None, "password"),
        ],
    )
    def test_empty_credentials_rejected(self, session, ldap_config, username, password):
        make_local_user(session, "admin", "Str0ng!Pass")
        service = AuthService(session, ldap_config)

        with pytest.raises(AuthenticationFailed):
            service.authenticate(username, password)  # type: ignore[arg-type]

    def test_empty_password_never_reaches_ldap_bind(self, session, ldap_config):
        """空密碼必須在送到 LDAP 之前就被擋下。"""
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection") as mock_conn:
            with pytest.raises(AuthenticationFailed):
                service.authenticate("someone", "")

            mock_conn.assert_not_called()

    def test_whitespace_only_username_rejected(self, session, ldap_config):
        service = AuthService(session, ldap_config)

        with pytest.raises(AuthenticationFailed):
            service.authenticate("   ", "password")


class TestAdAuthentication:
    """FR-13：AD 登入。"""

    def _mock_successful_bind(self):
        conn = MagicMock()
        conn.bind.return_value = True
        conn.bound = True
        return conn

    def _mock_failed_bind(self):
        conn = MagicMock()
        conn.bind.return_value = False
        conn.bound = False
        return conn

    def test_successful_ad_bind_creates_user(self, session, ldap_config):
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", return_value=self._mock_successful_bind()):
            result = service.authenticate("newuser", "TheirPassword")

        assert result.method == "ad"
        assert result.user.username == "newuser"
        assert not result.user.is_local

    def test_ad_password_is_never_stored(self, session, ldap_config):
        """AC-13：登入用的 AD 帳密不得被儲存。"""
        password = "TheirSecretPassword"
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", return_value=self._mock_successful_bind()):
            result = service.authenticate("newuser", password)

        assert result.user.password_hash == ""
        # 稽核紀錄中也不可出現密碼
        logs = session.query(AuditLog).all()
        assert all(password not in (log.detail or "") for log in logs)

    def test_new_ad_user_gets_least_privilege_role(self, session, ldap_config):
        """安全預設：自動建立的使用者是稽核者（唯讀），不是管理者。"""
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", return_value=self._mock_successful_bind()):
            result = service.authenticate("newuser", "pass")

        assert result.user.role == UserRole.AUDITOR.value
        assert not result.user.is_admin

    def test_failed_ad_bind_raises(self, session, ldap_config):
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", return_value=self._mock_failed_bind()):
            with pytest.raises(AuthenticationFailed):
                service.authenticate("someone", "wrongpass")

    def test_bind_true_but_not_bound_is_rejected(self, session, ldap_config):
        """防禦匿名 bind：bind() 回 True 但連線未實際認證時必須拒絕。"""
        conn = MagicMock()
        conn.bind.return_value = True
        conn.bound = False  # 未真正認證
        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", return_value=conn):
            with pytest.raises(AuthenticationFailed):
                service.authenticate("someone", "password")

    def test_ad_user_cannot_bypass_ad_via_local_path(self, session, ldap_config):
        """AD 使用者不可繞過 AD、改走本地密碼驗證。

        兩層防護：
        1. 路由依 ``is_local`` 判斷，AD 帳號不會進入本地驗證分支。
        2. 即使進入，空的 password_hash 也讓 verify_password 必定失敗。
        """
        ad_user = User(
            username="aduser",
            role=UserRole.ADMIN.value,
            is_local=False,
            password_hash="",
            is_active=True,
        )
        session.add(ad_user)
        session.commit()

        service = AuthService(session, ldap_config)

        # AD bind 失敗時，不可因為 password_hash 為空就放行
        conn = MagicMock()
        conn.bind.return_value = False
        conn.bound = False
        with patch("app.auth.service.Connection", return_value=conn):
            with pytest.raises(AuthenticationFailed):
                service.authenticate("aduser", "")
            with pytest.raises(AuthenticationFailed):
                service.authenticate("aduser", "any-guess")

    def test_empty_hash_never_verifies(self):
        """第二層防護：空雜湊值對任何密碼都不成立。"""
        assert not verify_password("", "")
        assert not verify_password("", "anything")

    def test_no_ldap_config_means_ad_login_unavailable(self, session):
        service = AuthService(session, ldap_config=None)

        with pytest.raises(AuthenticationFailed):
            service.authenticate("aduser", "password")

    def test_ldap_exception_does_not_leak_details(self, session, ldap_config):
        from ldap3.core.exceptions import LDAPExceptionError

        service = AuthService(session, ldap_config)

        with patch("app.auth.service.Connection", side_effect=LDAPExceptionError("內部細節")):
            with pytest.raises(AuthenticationFailed) as exc:
                service.authenticate("someone", "password")

        assert "內部細節" not in exc.value.message


class TestAccountEnumerationDefense:
    """AC-13b：不可讓攻擊者分辨「帳號不存在」與「密碼錯誤」。"""

    def test_identical_message_for_unknown_user_and_wrong_password(self, session, ldap_config):
        make_local_user(session, "known", "Str0ng!Pass")
        service = AuthService(session, ldap_config)

        with pytest.raises(AuthenticationFailed) as wrong_pass:
            service.authenticate("known", "WrongPassword")

        conn = MagicMock()
        conn.bind.return_value = False
        conn.bound = False
        with patch("app.auth.service.Connection", return_value=conn):
            with pytest.raises(AuthenticationFailed) as unknown_user:
                service.authenticate("does_not_exist", "AnyPassword")

        assert wrong_pass.value.message == unknown_user.value.message == GENERIC_LOGIN_ERROR

    def test_disabled_account_uses_generic_message(self, session):
        user = make_local_user(session, "disabled", "Str0ng!Pass")
        user.is_active = False
        session.commit()

        service = AuthService(session)

        with pytest.raises(AuthenticationFailed) as exc:
            service.authenticate("disabled", "Str0ng!Pass")

        assert exc.value.message == GENERIC_LOGIN_ERROR


class TestBruteForceThrottling:
    """AC-13b：連續失敗觸發鎖定。"""

    def test_account_locks_after_max_attempts(self, session):
        make_local_user(session, "target", "Str0ng!Pass")
        service = AuthService(session)

        for _ in range(MAX_FAILED_ATTEMPTS):
            with pytest.raises(AuthenticationFailed):
                service.authenticate("target", "wrong")

        # 下一次即使密碼正確也應被鎖定擋下
        with pytest.raises(AccountLocked):
            service.authenticate("target", "Str0ng!Pass")

    def test_locked_account_rejects_correct_password(self, session):
        user = make_local_user(session, "target", "Str0ng!Pass")
        user.locked_until = datetime.now(UTC) + timedelta(minutes=10)
        session.commit()

        with pytest.raises(AccountLocked):
            AuthService(session).authenticate("target", "Str0ng!Pass")

    def test_expired_lock_allows_login(self, session):
        user = make_local_user(session, "target", "Str0ng!Pass")
        user.locked_until = datetime.now(UTC) - timedelta(minutes=1)  # 已過期
        session.commit()

        result = AuthService(session).authenticate("target", "Str0ng!Pass")

        assert result.user.username == "target"


class TestAuditTrail:
    """AC-14：登入行為必須留下稽核軌跡。"""

    def test_successful_login_audited(self, session):
        make_local_user(session, "admin", "Str0ng!Pass")

        AuthService(session).authenticate("admin", "Str0ng!Pass", ip_address="10.0.0.5")

        log = session.query(AuditLog).filter_by(action="login_success").one()
        assert log.actor_username == "admin"
        assert log.ip_address == "10.0.0.5"

    def test_failed_login_audited(self, session):
        make_local_user(session, "admin", "Str0ng!Pass")

        with pytest.raises(AuthenticationFailed):
            AuthService(session).authenticate("admin", "wrong", ip_address="10.0.0.9")

        log = session.query(AuditLog).filter_by(action="login_failed").one()
        assert log.actor_username == "admin"


class TestBootstrapAdmin:
    def test_creates_admin_on_first_run(self, session):
        service = AuthService(session)

        admin = service.ensure_bootstrap_admin("admin", "Initial!Pass")

        assert admin is not None
        assert admin.is_admin
        assert admin.is_local

    def test_does_not_overwrite_existing_password(self, session):
        """重啟服務不可把管理員密碼重設回環境變數的值。"""
        service = AuthService(session)
        service.ensure_bootstrap_admin("admin", "Initial!Pass")

        user = session.query(User).filter_by(username="admin").one()
        user.password_hash = hash_password("UserChangedIt")
        session.commit()

        service.ensure_bootstrap_admin("admin", "Initial!Pass")

        assert verify_password(user.password_hash, "UserChangedIt")
        assert not verify_password(user.password_hash, "Initial!Pass")

    def test_skips_when_not_configured(self, session):
        assert AuthService(session).ensure_bootstrap_admin("", "") is None


class TestSessionToken:
    def test_tokens_are_unique_and_high_entropy(self):
        tokens = {generate_session_token() for _ in range(100)}

        assert len(tokens) == 100
        assert all(len(t) >= 32 for t in tokens)
