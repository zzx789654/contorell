"""驗證 Gate G3 資安修補 — FIND-001~006 的迴歸測試。

每個 finding 都必須有測試佐證修補確實生效，否則「已修補」只是宣稱。
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.auth.service import (
    MAX_ATTEMPTS_PER_IDENTITY,
    AccountLocked,
    AuthenticationFailed,
    AuthService,
    normalize_username,
)
from app.db.models import Base, LoginAttempt, User, UserRole
from app.providers.api_provider import (
    FORBIDDEN_HEADER_NAMES,
    ApiConfig,
    ApiProvider,
    AuthType,
    FieldMapping,
)
from app.providers.base import ConfigurationError
from app.security.crypto import hash_password
from app.security.url_guard import UrlNotAllowed, validate_external_url


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        yield s


# ---------------------------------------------------------------------------
# FIND-002：SSRF 防護（CWE-918）
# ---------------------------------------------------------------------------


class TestSsrfDefense:
    """外部 URL 不可指向內網、本機或雲端 metadata。"""

    @pytest.mark.parametrize(
        ("url", "why"),
        [
            ("http://127.0.0.1:8080/api", "loopback"),
            ("http://localhost/api", "loopback 名稱"),
            ("http://169.254.169.254/latest/meta-data/", "AWS/Azure metadata 端點"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
            ("http://10.0.0.5/api", "RFC1918 內網"),
            ("http://192.168.1.1/api", "RFC1918 內網"),
            ("http://172.16.0.1/api", "RFC1918 內網"),
            ("http://0.0.0.0/api", "未指定位址"),
            ("http://[::1]/api", "IPv6 loopback"),
        ],
    )
    def test_internal_addresses_blocked(self, url, why):
        with pytest.raises(UrlNotAllowed):
            validate_external_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "gopher://example.com/",
            "//example.com/api",
        ],
    )
    def test_non_http_schemes_rejected(self, url):
        with pytest.raises(UrlNotAllowed):
            validate_external_url(url)

    def test_allowlist_blocks_unlisted_host(self):
        with pytest.raises(UrlNotAllowed, match="允許清單"):
            validate_external_url(
                "https://evil.example.com/api",
                allowed_hosts=frozenset({"erp.company.com"}),
            )

    def test_allowlist_permits_listed_host(self):
        # 允許清單命中即放行，不再做 DNS 解析
        validate_external_url(
            "https://erp.company.com/api",
            allowed_hosts=frozenset({"erp.company.com"}),
        )

    def test_allowlist_is_case_insensitive(self):
        validate_external_url(
            "https://ERP.Company.com/api",
            allowed_hosts=frozenset({"erp.company.com"}),
        )

    def test_private_network_allowed_when_explicitly_enabled(self):
        """企業內部系統常在內網，但必須是明確的設定決定。"""
        validate_external_url("http://10.0.0.5/api", allow_private=True)

    def test_api_config_rejects_ssrf_target(self):
        """SSRF 防護必須在設定驗證時就生效。"""
        config = ApiConfig(
            url="http://169.254.169.254/latest/meta-data/",
            field_mapping=FieldMapping(identifier="username"),
        )

        with pytest.raises(ConfigurationError):
            config.validate()

    def test_api_provider_construction_blocked_for_internal_url(self):
        with pytest.raises(ConfigurationError):
            ApiProvider(
                ApiConfig(
                    url="http://127.0.0.1/api",
                    field_mapping=FieldMapping(identifier="user"),
                )
            )


# ---------------------------------------------------------------------------
# FIND-005：自訂標頭過濾
# ---------------------------------------------------------------------------


class TestHeaderFiltering:
    def _provider(self, extra_headers):
        return ApiProvider(
            ApiConfig(
                url="https://erp.example.com/api",
                field_mapping=FieldMapping(identifier="user"),
                extra_headers=extra_headers,
                allowed_hosts=frozenset({"erp.example.com"}),
            )
        )

    @pytest.mark.parametrize(
        "header", ["Host", "X-Forwarded-For", "X-Real-IP", "Cookie", "Authorization"]
    )
    def test_dangerous_headers_dropped(self, header):
        provider = self._provider({header: "attacker-value"})

        headers = provider._build_request_args()["headers"]

        assert header not in headers
        assert header.lower() not in {k.lower() for k in headers}

    def test_benign_headers_preserved(self):
        provider = self._provider({"X-Tenant-Id": "acme", "Accept-Language": "zh-TW"})

        headers = provider._build_request_args()["headers"]

        assert headers["X-Tenant-Id"] == "acme"
        assert headers["Accept-Language"] == "zh-TW"

    def test_auth_header_still_applied_after_filtering(self):
        """過濾不可影響正常的驗證標頭設定。"""
        provider = ApiProvider(
            ApiConfig(
                url="https://erp.example.com/api",
                field_mapping=FieldMapping(identifier="user"),
                auth_type=AuthType.BEARER,
                auth_secret="token123",  # noqa: S106
                extra_headers={"Authorization": "attacker-supplied"},
                allowed_hosts=frozenset({"erp.example.com"}),
            )
        )

        headers = provider._build_request_args()["headers"]

        # 使用者自訂的 Authorization 被丟棄，設定的 Bearer token 生效
        assert headers["Authorization"] == "Bearer token123"

    def test_forbidden_list_covers_routing_headers(self):
        for name in ("host", "x-forwarded-for", "x-forwarded-host", "x-real-ip"):
            assert name in FORBIDDEN_HEADER_NAMES


# ---------------------------------------------------------------------------
# FIND-003：大小寫變形繞過鎖定
# ---------------------------------------------------------------------------


class TestUsernameNormalization:
    def test_normalize_is_case_insensitive(self):
        assert normalize_username("Admin") == normalize_username("ADMIN")
        assert normalize_username("  aDmIn  ") == "admin"

    def test_case_variants_find_same_user(self, session):
        session.add(
            User(
                username="admin",
                role=UserRole.ADMIN.value,
                is_local=True,
                password_hash=hash_password("Str0ng!Pass"),
                is_active=True,
            )
        )
        session.commit()
        service = AuthService(session)

        for variant in ("admin", "Admin", "ADMIN", "aDmIn"):
            result = service.authenticate(variant, "Str0ng!Pass")
            assert result.user.username == "admin"

    def test_case_variants_share_failure_count(self, session):
        """FIND-003 核心：不可用大小寫變形取得額外的嘗試次數。"""
        session.add(
            User(
                username="target",
                role=UserRole.ADMIN.value,
                is_local=True,
                password_hash=hash_password("Str0ng!Pass"),
                is_active=True,
            )
        )
        session.commit()
        service = AuthService(session)

        variants = ["target", "Target", "TARGET", "tArGeT", "TaRgEt", "targeT"]
        locked = False

        for variant in variants:
            try:
                service.authenticate(variant, "wrong-password")
            except AccountLocked:
                locked = True
                break
            except AuthenticationFailed:
                continue

        assert locked, "大小寫變形應共用同一組失敗計數，達門檻後必須鎖定"


# ---------------------------------------------------------------------------
# FIND-004：未佈建帳號的節流
# ---------------------------------------------------------------------------


class TestUnprovisionedAccountThrottling:
    def test_unknown_account_attempts_are_counted(self, session):
        """本地沒有記錄的帳號（AD 首次登入）也必須被計數。"""
        service = AuthService(session, ldap_config=None)

        for _ in range(3):
            with pytest.raises(AuthenticationFailed):
                service.authenticate("never-seen-before", "guess")

        attempt = session.query(LoginAttempt).filter_by(identity_key="never-seen-before").one()
        assert attempt.failure_count == 3

    def test_unknown_account_eventually_throttled(self, session):
        """FIND-004 核心：AD 帳號首次爆破必須被擋下。"""
        service = AuthService(session, ldap_config=None)

        throttled = False
        for _ in range(MAX_ATTEMPTS_PER_IDENTITY + 2):
            try:
                service.authenticate("victim", "guess")
            except AccountLocked:
                throttled = True
                break
            except AuthenticationFailed:
                continue

        assert throttled, "超過身分層級門檻後必須拒絕繼續嘗試"

    def test_throttle_key_is_normalized(self, session):
        """節流計數也不可被大小寫變形繞過。"""
        service = AuthService(session, ldap_config=None)

        for variant in ("Victim", "VICTIM", "victim"):
            with pytest.raises(AuthenticationFailed):
                service.authenticate(variant, "guess")

        records = session.query(LoginAttempt).all()
        assert len(records) == 1, "大小寫變形應共用同一筆節流記錄"
        assert records[0].failure_count == 3

    def test_successful_login_clears_throttle(self, session):
        session.add(
            User(
                username="user1",
                role=UserRole.ADMIN.value,
                is_local=True,
                password_hash=hash_password("Str0ng!Pass"),
                is_active=True,
            )
        )
        session.commit()
        service = AuthService(session)

        with pytest.raises(AuthenticationFailed):
            service.authenticate("user1", "wrong")
        assert session.query(LoginAttempt).count() == 1

        service.authenticate("user1", "Str0ng!Pass")

        assert session.query(LoginAttempt).count() == 0
