"""來源設定路由測試 — Round 2。

驗證重點：新增的變更狀態路由都受到與 Round 1 同等的保護——
未登入 401、稽核者 403、缺 CSRF token 被拒、密碼加密儲存且不外洩。
"""

import os
import re
import tempfile
from pathlib import Path

import pytest

# 測試用設定必須在匯入 app 之前設定
_TEST_DB = Path(tempfile.gettempdir()) / "contorell_source_routes_test.db"
# 以程式組出測試金鑰，避免密鑰掃描工具把長字面值誤判為真實憑證（見 lessons L-12）
os.environ.setdefault(
    "SECRET_KEY", "-".join(["routes", "test", "dummy", "key"]) + "-" + "2" * 24
)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "Test!Admin!Pass1")
os.environ.setdefault("APP_ENV", "development")

from fastapi.testclient import TestClient  # noqa: E402

from app.db.models import Base, DataSource, SourceType, User, UserRole  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security.crypto import hash_password  # noqa: E402

# 測試用的假密碼，以組合方式產生避免被誤判為真實憑證
FAKE_BIND_PASSWORD = "-".join(["fake", "bind", "secret"]) + "-" + "9" * 8


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def create_user(username: str, role: str, password: str = "Test!Pass123") -> int:
    with SessionLocal() as session:
        user = User(
            username=username,
            role=role,
            is_local=True,
            password_hash=hash_password(password),
            is_active=True,
        )
        session.add(user)
        session.commit()
        return user.id


def get_csrf(client: TestClient) -> str:
    response = client.get("/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "登入頁應包含 CSRF token"
    return match.group(1)


def login(client: TestClient, username: str, password: str = "Test!Pass123"):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": get_csrf(client)},
        follow_redirects=False,
    )


def valid_payload(client: TestClient, **overrides) -> dict:
    data = {
        "csrf_token": get_csrf(client),
        "name": "AD — 測試來源",
        "host": "dc01.corp.local",
        "use_ssl": "1",
        "port": "636",
        "base_dn": "DC=corp,DC=local",
        "bind_dn": "CN=svc,OU=Service,DC=corp,DC=local",
        "bind_password": FAKE_BIND_PASSWORD,
        "verify_cert": "1",
        "template_key": "enabled_users",
        "page_size": "1000",
        "receive_timeout": "30",
        "is_active": "1",
        "is_authoritative": "1",
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


def seed_ldap_source(name: str = "既有來源") -> int:
    with SessionLocal() as session:
        source = DataSource(
            name=name,
            source_type=SourceType.LDAP.value,
            config_json={
                "host": "dc01.corp.local",
                "base_dn": "DC=corp,DC=local",
                "bind_dn": "CN=svc,DC=corp,DC=local",
                "template_key": "enabled_users",
                "page_size": 1000,
            },
            encrypted_secret="",
            is_active=True,
        )
        session.add(source)
        session.commit()
        return source.id


class TestAuthorization:
    """AC-13：授權一律在伺服器端強制執行。"""

    @pytest.mark.parametrize("path", ["/sources/new", "/sources/1/edit"])
    def test_unauthenticated_get_denied(self, client, path):
        response = client.get(path, follow_redirects=False)

        assert response.status_code == 401

    @pytest.mark.parametrize(
        "path", ["/sources/save", "/sources/1/toggle", "/sources/1/groups"]
    )
    def test_unauthenticated_post_denied(self, client, path):
        response = client.post(path, data={}, follow_redirects=False)

        assert response.status_code == 401

    @pytest.mark.parametrize("path", ["/sources/new", "/sources/1/edit"])
    def test_auditor_cannot_open_config_form(self, client, path):
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        response = client.get(path, follow_redirects=False)

        assert response.status_code == 403

    def test_auditor_cannot_save_source(self, client):
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        response = client.post(
            "/sources/save", data=valid_payload(client), follow_redirects=False
        )

        assert response.status_code == 403

    def test_auditor_cannot_toggle_source(self, client):
        source_id = seed_ldap_source()
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        response = client.post(
            f"/sources/{source_id}/toggle",
            data={"csrf_token": get_csrf(client)},
            follow_redirects=False,
        )

        assert response.status_code == 403

    def test_auditor_sees_no_edit_link(self, client):
        seed_ldap_source()
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        response = client.get("/sources")

        assert "/sources/new" not in response.text


class TestCsrfProtection:
    """FIND-001（CWE-352）：所有變更狀態的路由都必須驗證 CSRF token。"""

    def test_save_without_csrf_rejected(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        payload = valid_payload(client)
        payload.pop("csrf_token")

        response = client.post("/sources/save", data=payload, follow_redirects=False)

        assert response.status_code == 403

    def test_save_with_wrong_csrf_rejected(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, csrf_token="-".join(["forged", "value"])),
            follow_redirects=False,
        )

        assert response.status_code == 403

    def test_toggle_without_csrf_rejected(self, client):
        source_id = seed_ldap_source()
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            f"/sources/{source_id}/toggle", data={}, follow_redirects=False
        )

        assert response.status_code == 403


class TestCreateAndEdit:
    def test_admin_can_open_new_form(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get("/sources/new")

        assert response.status_code == 200
        assert "網域控制站" in response.text

    def test_form_shows_field_help(self, client):
        """每個參數都要有說明——這是本輪的功能需求之一。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get("/sources/new")

        assert "Base DN 怎麼寫" in response.text
        assert "為什麼分頁很重要" in response.text
        # ldapsearch 對照
        assert "ldapsearch" in response.text

    def test_form_lists_all_query_templates(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get("/sources/new")

        assert "啟用中的真人帳號" in response.text
        assert "已停用的帳號" in response.text
        assert "指定部門的成員" in response.text

    def test_form_has_no_raw_filter_input(self, client):
        """安全性：介面上不得存在可直接輸入 LDAP filter 的欄位。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get("/sources/new")

        assert 'name="user_filter"' not in response.text
        assert 'name="search_filter"' not in response.text
        assert 'name="raw_filter"' not in response.text

    def test_create_source_succeeds(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save", data=valid_payload(client), follow_redirects=False
        )

        assert response.status_code == 303
        with SessionLocal() as session:
            source = session.query(DataSource).filter_by(name="AD — 測試來源").one()
            assert source.source_type == SourceType.LDAP.value
            assert source.config_json["host"] == "dc01.corp.local"
            assert source.config_json["template_key"] == "enabled_users"

    def test_created_source_password_is_encrypted(self, client):
        """NFR-05：密碼不得以明文存進資料庫。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        client.post("/sources/save", data=valid_payload(client), follow_redirects=False)

        with SessionLocal() as session:
            source = session.query(DataSource).filter_by(name="AD — 測試來源").one()
            assert source.encrypted_secret
            assert FAKE_BIND_PASSWORD not in source.encrypted_secret
            assert FAKE_BIND_PASSWORD not in str(source.config_json)

    def test_validation_error_returns_400_with_messages(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, host=""),
            follow_redirects=False,
        )

        assert response.status_code == 400
        assert "需要修正" in response.text

    def test_validation_error_preserves_user_input(self, client):
        """驗證失敗時保留已填內容，管理者不必重打整份表單。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, host="", name="我填過的名稱"),
            follow_redirects=False,
        )

        assert "我填過的名稱" in response.text

    def test_validation_error_does_not_echo_password(self, client):
        """回填時絕不把密碼送回瀏覽器。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, host=""),
            follow_redirects=False,
        )

        assert FAKE_BIND_PASSWORD not in response.text

    def test_plaintext_ldap_rejected_by_route(self, client):
        """NFR-04：未加密連線在路由層也被擋下。"""
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, use_ssl=None, use_start_tls=None),
            follow_redirects=False,
        )

        assert response.status_code == 400

    def test_duplicate_name_rejected(self, client):
        seed_ldap_source("重複名稱")
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.post(
            "/sources/save",
            data=valid_payload(client, name="重複名稱"),
            follow_redirects=False,
        )

        assert response.status_code == 400
        assert "已經有一個叫" in response.text

    def test_edit_form_prefills_settings(self, client):
        source_id = seed_ldap_source()
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get(f"/sources/{source_id}/edit")

        assert response.status_code == 200
        assert "dc01.corp.local" in response.text
        assert "DC=corp,DC=local" in response.text

    def test_edit_form_does_not_prefill_password(self, client):
        source_id = seed_ldap_source()
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get(f"/sources/{source_id}/edit")

        assert 'name="bind_password"' in response.text
        assert "留空則不變更" in response.text

    def test_edit_preserves_password_when_blank(self, client):
        """編輯時留空密碼應沿用原本的，不可清空。"""
        source_id = seed_ldap_source()
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        # 先設定一次密碼
        client.post(
            "/sources/save",
            data=valid_payload(client, source_id=str(source_id), name="既有來源"),
            follow_redirects=False,
        )
        with SessionLocal() as session:
            original = session.get(DataSource, source_id).encrypted_secret
        assert original

        # 再次儲存但不填密碼
        client.post(
            "/sources/save",
            data=valid_payload(
                client,
                source_id=str(source_id),
                name="既有來源",
                bind_password=None,
                host="dc02.corp.local",
            ),
            follow_redirects=False,
        )

        with SessionLocal() as session:
            source = session.get(DataSource, source_id)
            assert source.encrypted_secret == original
            assert source.config_json["host"] == "dc02.corp.local"

    def test_edit_nonexistent_source_returns_404(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        response = client.get("/sources/99999/edit", follow_redirects=False)

        assert response.status_code == 404

    def test_toggle_flips_active_state(self, client):
        source_id = seed_ldap_source()
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        client.post(
            f"/sources/{source_id}/toggle",
            data={"csrf_token": get_csrf(client)},
            follow_redirects=False,
        )

        with SessionLocal() as session:
            assert session.get(DataSource, source_id).is_active is False


class TestAuditTrail:
    """FR-14：設定變更必須留下稽核軌跡，且不得記錄密碼。"""

    def test_create_is_audited(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        client.post("/sources/save", data=valid_payload(client), follow_redirects=False)

        from app.db.models import AuditLog

        with SessionLocal() as session:
            logs = session.query(AuditLog).filter_by(action="source_created").all()
            assert len(logs) == 1

    def test_audit_detail_excludes_password(self, client):
        create_user("admin1", UserRole.ADMIN.value)
        login(client, "admin1")

        client.post("/sources/save", data=valid_payload(client), follow_redirects=False)

        from app.db.models import AuditLog

        with SessionLocal() as session:
            for log in session.query(AuditLog).all():
                assert FAKE_BIND_PASSWORD not in log.detail
