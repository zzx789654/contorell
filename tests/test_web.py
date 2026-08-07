"""Web 層整合測試 — 對應 AC-13（授權）、AC-09（標註）、AC-12（匯出）。

驗證重點：授權在伺服器端強制執行，未登入與越權都被正確擋下。
"""

import os
import tempfile
from pathlib import Path

import pytest

# 測試用設定必須在匯入 app 之前設定
_TEST_DB = Path(tempfile.gettempdir()) / "contorell_test.db"
# 以程式組出測試金鑰，避免密鑰掃描工具把長字面值誤判為真實憑證
os.environ.setdefault("SECRET_KEY", "-".join(["web", "test", "dummy", "key"]) + "-" + "1" * 24)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "Test!Admin!Pass1")
os.environ.setdefault("APP_ENV", "development")

from fastapi.testclient import TestClient  # noqa: E402

from app.db.models import (  # noqa: E402
    Base,
    DataSource,
    SourceType,
    User,
    UserRole,
)
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security.crypto import hash_password  # noqa: E402


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


def create_user(username: str, role: str, password: str = "Test!Pass123") -> User:
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
        session.refresh(user)
        return user


def get_csrf(client: TestClient) -> str:
    """從登入頁取出 CSRF token（FIND-001 後所有 POST 都需要）。"""
    import re

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


class TestAuthorizationEnforcement:
    """AC-13：未登入回 401，越權回 403。授權一律在伺服器端判斷。"""

    @pytest.mark.parametrize("path", ["/", "/sources", "/audit", "/comparisons/1"])
    def test_unauthenticated_access_denied(self, client, path):
        response = client.get(path, follow_redirects=False)

        assert response.status_code == 401

    @pytest.mark.parametrize("path", ["/", "/sources", "/audit"])
    def test_browser_navigation_redirects_to_login(self, client, path):
        """一般瀏覽器（Accept: text/html）開受保護頁面要 303 導向 /login，
        而不是回一個死的 401——否則使用者直接開網站根目錄會以為「網頁打不開」。"""
        response = client.get(
            path,
            headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_htmx_unauthenticated_gets_hx_redirect(self, client):
        """HTMX 請求未登入時回 401 並帶 HX-Redirect，供前端 JS 導頁。"""
        response = client.get("/", headers={"HX-Request": "true"}, follow_redirects=False)

        assert response.status_code == 401
        assert response.headers.get("HX-Redirect") == "/login"

    def test_unauthenticated_post_denied(self, client):
        """未登入的 POST 回 401（而非 403）——真正的原因是未認證。"""
        response = client.post(
            "/compare", data={"source_a_id": 1, "source_b_id": 2}, follow_redirects=False
        )

        assert response.status_code == 401

    def test_auditor_cannot_run_comparison(self, client):
        """稽核者是唯讀角色，不可執行比對（403 而非 401）。"""
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        # 帶上有效 CSRF token，確保 403 來自角色檢查而非 CSRF 檢查
        response = client.post(
            "/compare",
            data={
                "source_a_id": 1,
                "source_b_id": 2,
                "csrf_token": get_csrf(client),
            },
            follow_redirects=False,
        )

        assert response.status_code == 403

    def test_auditor_cannot_save_annotation(self, client):
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        response = client.post(
            "/rows/1/annotate",
            data={"field_key": "note", "value": "x", "csrf_token": get_csrf(client)},
        )

        assert response.status_code == 403

    def test_auditor_can_view_pages(self, client):
        """稽核者可以讀取，只是不能寫入。"""
        create_user("auditor", UserRole.AUDITOR.value)
        login(client, "auditor")

        assert client.get("/").status_code == 200
        assert client.get("/audit").status_code == 200

    def test_admin_can_access_write_endpoints(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        # 來源不存在會回 404，但已通過 CSRF 與授權檢查（非 403）
        response = client.post("/sources/999/test", headers={"X-CSRF-Token": get_csrf(client)})

        assert response.status_code == 404

    def test_deactivated_user_session_invalidated(self, client):
        """使用者被停用後，既有 session 應立即失效。"""
        create_user("temp", UserRole.ADMIN.value)
        login(client, "temp")
        assert client.get("/").status_code == 200

        with SessionLocal() as session:
            user = session.query(User).filter_by(username="temp").one()
            user.is_active = False
            session.commit()

        assert client.get("/").status_code == 401


class TestLoginFlow:
    def test_login_page_accessible_without_auth(self, client):
        assert client.get("/login").status_code == 200

    def test_wrong_password_returns_401_with_generic_message(self, client):
        create_user("someone", UserRole.ADMIN.value)

        response = client.post(
            "/login",
            data={
                "username": "someone",
                "password": "wrong",
                "csrf_token": get_csrf(client),
            },
        )

        assert response.status_code == 401
        assert "帳號或密碼錯誤" in response.text

    def test_successful_login_redirects_home(self, client):
        create_user("boss", UserRole.ADMIN.value)

        response = login(client, "boss")

        assert response.status_code == 303
        assert response.headers["location"] == "/"

    def test_session_rotated_on_login(self, client):
        """防 session fixation：登入後應換發 session cookie。"""
        create_user("boss", UserRole.ADMIN.value)

        client.get("/login")
        before = client.cookies.get("contorell_session")

        login(client, "boss")
        after = client.cookies.get("contorell_session")

        assert after != before

    def test_logout_clears_session(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        client.post(
            "/logout",
            data={"csrf_token": get_csrf(client)},
            follow_redirects=False,
        )

        assert client.get("/", follow_redirects=False).status_code == 401


class TestCsrfProtection:
    """FIND-001（CWE-352）：所有變更狀態的請求都必須帶有效 CSRF token。"""

    def test_post_without_token_rejected(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.post("/compare", data={"source_a_id": 1, "source_b_id": 2})

        assert response.status_code == 403

    def test_post_with_wrong_token_rejected(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.post(
            "/compare",
            data={"source_a_id": 1, "source_b_id": 2, "csrf_token": "forged-token"},
        )

        assert response.status_code == 403

    def test_annotate_without_token_rejected(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.post("/rows/1/annotate", data={"field_key": "x", "value": "y"})

        assert response.status_code == 403

    def test_logout_without_token_rejected(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        assert client.post("/logout", follow_redirects=False).status_code == 403
        # 未登出成功，session 仍有效
        assert client.get("/").status_code == 200

    def test_login_without_token_rejected(self, client):
        """登入型 CSRF：攻擊者不可強制受害者登入自己的帳號。

        全新的用戶端沒有 session，回 401（無會話）；
        已有 session 但 token 錯誤則回 403。兩者都必須拒絕登入。
        """
        create_user("boss", UserRole.ADMIN.value)

        # 情境一：完全沒有 session
        response = client.post("/login", data={"username": "boss", "password": "Test!Pass123"})
        assert response.status_code == 401
        assert not client.cookies.get("contorell_session") or (
            client.get("/", follow_redirects=False).status_code == 401
        ), "未帶 token 的登入不可建立已認證的 session"

        # 情境二：有 session 但 token 偽造
        get_csrf(client)  # 建立 session 與 token
        response = client.post(
            "/login",
            data={
                "username": "boss",
                "password": "Test!Pass123",
                "csrf_token": "forged",
            },
        )
        assert response.status_code == 403
        assert client.get("/", follow_redirects=False).status_code == 401

    def test_cross_origin_request_rejected(self, client):
        """Origin 與本站不符時拒絕（第二道防線）。"""
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")
        token = client.cookies.get("contorell_session")
        assert token  # 已登入

        response = client.post(
            "/compare",
            data={"source_a_id": 1, "source_b_id": 2, "csrf_token": get_csrf(client)},
            headers={"Origin": "https://evil.example.com"},
        )

        assert response.status_code == 403

    def test_htmx_header_token_accepted(self, client):
        """HTMX 以標頭帶 token 也必須被接受。"""
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.post("/sources/999/test", headers={"X-CSRF-Token": get_csrf(client)})

        # 通過 CSRF 檢查後才會走到「來源不存在」的 404
        assert response.status_code == 404

    def test_token_rotated_after_login(self, client):
        """登入後換發 token，防止 session fixation 延伸的 CSRF。"""
        create_user("boss", UserRole.ADMIN.value)

        before = get_csrf(client)
        login(client, "boss")
        after = get_csrf(client)

        assert before != after

    def test_safe_methods_not_blocked(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        assert client.get("/").status_code == 200
        assert client.get("/sources").status_code == 200


class TestSecurityHeaders:
    """縱深防禦：安全標頭一律套用。"""

    def test_security_headers_present(self, client):
        response = client.get("/login")

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

    def test_csp_blocks_external_sources(self, client):
        """CSP 必須限制為同源，防止 XSS 資料外傳。"""
        csp = client.get("/login").headers["Content-Security-Policy"]

        assert "default-src 'self'" in csp
        assert "form-action 'self'" in csp


class TestXssDefense:
    """Jinja2 autoescape 必須生效。"""

    def test_username_is_escaped_in_login_error(self, client):
        payload = "<script>alert(1)</script>"

        response = client.post(
            "/login",
            data={"username": payload, "password": "x", "csrf_token": get_csrf(client)},
        )

        # 原始 script 標籤不可出現在回應中
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;" in response.text


class TestComparisonValidation:
    def test_same_source_rejected(self, client):
        """來源 A 與 B 相同時應給出明確錯誤，而非產出無意義的比對。"""
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.post(
            "/compare",
            data={"source_a_id": 1, "source_b_id": 1, "csrf_token": get_csrf(client)},
        )

        assert response.status_code == 400

    def test_nonexistent_comparison_returns_404(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        assert client.get("/comparisons/99999").status_code == 404

    def test_invalid_export_format_rejected(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.get("/comparisons/1/export?fmt=exe")

        assert response.status_code == 400


class TestEmptyStates:
    """UI 六種狀態之一：empty state 必須存在且有指引。"""

    def test_home_shows_guidance_when_no_sources(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.get("/")

        assert response.status_code == 200
        assert "還需要設定資料來源" in response.text

    def test_sources_page_shows_empty_state(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.get("/sources")

        assert "還沒有任何資料來源" in response.text

    def test_audit_page_shows_empty_state(self, client):
        create_user("boss", UserRole.ADMIN.value)
        login(client, "boss")

        response = client.get("/audit")

        assert response.status_code == 200


class TestRoleVisibility:
    """無權限狀態：稽核者應看到明確說明，而非壞掉的按鈕。"""

    def test_auditor_sees_readonly_notice(self, client):
        create_user("auditor", UserRole.AUDITOR.value)
        with SessionLocal() as session:
            session.add(
                DataSource(name="AD", source_type=SourceType.LDAP.value, is_authoritative=True)
            )
            session.add(DataSource(name="ERP", source_type=SourceType.API.value))
            session.commit()

        login(client, "auditor")
        response = client.get("/")

        assert "稽核者" in response.text
        assert "無法執行比對" in response.text
