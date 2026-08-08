"""權限檢視 web 層測試（Round 8）：矩陣主畫面、權限來源分頁、註記。"""

import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

_TEST_DB = Path(tempfile.gettempdir()) / "contorell_review_test.db"
os.environ.setdefault("SECRET_KEY", "-".join(["review", "test", "dummy", "key"]) + "-" + "3" * 24)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "Test!Admin!Pass1")
os.environ.setdefault("APP_ENV", "development")

from fastapi.testclient import TestClient  # noqa: E402

from app.db.models import (  # noqa: E402
    Base,
    DataSource,
    EntitlementNote,
    Snapshot,
    SnapshotAccount,
    SourceType,
)
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


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


def get_csrf(client: TestClient) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text)
    assert match
    return match.group(1)


def _make_user(username: str, role: str, password: str = "Test!Pass123"):
    """建立本地帳號並登入 —— 不依賴 bootstrap admin 密碼（避免 CI 環境變數覆寫導致 401）。"""
    from app.db.models import User
    from app.security.crypto import hash_password

    with SessionLocal() as db:
        db.add(
            User(
                username=username,
                role=role,
                is_local=True,
                password_hash=hash_password(password),
                is_active=True,
            )
        )
        db.commit()


def login(client: TestClient, username: str, password: str = "Test!Pass123"):
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": get_csrf(client)},
        follow_redirects=False,
    )


def login_admin(client: TestClient):
    from app.db.models import UserRole

    _make_user("rvadmin", UserRole.ADMIN.value)
    return login(client, "rvadmin")


def _acct(snap_id: int, uid: str, name: str = "", status: str = "enabled", **attrs):
    return SnapshotAccount(
        snapshot_id=snap_id,
        identifier=uid,
        normalized_key=uid.lower(),
        display_name=name,
        status=status,
        attributes_json=attrs,
    )


def _seed() -> int:
    """建立主檔（0001,0002 啟用）+ 權限群組（0001 啟用、0009 停用）。回傳權限來源 id。"""
    with SessionLocal() as db:
        master = DataSource(
            name="AD 已啟用帳號", source_type=SourceType.LDAP.value, is_authoritative=True
        )
        net = DataSource(name="網路權限", source_type=SourceType.LDAP.value)
        db.add_all([master, net])
        db.flush()

        ms = Snapshot(source_id=master.id, account_count=2, fetched_at=datetime.now(UTC))
        db.add(ms)
        db.flush()
        db.add(_acct(ms.id, "0001", "王小明", employeeID="0001", department="資訊部"))
        db.add(_acct(ms.id, "0002", "李大華", employeeID="0002", department="財務部"))

        ns = Snapshot(source_id=net.id, account_count=2, fetched_at=datetime.now(UTC))
        db.add(ns)
        db.flush()
        db.add(_acct(ns.id, "0001", "王小明"))
        db.add(_acct(ns.id, "0009", "張前員", status="disabled"))  # 異常：停用未回收

        db.commit()
        return net.id


class TestReviewMatrix:
    def test_review_page_shows_matrix_and_anomaly(self, client):
        _seed()
        login_admin(client)
        resp = client.get("/review")
        assert resp.status_code == 200
        # 主檔人員在矩陣中
        assert "王小明" in resp.text
        # 權限群組欄
        assert "網路權限" in resp.text
        # 停用未回收異常被標出
        assert "停用未回收" in resp.text
        assert "0009" in resp.text

    def test_review_empty_state_without_master(self, client):
        login_admin(client)
        resp = client.get("/review")
        assert resp.status_code == 200
        assert "還需要一份" in resp.text  # 引導設定主檔


class TestEntitlementDetail:
    def test_detail_page_lists_members_and_anomaly(self, client):
        source_id = _seed()
        login_admin(client)
        resp = client.get(f"/review/source/{source_id}")
        assert resp.status_code == 200
        assert "網路權限" in resp.text
        assert "0009" in resp.text
        assert "停用未回收" in resp.text

    def test_detail_404_for_unknown_source(self, client):
        login_admin(client)
        assert client.get("/review/source/9999").status_code == 404

    def test_admin_can_save_note(self, client):
        source_id = _seed()
        login_admin(client)
        resp = client.post(
            f"/review/source/{source_id}/note",
            data={
                "account_key": "0009",
                "note": "已通知資訊部回收",
                "csrf_token": get_csrf(client),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with SessionLocal() as db:
            note = (
                db.query(EntitlementNote).filter_by(source_id=source_id, account_key="0009").one()
            )
            assert note.note == "已通知資訊部回收"

    def test_auditor_cannot_save_note(self, client):
        source_id = _seed()
        # 稽核者（唯讀）不可寫註記
        from app.db.models import User, UserRole
        from app.security.crypto import hash_password

        with SessionLocal() as db:
            db.add(
                User(
                    username="auditor",
                    role=UserRole.AUDITOR.value,
                    is_local=True,
                    password_hash=hash_password("Test!Pass123"),
                    is_active=True,
                )
            )
            db.commit()
        client.post(
            "/login",
            data={
                "username": "auditor",
                "password": "Test!Pass123",
                "csrf_token": get_csrf(client),
            },
            follow_redirects=False,
        )
        resp = client.post(
            f"/review/source/{source_id}/note",
            data={"account_key": "0009", "note": "x", "csrf_token": get_csrf(client)},
            follow_redirects=False,
        )
        assert resp.status_code == 403


class TestManualEntitlement:
    def test_admin_creates_manual_entitlement(self, client):
        _seed()  # 主檔已存在
        login_admin(client)
        resp = client.post(
            "/review/manual",
            data={
                "name": "VPN",
                "account_ids": "0001, 0009\n9999\n0001",  # 0001 重複、含異常帳號
                "csrf_token": get_csrf(client),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with SessionLocal() as db:
            src = db.query(DataSource).filter_by(name="VPN").one()
            assert src.source_type == SourceType.FILE.value
        detail = client.get(resp.headers["location"])
        assert detail.status_code == 200
        # 0001 在主檔（在職）、9999 不在（孤兒異常）；0001 去重後只一筆
        assert "9999" in detail.text
        assert "孤兒帳號" in detail.text

    def test_auditor_cannot_open_manual_form(self, client):
        from app.db.models import User, UserRole
        from app.security.crypto import hash_password

        with SessionLocal() as db:
            db.add(
                User(
                    username="aud",
                    role=UserRole.AUDITOR.value,
                    is_local=True,
                    password_hash=hash_password("Test!Pass123"),
                    is_active=True,
                )
            )
            db.commit()
        client.post(
            "/login",
            data={"username": "aud", "password": "Test!Pass123", "csrf_token": get_csrf(client)},
            follow_redirects=False,
        )
        assert client.get("/review/manual").status_code == 403


class TestHomeFilterAutosave:
    def test_home_is_review_matrix(self, client):
        _seed()
        login_admin(client)
        r = client.get("/")
        assert r.status_code == 200
        assert "人員權限矩陣" in r.text
        assert "王小明" in r.text

    def test_review_url_redirects_to_home(self, client):
        login_admin(client)
        r = client.get("/review", follow_redirects=False)
        assert r.status_code == 307
        assert r.headers["location"] == "/"

    def test_search_filters_people(self, client):
        _seed()
        login_admin(client)
        r = client.get("/", params={"q": "李大華"})
        assert r.status_code == 200
        assert "李大華" in r.text
        assert "王小明" not in r.text  # 被搜尋濾掉

    def test_filter_by_department(self, client):
        _seed()
        login_admin(client)
        r = client.get("/", params={"dept": "財務部"})
        assert "李大華" in r.text  # 財務部
        assert "王小明" not in r.text  # 資訊部

    def test_note_autosave_via_htmx(self, client):
        sid = _seed()
        login_admin(client)
        r = client.post(
            f"/review/source/{sid}/note",
            data={"account_key": "0009", "note": "處理中"},
            headers={"HX-Request": "true", "X-CSRF-Token": get_csrf(client)},
        )
        assert r.status_code == 200
        assert "已儲存" in r.text
        with SessionLocal() as db:
            note = db.query(EntitlementNote).filter_by(source_id=sid, account_key="0009").one()
            assert note.note == "處理中"
