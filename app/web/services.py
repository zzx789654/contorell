"""把資料庫的來源設定轉成 Provider，以及快照的存取。

這一層是 DB 模型與 Provider 抽象之間的橋接，
讓路由層不需要知道各 Provider 的建構細節。
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.access_review.engine import AccessReviewResult, Entitlement, build_access_review
from app.config import get_settings
from app.db.models import (
    DataSource,
    EntitlementNote,
    Snapshot,
    SnapshotAccount,
    SourceType,
)
from app.providers.api_provider import ApiConfig, ApiProvider, AuthType, PaginationType
from app.providers.api_provider import FieldMapping as ApiFieldMapping
from app.providers.base import (
    Account,
    AccountProvider,
    AccountStatus,
    ConfigurationError,
    FetchResult,
)
from app.providers.ldap_provider import LdapConfig, LdapProvider, NestingStrategy
from app.providers.ldap_queries import DEFAULT_TEMPLATE_KEY, SearchScope
from app.security.crypto import SecretBox


def _secret_box() -> SecretBox:
    return SecretBox(get_settings().secret_key)


def build_provider(source: DataSource) -> AccountProvider:
    """依來源型態建立對應的 Provider。

    敏感值在此解密後才交給 Provider，用完即隨物件回收——
    絕不寫回資料庫、絕不寫進 log。
    """
    config = source.config_json or {}
    secret = _secret_box().decrypt(source.encrypted_secret) if source.encrypted_secret else ""

    match source.source_type:
        case SourceType.LDAP.value:
            return _build_ldap_provider(source, config, secret)
        case SourceType.API.value:
            return _build_api_provider(source, config, secret)
        case SourceType.FILE.value:
            raise ConfigurationError(
                "檔案來源需在上傳當下建立 Provider，無法由設定重建。",
                remediation="請重新上傳檔案以建立新的快照。",
            )
        case _:
            raise ConfigurationError(f"未知的來源型態：{source.source_type}")


def _build_ldap_provider(source: DataSource, config: dict, secret: str) -> LdapProvider:
    settings = get_settings()

    ldap_config = LdapConfig(
        host=config.get("host") or settings.ldap_host,
        port=int(config.get("port", settings.ldap_port)),
        use_ssl=bool(config.get("use_ssl", settings.ldap_use_ssl)),
        use_start_tls=bool(config.get("use_start_tls", False)),
        allow_plaintext=bool(config.get("allow_plaintext", False)),
        base_dn=config.get("base_dn") or settings.ldap_base_dn,
        bind_dn=config.get("bind_dn") or settings.ldap_bind_dn,
        bind_password=secret or settings.ldap_bind_password,
        verify_cert=bool(config.get("verify_cert", settings.ldap_verify_cert)),
        ca_cert_file=config.get("ca_cert_file") or settings.ldap_ca_cert_file or None,
        page_size=int(config.get("page_size", settings.ldap_page_size)),
        nesting_strategy=NestingStrategy(config.get("nesting_strategy", "recursive")),
        receive_timeout=int(config.get("receive_timeout", 30)),
        search_scope=SearchScope(config.get("search_scope", SearchScope.SUBTREE.value)),
        extra_attributes=list(config.get("extra_attributes") or []),
    )

    return LdapProvider(
        ldap_config,
        group_dn=config.get("group_dn") or None,
        template_key=config.get("template_key") or DEFAULT_TEMPLATE_KEY,
        template_parameters=config.get("template_parameters") or {},
        label=source.name,
    )


def _build_api_provider(source: DataSource, config: dict, secret: str) -> ApiProvider:
    mapping_config = config.get("field_mapping", {})

    api_config = ApiConfig(
        url=config.get("url", ""),
        method=config.get("method", "GET"),
        auth_type=AuthType(config.get("auth_type", "none")),
        auth_secret=secret,
        auth_header_name=config.get("auth_header_name", "X-API-Key"),
        auth_username=config.get("auth_username", ""),
        records_path=config.get("records_path", ""),
        extra_headers=config.get("extra_headers", {}),
        pagination=PaginationType(config.get("pagination", "none")),
        page_size=int(config.get("page_size", 100)),
        cursor_path=config.get("cursor_path", ""),
        verify_tls=bool(config.get("verify_tls", True)),
        timeout_seconds=float(config.get("timeout_seconds", 30.0)),
        field_mapping=ApiFieldMapping(
            identifier=mapping_config.get("identifier", ""),
            display_name=mapping_config.get("display_name", ""),
            email=mapping_config.get("email", ""),
            status=mapping_config.get("status", ""),
        ),
    )

    return ApiProvider(api_config, label=source.name)


def store_snapshot(
    session: Session, source: DataSource, result: FetchResult, username: str
) -> Snapshot:
    """把抓取結果存成快照（FR-11）。"""
    snapshot = Snapshot(
        source_id=source.id,
        fetched_by=username,
        account_count=result.count,
        total_reported=result.total_reported,
        warnings_json=result.warnings,
        diagnostics_json=result.diagnostics,
    )
    session.add(snapshot)
    session.flush()

    session.add_all(
        SnapshotAccount(
            snapshot_id=snapshot.id,
            identifier=account.identifier,
            normalized_key=account.normalized_key,
            display_name=account.display_name,
            email=account.email,
            status=account.status.value,
            attributes_json=account.attributes,
        )
        for account in result.accounts
    )

    source.last_fetch_at = datetime.now(UTC)
    session.flush()
    return snapshot


def snapshot_to_fetch_result(snapshot: Snapshot) -> FetchResult:
    """把已儲存的快照還原成 FetchResult，供快照間比對使用（FR-11）。"""
    accounts = [
        Account(
            identifier=record.identifier,
            display_name=record.display_name,
            email=record.email,
            status=AccountStatus(record.status),
            attributes=record.attributes_json or {},
        )
        for record in snapshot.accounts
    ]

    label = snapshot.source.name if snapshot.source else f"快照 #{snapshot.id}"

    return FetchResult(
        accounts=accounts,
        fetched_at=snapshot.fetched_at,
        source_label=f"{label}（{snapshot.fetched_at:%Y-%m-%d %H:%M}）",
        total_reported=snapshot.total_reported,
        warnings=list(snapshot.warnings_json or []),
        diagnostics=dict(snapshot.diagnostics_json or {}),
    )


def encrypt_secret(plaintext: str) -> str:
    """加密要存入資料庫的敏感值。"""
    return _secret_box().encrypt(plaintext) if plaintext else ""


# ---------------------------------------------------------------------------
# 權限檢視（Round 8）：以「主檔（AD 已啟用帳號）」為主，逐一比對各權限群組
# ---------------------------------------------------------------------------


def latest_snapshot(session: Session, source_id: int) -> Snapshot | None:
    """取得某來源最新的一份快照（找不到回 None）。"""
    return session.scalars(
        select(Snapshot)
        .where(Snapshot.source_id == source_id)
        .order_by(desc(Snapshot.fetched_at))
        .limit(1)
    ).first()


def build_review(session: Session) -> AccessReviewResult | None:
    """從各來源的最新快照組出「人員 × 權限」檢視。

    角色分派沿用既有的 ``is_authoritative`` 旗標：
    - **主檔** = 權威來源（AD 已啟用帳號），做為每列人員的權限基準。
    - **權限群組** = 其餘啟用中的來源（網路權限／VPN／LINE…），依名稱排序成欄。

    尚未設定權威主檔、或主檔還沒有任何快照時回 ``None``，由路由層顯示引導。
    """
    active = list(
        session.scalars(select(DataSource).where(DataSource.is_active).order_by(DataSource.name))
    )
    master_source = next((s for s in active if s.is_authoritative), None)
    if master_source is None:
        return None

    master_snap = latest_snapshot(session, master_source.id)
    if master_snap is None:
        return None
    master_fr = snapshot_to_fetch_result(master_snap)

    entitlements: list[Entitlement] = []
    for source in active:
        if source.is_authoritative:
            continue
        snap = latest_snapshot(session, source.id)
        if snap is None:
            continue
        entitlements.append(Entitlement(name=source.name, members=snapshot_to_fetch_result(snap)))

    return build_access_review(master_fr, entitlements)


def master_enabled_keys(session: Session) -> set[str]:
    """權威主檔（AD 已啟用帳號）最新快照的正規化鍵集合。找不到回空集合。"""
    master_source = session.scalars(
        select(DataSource).where(DataSource.is_active, DataSource.is_authoritative).limit(1)
    ).first()
    if master_source is None:
        return set()
    snap = latest_snapshot(session, master_source.id)
    if snap is None:
        return set()
    return {a.normalized_key for a in snap.accounts}


def entitlement_detail(session: Session, source_id: int) -> dict | None:
    """組出某權限來源分頁所需資料：成員 + 狀態 + 異常旗標 + 註記（規格第 6 點）。

    每個成員對照「已啟用主檔」判定：
    - 在主檔內 → 正常（在職且具此權限）。
    - 不在主檔、AD 狀態為停用 → 異常「停用未回收」。
    - 不在主檔、其餘 → 異常「孤兒帳號」（KEY-IN 帳號查無亦歸此類）。
    """
    source = session.get(DataSource, source_id)
    if source is None:
        return None

    snap = latest_snapshot(session, source_id)
    members = list(snap.accounts) if snap else []
    master_keys = master_enabled_keys(session)
    notes = {
        n.account_key: n.note
        for n in session.scalars(
            select(EntitlementNote).where(EntitlementNote.source_id == source_id)
        )
    }

    rows: list[dict] = []
    anomaly_count = 0
    for m in members:
        in_master = m.normalized_key in master_keys
        if in_master:
            anomaly = ""
        elif m.status == "disabled":
            anomaly = "disabled"
        else:
            anomaly = "orphan"
        if anomaly:
            anomaly_count += 1
        rows.append(
            {
                "identifier": m.identifier,
                "account_key": m.normalized_key,
                "display_name": m.display_name,
                "member_status": m.status,
                "in_master": in_master,
                "anomaly": anomaly,
                "note": notes.get(m.normalized_key, ""),
            }
        )

    # 異常排在前面，方便稽核
    rows.sort(key=lambda r: (0 if r["anomaly"] else 1, r["identifier"]))
    return {
        "source": source,
        "rows": rows,
        "member_count": len(members),
        "anomaly_count": anomaly_count,
        "fetched_at": snap.fetched_at if snap else None,
    }


def parse_manual_ids(raw: str) -> list[str]:
    """把手動貼上的帳號字串（換行／逗號／空白分隔）解析成去重清單，保留原始大小寫。"""
    tokens = re.split(r"[\s,;]+", raw or "")
    seen: set[str] = set()
    result: list[str] = []
    for token in tokens:
        cleaned = token.strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(cleaned)
    return result


def create_manual_entitlement(
    session: Session, name: str, raw_ids: str, username: str
) -> DataSource:
    """以手動 KEY-IN 的帳號清單建立一個權限來源與其快照（規格第 5 點）。

    KEY-IN 的帳號狀態未知；是否仍啟用交由權限檢視對照「已啟用主檔」判定——
    在主檔內＝在職有效，不在＝異常（停用未回收／查無）。
    """
    ids = parse_manual_ids(raw_ids)
    source = DataSource(
        name=name.strip(),
        source_type=SourceType.FILE.value,
        description="手動 KEY-IN 權限名單",
        config_json={"manual": True},
        is_authoritative=False,
        is_active=True,
        created_by=username,
    )
    session.add(source)
    session.flush()

    result = FetchResult(
        accounts=[Account(identifier=i, status=AccountStatus.UNKNOWN) for i in ids],
        fetched_at=datetime.now(UTC),
        source_label=name,
        total_reported=len(ids),
    )
    store_snapshot(session, source, result, username)
    return source


def upsert_entitlement_note(
    session: Session, source_id: int, account_key: str, note: str, username: str
) -> None:
    """新增或更新某來源某帳號的註記（規格第 6 點）。"""
    existing = session.scalars(
        select(EntitlementNote).where(
            EntitlementNote.source_id == source_id,
            EntitlementNote.account_key == account_key,
        )
    ).first()
    if existing is None:
        session.add(
            EntitlementNote(
                source_id=source_id, account_key=account_key, note=note, updated_by=username
            )
        )
    else:
        existing.note = note
        existing.updated_by = username
