"""把資料庫的來源設定轉成 Provider，以及快照的存取。

這一層是 DB 模型與 Provider 抽象之間的橋接，
讓路由層不需要知道各 Provider 的建構細節。
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import DataSource, Snapshot, SnapshotAccount, SourceType
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
