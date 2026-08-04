"""LDAP / Active Directory 帳號來源 — 實作 IR-01～IR-07。

相容性目標：Windows Server 2016 / 2019 / 2022 / 2025。
各版本的預設安全策略差異很大（見 docs/SRS.md 第 5.1 節矩陣），
本模組的核心設計原則是：**一律自動協商，絕不寫死**。

關鍵風險：AD 單次查詢硬性上限 1000 筆且**不會報錯**，直接靜默截斷。
對「比對差異」這種業務，截斷會產出看起來正常但實際錯誤的稽核結論，
比程式當掉更危險。因此本模組**一律使用分頁查詢**（IR-03）。
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ldap3 import ALL, SIMPLE, Connection, Server, Tls
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCertificateError,
    LDAPExceptionError,
    LDAPInvalidCredentialsResult,
    LDAPSocketOpenError,
    LDAPStartTLSError,
)

from app.providers.base import (
    Account,
    AccountProvider,
    AccountStatus,
    AuthenticationError,
    ConfigurationError,
    ConnectionError_,
    FetchResult,
    TlsError,
)
from app.security.ldap_escape import build_filter, escape_filter_value

logger = logging.getLogger(__name__)

# AD userAccountControl 的 ACCOUNTDISABLE 位元（值 2）。
# 詳見 docs/SRS.md 第 5.1 節。
UAC_ACCOUNTDISABLE = 0x0002

# LDAP_MATCHING_RULE_IN_CHAIN — 由 DC 端遞迴展開群組成員。
# 所有支援版本（WS2003 SP2 以上）皆可用，但大型群組效能較差。
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

# 要讀取的 AD 屬性（見 docs/SRS.md 第 5.1 節）
USER_ATTRIBUTES = [
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "mail",
    "distinguishedName",
    "objectSid",
    "userAccountControl",
    "whenCreated",
    "whenChanged",
]

# 遞迴展開的深度上限 —— 防止循環群組參照造成無限遞迴（風險 R-03）
MAX_NESTING_DEPTH = 20


class NestingStrategy(str, Enum):
    """巢狀群組展開策略（IR-04）。

    兩種策略在所有支援的 AD 版本皆可用，差別在運算位置與效能特性，
    因此設計為可切換而非寫死。
    """

    IN_CHAIN = "in_chain"
    """單次查詢，由 DC 端遞迴。查詢簡單，但大型群組在 DC 上很慢。"""

    RECURSIVE = "recursive"
    """應用端多次查詢逐層展開。查詢次數多，但每次都快且可控、可顯示進度。"""

    DIRECT_ONLY = "direct_only"
    """只取直接成員，不展開巢狀。"""


@dataclass(slots=True)
class LdapConfig:
    """AD 連線設定。

    安全預設（NFR-04、IR-06）：``use_ssl=True``、``verify_cert=True``。
    明文 389 bind 會被 :meth:`validate` 直接拒絕。
    """

    host: str
    base_dn: str
    bind_dn: str
    bind_password: str
    port: int = 636
    use_ssl: bool = True
    use_start_tls: bool = False
    verify_cert: bool = True
    ca_cert_file: str | None = None
    page_size: int = 1000
    nesting_strategy: NestingStrategy = NestingStrategy.RECURSIVE
    receive_timeout: int = 30

    def validate(self) -> None:
        """驗證設定，拒絕不安全的組合。

        Raises:
            ConfigurationError: 設定缺漏或違反安全要求。
        """
        if not self.host:
            raise ConfigurationError("LDAP host 不可為空")
        if not self.base_dn:
            raise ConfigurationError("Base DN 不可為空")

        # NFR-04：禁止明文 bind。這是硬性安全要求，不提供繞過選項。
        if not self.use_ssl and not self.use_start_tls:
            raise ConfigurationError(
                "拒絕使用未加密的 LDAP 連線：帳號密碼會以明文在網路上傳輸。",
                remediation=(
                    "請改用 LDAPS（port 636，use_ssl=True）"
                    "或在 port 389 上啟用 StartTLS（use_start_tls=True）。"
                ),
            )

        if not 1 <= self.page_size <= 1000:
            raise ConfigurationError(
                f"page_size 必須介於 1~1000，收到 {self.page_size}。"
                "AD 的 MaxPageSize 硬性上限為 1000。"
            )


def _build_tls_config(config: LdapConfig) -> Tls:
    """建立 TLS 設定 —— IR-02（自動協商）、IR-05（排除 RC4）、IR-06（憑證驗證）。

    **關鍵**：不寫死 TLS 版本。WS2016~2022 只支援 TLS 1.2，
    WS2025 支援 TLS 1.3。使用 ``PROTOCOL_TLS_CLIENT`` 讓 OpenSSL
    自動協商雙方共同支援的最高版本；寫死任一版本都會在另一端失敗。
    """
    validate_mode = ssl.CERT_REQUIRED if config.verify_cert else ssl.CERT_NONE

    if not config.verify_cert:
        # 停用憑證驗證會使連線易受中間人攻擊，必須留下稽核痕跡。
        logger.warning(
            "LDAP 憑證驗證已停用（host=%s）。此設定僅供測試環境，"
            "正式環境請提供企業 CA 憑證並開啟驗證。",
            config.host,
        )

    tls = Tls(
        validate=validate_mode,
        version=ssl.PROTOCOL_TLS_CLIENT,  # 自動協商 TLS 1.2 / 1.3（IR-02）
        ca_certs_file=config.ca_cert_file or None,
    )

    # IR-05：排除已被 WS2025 棄用的 RC4，以及其他弱式加密套件。
    # 對舊版 AD 無影響（它們都支援 AES）。
    tls.ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK"

    return tls


class LdapProvider(AccountProvider):
    """從 AD 群組抓取成員帳號。

    典型用法::

        provider = LdapProvider(config, group_dn="CN=Finance,OU=Groups,DC=example,DC=local")
        result = provider.fetch()
    """

    def __init__(
        self,
        config: LdapConfig,
        *,
        group_dn: str | None = None,
        user_filter: str | None = None,
        label: str = "",
    ) -> None:
        """
        Args:
            config: 連線設定。
            group_dn: 要抓取成員的群組 DN。None 表示抓取 base_dn 下所有使用者。
            user_filter: 額外的 LDAP filter 條件（僅限程式內常數，不接受使用者輸入）。
            label: 供 UI 顯示的名稱。
        """
        config.validate()
        self._config = config
        self._group_dn = group_dn
        self._user_filter = user_filter
        self._label = label or (group_dn or config.base_dn)
        self._diagnostics: dict[str, str] = {}

    @property
    def label(self) -> str:
        return self._label

    # ------------------------------------------------------------------
    # 連線
    # ------------------------------------------------------------------

    def _connect(self) -> Connection:
        """建立並綁定連線 —— IR-01（LDAPS/StartTLS + signing）。

        WS2025 的新部署預設要求 LDAP signing，WS2016~2022 則不強制。
        因此優先嘗試 SASL/NTLM bind（支援 signing 協商），
        失敗時退回 simple bind over TLS——後者在 TLS 通道內仍是加密的，
        對不要求 signing 的舊版 AD 完全可用。
        """
        tls = _build_tls_config(self._config)
        server = Server(
            host=self._config.host,
            port=self._config.port,
            use_ssl=self._config.use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=self._config.receive_timeout,
        )

        try:
            conn = self._bind(server)
        except (LDAPSocketOpenError, LDAPStartTLSError) as exc:
            raise self._classify_socket_error(exc) from exc
        except LDAPCertificateError as exc:
            raise TlsError(
                f"TLS 憑證驗證失敗：{exc}",
                remediation=(
                    "若使用企業自簽 CA，請於連線設定提供 CA 憑證檔；"
                    "請確認憑證的主機名稱與 LDAP_HOST 相符且未過期。"
                ),
            ) from exc
        except (LDAPBindError, LDAPInvalidCredentialsResult) as exc:
            raise AuthenticationError(
                "AD 認證失敗：服務帳號的 DN 或密碼有誤。",
                remediation=(
                    "請確認 bind DN 為完整 DN（如 CN=svc,OU=...,DC=...）或 UPN 格式，"
                    "且帳號未被鎖定或密碼未過期。"
                ),
            ) from exc

        self._collect_diagnostics(conn, server)
        return conn

    def _bind(self, server: Server) -> Connection:
        """執行 bind，優先使用支援 signing 的方式（IR-01）。"""
        common: dict[str, Any] = {
            "user": self._config.bind_dn,
            "password": self._config.bind_password,
            "auto_bind": False,
            "receive_timeout": self._config.receive_timeout,
            "raise_exceptions": True,
        }

        # 先試 NTLM（SASL 家族），它會協商 signing/sealing，
        # 滿足 WS2025 新部署的預設要求。
        if "\\" in self._config.bind_dn:
            try:
                conn = Connection(server, authentication="NTLM", **common)
                self._start_tls_if_needed(conn)
                conn.bind()
                self._diagnostics["bind_method"] = "NTLM (signing 已協商)"
                return conn
            except LDAPExceptionError:
                logger.debug("NTLM bind 失敗，退回 SIMPLE bind over TLS")

        # 退回 simple bind。連線本身已由 TLS 加密（設定驗證已強制），
        # 對不要求 signing 的 WS2016~2022 完全可用。
        conn = Connection(server, authentication=SIMPLE, **common)
        self._start_tls_if_needed(conn)
        conn.bind()
        self._diagnostics["bind_method"] = "SIMPLE over TLS"
        return conn

    def _start_tls_if_needed(self, conn: Connection) -> None:
        if self._config.use_start_tls and not self._config.use_ssl:
            conn.start_tls()

    def _classify_socket_error(self, exc: Exception) -> ConnectionError_ | TlsError:
        """把底層錯誤轉成可行動的分類（AC-01）。"""
        text = str(exc).lower()

        if any(kw in text for kw in ("certificate", "ssl", "tls", "handshake")):
            return TlsError(
                f"TLS 連線失敗：{exc}",
                remediation=(
                    "請確認伺服器已啟用 LDAPS（port 636）且憑證有效。"
                    "企業自簽 CA 需在設定中提供 CA 憑證檔。"
                ),
            )

        if any(kw in text for kw in ("name or service not known", "getaddrinfo", "resolve")):
            return ConnectionError_(
                f"無法解析主機名稱：{self._config.host}",
                remediation="請確認 DNS 設定正確，或改用網域控制站的 IP 位址。",
            )

        return ConnectionError_(
            f"無法連線到 {self._config.host}:{self._config.port} — {exc}",
            remediation=(
                "請確認網域控制站可達、防火牆已開放對應連接埠"
                "（LDAPS 為 636、StartTLS 為 389）。"
            ),
        )

    def _collect_diagnostics(self, conn: Connection, server: Server) -> None:
        """蒐集連線診斷資訊 —— IR-07。

        讓管理者能自我診斷相容性問題（PP-06），而非只看到 "bind failed"。
        """
        self._diagnostics["server"] = f"{self._config.host}:{self._config.port}"
        self._diagnostics["encryption"] = "LDAPS" if self._config.use_ssl else "StartTLS"
        self._diagnostics["cert_validation"] = (
            "已啟用" if self._config.verify_cert else "已停用（不建議用於正式環境）"
        )

        # 實際協商到的 TLS 版本 —— 用來確認 WS2025 的 TLS 1.3 是否生效
        try:
            sock = conn.socket
            if sock is not None and hasattr(sock, "version"):
                self._diagnostics["tls_version"] = sock.version() or "未知"
        except (AttributeError, OSError):
            self._diagnostics["tls_version"] = "無法取得"

        # 伺服器版本資訊，供相容性判讀
        try:
            info = server.info
            if info is not None:
                naming_contexts = getattr(info, "naming_contexts", None)
                if naming_contexts:
                    self._diagnostics["naming_contexts"] = ", ".join(naming_contexts[:3])
                other = getattr(info, "other", {}) or {}
                for key in ("domainFunctionality", "forestFunctionality", "domainControllerFunctionality"):
                    if key in other:
                        value = other[key]
                        self._diagnostics[key] = (
                            value[0] if isinstance(value, list) and value else str(value)
                        )
        except (AttributeError, KeyError):
            logger.debug("無法取得伺服器 info", exc_info=True)

    # ------------------------------------------------------------------
    # 查詢
    # ------------------------------------------------------------------

    def _paged_search(
        self,
        conn: Connection,
        search_filter: str,
        attributes: list[str],
        search_base: str | None = None,
    ) -> list[dict[str, Any]]:
        """執行分頁查詢 —— IR-03。

        **這是本模組最關鍵的函式。** AD 單次查詢最多回傳 1000 筆且不會報錯，
        未分頁會靜默截斷，導致比對結果錯誤卻看起來正常（風險 R-02）。
        因此所有查詢一律經過此函式，不提供未分頁的捷徑。
        """
        entries: list[dict[str, Any]] = []

        # ldap3 的 paged_search 產生器會自動處理 cookie 換頁
        generator = conn.extend.standard.paged_search(
            search_base=search_base or self._config.base_dn,
            search_filter=search_filter,
            attributes=attributes,
            paged_size=self._config.page_size,
            generator=True,
        )

        for entry in generator:
            # 過濾掉 searchResRef（referral），只保留實際的 searchResEntry
            if entry.get("type") != "searchResEntry":
                continue
            entries.append(entry)

        logger.info(
            "分頁查詢完成：filter=%s，取得 %d 筆（page_size=%d）",
            search_filter,
            len(entries),
            self._config.page_size,
        )
        return entries

    def _fetch_group_members(self, conn: Connection, group_dn: str) -> list[dict[str, Any]]:
        """依設定的策略抓取群組成員（IR-04）。"""
        if self._config.nesting_strategy is NestingStrategy.IN_CHAIN:
            return self._fetch_in_chain(conn, group_dn)
        if self._config.nesting_strategy is NestingStrategy.RECURSIVE:
            return self._fetch_recursive(conn, group_dn)
        return self._fetch_direct(conn, group_dn)

    def _fetch_in_chain(self, conn: Connection, group_dn: str) -> list[dict[str, Any]]:
        """用 LDAP_MATCHING_RULE_IN_CHAIN 讓 DC 端遞迴展開。"""
        search_filter = (
            f"(&(objectCategory=person)(objectClass=user)"
            f"(memberOf:{MATCHING_RULE_IN_CHAIN}:={escape_filter_value(group_dn)}))"
        )
        return self._paged_search(conn, search_filter, USER_ATTRIBUTES)

    def _fetch_direct(self, conn: Connection, group_dn: str) -> list[dict[str, Any]]:
        """只取直接成員，不展開巢狀群組。"""
        search_filter = build_filter(
            "(&(objectCategory=person)(objectClass=user)(memberOf={group}))",
            group=group_dn,
        )
        return self._paged_search(conn, search_filter, USER_ATTRIBUTES)

    def _fetch_recursive(self, conn: Connection, group_dn: str) -> list[dict[str, Any]]:
        """在應用端逐層展開巢狀群組。

        以「已訪問集合」防止循環群組參照（A∈B, B∈A）造成無限遞迴，
        並設深度上限作為第二道防線（風險 R-03）。
        """
        visited_groups: set[str] = set()
        collected: dict[str, dict[str, Any]] = {}
        pending: list[tuple[str, int]] = [(group_dn, 0)]

        while pending:
            current_dn, depth = pending.pop()
            normalized = current_dn.lower()

            if normalized in visited_groups:
                logger.debug("略過已訪問的群組（循環參照）：%s", current_dn)
                continue
            visited_groups.add(normalized)

            if depth > MAX_NESTING_DEPTH:
                logger.warning(
                    "巢狀群組深度超過上限 %d，停止展開：%s", MAX_NESTING_DEPTH, current_dn
                )
                continue

            # 直接成員中的使用者
            for entry in self._fetch_direct(conn, current_dn):
                dn = entry.get("dn", "")
                if dn:
                    collected[dn.lower()] = entry

            # 直接成員中的子群組，加入待展開佇列
            sub_filter = build_filter(
                "(&(objectClass=group)(memberOf={group}))", group=current_dn
            )
            for sub in self._paged_search(conn, sub_filter, ["distinguishedName"]):
                sub_dn = sub.get("dn", "")
                if sub_dn and sub_dn.lower() not in visited_groups:
                    pending.append((sub_dn, depth + 1))

        return list(collected.values())

    # ------------------------------------------------------------------
    # 公開介面
    # ------------------------------------------------------------------

    def fetch(self) -> FetchResult:
        """抓取帳號清單。"""
        conn = self._connect()
        warnings: list[str] = []

        try:
            if self._group_dn:
                raw_entries = self._fetch_group_members(conn, self._group_dn)
                if self._config.nesting_strategy is NestingStrategy.DIRECT_ONLY:
                    warnings.append(
                        "本次僅抓取直接成員，未展開巢狀群組。"
                        "若群組含子群組，成員數會少於實際人數。"
                    )
            else:
                base_filter = "(&(objectCategory=person)(objectClass=user))"
                if self._user_filter:
                    base_filter = f"(&{base_filter}{self._user_filter})"
                raw_entries = self._paged_search(conn, base_filter, USER_ATTRIBUTES)

            accounts = [self._to_account(entry) for entry in raw_entries]
            accounts = [acc for acc in accounts if acc is not None]  # type: ignore[misc]

            skipped = len(raw_entries) - len(accounts)
            if skipped > 0:
                warnings.append(
                    f"有 {skipped} 筆項目缺少 sAMAccountName 而略過（可能為非使用者物件）。"
                )

            return FetchResult(
                accounts=accounts,  # type: ignore[arg-type]
                fetched_at=datetime.now(UTC),
                source_label=self._label,
                total_reported=len(raw_entries),
                warnings=warnings,
                diagnostics=dict(self._diagnostics),
            )
        finally:
            conn.unbind()

    def test_connection(self) -> dict[str, str]:
        """測試連線並回傳診斷資訊（IR-07、AC-01）。"""
        conn = self._connect()
        try:
            diagnostics = dict(self._diagnostics)
            diagnostics["status"] = "連線成功"

            # 驗證 Base DN 確實存在 —— 常見的設定錯誤來源
            try:
                conn.search(
                    search_base=self._config.base_dn,
                    search_filter="(objectClass=*)",
                    search_scope="BASE",
                    attributes=["distinguishedName"],
                )
                diagnostics["base_dn"] = f"{self._config.base_dn}（驗證通過）"
            except LDAPExceptionError:
                diagnostics["base_dn"] = f"{self._config.base_dn}（**查無此 DN，請確認拼寫**）"

            return diagnostics
        finally:
            conn.unbind()

    @staticmethod
    def _to_account(entry: dict[str, Any]) -> Account | None:
        """把 LDAP 查詢結果轉成統一的 Account。"""
        attrs = entry.get("attributes", {})

        account_name = _first_value(attrs.get("sAMAccountName"))
        if not account_name:
            return None  # 非使用者物件，由呼叫端計入警告

        uac_raw = _first_value(attrs.get("userAccountControl"))
        status = AccountStatus.UNKNOWN
        if uac_raw:
            try:
                status = (
                    AccountStatus.DISABLED
                    if int(uac_raw) & UAC_ACCOUNTDISABLE
                    else AccountStatus.ENABLED
                )
            except (TypeError, ValueError):
                logger.debug("無法解析 userAccountControl：%r", uac_raw)

        extra = {
            "distinguishedName": entry.get("dn", ""),
            "userPrincipalName": _first_value(attrs.get("userPrincipalName")),
            "whenCreated": _first_value(attrs.get("whenCreated")),
            "whenChanged": _first_value(attrs.get("whenChanged")),
        }

        return Account(
            identifier=account_name,
            display_name=_first_value(attrs.get("displayName")),
            email=_first_value(attrs.get("mail")),
            status=status,
            attributes={k: v for k, v in extra.items() if v},
        )


def _first_value(raw: Any) -> str:
    """LDAP 屬性可能是單值或多值清單，統一取第一個並轉成字串。"""
    if raw is None:
        return ""
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    return str(raw)
