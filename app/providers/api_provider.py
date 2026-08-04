"""外部系統 REST API 帳號來源 — 對應 FR-04、NFR-09、NFR-12。

設計為**通用可設定連接器**：管理者在 UI 填 URL、驗證方式、JSON 欄位對應，
系統就能抓取。新增一個外部系統不需要改程式、不需要重新部署（NFR-12）。

**SSRF 防護（FIND-002、CWE-918）**：管理者可自訂目標 URL，若不加限制，
這個功能會變成內網探測工具。因此位址在設定時驗證，且重導向逐跳重驗。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx

from app.providers.base import (
    Account,
    AccountProvider,
    AccountStatus,
    AuthenticationError,
    ConfigurationError,
    ConnectionError_,
    DataError,
    FetchResult,
    TlsError,
)
from app.security.url_guard import UrlNotAllowed, validate_external_url

logger = logging.getLogger(__name__)

# 單次抓取的硬性上限，防止惡意或設定錯誤的端點耗盡記憶體
MAX_TOTAL_RECORDS = 200_000
MAX_PAGES = 500

# 重導向上限。每一跳都會重新驗證位址，防止用 302 繞過 SSRF 防護。
MAX_REDIRECTS = 5

# 這些標頭會影響路由或被下游服務當作信任來源，不允許管理者自訂（FIND-005）
FORBIDDEN_HEADER_NAMES = frozenset(
    {
        "host",
        "authorization",
        "cookie",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
        "content-length",
        "transfer-encoding",
    }
)


class AuthType(str, Enum):
    NONE = "none"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BEARER = "bearer"
    BASIC = "basic"


class PaginationType(str, Enum):
    NONE = "none"
    OFFSET_LIMIT = "offset_limit"
    PAGE_NUMBER = "page_number"
    CURSOR = "cursor"


@dataclass(slots=True)
class FieldMapping:
    """JSON 欄位到 Account 屬性的對應。"""

    identifier: str
    display_name: str = ""
    email: str = ""
    status: str = ""
    # status 欄位中代表「啟用」的值（不分大小寫）
    enabled_values: tuple[str, ...] = ("true", "1", "active", "enabled", "y", "yes")


@dataclass(slots=True)
class ApiConfig:
    """外部 API 來源設定。"""

    url: str
    field_mapping: FieldMapping
    method: str = "GET"
    auth_type: AuthType = AuthType.NONE
    auth_secret: str = ""
    auth_header_name: str = "X-API-Key"
    auth_username: str = ""
    # JSON 路徑，以點號分隔指向帳號陣列，如 "data.users"。空字串代表根層即為陣列。
    records_path: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    pagination: PaginationType = PaginationType.NONE
    page_size: int = 100
    cursor_path: str = ""
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    max_retries: int = 3

    # --- SSRF 防護（FIND-002、CWE-918）---
    allowed_hosts: frozenset[str] | None = None
    """若設定，只允許清單內的主機。正式環境建議設定，這是最嚴格的防護。"""

    allow_private_network: bool = False
    """是否允許連線到內網位址。企業內部系統常在內網，故保留此開關，
    但必須是管理員明確的設定決定，預設為關閉。"""

    def validate(self) -> None:
        """驗證設定，拒絕不安全或不完整的組合。"""
        if not self.url:
            raise ConfigurationError("API URL 不可為空")

        # SSRF 防護：拒絕指向 loopback、內網、雲端 metadata 的目標
        try:
            validate_external_url(
                self.url,
                allowed_hosts=self.allowed_hosts,
                allow_private=self.allow_private_network,
            )
        except UrlNotAllowed as exc:
            raise ConfigurationError(exc.message, remediation=exc.remediation) from exc

        if not self.field_mapping.identifier:
            raise ConfigurationError(
                "必須指定「帳號」欄位對應",
                remediation="請指定 JSON 回應中哪個欄位是帳號名稱（比對的鍵）。",
            )

        if self.auth_type is not AuthType.NONE and not self.auth_secret:
            raise ConfigurationError(f"驗證方式為 {self.auth_type.value} 但未提供密鑰")

        if self.pagination is PaginationType.CURSOR and not self.cursor_path:
            raise ConfigurationError("使用 cursor 分頁時必須指定 cursor 欄位路徑")


class ApiProvider(AccountProvider):
    """從外部系統 REST API 抓取帳號清單。"""

    def __init__(self, config: ApiConfig, *, label: str = "") -> None:
        config.validate()
        self._config = config
        self._label = label or urlparse(config.url).hostname or config.url

    @property
    def label(self) -> str:
        return self._label

    def _build_request_args(self) -> dict[str, Any]:
        """組出 headers 與 query params。

        自訂標頭會先過濾掉會影響路由或被下游當作信任來源的名稱（FIND-005）。
        驗證用的標頭在過濾之後才加入，因此不會被誤擋。
        """
        headers = {
            name: value
            for name, value in self._config.extra_headers.items()
            if name.lower() not in FORBIDDEN_HEADER_NAMES
        }
        dropped = set(self._config.extra_headers) - set(headers)
        if dropped:
            logger.warning("已忽略不允許的自訂標頭：%s", ", ".join(sorted(dropped)))

        params: dict[str, Any] = {}
        auth: tuple[str, str] | None = None

        match self._config.auth_type:
            case AuthType.API_KEY_HEADER:
                headers[self._config.auth_header_name] = self._config.auth_secret
            case AuthType.API_KEY_QUERY:
                params[self._config.auth_header_name] = self._config.auth_secret
            case AuthType.BEARER:
                headers["Authorization"] = f"Bearer {self._config.auth_secret}"
            case AuthType.BASIC:
                auth = (self._config.auth_username, self._config.auth_secret)
            case AuthType.NONE:
                pass

        return {"headers": headers, "params": params, "auth": auth}

    def _follow_redirects_safely(
        self, client: httpx.Client, response: httpx.Response, **kwargs: Any
    ) -> httpx.Response:
        """手動處理重導向，每一跳都重新驗證位址（FIND-002）。

        若交給 httpx 自動跟隨重導向，攻擊者只要讓合法的外部端點回傳 302
        指向 169.254.169.254，就能完全繞過 SSRF 防護。
        """
        hops = 0

        while response.is_redirect and hops < MAX_REDIRECTS:
            location = response.headers.get("location", "")
            if not location:
                break

            next_url = str(response.url.join(location))

            try:
                validate_external_url(
                    next_url,
                    allowed_hosts=self._config.allowed_hosts,
                    allow_private=self._config.allow_private_network,
                )
            except UrlNotAllowed as exc:
                logger.warning("拒絕重導向至不允許的位址：%s", next_url)
                raise ConfigurationError(
                    f"API 端點重導向到不被允許的位址。{exc.message}",
                    remediation=exc.remediation,
                ) from exc

            response.close()
            response = client.request(**{**kwargs, "url": next_url})
            hops += 1

        if response.is_redirect:
            raise ConfigurationError(
                f"重導向次數超過上限（{MAX_REDIRECTS} 次）",
                remediation="請確認 API 端點設定正確，未形成重導向迴圈。",
            )

        return response

    def _request_with_retry(self, client: httpx.Client, **kwargs: Any) -> httpx.Response:
        """發送請求，失敗時以指數退避重試（NFR-09）。

        只重試**暫時性**失敗（連線問題、5xx、429）。
        4xx 是設定錯誤，重試無意義且會浪費時間。
        """
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries):
            try:
                response = client.request(**kwargs)
                # 重導向逐跳驗證，防止 302 繞過 SSRF 防護
                response = self._follow_redirects_safely(client, response, **kwargs)

                if response.status_code in (401, 403):
                    raise AuthenticationError(
                        f"API 認證失敗（HTTP {response.status_code}）",
                        remediation=(
                            "請確認 API 金鑰或 token 正確且未過期，"
                            "並具備讀取帳號清單的權限。"
                        ),
                    )

                if response.status_code == 429 or response.status_code >= 500:
                    last_error = ConnectionError_(f"API 回應 HTTP {response.status_code}")
                    if attempt < self._config.max_retries - 1:
                        backoff = 2**attempt
                        logger.warning(
                            "API 回應 %d，%d 秒後重試（第 %d/%d 次）",
                            response.status_code,
                            backoff,
                            attempt + 1,
                            self._config.max_retries,
                        )
                        time.sleep(backoff)
                        continue

                response.raise_for_status()
                return response

            except httpx.TimeoutException as exc:
                last_error = ConnectionError_(
                    f"API 請求逾時（{self._config.timeout_seconds} 秒）",
                    remediation="請確認端點回應速度，或調高逾時設定。",
                )
                if attempt < self._config.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise last_error from exc

            except httpx.ConnectError as exc:
                text = str(exc).lower()
                if any(keyword in text for keyword in ("certificate", "ssl", "tls")):
                    raise TlsError(
                        f"TLS 憑證驗證失敗：{exc}",
                        remediation="若為內部自簽憑證，請確認憑證有效或調整驗證設定。",
                    ) from exc
                last_error = ConnectionError_(
                    f"無法連線到 API：{exc}",
                    remediation="請確認 URL 正確、主機可達且防火牆已開放。",
                )
                if attempt < self._config.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise last_error from exc

            except httpx.HTTPStatusError as exc:
                raise ConfigurationError(
                    f"API 回應錯誤 HTTP {exc.response.status_code}",
                    remediation="請確認 URL 路徑與請求方法正確。",
                ) from exc

        raise last_error or ConnectionError_("API 請求失敗")

    def _make_client(self) -> httpx.Client:
        """建立 HTTP 用戶端。

        follow_redirects 一律關閉，改由 _follow_redirects_safely 逐跳驗證，
        否則 302 可繞過 SSRF 防護（FIND-002）。
        """
        return httpx.Client(
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_tls,
            follow_redirects=False,
        )

    def fetch(self) -> FetchResult:
        """抓取完整帳號清單，自動處理分頁。"""
        request_args = self._build_request_args()
        raw_records: list[dict[str, Any]] = []
        warnings: list[str] = []
        page = 0

        with self._make_client() as client:
            cursor: str | None = None

            while page < MAX_PAGES:
                params = dict(request_args["params"])
                params.update(self._pagination_params(page, len(raw_records), cursor))

                response = self._request_with_retry(
                    client,
                    method=self._config.method,
                    url=self._config.url,
                    headers=request_args["headers"],
                    params=params,
                    auth=request_args["auth"],
                )

                payload = self._parse_json(response)
                records = self._extract_records(payload)

                if not records:
                    break

                raw_records.extend(records)

                if len(raw_records) >= MAX_TOTAL_RECORDS:
                    warnings.append(
                        f"帳號數已達上限 {MAX_TOTAL_RECORDS:,} 筆，停止抓取。結果可能不完整。"
                    )
                    break

                if self._config.pagination is PaginationType.NONE:
                    break

                if self._config.pagination is PaginationType.CURSOR:
                    cursor = self._extract_cursor(payload)
                    if not cursor:
                        break
                elif len(records) < self._config.page_size:
                    break  # 最後一頁

                page += 1
            else:
                warnings.append(f"已達分頁上限 {MAX_PAGES} 頁，停止抓取。結果可能不完整。")

        accounts, skipped = self._to_accounts(raw_records)
        if skipped:
            warnings.append(
                f"有 {skipped} 筆記錄缺少「{self._config.field_mapping.identifier}」欄位而略過。"
                "請確認欄位對應設定正確。"
            )

        return FetchResult(
            accounts=accounts,
            fetched_at=datetime.now(UTC),
            source_label=self._label,
            total_reported=len(raw_records),
            warnings=warnings,
            diagnostics={
                "url": self._config.url,
                "auth_type": self._config.auth_type.value,
                "pagination": self._config.pagination.value,
                "pages_fetched": str(page + 1),
            },
        )

    def _pagination_params(self, page: int, offset: int, cursor: str | None) -> dict[str, Any]:
        match self._config.pagination:
            case PaginationType.OFFSET_LIMIT:
                return {"offset": offset, "limit": self._config.page_size}
            case PaginationType.PAGE_NUMBER:
                return {"page": page + 1, "page_size": self._config.page_size}
            case PaginationType.CURSOR:
                return {"cursor": cursor} if cursor else {}
            case _:
                return {}

    @staticmethod
    def _parse_json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            content_type = response.headers.get("content-type", "未知")
            raise DataError(
                f"API 回應不是有效的 JSON（Content-Type: {content_type}）",
                remediation="請確認 URL 指向的是 JSON API 端點，而非網頁或其他格式。",
            ) from exc

    def _extract_records(self, payload: Any) -> list[dict[str, Any]]:
        """依設定的 JSON 路徑取出帳號陣列。"""
        current = payload

        if self._config.records_path:
            for segment in self._config.records_path.split("."):
                if not isinstance(current, dict):
                    raise DataError(
                        f"JSON 路徑「{self._config.records_path}」在「{segment}」處中斷："
                        f"上層不是物件而是 {type(current).__name__}",
                        remediation="請確認資料路徑設定與實際 API 回應結構相符。",
                    )
                if segment not in current:
                    available = ", ".join(list(current.keys())[:10]) or "（無欄位）"
                    raise DataError(
                        f"JSON 回應中找不到欄位「{segment}」。可用欄位：{available}",
                        remediation="請依實際回應結構修正資料路徑設定。",
                    )
                current = current[segment]

        if not isinstance(current, list):
            raise DataError(
                f"資料路徑指向的不是陣列，而是 {type(current).__name__}",
                remediation="請確認資料路徑指向帳號清單的陣列。",
            )

        return [item for item in current if isinstance(item, dict)]

    def _extract_cursor(self, payload: Any) -> str | None:
        current = payload
        for segment in self._config.cursor_path.split("."):
            if not isinstance(current, dict) or segment not in current:
                return None
            current = current[segment]
        return str(current) if current else None

    def _to_accounts(self, records: list[dict[str, Any]]) -> tuple[list[Account], int]:
        mapping = self._config.field_mapping
        accounts: list[Account] = []
        skipped = 0

        for record in records:
            identifier = _stringify(record.get(mapping.identifier))
            if not identifier:
                skipped += 1
                continue

            status = AccountStatus.UNKNOWN
            if mapping.status and mapping.status in record:
                raw_status = _stringify(record[mapping.status]).lower()
                status = (
                    AccountStatus.ENABLED
                    if raw_status in mapping.enabled_values
                    else AccountStatus.DISABLED
                )

            accounts.append(
                Account(
                    identifier=identifier,
                    display_name=_stringify(record.get(mapping.display_name)),
                    email=_stringify(record.get(mapping.email)),
                    status=status,
                )
            )

        return accounts, skipped

    def test_connection(self) -> dict[str, str]:
        """測試 API 連線並回報實際看到的資料結構，協助設定欄位對應。"""
        request_args = self._build_request_args()

        with self._make_client() as client:
            response = self._request_with_retry(
                client,
                method=self._config.method,
                url=self._config.url,
                headers=request_args["headers"],
                params=request_args["params"],
                auth=request_args["auth"],
            )
            payload = self._parse_json(response)
            records = self._extract_records(payload)

        diagnostics = {
            "status": "連線成功",
            "http_status": str(response.status_code),
            "records_found": str(len(records)),
        }

        if records:
            diagnostics["available_fields"] = ", ".join(list(records[0].keys())[:15])
            mapped = self._config.field_mapping.identifier
            diagnostics["identifier_field"] = (
                f"{mapped}（存在）" if mapped in records[0] else f"{mapped}（**回應中不存在**）"
            )
        else:
            diagnostics["warning"] = (
                "端點回應成功，但沒有取得任何帳號記錄。請確認資料路徑設定。"
            )

        return diagnostics


def _stringify(value: Any) -> str:
    """把 JSON 值轉成字串，None 與空值統一為空字串。"""
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()
