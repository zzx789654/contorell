"""帳號來源抽象層 — 對應 NFR-10（新增來源型態不需修改比對引擎）。

三種來源（LDAP / API / Excel）都實作 :class:`AccountProvider`，
比對引擎只認識 :class:`Account`，完全不知道資料從哪來。
這是「依賴反轉」的落點：新增第四種來源只需新增一個 Provider。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AccountStatus(str, Enum):
    """帳號在其來源系統中的啟用狀態。"""

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"  # 來源未提供此資訊（如僅有帳號清單的 Excel）


@dataclass(frozen=True, slots=True)
class Account:
    """跨來源統一的帳號表示。

    ``identifier`` 是比對的鍵。跨系統比對的成敗完全取決於這個鍵能否對齊，
    因此正規化規則（見 :meth:`normalized_key`）必須一致且可預期。
    """

    identifier: str
    display_name: str = ""
    email: str = ""
    status: AccountStatus = AccountStatus.UNKNOWN
    # 來源特有的原始屬性，供 UI 顯示與屬性差異比對用
    attributes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.identifier or not self.identifier.strip():
            raise ValueError("Account.identifier 不可為空")

    @property
    def normalized_key(self) -> str:
        """比對用的正規化鍵。

        AD 的 sAMAccountName 不分大小寫，多數外部系統亦然，
        因此統一轉小寫並去除前後空白。若不正規化，
        ``J.Doe`` 與 ``j.doe`` 會被誤判為兩個不同的人。
        """
        return self.identifier.strip().lower()

    @property
    def is_disabled(self) -> bool:
        return self.status is AccountStatus.DISABLED


@dataclass(slots=True)
class FetchResult:
    """一次抓取的結果，含供交叉檢查的中繼資料。

    ``total_reported`` 讓使用者能人工核對「來源說有幾筆」與「實際拿到幾筆」，
    這是防範 AD 分頁靜默截斷（風險 R-02）的第二道防線。
    """

    accounts: list[Account]
    fetched_at: datetime
    source_label: str
    total_reported: int | None = None
    warnings: list[str] = field(default_factory=list)
    diagnostics: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.accounts)

    @property
    def has_count_mismatch(self) -> bool:
        """來源回報筆數與實際取得筆數不符 —— 可能是分頁截斷。"""
        return self.total_reported is not None and self.total_reported != self.count


class ProviderError(Exception):
    """Provider 操作失敗的基底例外。

    ``category`` 讓 UI 能顯示可行動的錯誤分類，而非籠統的 "failed"（AC-01）。
    """

    category: str = "unknown"

    def __init__(self, message: str, *, remediation: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation


class ConnectionError_(ProviderError):
    """無法連線到來源（DNS、網路、port 不通）。"""

    category = "connection"


class TlsError(ProviderError):
    """TLS 交握或憑證驗證失敗。"""

    category = "tls"


class AuthenticationError(ProviderError):
    """認證失敗（帳密錯誤、token 失效）。"""

    category = "authentication"


class ConfigurationError(ProviderError):
    """設定有誤（Base DN 錯誤、欄位對應錯誤）。"""

    category = "configuration"


class DataError(ProviderError):
    """資料解析失敗（格式錯誤、編碼問題）。"""

    category = "data"


class AccountProvider(ABC):
    """所有帳號來源的共同介面。

    實作者必須保證：回傳的帳號清單是**完整**的。
    對有分頁的來源，Provider 負責處理完整分頁，
    絕不可回傳被截斷的部分結果而不發出警告。
    """

    @property
    @abstractmethod
    def label(self) -> str:
        """供 UI 顯示的來源名稱。"""

    @abstractmethod
    def fetch(self) -> FetchResult:
        """抓取完整帳號清單。

        Raises:
            ProviderError: 抓取失敗，並帶有可行動的錯誤分類。
        """

    @abstractmethod
    def test_connection(self) -> dict[str, str]:
        """測試連線並回傳診斷資訊（IR-07）。

        Returns:
            診斷鍵值對，如 TLS 版本、是否啟用 signing、伺服器資訊。
            這讓管理者能自我診斷相容性問題，而非只看到 "bind failed"。
        """
