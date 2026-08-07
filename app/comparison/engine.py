"""權限比對引擎 — 對應 FR-06、FR-07、FR-08。

比對引擎**完全不知道資料從哪來**，只認識 :class:`Account`（NFR-10）。
效能設計：以雜湊索引達成 O(n+m)，而非巢狀迴圈的 O(n×m)——
5000×5000 用巢狀迴圈是 2500 萬次比較，用雜湊索引是 1 萬次（NFR-01）。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from app.providers.base import Account, AccountStatus, FetchResult


class MatchStatus(str, Enum):
    """比對結果的四種狀態（FR-07）。

    命名以 A/B 兩側表述，避免預設哪一邊「才是對的」——
    實際的風險判讀交給 :class:`RiskLevel`。
    """

    ONLY_IN_A = "only_in_a"
    """僅存在於來源 A。若 A 是 AD，代表外部系統缺漏此人的權限。"""

    ONLY_IN_B = "only_in_b"
    """僅存在於來源 B。若 A 是 AD，代表外部系統有 AD 中不存在的孤兒帳號。"""

    MATCHED = "matched"
    """兩邊都有且屬性一致。"""

    ATTRIBUTE_MISMATCH = "attribute_mismatch"
    """兩邊都有但屬性不一致（如 AD 已停用、外部系統仍啟用）。"""


class RiskLevel(str, Enum):
    """風險等級，決定結果頁的預設排序（UX 決策：高風險優先）。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def sort_order(self) -> int:
        return {
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.LOW: 2,
            RiskLevel.NONE: 3,
        }[self]


@dataclass(slots=True)
class ComparisonRow:
    """一筆比對結果。"""

    key: str
    status: MatchStatus
    risk: RiskLevel
    risk_reason: str
    account_a: Account | None
    account_b: Account | None
    differences: list[str] = field(default_factory=list)

    @property
    def display_identifier(self) -> str:
        source = self.account_a or self.account_b
        return source.identifier if source else self.key

    @property
    def display_name(self) -> str:
        for account in (self.account_a, self.account_b):
            if account and account.display_name:
                return account.display_name
        return ""


@dataclass(slots=True)
class ComparisonSummary:
    """比對統計。

    ``source_a_count`` / ``source_b_count`` 供人工交叉檢查來源筆數，
    是防範 AD 分頁靜默截斷的第三道防線（風險 R-02）。
    """

    source_a_label: str
    source_b_label: str
    source_a_count: int
    source_b_count: int
    status_counts: dict[MatchStatus, int]
    risk_counts: dict[RiskLevel, int]
    compared_at: datetime
    warnings: list[str] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        return sum(self.status_counts.values())

    @property
    def has_high_risk(self) -> bool:
        return self.risk_counts.get(RiskLevel.HIGH, 0) > 0


@dataclass(slots=True)
class ComparisonResult:
    """完整比對結果。"""

    summary: ComparisonSummary
    rows: list[ComparisonRow]

    def filter_by_status(self, status: MatchStatus) -> list[ComparisonRow]:
        return [row for row in self.rows if row.status is status]

    def filter_by_risk(self, risk: RiskLevel) -> list[ComparisonRow]:
        return [row for row in self.rows if row.risk is risk]


def _assess_risk(
    status: MatchStatus,
    account_a: Account | None,
    account_b: Account | None,
    *,
    a_is_authoritative: bool,
) -> tuple[RiskLevel, str]:
    """判定風險等級與原因（FR-08 離職稽核的核心邏輯）。

    當 A 是 AD（權威來源）時，最高風險的情境是：
    **AD 已停用或查無此人，但外部系統的帳號仍然是啟用的**——
    這正是離職者還能登入系統的漏洞。

    Args:
        a_is_authoritative: A 是否為 AD 這類權威身分來源。
            非權威時（如 Excel×Excel）不做離職判定，只標示差異。
    """
    if status is MatchStatus.MATCHED:
        return RiskLevel.NONE, ""

    if not a_is_authoritative:
        if status is MatchStatus.ATTRIBUTE_MISMATCH:
            return RiskLevel.LOW, "兩來源的屬性不一致"
        return RiskLevel.LOW, "僅存在於單一來源"

    # 以下為 A = AD（權威來源）的判讀
    if status is MatchStatus.ONLY_IN_B:
        # 外部系統有、AD 沒有 → 孤兒帳號
        if account_b and account_b.status is AccountStatus.ENABLED:
            return (
                RiskLevel.HIGH,
                "孤兒帳號：AD 中查無此人，但外部系統的帳號仍為啟用狀態。"
                "可能是離職未回收，或未經核准私自建立的帳號。",
            )
        return (
            RiskLevel.MEDIUM,
            "AD 中查無此人。外部系統帳號未啟用，風險較低，但仍應確認是否該刪除。",
        )

    if status is MatchStatus.ATTRIBUTE_MISMATCH:
        # 最高風險情境：AD 停用但外部仍啟用
        if (
            account_a
            and account_b
            and account_a.is_disabled
            and account_b.status is AccountStatus.ENABLED
        ):
            return (
                RiskLevel.HIGH,
                "權限未回收：AD 帳號已停用（可能已離職），"
                "但外部系統的帳號仍為啟用狀態，此人仍可登入該系統。",
            )
        return RiskLevel.LOW, "兩來源的帳號屬性不一致"

    # ONLY_IN_A：AD 有、外部系統沒有 → 權限缺漏，非安全風險
    if account_a and account_a.is_disabled:
        return RiskLevel.NONE, "AD 帳號已停用，外部系統本就無此帳號，狀態一致。"
    return (
        RiskLevel.LOW,
        "權限缺漏：AD 中有此人，但外部系統未開通帳號。屬功能面缺口，非安全風險。",
    )


def _diff_attributes(account_a: Account, account_b: Account) -> list[str]:
    """找出兩個帳號之間的屬性差異。

    只在兩邊都有明確資訊時才判定為差異——
    來源未提供該資訊（UNKNOWN / 空字串）不算差異，避免大量誤報。
    """
    differences: list[str] = []

    if (
        account_a.status is not AccountStatus.UNKNOWN
        and account_b.status is not AccountStatus.UNKNOWN
        and account_a.status is not account_b.status
    ):
        differences.append(
            f"啟用狀態不同：A={_status_label(account_a.status)}、"
            f"B={_status_label(account_b.status)}"
        )

    if account_a.email and account_b.email and account_a.email.lower() != account_b.email.lower():
        differences.append(f"Email 不同：A={account_a.email}、B={account_b.email}")

    if (
        account_a.display_name
        and account_b.display_name
        and account_a.display_name.strip() != account_b.display_name.strip()
    ):
        differences.append(f"顯示名稱不同：A={account_a.display_name}、B={account_b.display_name}")

    return differences


def _status_label(status: AccountStatus) -> str:
    return {
        AccountStatus.ENABLED: "啟用",
        AccountStatus.DISABLED: "停用",
        AccountStatus.UNKNOWN: "未知",
    }[status]


def compare(
    result_a: FetchResult,
    result_b: FetchResult,
    *,
    a_is_authoritative: bool = True,
) -> ComparisonResult:
    """比對兩個來源的帳號清單。

    效能：以字典建索引，時間複雜度 O(n+m)。
    5000×5000 的比對約需毫秒級，遠低於 NFR-01 的 5 秒門檻。

    Args:
        result_a: 來源 A 的抓取結果（通常是 AD，權威來源）。
        result_b: 來源 B 的抓取結果。
        a_is_authoritative: A 是否為權威身分來源（AD）。
            為 True 時才做離職稽核的風險判定。

    Returns:
        含統計與逐筆結果的比對結果，預設依風險高低排序。
    """
    index_a = _build_index(result_a.accounts)
    index_b = _build_index(result_b.accounts)

    warnings = list(result_a.warnings) + list(result_b.warnings)

    # 重複帳號警告：同一份名單出現重複的正規化鍵，代表來源資料有問題
    _warn_on_duplicates(result_a, index_a, "A", warnings)
    _warn_on_duplicates(result_b, index_b, "B", warnings)

    # 筆數不符警告：來源回報數與實際取得數不同，可能是分頁截斷（R-02）
    for result, side in ((result_a, "A"), (result_b, "B")):
        if result.has_count_mismatch:
            warnings.append(
                f"來源 {side}（{result.source_label}）回報 {result.total_reported} 筆，"
                f"實際取得 {result.count} 筆。請確認資料是否完整。"
            )

    rows: list[ComparisonRow] = []

    for key in index_a.keys() | index_b.keys():
        account_a = index_a.get(key)
        account_b = index_b.get(key)

        if account_a and account_b:
            differences = _diff_attributes(account_a, account_b)
            status = MatchStatus.ATTRIBUTE_MISMATCH if differences else MatchStatus.MATCHED
        elif account_a:
            status = MatchStatus.ONLY_IN_A
            differences = []
        else:
            status = MatchStatus.ONLY_IN_B
            differences = []

        risk, reason = _assess_risk(
            status, account_a, account_b, a_is_authoritative=a_is_authoritative
        )

        rows.append(
            ComparisonRow(
                key=key,
                status=status,
                risk=risk,
                risk_reason=reason,
                account_a=account_a,
                account_b=account_b,
                differences=differences,
            )
        )

    # 預設排序：高風險優先，同風險內依帳號字母序（UX 決策，見 docs/UX-Design.md）
    rows.sort(key=lambda row: (row.risk.sort_order, row.key))

    summary = ComparisonSummary(
        source_a_label=result_a.source_label,
        source_b_label=result_b.source_label,
        source_a_count=result_a.count,
        source_b_count=result_b.count,
        status_counts=_count_by(rows, lambda row: row.status, MatchStatus),
        risk_counts=_count_by(rows, lambda row: row.risk, RiskLevel),
        compared_at=datetime.now(UTC),
        warnings=warnings,
    )

    return ComparisonResult(summary=summary, rows=rows)


def _build_index(accounts: list[Account]) -> dict[str, Account]:
    """建立正規化鍵到帳號的索引。

    重複鍵保留第一筆——重複本身會另外發出警告，
    此處的選擇只求行為可預期。
    """
    index: dict[str, Account] = {}
    for account in accounts:
        index.setdefault(account.normalized_key, account)
    return index


def _warn_on_duplicates(
    result: FetchResult, index: dict[str, Account], side: str, warnings: list[str]
) -> None:
    duplicate_count = result.count - len(index)
    if duplicate_count > 0:
        warnings.append(
            f"來源 {side}（{result.source_label}）有 {duplicate_count} 筆重複帳號"
            f"（忽略大小寫後），比對時只採計第一筆。"
        )


def _count_by(rows: list[ComparisonRow], key_func, enum_type) -> dict:  # type: ignore[no-untyped-def]
    """統計各分類筆數。

    **一律包含所有列舉值**（計數為 0 也保留）。若省略零值，
    UI 模板與匯出程式都得逐處寫 ``.get(key, 0)``，
    漏掉一處就會在「某分類剛好沒有資料」時壞掉——
    這是只在特定資料下才出現、難以察覺的錯誤。
    """
    counter: Counter = Counter(key_func(row) for row in rows)
    return {member: counter.get(member, 0) for member in enum_type}
