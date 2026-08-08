"""以人員為主的權限檢視（Access Review）引擎 — 對應 Round 8 新核心模型。

與 ``comparison.engine`` 的「兩來源對稱比對」不同：本引擎以一份**權威人員名冊**
（AD 已啟用帳號）為主，逐一檢視每個人在各**權限群組**（網路權限／VPN／LINE…）中
是否具有權限，並找出「帳號已停用卻仍在群組」這類**該收沒收**的異常。

相同紀律：引擎**不知道資料從哪來**，只認識 :class:`Account`（NFR-10）。
主檔與每個權限群組都由既有的 Provider（LDAP／API／File／手動）產生 FetchResult，
本引擎只做集合運算，因此可在無 AD 環境下被完整測試。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from app.providers.base import Account, AccountStatus, FetchResult


class AnomalyKind(str, Enum):
    """權限異常的兩種型態（皆為「該收沒收」的稽核重點）。"""

    DISABLED = "disabled"
    """在權限群組中，但主檔（AD）帳號已**停用** —— 離職／異動未回收權限。"""

    ORPHAN = "orphan"
    """在權限群組中，但主檔**查無此人** —— 孤兒帳號或未經核准建立。"""


@dataclass(frozen=True, slots=True)
class Entitlement:
    """一個權限群組來源（如「網路權限」）與其成員名冊。

    ``members`` 由 Provider 抓取，成員各自帶有 AD 啟用狀態；
    手動 KEY-IN 的來源會在抓取時逐一向 AD 查證狀態後填入（規格第 5 點）。
    """

    name: str
    members: FetchResult


@dataclass(slots=True)
class PersonRow:
    """矩陣中的一列 —— 一位主檔人員，及其在各權限群組的有／無。"""

    account: Account
    access: dict[str, bool]  # 權限群組名 -> 是否具有

    @property
    def granted_count(self) -> int:
        return sum(1 for has in self.access.values() if has)


@dataclass(slots=True)
class Anomaly:
    """一筆權限異常（權限群組成員不在「已啟用主檔」中）。"""

    entitlement: str
    identifier: str
    display_name: str
    kind: AnomalyKind
    detail: str


@dataclass(slots=True)
class AccessReviewSummary:
    person_count: int
    entitlement_names: list[str]
    granted_counts: dict[str, int]  # 每個權限群組：有多少在職人員具有
    anomaly_counts: dict[str, int]  # 每個權限群組：有多少異常
    reviewed_at: datetime
    warnings: list[str] = field(default_factory=list)

    @property
    def total_anomalies(self) -> int:
        return sum(self.anomaly_counts.values())

    @property
    def has_anomaly(self) -> bool:
        return self.total_anomalies > 0


@dataclass(slots=True)
class AccessReviewResult:
    summary: AccessReviewSummary
    people: list[PersonRow]
    anomalies: list[Anomaly]

    def anomalies_for(self, entitlement: str) -> list[Anomaly]:
        return [a for a in self.anomalies if a.entitlement == entitlement]


def _build_index(accounts: list[Account]) -> dict[str, Account]:
    """以正規化鍵建索引；重複鍵保留第一筆（重複另由警告處理）。"""
    index: dict[str, Account] = {}
    for account in accounts:
        index.setdefault(account.normalized_key, account)
    return index


def build_access_review(
    master: FetchResult,
    entitlements: list[Entitlement],
) -> AccessReviewResult:
    """建立「人員 × 權限」檢視。

    Args:
        master: 權威人員名冊（AD 已啟用帳號），每列人員的權限基準。
        entitlements: 各權限群組來源；順序即畫面欄位順序。

    Returns:
        含矩陣（people）、異常清單（anomalies）與統計（summary）的結果。

    邏輯：
        - 矩陣列 = 主檔每個人；每個權限欄 = 此人是否在該群組成員集合中。
        - 異常 = 權限群組成員**不在已啟用主檔**中：
          成員 AD 狀態為停用 → :data:`AnomalyKind.DISABLED`（該收沒收）；
          否則（查無／未知）→ :data:`AnomalyKind.ORPHAN`（孤兒帳號）。
    """
    master_index = _build_index(master.accounts)
    names = [e.name for e in entitlements]
    ent_indexes: dict[str, dict[str, Account]] = {
        e.name: _build_index(e.members.accounts) for e in entitlements
    }

    warnings = list(master.warnings)
    if master.has_count_mismatch:
        warnings.append(
            f"主檔（{master.source_label}）回報 {master.total_reported} 筆、"
            f"實際取得 {master.count} 筆，請確認資料是否完整。"
        )
    for e in entitlements:
        warnings.extend(e.members.warnings)
        if e.members.has_count_mismatch:
            warnings.append(
                f"權限群組「{e.name}」回報 {e.members.total_reported} 筆、"
                f"實際取得 {e.members.count} 筆，請確認資料是否完整。"
            )

    # 矩陣列：依正規化鍵排序，行為可預期
    people: list[PersonRow] = []
    for key in sorted(master_index):
        account = master_index[key]
        access = {name: (key in ent_indexes[name]) for name in names}
        people.append(PersonRow(account=account, access=access))

    # 異常：權限群組成員不在「已啟用主檔」中
    anomalies: list[Anomaly] = []
    for e in entitlements:
        for key in ent_indexes[e.name]:
            if key in master_index:
                continue  # 正常：具有權限且為在職人員
            member = ent_indexes[e.name][key]
            if member.status is AccountStatus.DISABLED:
                kind = AnomalyKind.DISABLED
                detail = "AD 帳號已停用，但仍在此權限群組中 —— 應回收權限。"
            else:
                kind = AnomalyKind.ORPHAN
                detail = "在此權限群組中，但不在已啟用人員名冊內 —— 請確認此帳號是否應存在。"
            anomalies.append(
                Anomaly(
                    entitlement=e.name,
                    identifier=member.identifier,
                    display_name=member.display_name,
                    kind=kind,
                    detail=detail,
                )
            )

    # 停用類異常優先（風險較高），其次孤兒；同類依群組、帳號排序
    anomalies.sort(
        key=lambda a: (0 if a.kind is AnomalyKind.DISABLED else 1, a.entitlement, a.identifier)
    )

    granted_counts = {name: sum(1 for p in people if p.access[name]) for name in names}
    anomaly_counts = {name: sum(1 for a in anomalies if a.entitlement == name) for name in names}

    summary = AccessReviewSummary(
        person_count=len(people),
        entitlement_names=names,
        granted_counts=granted_counts,
        anomaly_counts=anomaly_counts,
        reviewed_at=datetime.now(UTC),
        warnings=warnings,
    )
    return AccessReviewResult(summary=summary, people=people, anomalies=anomalies)
