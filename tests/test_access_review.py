"""access_review 引擎測試 — 人員 × 權限矩陣與異常判定（Round 8）。

引擎為純邏輯、不依賴 AD，因此在此以直接建構的 FetchResult 涵蓋所有情境。
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.access_review.engine import (
    AnomalyKind,
    Entitlement,
    build_access_review,
)
from app.providers.base import Account, AccountStatus, FetchResult


def _fetch(accounts: list[Account], label: str = "來源", total: int | None = None) -> FetchResult:
    return FetchResult(
        accounts=accounts,
        fetched_at=datetime.now(UTC),
        source_label=label,
        total_reported=total,
    )


def _person(uid: str, name: str = "", status: AccountStatus = AccountStatus.ENABLED) -> Account:
    return Account(identifier=uid, display_name=name or uid, status=status)


def _master(*people: Account) -> FetchResult:
    return _fetch(list(people), "AD 已啟用帳號")


def _ent(name: str, *members: Account) -> Entitlement:
    return Entitlement(name=name, members=_fetch(list(members), name))


class TestMatrix:
    def test_person_has_and_lacks_entitlement(self):
        master = _master(_person("0001", "Alice"), _person("0002", "Bob"))
        net = _ent("網路權限", _person("0001", "Alice"))  # 只有 Alice
        result = build_access_review(master, [net])

        assert result.summary.person_count == 2
        assert result.summary.entitlement_names == ["網路權限"]
        rows = {p.account.identifier: p for p in result.people}
        assert rows["0001"].access["網路權限"] is True
        assert rows["0002"].access["網路權限"] is False

    def test_multiple_entitlements_and_counts(self):
        master = _master(_person("0001"), _person("0002"), _person("0003"))
        net = _ent("網路權限", _person("0001"), _person("0002"))
        vpn = _ent("VPN", _person("0001"))
        result = build_access_review(master, [net, vpn])

        assert result.summary.entitlement_names == ["網路權限", "VPN"]
        assert result.summary.granted_counts == {"網路權限": 2, "VPN": 1}
        r1 = next(p for p in result.people if p.account.identifier == "0001")
        assert r1.granted_count == 2

    def test_rows_sorted_by_normalized_key(self):
        master = _master(_person("0003"), _person("0001"), _person("0002"))
        result = build_access_review(master, [])
        assert [p.account.identifier for p in result.people] == ["0001", "0002", "0003"]

    def test_case_insensitive_membership(self):
        # 主檔用大寫、群組用小寫，仍應對齊（normalized_key）
        master = _master(_person("User1"))
        net = _ent("網路權限", _person("user1"))
        result = build_access_review(master, [net])
        assert result.people[0].access["網路權限"] is True
        assert result.summary.total_anomalies == 0


class TestAnomalies:
    def test_disabled_member_is_anomaly(self):
        """在群組中、但主檔（已啟用）查無，且該帳號為停用 → 停用異常（該收沒收）。"""
        master = _master(_person("0001"))
        # 0002 在網路權限群組，AD 狀態為停用，且不在已啟用主檔
        net = _ent("網路權限", _person("0001"), _person("0002", "離職者", AccountStatus.DISABLED))
        result = build_access_review(master, [net])

        assert result.summary.anomaly_counts["網路權限"] == 1
        anomaly = result.anomalies[0]
        assert anomaly.kind is AnomalyKind.DISABLED
        assert anomaly.identifier == "0002"
        assert anomaly.entitlement == "網路權限"
        # 0002 不應出現在矩陣列（矩陣＝已啟用主檔）
        assert all(p.account.identifier != "0002" for p in result.people)

    def test_orphan_member_is_anomaly(self):
        """在群組中、但主檔查無此人（狀態非停用）→ 孤兒異常。"""
        master = _master(_person("0001"))
        net = _ent("網路權限", _person("9999", "不明帳號", AccountStatus.UNKNOWN))
        result = build_access_review(master, [net])

        assert result.summary.anomaly_counts["網路權限"] == 1
        assert result.anomalies[0].kind is AnomalyKind.ORPHAN
        assert result.anomalies[0].identifier == "9999"

    def test_disabled_sorted_before_orphan(self):
        master = _master(_person("0001"))
        net = _ent(
            "網路權限",
            _person("orphan1", "孤兒", AccountStatus.UNKNOWN),
            _person("dis1", "停用", AccountStatus.DISABLED),
        )
        result = build_access_review(master, [net])
        assert [a.kind for a in result.anomalies] == [AnomalyKind.DISABLED, AnomalyKind.ORPHAN]

    def test_enabled_person_in_group_is_not_anomaly(self):
        master = _master(_person("0001"), _person("0002"))
        net = _ent("網路權限", _person("0001"), _person("0002"))
        result = build_access_review(master, [net])
        assert result.summary.total_anomalies == 0

    def test_summary_total_and_has_anomaly(self):
        master = _master(_person("0001"))
        net = _ent("網路權限", _person("d", status=AccountStatus.DISABLED))
        vpn = _ent("VPN", _person("o", status=AccountStatus.UNKNOWN))
        result = build_access_review(master, [net, vpn])
        assert result.summary.total_anomalies == 2
        assert result.summary.has_anomaly is True
        assert len(result.anomalies_for("網路權限")) == 1
        assert len(result.anomalies_for("VPN")) == 1


class TestEdgeCases:
    def test_no_entitlements(self):
        master = _master(_person("0001"), _person("0002"))
        result = build_access_review(master, [])
        assert result.summary.person_count == 2
        assert result.summary.entitlement_names == []
        assert result.people[0].access == {}
        assert result.summary.total_anomalies == 0

    def test_empty_master_still_reports_orphans(self):
        """主檔為空，但群組有成員 → 全部視為異常，不會靜默漏掉。"""
        master = _master()
        net = _ent("網路權限", _person("x", status=AccountStatus.DISABLED))
        result = build_access_review(master, [net])
        assert result.people == []
        assert result.summary.anomaly_counts["網路權限"] == 1

    def test_count_mismatch_warns(self):
        """來源回報筆數與實際不符（可能分頁截斷）→ 產生警告。"""
        master = _fetch([_person("0001")], "AD", total=5)  # 回報 5、實得 1
        result = build_access_review(master, [])
        assert any("回報" in w and "實際取得" in w for w in result.summary.warnings)
