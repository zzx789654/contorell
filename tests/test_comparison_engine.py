"""比對引擎測試 — 對應 FR-06、FR-07、FR-08、AC-06、AC-07、AC-08。"""

from datetime import UTC, datetime

import pytest

from app.comparison.engine import MatchStatus, RiskLevel, compare
from app.providers.base import Account, AccountStatus, FetchResult


def make_result(accounts: list[Account], label: str = "來源", **kwargs) -> FetchResult:
    return FetchResult(
        accounts=accounts,
        fetched_at=datetime.now(UTC),
        source_label=label,
        **kwargs,
    )


def account(identifier: str, *, status=AccountStatus.ENABLED, **kwargs) -> Account:
    return Account(identifier=identifier, status=status, **kwargs)


class TestFourStatusClassification:
    """AC-07：四種狀態分類正確。"""

    def test_matched_when_both_sides_agree(self):
        a = make_result([account("alice")])
        b = make_result([account("alice")])

        result = compare(a, b)

        assert len(result.rows) == 1
        assert result.rows[0].status is MatchStatus.MATCHED
        assert result.rows[0].risk is RiskLevel.NONE

    def test_only_in_a(self):
        a = make_result([account("alice")])
        b = make_result([])

        result = compare(a, b)

        assert result.rows[0].status is MatchStatus.ONLY_IN_A

    def test_only_in_b(self):
        a = make_result([])
        b = make_result([account("orphan")])

        result = compare(a, b)

        assert result.rows[0].status is MatchStatus.ONLY_IN_B

    def test_attribute_mismatch_on_status_difference(self):
        a = make_result([account("bob", status=AccountStatus.DISABLED)])
        b = make_result([account("bob", status=AccountStatus.ENABLED)])

        result = compare(a, b)

        assert result.rows[0].status is MatchStatus.ATTRIBUTE_MISMATCH
        assert any("啟用狀態不同" in d for d in result.rows[0].differences)

    def test_unknown_status_is_not_a_difference(self):
        """來源未提供狀態資訊時不算差異，避免 Excel 來源產生大量誤報。"""
        a = make_result([account("carol", status=AccountStatus.ENABLED)])
        b = make_result([account("carol", status=AccountStatus.UNKNOWN)])

        result = compare(a, b)

        assert result.rows[0].status is MatchStatus.MATCHED

    def test_status_counts_are_accurate(self):
        a = make_result([account("both"), account("only_a")])
        b = make_result([account("both"), account("only_b")])

        result = compare(a, b)

        assert result.summary.status_counts[MatchStatus.MATCHED] == 1
        assert result.summary.status_counts[MatchStatus.ONLY_IN_A] == 1
        assert result.summary.status_counts[MatchStatus.ONLY_IN_B] == 1
        assert result.summary.total_rows == 3


class TestOffboardingAudit:
    """AC-08：離職稽核 —— 本系統最高價值的判定邏輯。"""

    def test_disabled_in_ad_but_enabled_externally_is_high_risk(self):
        """最高風險情境：離職者仍能登入外部系統。"""
        ad = make_result([account("leaver", status=AccountStatus.DISABLED)], "AD")
        erp = make_result([account("leaver", status=AccountStatus.ENABLED)], "ERP")

        result = compare(ad, erp, a_is_authoritative=True)

        row = result.rows[0]
        assert row.status is MatchStatus.ATTRIBUTE_MISMATCH
        assert row.risk is RiskLevel.HIGH
        assert "權限未回收" in row.risk_reason
        assert result.summary.has_high_risk

    def test_orphan_enabled_account_is_high_risk(self):
        """外部系統有啟用帳號，但 AD 查無此人 —— 孤兒帳號。"""
        ad = make_result([], "AD")
        erp = make_result([account("ghost", status=AccountStatus.ENABLED)], "ERP")

        result = compare(ad, erp, a_is_authoritative=True)

        row = result.rows[0]
        assert row.status is MatchStatus.ONLY_IN_B
        assert row.risk is RiskLevel.HIGH
        assert "孤兒帳號" in row.risk_reason

    def test_orphan_disabled_account_is_medium_risk(self):
        """外部帳號已停用，風險較低但仍需確認。"""
        ad = make_result([], "AD")
        erp = make_result([account("old", status=AccountStatus.DISABLED)], "ERP")

        result = compare(ad, erp, a_is_authoritative=True)

        assert result.rows[0].risk is RiskLevel.MEDIUM

    def test_missing_in_external_is_low_risk_not_security_issue(self):
        """AD 有、外部沒有 = 權限缺漏，是功能面問題不是安全風險。"""
        ad = make_result([account("newbie", status=AccountStatus.ENABLED)], "AD")
        erp = make_result([], "ERP")

        result = compare(ad, erp, a_is_authoritative=True)

        row = result.rows[0]
        assert row.risk is RiskLevel.LOW
        assert "權限缺漏" in row.risk_reason

    def test_disabled_in_ad_and_absent_externally_is_consistent(self):
        """AD 已停用且外部本就沒有 —— 狀態一致，無風險。"""
        ad = make_result([account("gone", status=AccountStatus.DISABLED)], "AD")
        erp = make_result([], "ERP")

        result = compare(ad, erp, a_is_authoritative=True)

        assert result.rows[0].risk is RiskLevel.NONE

    def test_non_authoritative_comparison_skips_offboarding_logic(self):
        """Excel×Excel 這類非權威比對不做離職判定，避免誤導。"""
        a = make_result([account("x", status=AccountStatus.DISABLED)], "Excel A")
        b = make_result([account("x", status=AccountStatus.ENABLED)], "Excel B")

        result = compare(a, b, a_is_authoritative=False)

        assert result.rows[0].risk is RiskLevel.LOW
        assert "權限未回收" not in result.rows[0].risk_reason


class TestKeyNormalization:
    """帳號鍵的正規化 —— 跨系統比對成敗的關鍵。"""

    def test_case_insensitive_matching(self):
        """AD 的 sAMAccountName 不分大小寫，比對必須一致處理。"""
        ad = make_result([account("J.Doe")], "AD")
        erp = make_result([account("j.doe")], "ERP")

        result = compare(ad, erp)

        assert len(result.rows) == 1
        assert result.rows[0].status is MatchStatus.MATCHED

    def test_whitespace_trimmed(self):
        """Excel 匯出常有多餘空白。"""
        ad = make_result([account("alice")], "AD")
        excel = make_result([account("  alice  ")], "Excel")

        result = compare(ad, excel)

        assert len(result.rows) == 1
        assert result.rows[0].status is MatchStatus.MATCHED

    def test_empty_identifier_rejected_at_construction(self):
        with pytest.raises(ValueError, match="identifier 不可為空"):
            Account(identifier="")
        with pytest.raises(ValueError):
            Account(identifier="   ")


class TestDataIntegrityWarnings:
    """風險 R-02 的防線：讓資料完整性問題浮現，而非靜默通過。"""

    def test_count_mismatch_produces_warning(self):
        """來源回報數與實際取得數不符 —— 可能是分頁截斷。"""
        a = make_result([account("x")], "AD", total_reported=1000)
        b = make_result([account("x")], "ERP")

        result = compare(a, b)

        assert any("回報 1000 筆" in w for w in result.summary.warnings)

    def test_duplicate_accounts_produce_warning(self):
        a = make_result([account("dup"), account("DUP"), account("other")], "AD")
        b = make_result([account("dup")], "ERP")

        result = compare(a, b)

        assert any("重複帳號" in w for w in result.summary.warnings)

    def test_source_counts_exposed_for_cross_check(self):
        """統計中保留兩邊原始筆數，供人工交叉檢查。"""
        a = make_result([account("a1"), account("a2")], "AD")
        b = make_result([account("b1")], "ERP")

        result = compare(a, b)

        assert result.summary.source_a_count == 2
        assert result.summary.source_b_count == 1

    def test_provider_warnings_propagate(self):
        a = make_result([account("x")], "AD", warnings=["AD 警告"])
        b = make_result([account("x")], "ERP", warnings=["API 警告"])

        result = compare(a, b)

        assert "AD 警告" in result.summary.warnings
        assert "API 警告" in result.summary.warnings


class TestSortingAndFiltering:
    def test_high_risk_sorted_first(self):
        """UX 決策：結果預設高風險優先（docs/UX-Design.md）。"""
        ad = make_result(
            [
                account("normal"),
                account("leaver", status=AccountStatus.DISABLED),
            ],
            "AD",
        )
        erp = make_result(
            [
                account("normal"),
                account("leaver", status=AccountStatus.ENABLED),
            ],
            "ERP",
        )

        result = compare(ad, erp)

        assert result.rows[0].risk is RiskLevel.HIGH
        assert result.rows[0].key == "leaver"

    def test_filter_by_status(self):
        a = make_result([account("both"), account("only_a")])
        b = make_result([account("both")])

        result = compare(a, b)

        assert len(result.filter_by_status(MatchStatus.MATCHED)) == 1
        assert len(result.filter_by_status(MatchStatus.ONLY_IN_A)) == 1

    def test_filter_by_risk(self):
        ad = make_result([account("leaver", status=AccountStatus.DISABLED)], "AD")
        erp = make_result([account("leaver", status=AccountStatus.ENABLED)], "ERP")

        result = compare(ad, erp)

        assert len(result.filter_by_risk(RiskLevel.HIGH)) == 1


class TestEdgeCases:
    def test_both_sources_empty(self):
        result = compare(make_result([]), make_result([]))

        assert result.rows == []
        assert result.summary.total_rows == 0

    def test_no_overlap_at_all(self):
        a = make_result([account("a1"), account("a2")])
        b = make_result([account("b1"), account("b2")])

        result = compare(a, b)

        assert len(result.rows) == 4
        assert result.summary.status_counts[MatchStatus.MATCHED] == 0

    def test_very_long_identifier(self):
        """AD 的 DN 可達 255 字元，帳號本身也可能很長。"""
        long_id = "u" * 255
        a = make_result([account(long_id)])
        b = make_result([account(long_id)])

        result = compare(a, b)

        assert result.rows[0].status is MatchStatus.MATCHED


@pytest.mark.slow
class TestPerformance:
    """NFR-01：5000×5000 比對須在 5 秒內完成。"""

    def test_five_thousand_by_five_thousand(self):
        import time

        # 兩邊各 5000 筆，其中 4000 筆重疊
        list_a = [account(f"user{i:05d}") for i in range(5000)]
        list_b = [account(f"user{i:05d}") for i in range(1000, 6000)]

        a = make_result(list_a, "AD")
        b = make_result(list_b, "ERP")

        start = time.perf_counter()
        result = compare(a, b)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"比對耗時 {elapsed:.2f}s，超過 NFR-01 的 5 秒門檻"
        assert result.summary.status_counts[MatchStatus.MATCHED] == 4000
        assert result.summary.status_counts[MatchStatus.ONLY_IN_A] == 1000
        assert result.summary.status_counts[MatchStatus.ONLY_IN_B] == 1000
