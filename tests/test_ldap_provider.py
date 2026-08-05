"""LDAP Provider 測試 — 對應 IR-01～IR-07、AC-01、AC-03、風險 R-02、R-03。

以假的 Connection 取代真實 AD，讓分頁與遞迴邏輯能在無 AD 環境下被驗證。
真實 AD 的整合測試另標記為 integration，需 Samba AD DC 環境。
"""

from unittest.mock import MagicMock

import pytest

from app.providers.base import AccountStatus, ConfigurationError
from app.providers.ldap_provider import (
    MAX_NESTING_DEPTH,
    UAC_ACCOUNTDISABLE,
    LdapConfig,
    LdapProvider,
    NestingStrategy,
    _build_tls_config,
)


def make_config(**overrides) -> LdapConfig:
    defaults = {
        "host": "dc.example.local",
        "base_dn": "DC=example,DC=local",
        "bind_dn": "CN=svc,DC=example,DC=local",
        "bind_password": "secret",  # noqa: S106 - 測試用假值
    }
    defaults.update(overrides)
    return LdapConfig(**defaults)


def make_entry(account_name: str, *, uac: int = 512, dn: str | None = None) -> dict:
    """建立一筆假的 LDAP 查詢結果。"""
    return {
        "type": "searchResEntry",
        "dn": dn or f"CN={account_name},OU=Users,DC=example,DC=local",
        "attributes": {
            "sAMAccountName": account_name,
            "displayName": f"User {account_name}",
            "mail": f"{account_name}@example.local",
            "userAccountControl": uac,
        },
    }


class TestConfigValidation:
    """NFR-04、IR-03：設定驗證拒絕不安全與會導致錯誤的組合。"""

    def test_rejects_plaintext_ldap(self):
        """NFR-04：明文 389 bind 必須被拒絕，不提供繞過選項。"""
        with pytest.raises(ConfigurationError) as exc:
            make_config(use_ssl=False, use_start_tls=False, port=389).validate()

        assert "未加密" in exc.value.message
        assert "LDAPS" in exc.value.remediation

    def test_accepts_ldaps(self):
        make_config(use_ssl=True, port=636).validate()  # 不應拋出

    def test_accepts_start_tls(self):
        make_config(use_ssl=False, use_start_tls=True, port=389).validate()

    @pytest.mark.parametrize("page_size", [0, -1, 1001, 5000])
    def test_rejects_invalid_page_size(self, page_size):
        """IR-03：page_size 超過 1000 會被 AD 靜默截斷。"""
        with pytest.raises(ConfigurationError, match="1~1000"):
            make_config(page_size=page_size).validate()

    def test_accepts_boundary_page_size(self):
        make_config(page_size=1000).validate()
        make_config(page_size=1).validate()

    def test_rejects_empty_host_and_base_dn(self):
        with pytest.raises(ConfigurationError, match="host"):
            make_config(host="").validate()
        with pytest.raises(ConfigurationError, match="Base DN"):
            make_config(base_dn="").validate()


class TestTlsConfiguration:
    """IR-02、IR-05、IR-06：TLS 自動協商、排除 RC4、憑證驗證。"""

    def test_tls_version_is_auto_negotiated(self):
        """IR-02：不可寫死 TLS 版本。

        WS2016~2022 只支援 TLS 1.2，WS2025 支援 1.3。
        使用 PROTOCOL_TLS_CLIENT 讓 OpenSSL 自動協商雙方共同支援的最高版本。
        """
        import ssl

        tls = _build_tls_config(make_config())

        assert tls.version == ssl.PROTOCOL_TLS_CLIENT

    def test_rc4_excluded_from_ciphers(self):
        """IR-05：WS2025 已棄用 RC4，使用會導致連線失敗。"""
        tls = _build_tls_config(make_config())

        assert "!RC4" in tls.ciphers
        assert "!MD5" in tls.ciphers
        assert "!aNULL" in tls.ciphers

    def test_cert_validation_enabled_by_default(self):
        """IR-06：安全預設 —— 憑證驗證預設開啟。"""
        import ssl

        tls = _build_tls_config(make_config())

        assert tls.validate == ssl.CERT_REQUIRED

    def test_cert_validation_can_be_disabled_for_testing(self):
        import ssl

        tls = _build_tls_config(make_config(verify_cert=False))

        assert tls.validate == ssl.CERT_NONE


class TestPagination:
    """IR-03 / 風險 R-02：分頁查詢 —— 本專案最高風險項。

    AD 單次查詢硬性上限 1000 筆且**不會報錯**，未分頁會靜默截斷，
    導致比對結果錯誤卻看起來正常。這比程式當掉更危險。
    """

    def _provider_with_entries(self, entries: list[dict], **config_kwargs):
        provider = LdapProvider(make_config(**config_kwargs), group_dn="CN=G,DC=example,DC=local")
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter(entries)
        return provider, conn

    @pytest.mark.parametrize("count", [999, 1000, 1001, 2500])
    def test_all_entries_returned_across_page_boundary(self, count):
        """AC-03 邊界測試：1000 / 1001 筆都必須完整取得。"""
        entries = [make_entry(f"user{i:05d}") for i in range(count)]
        provider, conn = self._provider_with_entries(entries)

        result = provider._paged_search(conn, "(objectClass=user)", ["sAMAccountName"])

        assert len(result) == count, f"應取得 {count} 筆，實際 {len(result)} 筆 —— 疑似分頁截斷"

    def test_paged_search_is_called_with_page_size(self):
        """確認確實使用分頁 API，而非普通 search。"""
        provider, conn = self._provider_with_entries([])

        provider._paged_search(conn, "(objectClass=user)", ["sAMAccountName"])

        conn.extend.standard.paged_search.assert_called_once()
        kwargs = conn.extend.standard.paged_search.call_args.kwargs
        assert kwargs["paged_size"] == 1000
        assert kwargs["generator"] is True

    def test_referrals_are_filtered_out(self):
        """searchResRef（referral）不是實際資料，必須排除。"""
        entries = [
            make_entry("real1"),
            {"type": "searchResRef", "uri": ["ldap://other.example.local"]},
            make_entry("real2"),
        ]
        provider, conn = self._provider_with_entries(entries)

        result = provider._paged_search(conn, "(objectClass=user)", ["sAMAccountName"])

        assert len(result) == 2


class TestNestedGroupExpansion:
    """IR-04 / 風險 R-03：巢狀群組展開與循環參照防護。"""

    def test_recursive_expansion_collects_all_levels(self):
        """AC-03：巢狀群組成員數必須與 AD 實際遞迴成員完全一致。"""
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.RECURSIVE),
            group_dn="CN=Parent,DC=example,DC=local",
        )
        conn = MagicMock()

        def paged_search_side_effect(**kwargs):
            filter_str = kwargs["search_filter"]
            if "objectClass=group" in filter_str:
                if "Parent" in filter_str:
                    return iter([{"type": "searchResEntry", "dn": "CN=Child,DC=example,DC=local"}])
                return iter([])
            # 使用者查詢
            if "Parent" in filter_str:
                return iter([make_entry("parent_user")])
            if "Child" in filter_str:
                return iter([make_entry("child_user")])
            return iter([])

        conn.extend.standard.paged_search.side_effect = paged_search_side_effect

        entries = provider._fetch_recursive(conn, "CN=Parent,DC=example,DC=local")
        names = {e["attributes"]["sAMAccountName"] for e in entries}

        assert names == {"parent_user", "child_user"}

    def test_circular_reference_does_not_hang(self):
        """風險 R-03：A∈B 且 B∈A 的循環參照不可造成無限遞迴。"""
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.RECURSIVE),
            group_dn="CN=A,DC=example,DC=local",
        )
        conn = MagicMock()

        def circular_side_effect(**kwargs):
            filter_str = kwargs["search_filter"]
            if "objectClass=group" in filter_str:
                # A 指向 B、B 指向 A —— 循環
                if "CN=A," in filter_str:
                    return iter([{"type": "searchResEntry", "dn": "CN=B,DC=example,DC=local"}])
                if "CN=B," in filter_str:
                    return iter([{"type": "searchResEntry", "dn": "CN=A,DC=example,DC=local"}])
                return iter([])
            return iter([make_entry("member")])

        conn.extend.standard.paged_search.side_effect = circular_side_effect

        # 若防護失效，此呼叫會無限迴圈
        entries = provider._fetch_recursive(conn, "CN=A,DC=example,DC=local")

        assert len(entries) >= 1  # 有取得成員且正常結束

    def test_deduplicates_users_in_multiple_subgroups(self):
        """同一人同時屬於多個子群組時，只能算一次。"""
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.RECURSIVE),
            group_dn="CN=Parent,DC=example,DC=local",
        )
        conn = MagicMock()
        shared_dn = "CN=shared,OU=Users,DC=example,DC=local"

        def side_effect(**kwargs):
            filter_str = kwargs["search_filter"]
            if "objectClass=group" in filter_str:
                if "Parent" in filter_str:
                    return iter([
                        {"type": "searchResEntry", "dn": "CN=Sub1,DC=example,DC=local"},
                        {"type": "searchResEntry", "dn": "CN=Sub2,DC=example,DC=local"},
                    ])
                return iter([])
            # 兩個子群組都含同一人
            return iter([make_entry("shared", dn=shared_dn)])

        conn.extend.standard.paged_search.side_effect = side_effect

        entries = provider._fetch_recursive(conn, "CN=Parent,DC=example,DC=local")

        assert len(entries) == 1, "重複成員應被去重"

    def test_in_chain_strategy_uses_matching_rule_oid(self):
        """IR-04：IN_CHAIN 策略使用 OID 1.2.840.113556.1.4.1941。"""
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.IN_CHAIN),
            group_dn="CN=G,DC=example,DC=local",
        )
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])

        provider._fetch_in_chain(conn, "CN=G,DC=example,DC=local")

        filter_used = conn.extend.standard.paged_search.call_args.kwargs["search_filter"]
        assert "1.2.840.113556.1.4.1941" in filter_used

    def test_group_dn_is_escaped_in_filter(self):
        """CWE-90：群組 DN 含特殊字元時必須轉義。"""
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.DIRECT_ONLY),
            group_dn="CN=Finance (Global),DC=example,DC=local",
        )
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])

        provider._fetch_direct(conn, "CN=Finance (Global),DC=example,DC=local")

        filter_used = conn.extend.standard.paged_search.call_args.kwargs["search_filter"]
        assert "\\28" in filter_used  # 左括號已轉義
        assert "\\29" in filter_used  # 右括號已轉義

    def test_max_depth_constant_is_reasonable(self):
        assert 5 <= MAX_NESTING_DEPTH <= 50


class TestAccountConversion:
    """AC-08：AD 停用判斷（userAccountControl bit 2）。"""

    def test_normal_account_is_enabled(self):
        acc = LdapProvider._to_account(make_entry("alice", uac=512))

        assert acc is not None
        assert acc.status is AccountStatus.ENABLED
        assert not acc.is_disabled

    def test_disabled_account_detected(self):
        """UAC 514 = 512 (NORMAL_ACCOUNT) + 2 (ACCOUNTDISABLE)。"""
        acc = LdapProvider._to_account(make_entry("bob", uac=514))

        assert acc is not None
        assert acc.status is AccountStatus.DISABLED
        assert acc.is_disabled

    @pytest.mark.parametrize(
        ("uac", "expected_disabled"),
        [
            (512, False),      # 一般帳號
            (514, True),       # 一般帳號 + 停用
            (66048, False),    # 密碼永不過期
            (66050, True),     # 密碼永不過期 + 停用
            (66082, True),     # 停用 + 密碼永不過期 + 不需密碼
        ],
    )
    def test_uac_bit_combinations(self, uac, expected_disabled):
        acc = LdapProvider._to_account(make_entry("u", uac=uac))

        assert acc is not None
        assert acc.is_disabled is expected_disabled
        assert bool(uac & UAC_ACCOUNTDISABLE) is expected_disabled

    def test_entry_without_account_name_is_skipped(self):
        """非使用者物件（如 contact）沒有 sAMAccountName。"""
        entry = {"type": "searchResEntry", "dn": "CN=x", "attributes": {"displayName": "X"}}

        assert LdapProvider._to_account(entry) is None

    def test_malformed_uac_falls_back_to_unknown(self):
        """UAC 無法解析時不應崩潰，退回 UNKNOWN。"""
        entry = make_entry("weird")
        entry["attributes"]["userAccountControl"] = "not-a-number"

        acc = LdapProvider._to_account(entry)

        assert acc is not None
        assert acc.status is AccountStatus.UNKNOWN

    def test_multivalued_attributes_take_first(self):
        """LDAP 屬性可能是清單，需正確取值。"""
        entry = make_entry("multi")
        entry["attributes"]["sAMAccountName"] = ["multi", "ignored"]
        entry["attributes"]["mail"] = ["first@example.local", "second@example.local"]

        acc = LdapProvider._to_account(entry)

        assert acc is not None
        assert acc.identifier == "multi"
        assert acc.email == "first@example.local"


class TestErrorClassification:
    """AC-01：錯誤必須分類成可行動的訊息，而非籠統的 'bind failed'。"""

    def test_dns_failure_classified(self):
        provider = LdapProvider(make_config())

        error = provider._classify_socket_error(Exception("getaddrinfo failed"))

        assert error.category == "connection"
        assert "DNS" in error.remediation

    def test_tls_failure_classified(self):
        provider = LdapProvider(make_config())

        error = provider._classify_socket_error(Exception("certificate verify failed"))

        assert error.category == "tls"
        assert "CA" in error.remediation

    def test_generic_failure_still_actionable(self):
        provider = LdapProvider(make_config())

        error = provider._classify_socket_error(Exception("connection refused"))

        assert error.category == "connection"
        assert error.remediation  # 必須有修補建議


# ---------------------------------------------------------------------------
# Round 2：查詢範本、屬性選擇、搜尋範圍、群組反查
# ---------------------------------------------------------------------------


class TestQueryTemplateIntegration:
    """範本設定要真的影響送出的查詢，而不是只存在設定裡。"""

    def test_template_filter_is_used_in_fetch(self):
        provider = LdapProvider(make_config(), template_key="disabled_users")

        assert "userAccountControl" in provider.search_filter
        assert "(!(" not in provider.search_filter

    def test_template_parameter_is_escaped_in_search_filter(self):
        provider = LdapProvider(
            make_config(),
            template_key="by_department",
            template_parameters={"department": "*)(uid=*"},
        )

        # RFC 4515 轉義後的 '*' 是 \2a。用 raw string 表示，
        # 否則 "\2a" 會被 Python 讀成控制字元 \x02 加上 'a'。
        assert r"\2a" in provider.search_filter
        assert provider.search_filter.count("(") == provider.search_filter.count(")")

    def test_invalid_template_rejected_at_construction(self):
        """設定錯誤要在建立來源當下就爆出來，而不是等到抓取時。"""
        with pytest.raises(ConfigurationError):
            LdapProvider(make_config(), template_key="no_such_template")

    def test_missing_template_parameter_rejected_at_construction(self):
        with pytest.raises(ConfigurationError):
            LdapProvider(make_config(), template_key="by_department")

    def test_group_dn_takes_precedence_over_template(self):
        provider = LdapProvider(
            make_config(nesting_strategy=NestingStrategy.IN_CHAIN),
            group_dn="CN=IT,OU=Groups,DC=example,DC=local",
        )

        assert "memberOf" in provider.search_filter


class TestAttributeSelection:
    """管理者勾選的額外屬性要真的被索取並帶進結果。"""

    def test_extra_attributes_requested_from_ad(self):
        provider = LdapProvider(
            make_config(extra_attributes=["department", "title"]),
            group_dn="CN=G,DC=example,DC=local",
        )
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])

        provider._paged_search(conn, "(objectClass=user)", provider._attributes)

        requested = conn.extend.standard.paged_search.call_args.kwargs["attributes"]
        assert "department" in requested
        assert "title" in requested
        # 核心屬性不可因為勾選額外屬性而消失
        assert "sAMAccountName" in requested

    def test_unknown_attribute_rejected_by_config(self):
        with pytest.raises(ConfigurationError):
            LdapProvider(make_config(extra_attributes=["ntSecurityDescriptor"]))

    def test_extra_attribute_value_lands_in_account(self):
        entry = make_entry("jsmith")
        entry["attributes"]["department"] = "資訊部"

        account = LdapProvider._to_account(entry, ["department"])

        assert account.attributes["department"] == "資訊部"

    def test_multivalued_attribute_preserves_all_values(self):
        """memberOf 這類多值屬性只取第一個會遺失資訊。"""
        entry = make_entry("jsmith")
        entry["attributes"]["memberOf"] = ["CN=A,DC=x", "CN=B,DC=x", "CN=C,DC=x"]

        account = LdapProvider._to_account(entry, ["memberOf"])

        assert "CN=A,DC=x" in account.attributes["memberOf"]
        assert "CN=C,DC=x" in account.attributes["memberOf"]

    def test_absent_extra_attribute_is_omitted(self):
        """AD 沒有回傳該屬性時不應留下空字串鍵。"""
        account = LdapProvider._to_account(make_entry("jsmith"), ["department"])

        assert "department" not in account.attributes


class TestSearchScope:
    """搜尋範圍要傳給 ldap3，而不是被忽略。"""

    def test_scope_passed_to_paged_search(self):
        from app.providers.ldap_queries import SearchScope

        provider = LdapProvider(
            make_config(search_scope=SearchScope.LEVEL),
            group_dn="CN=G,DC=example,DC=local",
        )
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])

        provider._paged_search(conn, "(objectClass=user)", ["sAMAccountName"])

        kwargs = conn.extend.standard.paged_search.call_args.kwargs
        assert kwargs["search_scope"] == "LEVEL"

    def test_default_scope_is_subtree(self):
        provider = LdapProvider(make_config(), group_dn="CN=G,DC=example,DC=local")
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])

        provider._paged_search(conn, "(objectClass=user)", ["sAMAccountName"])

        kwargs = conn.extend.standard.paged_search.call_args.kwargs
        assert kwargs["search_scope"] == "SUBTREE"


class TestUserGroupLookup:
    """反查某帳號所屬群組（含巢狀）—— 設定驗證工具。"""

    def _provider_with_conn(self, conn):
        provider = LdapProvider(make_config())
        provider._connect = MagicMock(return_value=conn)  # type: ignore[method-assign]
        return provider

    def test_returns_groups_for_existing_user(self):
        conn = MagicMock()
        user_entry = make_entry("jsmith")
        group_entries = [
            {"type": "searchResEntry", "dn": "CN=IT_Admins,OU=G,DC=example,DC=local",
             "attributes": {"cn": "IT_Admins"}},
            {"type": "searchResEntry", "dn": "CN=Staff,OU=G,DC=example,DC=local",
             "attributes": {"cn": "Staff"}},
        ]
        conn.extend.standard.paged_search.side_effect = [
            iter([user_entry]),
            iter(group_entries),
        ]
        provider = self._provider_with_conn(conn)

        result = provider.find_user_groups("jsmith")

        assert result["user_dn"] == user_entry["dn"]
        assert len(result["groups"]) == 2
        assert "CN=IT_Admins,OU=G,DC=example,DC=local" in result["groups"]

    def test_unknown_user_reports_clearly(self):
        """查無帳號要給出可行動的訊息，而不是空結果讓人以為沒群組。"""
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])
        provider = self._provider_with_conn(conn)

        result = provider.find_user_groups("nosuchuser")

        assert result["user_dn"] == ""
        assert result["groups"] == []
        assert result["message"]

    def test_user_with_no_groups(self):
        conn = MagicMock()
        conn.extend.standard.paged_search.side_effect = [
            iter([make_entry("loner")]),
            iter([]),
        ]
        provider = self._provider_with_conn(conn)

        result = provider.find_user_groups("loner")

        assert result["user_dn"]
        assert result["groups"] == []

    def test_account_name_is_escaped(self):
        """反查的帳號名同樣不可改變 filter 結構。"""
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])
        provider = self._provider_with_conn(conn)

        provider.find_user_groups("*)(uid=*")

        used_filter = conn.extend.standard.paged_search.call_args.kwargs["search_filter"]
        assert r"\2a" in used_filter
        assert used_filter.count("(") == used_filter.count(")")

    def test_connection_is_released(self):
        conn = MagicMock()
        conn.extend.standard.paged_search.return_value = iter([])
        provider = self._provider_with_conn(conn)

        provider.find_user_groups("jsmith")

        conn.unbind.assert_called_once()
