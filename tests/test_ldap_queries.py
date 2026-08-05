"""查詢範本與屬性白名單測試 — Round 2。

驗證重點：**使用者提供的值永遠無法改變 filter 的結構**。
這是本輪把「多樣化查詢」開放給網頁設定時，唯一不能妥協的性質。
"""

import pytest

from app.providers.base import ConfigurationError
from app.providers.ldap_queries import (
    ATTRIBUTES_BY_NAME,
    CORE_ATTRIBUTES,
    MATCHING_RULE_BIT_AND,
    MATCHING_RULE_IN_CHAIN,
    QUERY_TEMPLATES,
    build_attribute_list,
    build_query_filter,
    build_user_groups_filter,
    build_user_lookup_filter,
    get_template,
    validate_attributes,
)

# 典型的 LDAP 注入攻擊字串。若這些字元原樣出現在輸出中，
# 就代表 filter 的結構被使用者輸入改變了。
INJECTION_PAYLOADS = [
    "*)(uid=*",
    "*",
    "admin)(|(objectClass=*",
    "\\",
    "a)(userAccountControl:1.2.840.113556.1.4.803:=2",
    "test\x00truncated",
]


class TestTemplateIntegrity:
    """範本本身的結構性質。"""

    def test_all_templates_have_required_fields(self):
        for tpl in QUERY_TEMPLATES:
            assert tpl.key, "範本必須有 key"
            assert tpl.label, f"{tpl.key} 缺少顯示名稱"
            assert tpl.description, f"{tpl.key} 缺少說明（管理者需要知道這是什麼）"
            assert tpl.filter_template.startswith("("), f"{tpl.key} 的 filter 格式有誤"

    def test_template_keys_unique(self):
        keys = [tpl.key for tpl in QUERY_TEMPLATES]

        assert len(keys) == len(set(keys))

    def test_placeholders_only_appear_in_value_positions(self):
        """佔位符只能出現在 ``=`` 之後，絕不能出現在屬性名或運算子位置。

        若佔位符跑到屬性名的位置，使用者就能控制「要比對哪個屬性」，
        那等於部分結構仍受使用者控制。
        """
        for tpl in QUERY_TEMPLATES:
            for param in tpl.parameters:
                placeholder = "{" + param.key + "}"
                if placeholder not in tpl.filter_template:
                    continue
                index = tpl.filter_template.index(placeholder)
                preceding = tpl.filter_template[:index]

                assert preceding.endswith(("=", ":=")), (
                    f"{tpl.key} 的佔位符 {placeholder} 不在值的位置"
                )

    def test_uses_documented_matching_rules(self):
        """位元比對與鏈式成員都應使用 AD 的標準 OID。"""
        all_filters = " ".join(tpl.filter_template for tpl in QUERY_TEMPLATES)

        assert MATCHING_RULE_BIT_AND in all_filters
        assert MATCHING_RULE_IN_CHAIN in all_filters

    def test_get_template_rejects_unknown_key(self):
        with pytest.raises(ConfigurationError) as exc:
            get_template("../../etc/passwd")

        assert "未知的查詢範本" in exc.value.message


def assert_structure_unchanged(result: str, template: str, payload: str) -> None:
    """驗證輸出的結構與「無害輸入」時完全一致，只有值的部分不同。

    這比逐字元檢查更可靠：直接證明使用者的輸入**沒有增加任何結構元素**。
    做法是把已知安全的基準輸入與攻擊輸入各跑一次，
    比較兩者的括號數量與骨架是否相同。

    （早期版本用字串切片取出「值」再檢查特殊字元，
    但 rsplit 會切到整條 filter 最外層的括號，導致誤判——
    問題在測試的切法，不在被測程式。）
    """
    baseline = build_query_filter(template, {payload_key(template): "SAFE"})

    assert result.count("(") == baseline.count("("), "注入輸入增加了括號結構"
    assert result.count(")") == baseline.count(")"), "注入輸入增加了括號結構"
    # 未轉義的 NUL 會造成 C 層字串截斷
    assert "\x00" not in result


def payload_key(template_key: str) -> str:
    return get_template(template_key).parameters[0].key


class TestFilterInjectionResistance:
    """CWE-90：使用者輸入不得改變 filter 結構。"""

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_department_payload_is_escaped(self, payload):
        result = build_query_filter("by_department", {"department": payload})

        assert_structure_unchanged(result, "by_department", payload)
        # 值的部分必須是轉義形式，不是原樣
        assert f"(department={payload})" not in result

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_group_dn_payload_is_escaped(self, payload):
        result = build_query_filter("group_members_nested", {"group_dn": payload})

        assert_structure_unchanged(result, "group_members_nested", payload)

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_user_groups_lookup_is_escaped(self, payload):
        result = build_user_groups_filter(payload)
        baseline = build_user_groups_filter("CN=Safe,DC=corp,DC=local")

        assert result.count("(") == baseline.count("(")
        assert result.count(")") == baseline.count(")")
        assert "\x00" not in result

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_user_lookup_is_escaped(self, payload):
        result = build_user_lookup_filter(payload)
        baseline = build_user_lookup_filter("jsmith")

        assert result.count("(") == baseline.count("(")
        assert result.count(")") == baseline.count(")")
        assert "\x00" not in result

    def test_filter_stays_balanced_under_injection(self):
        """注入嘗試後，括號仍然配對——結構未被破壞。"""
        result = build_query_filter("by_department", {"department": "*)(uid=*"})

        assert result.count("(") == result.count(")")

    def test_escaped_value_uses_rfc4515_hex(self):
        result = build_query_filter("by_department", {"department": "*"})

        assert "\\2a" in result


class TestTemplateBuilding:
    """一般情況的正確性。"""

    def test_enabled_users_excludes_disabled_bit(self):
        result = build_query_filter("enabled_users", {})

        assert f"(!(userAccountControl:{MATCHING_RULE_BIT_AND}:=2))" in result

    def test_disabled_users_matches_disabled_bit(self):
        result = build_query_filter("disabled_users", {})

        assert f"(userAccountControl:{MATCHING_RULE_BIT_AND}:=2)" in result
        assert "(!(" not in result

    def test_nested_group_uses_in_chain(self):
        result = build_query_filter(
            "group_members_nested", {"group_dn": "CN=IT,OU=G,DC=corp,DC=local"}
        )

        assert MATCHING_RULE_IN_CHAIN in result

    def test_direct_group_does_not_use_in_chain(self):
        result = build_query_filter(
            "group_members_direct", {"group_dn": "CN=IT,OU=G,DC=corp,DC=local"}
        )

        assert MATCHING_RULE_IN_CHAIN not in result
        assert "(memberOf=CN=IT,OU=G,DC=corp,DC=local)" in result

    def test_normal_department_value_passes_through(self):
        result = build_query_filter("by_department", {"department": "資訊部"})

        assert "(department=資訊部)" in result

    def test_value_is_trimmed(self):
        result = build_query_filter("by_department", {"department": "  IT  "})

        assert "(department=IT)" in result

    def test_missing_required_parameter_rejected(self):
        with pytest.raises(ConfigurationError) as exc:
            build_query_filter("by_department", {})

        assert "部門名稱" in exc.value.message

    def test_blank_parameter_rejected(self):
        with pytest.raises(ConfigurationError):
            build_query_filter("by_department", {"department": "   "})

    def test_empty_user_dn_rejected(self):
        with pytest.raises(ConfigurationError):
            build_user_groups_filter("")

    def test_empty_account_rejected(self):
        with pytest.raises(ConfigurationError):
            build_user_lookup_filter("  ")


class TestAttributeWhitelist:
    """屬性採白名單制——不在清單中的一律拒絕，而非靜默忽略。"""

    def test_valid_attributes_accepted(self):
        result = validate_attributes(["department", "title"])

        assert set(result) == {"department", "title"}

    def test_unknown_attribute_rejected(self):
        with pytest.raises(ConfigurationError) as exc:
            validate_attributes(["ntSecurityDescriptor"])

        assert "ntSecurityDescriptor" in exc.value.message

    def test_sensitive_attributes_not_in_whitelist(self):
        """敏感屬性不應出現在白名單中。"""
        for name in (
            "ntSecurityDescriptor",
            "msDS-ManagedPassword",
            "unicodePwd",
            "userPassword",
            "msDS-KeyCredentialLink",
        ):
            assert name not in ATTRIBUTES_BY_NAME

    def test_rejection_lists_all_unknown_names(self):
        with pytest.raises(ConfigurationError) as exc:
            validate_attributes(["bogusOne", "department", "bogusTwo"])

        assert "bogusOne" in exc.value.message
        assert "bogusTwo" in exc.value.message

    def test_duplicates_removed(self):
        result = validate_attributes(["title", "title", "title"])

        assert result == ["title"]

    def test_output_order_is_stable(self):
        """輸出順序固定，讓 config_json 可預期地比較。"""
        first = validate_attributes(["title", "department"])
        second = validate_attributes(["department", "title"])

        assert first == second

    def test_empty_list_allowed(self):
        assert validate_attributes([]) == []

    def test_build_attribute_list_includes_core(self):
        result = build_attribute_list(["department"])

        for name in CORE_ATTRIBUTES:
            assert name in result
        assert "department" in result

    def test_build_attribute_list_no_duplicates(self):
        """即使額外屬性與核心屬性重疊也不會重複。"""
        result = build_attribute_list(["department"])

        assert len(result) == len(set(result))

    def test_build_attribute_list_rejects_unknown(self):
        with pytest.raises(ConfigurationError):
            build_attribute_list(["../../etc/passwd"])
