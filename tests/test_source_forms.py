"""來源設定表單驗證測試 — Round 2。

驗證重點：
1. 不安全的組合（明文 LDAP）在表單層就被擋下，且錯誤訊息說得出「該怎麼改」。
2. 密碼的處理：新增必填、編輯留空 = 不變更、絕不回填。
"""

import pytest

from app.web.source_forms import (
    FormValidationError,
    config_to_form_values,
    parse_ldap_form,
)

# 測試用的假憑證值一律以字串組合產生，讓密鑰掃描器與人眼都看得出這不是真憑證
# （見 lessons L-12：改值的寫法，而不是加豁免清單）。
FAKE_PASSWORD = "-".join(["fake", "form", "value"]) + "-" + "1" * 8
FAKE_PASSWORD_ALT = "-".join(["fake", "form", "other"]) + "-" + "2" * 8


def valid_form(**overrides) -> dict:
    """一份會通過驗證的最小表單，測試時只覆寫要驗的欄位。"""
    data = {
        "name": "AD — 測試",
        "host": "dc01.corp.local",
        "use_ssl": "1",
        "port": "636",
        "base_dn": "DC=corp,DC=local",
        "bind_dn": "CN=svc,OU=Service,DC=corp,DC=local",
        "bind_password": FAKE_PASSWORD,
        "verify_cert": "1",
        "template_key": "enabled_users",
        "page_size": "1000",
        "receive_timeout": "30",
        "is_active": "1",
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


class TestEncryptionRequired:
    """NFR-04：明文 LDAP bind 一律拒絕，不提供繞過選項。"""

    def test_plaintext_rejected(self):
        form = valid_form(use_ssl=None, use_start_tls=None)

        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(form)

        assert "use_ssl" in exc.value.errors

    def test_plaintext_error_explains_why(self):
        """錯誤訊息要說明「為什麼不行」，而不只是「不行」。"""
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(use_ssl=None, use_start_tls=None))

        assert "明文" in exc.value.errors["use_ssl"]

    def test_ldaps_accepted(self):
        result = parse_ldap_form(valid_form(use_ssl="1"))

        assert result.use_ssl is True

    def test_start_tls_accepted(self):
        result = parse_ldap_form(valid_form(use_ssl=None, use_start_tls="1", port="389"))

        assert result.use_start_tls is True

    def test_both_encryption_modes_rejected(self):
        """LDAPS 與 StartTLS 只能擇一，同時勾選是設定錯誤。"""
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(use_ssl="1", use_start_tls="1"))

        assert "use_start_tls" in exc.value.errors


class TestPasswordHandling:
    """NFR-05：密碼不回填、不明文、編輯留空表示沿用。"""

    def test_password_required_on_create(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(bind_password=None), is_edit=False)

        assert "bind_password" in exc.value.errors

    def test_password_optional_on_edit(self):
        result = parse_ldap_form(valid_form(bind_password=None), is_edit=True)

        # None 代表「沿用原本的」，不是「清空成空字串」
        assert result.bind_password is None

    def test_password_updated_when_provided_on_edit(self):
        result = parse_ldap_form(valid_form(bind_password=FAKE_PASSWORD_ALT), is_edit=True)

        assert result.bind_password == FAKE_PASSWORD_ALT

    def test_password_never_in_config_json(self):
        result = parse_ldap_form(valid_form(bind_password=FAKE_PASSWORD_ALT))
        config = result.to_config_json()

        assert FAKE_PASSWORD_ALT not in str(config)
        assert "bind_password" not in config

    def test_config_to_form_values_omits_password(self):
        """回填編輯表單時絕不帶出密碼。"""
        values = config_to_form_values({"host": "dc01", "bind_dn": "CN=svc"})

        assert "bind_password" not in values


class TestNumericBoundaries:
    """邊界值：page_size 的上限對應 AD 的 MaxPageSize。"""

    @pytest.mark.parametrize("size", ["0", "1001", "-1", "99999"])
    def test_page_size_out_of_range_rejected(self, size):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(page_size=size))

        assert "page_size" in exc.value.errors

    @pytest.mark.parametrize("size", ["1", "500", "1000"])
    def test_page_size_in_range_accepted(self, size):
        result = parse_ldap_form(valid_form(page_size=size))

        assert result.page_size == int(size)

    def test_page_size_non_numeric_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(page_size="abc"))

        assert "page_size" in exc.value.errors

    @pytest.mark.parametrize("port", ["0", "65536", "-1"])
    def test_port_out_of_range_rejected(self, port):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(port=port))

        assert "port" in exc.value.errors

    @pytest.mark.parametrize("timeout", ["0", "601"])
    def test_timeout_out_of_range_rejected(self, timeout):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(receive_timeout=timeout))

        assert "receive_timeout" in exc.value.errors


class TestRequiredFields:
    @pytest.mark.parametrize("field", ["name", "host", "base_dn", "bind_dn"])
    def test_missing_required_field_rejected(self, field):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(**{field: ""}))

        assert field in exc.value.errors

    def test_all_errors_reported_together(self):
        """一次回報所有錯誤，管理者不必反覆送出才知道下一個問題。"""
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form({"name": "", "host": "", "base_dn": "", "bind_dn": ""})

        assert len(exc.value.errors) >= 4

    def test_whitespace_only_name_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(name="    "))

        assert "name" in exc.value.errors

    def test_overlong_name_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(name="ㄅ" * 300))

        assert "name" in exc.value.errors


class TestTemplateParameters:
    def test_template_requiring_parameter_rejects_blank(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(template_key="by_department"))

        assert "param_department" in exc.value.errors

    def test_template_parameter_captured(self):
        result = parse_ldap_form(
            valid_form(template_key="by_department", param_department="資訊部")
        )

        assert result.template_parameters == {"department": "資訊部"}

    def test_group_dn_bypasses_template(self):
        """填了群組 DN 就走群組成員路徑，範本不適用也不該要求其參數。"""
        result = parse_ldap_form(
            valid_form(
                template_key="by_department",
                group_dn="CN=IT,OU=Groups,DC=corp,DC=local",
            )
        )

        assert result.group_dn == "CN=IT,OU=Groups,DC=corp,DC=local"
        assert result.template_key == ""

    def test_invalid_nesting_strategy_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(nesting_strategy="drop_tables"))

        assert "nesting_strategy" in exc.value.errors

    def test_invalid_search_scope_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(search_scope="everything"))

        assert "search_scope" in exc.value.errors


class TestAttributeSelection:
    def test_valid_attributes_accepted(self):
        result = parse_ldap_form(valid_form(extra_attributes="department,title"))

        assert set(result.extra_attributes) == {"department", "title"}

    def test_unknown_attribute_rejected(self):
        with pytest.raises(FormValidationError) as exc:
            parse_ldap_form(valid_form(extra_attributes="ntSecurityDescriptor"))

        assert "extra_attributes" in exc.value.errors

    def test_empty_attributes_allowed(self):
        result = parse_ldap_form(valid_form(extra_attributes=""))

        assert result.extra_attributes == []


class TestRoundTrip:
    """表單 → config_json → 表單值，設定不應在轉換中遺失。"""

    def test_config_round_trip_preserves_settings(self):
        form = parse_ldap_form(
            valid_form(
                template_key="by_department",
                param_department="資訊部",
                extra_attributes="department,title",
                search_scope="level",
                nesting_strategy="in_chain",
                page_size="500",
            )
        )

        restored = config_to_form_values(form.to_config_json())

        assert restored["template_key"] == "by_department"
        assert restored["param_department"] == "資訊部"
        assert restored["search_scope"] == "level"
        assert restored["nesting_strategy"] == "in_chain"
        assert restored["page_size"] == 500
        assert set(restored["extra_attributes"]) == {"department", "title"}

    def test_config_defaults_when_empty(self):
        """空設定要能給出安全預設，而不是崩潰。"""
        values = config_to_form_values({})

        assert values["use_ssl"] is True
        assert values["verify_cert"] is True
        assert values["page_size"] == 1000
