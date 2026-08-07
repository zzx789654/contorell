"""LDAP 注入防護測試 — 對應 NFR-07、AC-15、CWE-90。

這是安全關鍵模組，Exit Criteria 要求覆蓋率 ≥ 90%。
"""

import pytest

from app.security.ldap_escape import build_filter, escape_dn_value, escape_filter_value


class TestEscapeFilterValue:
    """RFC 4515 filter 值轉義。"""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("j.doe", "j.doe"),
            ("", ""),
            ("王小明", "王小明"),  # 非 ASCII 不需轉義
            ("user name", "user name"),  # 空白不需轉義
        ],
    )
    def test_safe_values_unchanged(self, raw, expected):
        assert escape_filter_value(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("*", "\\2a"),
            ("(", "\\28"),
            (")", "\\29"),
            ("\\", "\\5c"),
            ("\0", "\\00"),
        ],
    )
    def test_each_special_char_escaped(self, raw, expected):
        assert escape_filter_value(raw) == expected

    def test_injection_payload_neutralized(self):
        """典型的 LDAP 注入字串必須被完全中和。

        未轉義時 ``*)(uid=*`` 會讓 ``(cn={value})`` 變成
        ``(cn=*)(uid=*)``，把「查一個人」變成「查全部」。
        """
        payload = "*)(uid=*"
        escaped = escape_filter_value(payload)

        # 所有能改變 filter 結構的字元都已被轉義
        assert "*" not in escaped.replace("\\2a", "")
        assert "(" not in escaped.replace("\\28", "")
        assert ")" not in escaped.replace("\\29", "")
        assert escaped == "\\2a\\29\\28uid=\\2a"

    def test_backslash_not_double_escaped(self):
        """反斜線只轉義一次，不可把轉義結果再次轉義。"""
        assert escape_filter_value("a\\b") == "a\\5cb"
        # 若實作錯誤（先 replace 反斜線再 replace 星號），
        # "\\*" 會變成 "\\5c\\5c2a" 這種錯誤結果
        assert escape_filter_value("\\*") == "\\5c\\2a"

    def test_rejects_non_string(self):
        """拒絕非字串，避免 None 被靜默轉成字串 'None'。"""
        with pytest.raises(TypeError):
            escape_filter_value(None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            escape_filter_value(123)  # type: ignore[arg-type]


class TestEscapeDnValue:
    """RFC 4514 DN 元件轉義。"""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Smith, John", "Smith\\, John"),
            ("a+b", "a\\+b"),
            ('say "hi"', 'say \\"hi\\"'),
            ("a<b>c", "a\\<b\\>c"),
            ("x;y", "x\\;y"),
            ("k=v", "k\\=v"),
            ("back\\slash", "back\\\\slash"),
        ],
    )
    def test_special_chars_escaped(self, raw, expected):
        assert escape_dn_value(raw) == expected

    def test_leading_hash_escaped(self):
        assert escape_dn_value("#tag").startswith("\\#")

    def test_leading_and_trailing_space_escaped(self):
        assert escape_dn_value(" lead").startswith("\\ ")
        assert escape_dn_value("trail ").endswith("\\ ")

    def test_rejects_non_string(self):
        with pytest.raises(TypeError):
            escape_dn_value(None)  # type: ignore[arg-type]


class TestBuildFilter:
    """組 filter 的唯一建議方式。"""

    def test_normal_value(self):
        assert build_filter("(sAMAccountName={a})", a="j.doe") == "(sAMAccountName=j.doe)"

    def test_injection_neutralized_in_template(self):
        result = build_filter("(cn={name})", name="*)(uid=*")
        assert result == "(cn=\\2a\\29\\28uid=\\2a)"

        # 剝掉 filter 自身的外層括號、再移除所有轉義序列後，
        # 內部不該殘留任何未轉義的 metachar —— 代表結構無法被注入改變。
        inner = result[1:-1]
        for escape_seq in ("\\2a", "\\28", "\\29", "\\5c", "\\00"):
            inner = inner.replace(escape_seq, "")
        assert not any(char in inner for char in "()*\\"), f"殘留未轉義的 metachar：{inner!r}"

    def test_multiple_placeholders(self):
        result = build_filter("(&(cn={name})(dept={dept}))", name="test*", dept="IT(x)")
        assert "\\2a" in result
        assert "\\28" in result

    def test_group_dn_with_special_chars(self):
        """實務案例：群組 DN 含逗號與括號。"""
        result = build_filter(
            "(memberOf={group})", group="CN=Finance (Global),OU=Groups,DC=example,DC=local"
        )
        assert "\\28" in result  # 左括號已轉義
        assert "\\29" in result  # 右括號已轉義
