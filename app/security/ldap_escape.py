"""LDAP 特殊字元轉義 — 防 LDAP Injection (CWE-90)。

對應需求：NFR-07、實作要求見 docs/SRS.md 第 5.1 節。

**安全紀律**：任何來自使用者的字串在組進 LDAP filter 或 DN 之前，
一律先經過本模組轉義。不得有例外、不得用字串拼接繞過。

參考標準：
- RFC 4515 §3 — LDAP search filter 的字串表示法（filter 值轉義）
- RFC 4514 §2.4 — LDAP DN 的字串表示法（DN 元件轉義）

這兩種轉義規則**不同**，不可互用，因此分成兩個函式。
"""

from __future__ import annotations

# RFC 4515 §3：filter 值中必須轉義的字元。
# NUL 也必須轉義，否則可能造成 C 層字串截斷。
_FILTER_ESCAPE_MAP = {
    "\\": "\\5c",  # 反斜線必須最先處理，否則會重複轉義後續插入的反斜線
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\0": "\\00",
}

# RFC 4514 §2.4：DN 元件值中必須轉義的字元。
_DN_ESCAPE_CHARS = '\\,+"<>;='


def escape_filter_value(value: str) -> str:
    """轉義要放進 LDAP search filter 的值（RFC 4515）。

    這是防 LDAP Injection 的主要防線。例如未轉義時，
    使用者輸入 ``*)(uid=*`` 會改變 filter 的語意結構，
    把「查某一個帳號」變成「查全部」。

    >>> escape_filter_value("*)(uid=*")
    '\\\\2a\\\\29\\\\28uid=\\\\2a'
    >>> escape_filter_value("normal.user")
    'normal.user'

    Args:
        value: 未受信任的輸入字串。

    Returns:
        可安全嵌入 filter 的字串。

    Raises:
        TypeError: value 不是字串時（避免 None 被靜默轉成 "None"）。
    """
    if not isinstance(value, str):
        raise TypeError(f"escape_filter_value 需要 str，收到 {type(value).__name__}")

    # 逐字元處理：確保 map 中的反斜線只被處理一次，
    # 不會把轉義後產生的反斜線再次轉義。
    return "".join(_FILTER_ESCAPE_MAP.get(ch, ch) for ch in value)


def escape_dn_value(value: str) -> str:
    """轉義要放進 DN 元件的值（RFC 4514）。

    DN 的轉義規則與 filter 不同：使用反斜線前綴而非十六進位碼，
    且開頭/結尾的空白與開頭的 ``#`` 需另外處理。

    >>> escape_dn_value("Smith, John")
    'Smith\\\\, John'

    Args:
        value: 未受信任的輸入字串。

    Returns:
        可安全嵌入 DN 的字串。
    """
    if not isinstance(value, str):
        raise TypeError(f"escape_dn_value 需要 str，收到 {type(value).__name__}")

    escaped = "".join(f"\\{ch}" if ch in _DN_ESCAPE_CHARS else ch for ch in value)

    # RFC 4514：開頭的 '#' 與開頭/結尾的空白需轉義
    if escaped.startswith("#"):
        escaped = "\\" + escaped
    if escaped.startswith(" "):
        escaped = "\\" + escaped
    if escaped.endswith(" ") and not escaped.endswith("\\ "):
        escaped = escaped[:-1] + "\\ "

    return escaped


def build_filter(template: str, **values: str) -> str:
    """以轉義後的值組出 LDAP filter，避免手動拼接時漏轉義。

    這是**建議的唯一組 filter 方式**——直接用 f-string 或 % 拼接
    LDAP filter 屬於違反安全紀律，程式碼審查時應退回。

    >>> build_filter("(sAMAccountName={account})", account="j.doe")
    '(sAMAccountName=j.doe)'
    >>> build_filter("(cn={name})", name="*)(uid=*")
    '(cn=\\\\2a\\\\29\\\\28uid=\\\\2a)'

    Args:
        template: 含 ``{名稱}`` 佔位符的 filter 樣板。樣板本身必須是
            程式內的常數字面值，**不可**來自使用者輸入。
        **values: 佔位符對應的未受信任值，會逐一被轉義。

    Returns:
        組好且已轉義的 filter 字串。
    """
    escaped = {key: escape_filter_value(val) for key, val in values.items()}
    return template.format(**escaped)
