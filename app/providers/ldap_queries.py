"""LDAP 查詢範本與屬性白名單 — 讓管理者在網頁上安全地設定「要撈什麼」。

## 為什麼是範本而不是自由輸入

管理者需要多樣化的查詢方式（只撈某部門、只撈停用帳號、撈某群組含巢狀…），
但**開放原始 LDAP filter 輸入等於開一個 CWE-90 的門**——
`app/security/ldap_escape.py` 的安全紀律明訂「樣板必須是程式內的常數字面值」，
自由輸入的 filter 從定義上就違反這條。

因此本模組的設計是：

    範本（程式內常數）+ 受控參數（使用者輸入，一律轉義） = 安全的 filter

管理者選一個範本、填幾個值，值經 :func:`~app.security.ldap_escape.escape_filter_value`
轉義後代入常數樣板。使用者**永遠無法影響 filter 的結構**，只能影響值。

這同時讓介面更順手（CoreMain 的設計原則）：管理者不需要學 LDAP filter 語法，
也不必知道 `1.2.840.113556.1.4.803` 是什麼意思。

## AD 專用比對規則

範本中用到兩個 AD 專屬的 OID，兩者都是稽核情境的關鍵：

- ``1.2.840.113556.1.4.803`` — 位元 AND（LDAP_MATCHING_RULE_BIT_AND）。
  用來判讀 ``userAccountControl`` 裡的旗標，例如判斷帳號是否已停用。
- ``1.2.840.113556.1.4.1941`` — 鏈式成員（LDAP_MATCHING_RULE_IN_CHAIN）。
  由 DC 端把巢狀群組攤平，做特權群組稽核時不會漏掉繼承來的人。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from app.providers.base import ConfigurationError
from app.security.ldap_escape import build_filter

# --------------------------------------------------------------------------
# AD 比對規則 OID
# --------------------------------------------------------------------------

MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
"""位元 AND 比對 — 用於判讀 userAccountControl 旗標。"""

MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
"""鏈式成員比對 — 由 DC 端遞迴展開巢狀群組。"""

# userAccountControl 旗標（見 docs/SRS.md 第 5.1 節）
UAC_ACCOUNTDISABLE = 2
UAC_DONT_EXPIRE_PASSWORD = 65536

# 只比對真人使用者物件，排除電腦帳號與服務主體。
# 這段是所有範本的共同前綴，寫成常數避免各範本各寫一次而不一致。
_PERSON = "(objectCategory=person)(objectClass=user)"


class SearchScope(str, Enum):
    """LDAP 搜尋範圍 — 對應 ldapsearch 的 ``-s`` 參數。"""

    SUBTREE = "subtree"
    """含所有子階層（ldapsearch ``-s sub``）。預設，也是最常用的。"""

    LEVEL = "level"
    """只找 Base DN 的直接子項（ldapsearch ``-s one``）。"""

    BASE = "base"
    """只找 Base DN 這個物件本身（ldapsearch ``-s base``）。"""


@dataclass(frozen=True, slots=True)
class QueryParameter:
    """範本需要使用者填的一個值。

    這裡描述的是**值**，不是 filter 結構——結構永遠由範本決定。
    """

    key: str
    label: str
    placeholder: str
    help_text: str
    example: str = ""


@dataclass(frozen=True, slots=True)
class QueryTemplate:
    """一個預先寫好的查詢範本。

    ``filter_template`` 是程式內的常數字面值，含 ``{key}`` 佔位符；
    佔位符的值由 :func:`build_query_filter` 轉義後代入。
    """

    key: str
    label: str
    description: str
    filter_template: str
    parameters: tuple[QueryParameter, ...] = ()
    ldapsearch_hint: str = ""
    """對應的 ldapsearch 指令片段，供熟悉指令列的管理者對照。"""

    notes: tuple[str, ...] = field(default_factory=tuple)
    """使用這個範本時要注意的事（顯示在可展開說明裡）。"""

    @property
    def needs_parameters(self) -> bool:
        return bool(self.parameters)


# --------------------------------------------------------------------------
# 範本清單
# --------------------------------------------------------------------------
#
# 新增範本時務必遵守：filter_template 只能是常數字面值，
# 佔位符只放「值」的位置，絕不讓佔位符出現在屬性名或運算子的位置。

_GROUP_DN_PARAM = QueryParameter(
    key="group_dn",
    label="群組 DN",
    placeholder="CN=IT_Admins,OU=Groups,DC=corp,DC=local",
    help_text="要抓取成員的 AD 群組完整識別名稱（DN）。在 ADUC 中右鍵群組 → 內容 → 屬性編輯器 → distinguishedName 可複製。",
    example="CN=IT_Admins,OU=Groups,DC=corp,DC=local",
)

QUERY_TEMPLATES: tuple[QueryTemplate, ...] = (
    QueryTemplate(
        key="enabled_users",
        label="啟用中的真人帳號",
        description="排除已停用的帳號，只抓仍可登入的使用者。最常用於「現職員工名單」。",
        filter_template=f"(&{_PERSON}(!(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_ACCOUNTDISABLE})))",
        ldapsearch_hint=(
            '"(&(objectCategory=person)(objectClass=user)'
            f'(!(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_ACCOUNTDISABLE})))"'
        ),
        notes=(
            "userAccountControl 的第 2 個位元（值 2）代表帳號已停用，這裡用「非」把它排除。",
            "電腦帳號與服務主體不會被抓到，因為條件限定 objectCategory=person。",
        ),
    ),
    QueryTemplate(
        key="disabled_users",
        label="已停用的帳號",
        description="只抓已停用的帳號。用於稽核「AD 已停用，但外部系統仍可登入」的離職未回收情境。",
        filter_template=f"(&{_PERSON}(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_ACCOUNTDISABLE}))",
        ldapsearch_hint=(
            '"(&(objectCategory=person)(objectClass=user)'
            f'(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_ACCOUNTDISABLE}))"'
        ),
        notes=(
            "把這個來源與外部系統的帳號清單比對，交集就是「該收沒收」的權限。",
            "已從 AD 刪除的帳號不會出現在這裡——刪除的帳號要靠與舊快照比對才找得到。",
        ),
    ),
    QueryTemplate(
        key="all_users",
        label="全部真人帳號（含停用）",
        description="不分啟用狀態，抓取範圍內所有使用者。帳號的啟用狀態仍會記錄在每筆資料上。",
        filter_template=f"(&{_PERSON})",
        ldapsearch_hint='"(&(objectCategory=person)(objectClass=user))"',
        notes=(
            "抓回來的每筆帳號都會標記啟用／停用狀態，比對時仍可辨別。",
            "在大型網域下這個範本的資料量最大，請確認分頁大小設定正確。",
        ),
    ),
    QueryTemplate(
        key="group_members_nested",
        label="指定群組的成員（含巢狀子群組）",
        description="抓取群組成員，並把子群組裡的人一起攤平展開。做特權群組稽核時應該用這個，才不會漏掉繼承來的人。",
        filter_template=f"(&{_PERSON}(memberOf:{MATCHING_RULE_IN_CHAIN}:={{group_dn}}))",
        parameters=(_GROUP_DN_PARAM,),
        ldapsearch_hint=(
            f'"(memberOf:{MATCHING_RULE_IN_CHAIN}:=CN=IT_Admins,OU=Groups,DC=corp,DC=local)"'
        ),
        notes=(
            "由網域控制站負責遞迴展開，應用端只發一次查詢。",
            "大型群組（數千人）在 DC 上展開會比較慢；若逾時，改用連線設定裡的「應用端逐層展開」策略。",
            "這是稽核特權群組的正確做法——只看直接成員會漏掉透過子群組繼承權限的人。",
        ),
    ),
    QueryTemplate(
        key="group_members_direct",
        label="指定群組的成員（僅直接成員）",
        description="只抓掛在群組底下的直接成員，不展開子群組。適合確認群組本身的成員名單。",
        filter_template=f"(&{_PERSON}(memberOf={{group_dn}}))",
        parameters=(_GROUP_DN_PARAM,),
        ldapsearch_hint='"(memberOf=CN=IT_Admins,OU=Groups,DC=corp,DC=local)"',
        notes=(
            "若群組底下有子群組，這個範本抓到的人數會少於實際有權限的人數。",
            "要做權限稽核請改用「含巢狀子群組」的範本。",
        ),
    ),
    QueryTemplate(
        key="by_department",
        label="指定部門的成員",
        description="依 AD 的 department 屬性抓取。用於「某部門應該有哪些系統權限」的比對。",
        filter_template=f"(&{_PERSON}(department={{department}}))",
        parameters=(
            QueryParameter(
                key="department",
                label="部門名稱",
                placeholder="資訊部",
                help_text="必須與 AD 中 department 屬性的值完全相同（含全形半形與空白）。此欄位不支援萬用字元。",
                example="資訊部",
            ),
        ),
        ldapsearch_hint='"(&(objectCategory=person)(objectClass=user)(department=IT))"',
        notes=(
            "AD 的 department 是自由文字欄位，各單位填法可能不一致（如「資訊部」vs「資訊處」），建議先用連線測試確認命中筆數。",
            "輸入值中的特殊字元會被自動轉義，因此無法用 * 做模糊比對——這是防注入的必要限制。",
        ),
    ),
    QueryTemplate(
        key="by_title",
        label="指定職稱的成員",
        description="依 AD 的 title 屬性抓取。用於「主管層級應有的權限」這類以職務為基準的稽核。",
        filter_template=f"(&{_PERSON}(title={{title}}))",
        parameters=(
            QueryParameter(
                key="title",
                label="職稱",
                placeholder="經理",
                help_text="必須與 AD 中 title 屬性的值完全相同。此欄位不支援萬用字元。",
                example="經理",
            ),
        ),
        ldapsearch_hint='"(&(objectCategory=person)(objectClass=user)(title=Manager))"',
        notes=("與部門相同，title 是自由文字欄位，建議先測試確認命中筆數。",),
    ),
    QueryTemplate(
        key="password_never_expires",
        label="密碼永不過期的帳號",
        description="抓取設定了「密碼永不過期」的帳號。這類帳號是常見的資安稽核項目。",
        filter_template=(
            f"(&{_PERSON}(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_DONT_EXPIRE_PASSWORD}))"
        ),
        ldapsearch_hint=(
            '"(&(objectCategory=person)(objectClass=user)'
            f'(userAccountControl:{MATCHING_RULE_BIT_AND}:={UAC_DONT_EXPIRE_PASSWORD}))"'
        ),
        notes=(
            "密碼永不過期的帳號若外洩，風險會一直存在，通常需要列管。",
            "服務帳號常有此設定，比對時可搭配自訂欄位標註「已核准的服務帳號」。",
        ),
    ),
)

TEMPLATES_BY_KEY: dict[str, QueryTemplate] = {tpl.key: tpl for tpl in QUERY_TEMPLATES}

DEFAULT_TEMPLATE_KEY = "enabled_users"


# --------------------------------------------------------------------------
# 屬性白名單
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AttributeOption:
    """一個可勾選抓取的 AD 屬性。"""

    name: str
    label: str
    help_text: str


# 一律抓取的基本屬性——比對引擎與 UI 依賴這些欄位，不可由使用者關閉。
CORE_ATTRIBUTES: tuple[str, ...] = (
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "mail",
    "distinguishedName",
    "objectSid",
    "userAccountControl",
    "whenCreated",
    "whenChanged",
)

# 可選的額外屬性。**白名單制**：不在這份清單裡的屬性名一律拒絕。
#
# 為什麼要白名單：屬性名會被送進 LDAP 查詢的 attributes 參數，
# 若接受任意輸入，(1) 可能撈出不該給稽核者看的敏感屬性
# （如 ntSecurityDescriptor、msDS-ManagedPassword），
# (2) 也讓輸入面變成攻擊面。允許清單能同時解決這兩件事。
OPTIONAL_ATTRIBUTES: tuple[AttributeOption, ...] = (
    AttributeOption("department", "部門", "使用者所屬部門，常用於依組織單位分析權限分佈。"),
    AttributeOption("title", "職稱", "職務名稱，可用於判斷權限是否與職級相稱。"),
    AttributeOption("company", "公司", "多法人環境下用來區分不同公司的員工。"),
    AttributeOption(
        "physicalDeliveryOfficeName", "辦公室", "辦公室位置，用於實體存取權限的交叉比對。"
    ),
    AttributeOption("telephoneNumber", "電話", "聯絡電話，方便稽核時直接聯繫帳號負責人。"),
    AttributeOption("mobile", "行動電話", "行動電話號碼。"),
    AttributeOption("manager", "主管 DN", "直屬主管的 DN，可用來找出該由誰簽核權限。"),
    AttributeOption("employeeID", "員工編號", "與 HR 系統對接時，員工編號通常比帳號名更穩定可靠。"),
    AttributeOption("employeeNumber", "員工號碼", "另一個常見的員工識別欄位，視組織慣例使用。"),
    AttributeOption("description", "描述", "AD 帳號的描述欄位，服務帳號的用途常記在這裡。"),
    AttributeOption(
        "lastLogonTimestamp",
        "最後登入時間",
        "約略的最後登入時間（AD 有數天誤差），用於找出長期未使用的殭屍帳號。",
    ),
    AttributeOption("pwdLastSet", "密碼最後設定時間", "用於稽核長期未更換密碼的帳號。"),
    AttributeOption("accountExpires", "帳號到期時間", "約聘或外包人員的帳號到期日。"),
    AttributeOption("memberOf", "所屬群組", "直接隸屬的群組清單（不含巢狀繼承）。資料量可能很大。"),
)

ATTRIBUTES_BY_NAME: dict[str, AttributeOption] = {opt.name: opt for opt in OPTIONAL_ATTRIBUTES}


def validate_attributes(names: list[str]) -> list[str]:
    """驗證使用者勾選的屬性名，回傳正規化後的清單。

    白名單制：任何不在 :data:`OPTIONAL_ATTRIBUTES` 中的名稱都會被拒絕，
    而不是靜默忽略——靜默忽略會讓管理者以為抓到了某個欄位，
    實際上比對時該欄位永遠是空的（又一個「錯得很安靜」的失敗模式）。

    Args:
        names: 使用者勾選的屬性名。

    Returns:
        去重且保持白名單順序的屬性名清單。

    Raises:
        ConfigurationError: 含有白名單外的屬性名。
    """
    unknown = [name for name in names if name not in ATTRIBUTES_BY_NAME]
    if unknown:
        raise ConfigurationError(
            f"不支援的 AD 屬性：{'、'.join(unknown)}",
            remediation="請只從介面提供的屬性清單中勾選。若需要其他屬性，請洽系統維護者評估後加入白名單。",
        )

    # 依白名單順序輸出，讓 config_json 的內容穩定、可預期地比較
    selected = set(names)
    return [opt.name for opt in OPTIONAL_ATTRIBUTES if opt.name in selected]


def build_attribute_list(extra: list[str]) -> list[str]:
    """組出實際要向 AD 索取的屬性清單（核心屬性 + 已驗證的額外屬性）。"""
    validated = validate_attributes(extra)
    core = set(CORE_ATTRIBUTES)
    return [*CORE_ATTRIBUTES, *(name for name in validated if name not in core)]


# --------------------------------------------------------------------------
# Filter 組建
# --------------------------------------------------------------------------


def get_template(key: str) -> QueryTemplate:
    """取得指定範本，找不到時給出可行動的錯誤。"""
    template = TEMPLATES_BY_KEY.get(key)
    if template is None:
        raise ConfigurationError(
            f"未知的查詢範本：{key}",
            remediation=f"可用的範本為：{'、'.join(TEMPLATES_BY_KEY)}。",
        )
    return template


def build_query_filter(template_key: str, parameters: dict[str, str]) -> str:
    """依範本與使用者填的值組出 LDAP filter。

    **這是本模組唯一對外產生 filter 的入口。**
    值一律經 :func:`~app.security.ldap_escape.build_filter` 轉義後代入常數樣板，
    使用者無法影響 filter 的結構。

    >>> build_query_filter("by_department", {"department": "資訊部"})
    '(&(objectCategory=person)(objectClass=user)(department=資訊部))'

    注入嘗試會被轉義成字面值，而不是改變查詢結構：

    >>> build_query_filter("by_department", {"department": "*)(uid=*"})
    '(&(objectCategory=person)(objectClass=user)(department=\\\\2a\\\\29\\\\28uid=\\\\2a))'

    Args:
        template_key: 範本代號。
        parameters: 範本所需的值（未受信任）。

    Returns:
        可安全送給 AD 的 filter 字串。

    Raises:
        ConfigurationError: 範本不存在，或必填參數缺漏。
    """
    template = get_template(template_key)

    values: dict[str, str] = {}
    for param in template.parameters:
        raw = (parameters.get(param.key) or "").strip()
        if not raw:
            raise ConfigurationError(
                f"查詢範本「{template.label}」需要填寫「{param.label}」。",
                remediation=param.help_text,
            )
        values[param.key] = raw

    return build_filter(template.filter_template, **values)


def build_user_groups_filter(user_dn: str) -> str:
    """組出「這個使用者屬於哪些群組」的反查 filter（含巢狀繼承）。

    用 ``member:1.2.840.113556.1.4.1941:=<使用者DN>`` 從群組端反查，
    一次拿到直接隸屬與透過子群組繼承的所有群組。

    Args:
        user_dn: 使用者的完整 DN（未受信任，會被轉義）。

    Returns:
        可安全送給 AD 的 filter 字串。

    Raises:
        ConfigurationError: user_dn 為空。
    """
    cleaned = (user_dn or "").strip()
    if not cleaned:
        raise ConfigurationError(
            "請提供使用者的 DN。",
            remediation="DN 格式如 CN=John Smith,OU=Employees,DC=corp,DC=local。",
        )

    return build_filter(
        f"(&(objectClass=group)(member:{MATCHING_RULE_IN_CHAIN}:={{user_dn}}))",
        user_dn=cleaned,
    )


def build_user_lookup_filter(account_name: str) -> str:
    """組出「用帳號名找使用者」的 filter，供反查功能先取得 DN。

    Args:
        account_name: sAMAccountName（未受信任，會被轉義）。

    Returns:
        可安全送給 AD 的 filter 字串。

    Raises:
        ConfigurationError: account_name 為空。
    """
    cleaned = (account_name or "").strip()
    if not cleaned:
        raise ConfigurationError(
            "請提供要查詢的帳號名稱。",
            remediation="請輸入 AD 的登入帳號（sAMAccountName），例如 jsmith。",
        )

    return build_filter(
        f"(&{_PERSON}(sAMAccountName={{account}}))",
        account=cleaned,
    )
