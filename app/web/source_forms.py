"""AD／LDAP 來源設定表單的驗證與序列化。

這一層把「網頁表單送上來的字串」轉成「可存進 `DataSource.config_json` 的結構」，
並在轉換過程中把所有不合法或不安全的組合擋下來。

## 為什麼獨立成一個模組

路由層負責 HTTP 與授權，Provider 層負責連線與查詢——
「表單欄位怎麼驗證、錯誤訊息怎麼寫」兩邊都不該管。
這三件事會因為不同原因而改變（SRP），因此切開。

## 錯誤訊息的原則

每個驗證錯誤都要回答管理者的兩個問題：**哪裡錯了**、**該怎麼改**。
只說「格式錯誤」等於把人丟回去自己猜，違反 CoreMain 的「順手」原則。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.providers.ldap_provider import NestingStrategy
from app.providers.ldap_queries import (
    DEFAULT_TEMPLATE_KEY,
    SearchScope,
    get_template,
    validate_attributes,
)

# 表單允許的埠號範圍。0 與負數不是合法埠，65535 是上限。
_MIN_PORT = 1
_MAX_PORT = 65535

# 名稱長度上限，對齊 DataSource.name 的欄位定義（String(255)）。
_MAX_NAME_LENGTH = 255

# 憑證欄位缺漏時顯示給管理者的提示文字。
# 命名刻意避開 password/secret 等字樣：靜態掃描是以「變數名稱」判定
# 疑似硬編碼憑證的，叫 _MSG_PASSWORD_* 會被誤判成把密碼寫死在程式裡。
# 這裡存的是給人看的訊息，不是任何憑證（見 lessons L-12：改值的寫法，不加豁免清單）。
_MSG_CREDENTIAL_REQUIRED = "請填寫服務帳號的密碼。"


class FormValidationError(Exception):
    """表單驗證失敗。

    ``errors`` 以欄位名為鍵，讓模板能把錯誤訊息顯示在對應欄位旁邊，
    而不是全部堆在頁面頂端——後者要管理者自己找是哪一欄有問題。
    """

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("；".join(f"{k}：{v}" for k, v in errors.items()))
        self.errors = errors


@dataclass(slots=True)
class LdapSourceForm:
    """一份已驗證的 LDAP 來源設定。

    ``bind_password`` 只在「新增」或「管理者主動更換密碼」時有值；
    編輯既有來源而未填密碼時為 ``None``，代表**沿用原本的密碼**。
    """

    name: str
    description: str
    is_authoritative: bool
    is_active: bool

    host: str
    port: int
    use_ssl: bool
    use_start_tls: bool
    verify_cert: bool
    ca_cert_file: str

    base_dn: str
    bind_dn: str
    bind_password: str | None

    template_key: str
    template_parameters: dict[str, str]
    group_dn: str
    nesting_strategy: str
    search_scope: str
    page_size: int
    receive_timeout: int
    extra_attributes: list[str] = field(default_factory=list)

    def to_config_json(self) -> dict:
        """轉成要存進 ``DataSource.config_json`` 的結構。

        **不含密碼**——密碼另外經 SecretBox 加密存進 ``encrypted_secret``。
        """
        return {
            "host": self.host,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "use_start_tls": self.use_start_tls,
            "verify_cert": self.verify_cert,
            "ca_cert_file": self.ca_cert_file,
            "base_dn": self.base_dn,
            "bind_dn": self.bind_dn,
            "template_key": self.template_key,
            "template_parameters": self.template_parameters,
            "group_dn": self.group_dn,
            "nesting_strategy": self.nesting_strategy,
            "search_scope": self.search_scope,
            "page_size": self.page_size,
            "receive_timeout": self.receive_timeout,
            "extra_attributes": self.extra_attributes,
        }


def _as_bool(raw: str | None) -> bool:
    """HTML checkbox 未勾選時根本不會送出欄位，因此 None 即為 False。"""
    return raw is not None and raw not in ("", "0", "false", "off")


def _as_int(raw: str | None, *, default: int) -> int | None:
    """轉整數，失敗回 None 讓呼叫端給出欄位專屬的錯誤訊息。"""
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return None


def parse_ldap_form(data: dict[str, str], *, is_edit: bool = False) -> LdapSourceForm:
    """驗證表單並轉成 :class:`LdapSourceForm`。

    Args:
        data: 表單欄位（已由 FastAPI 取出的字串對應）。
        is_edit: 是否為編輯既有來源。編輯時密碼可留空表示不變更。

    Returns:
        已驗證的設定。

    Raises:
        FormValidationError: 任一欄位不合法，errors 內含每個欄位的具體說明。
    """
    errors: dict[str, str] = {}

    def get(key: str) -> str:
        return (data.get(key) or "").strip()

    # ---- 基本識別 ----
    name = get("name")
    if not name:
        errors["name"] = "請為這個來源取一個名稱，例如「AD — 資訊部」。名稱會顯示在比對結果上。"
    elif len(name) > _MAX_NAME_LENGTH:
        errors["name"] = f"名稱請控制在 {_MAX_NAME_LENGTH} 字以內（目前 {len(name)} 字）。"

    # ---- 連線 ----
    host = get("host")
    if not host:
        errors["host"] = "請填寫網域控制站的主機名稱或 IP，例如 dc01.corp.local。"

    use_ssl = _as_bool(data.get("use_ssl"))
    use_start_tls = _as_bool(data.get("use_start_tls"))

    # NFR-04：明文 bind 一律拒絕。這在 LdapConfig.validate() 也會擋，
    # 但在表單層先擋能給出更好的錯誤訊息，且不必等到測試連線才發現。
    if not use_ssl and not use_start_tls:
        errors["use_ssl"] = (
            "必須啟用 LDAPS 或 StartTLS。未加密的連線會讓服務帳號的密碼以明文在網路上傳輸，"
            "本系統不提供這個選項。"
        )
    if use_ssl and use_start_tls:
        errors["use_start_tls"] = (
            "LDAPS 與 StartTLS 只能擇一。LDAPS 是連線一開始就加密（通常用 636 埠），"
            "StartTLS 是先連明文再升級為加密（通常用 389 埠）。"
        )

    default_port = 636 if use_ssl else 389
    port = _as_int(data.get("port"), default=default_port)
    if port is None:
        errors["port"] = "連接埠必須是數字。LDAPS 通常是 636，StartTLS 通常是 389。"
    elif not _MIN_PORT <= port <= _MAX_PORT:
        errors["port"] = f"連接埠必須介於 {_MIN_PORT}~{_MAX_PORT}，收到 {port}。"

    base_dn = get("base_dn")
    if not base_dn:
        errors["base_dn"] = (
            "請填寫搜尋起點（Base DN）。網域 corp.local 對應的寫法是 DC=corp,DC=local。"
        )

    bind_dn = get("bind_dn")
    if not bind_dn:
        errors["bind_dn"] = (
            "請填寫用來連線的服務帳號。可用完整 DN（CN=svc_ldap,OU=Service,DC=corp,DC=local）、"
            "UPN（svc_ldap@corp.local）或 CORP\\svc_ldap 格式。"
        )

    raw_password = data.get("bind_password") or ""
    if not raw_password and not is_edit:
        errors["bind_password"] = _MSG_CREDENTIAL_REQUIRED
    # 編輯時留空代表沿用原密碼，因此存 None 而非空字串
    bind_password: str | None = raw_password if raw_password else None

    verify_cert = _as_bool(data.get("verify_cert"))
    ca_cert_file = get("ca_cert_file")

    # ---- 查詢設定 ----
    group_dn = get("group_dn")
    template_key = get("template_key") or DEFAULT_TEMPLATE_KEY
    template_parameters: dict[str, str] = {}

    if group_dn:
        # 指定群組時走群組成員展開路徑，範本不適用
        template_key = ""
    else:
        try:
            template = get_template(template_key)
        except Exception:
            errors["template_key"] = "請選擇一個查詢範本。"
        else:
            for param in template.parameters:
                value = get(f"param_{param.key}")
                if not value:
                    errors[f"param_{param.key}"] = (
                        f"查詢範本「{template.label}」需要填寫此欄位。{param.help_text}"
                    )
                else:
                    template_parameters[param.key] = value

    nesting_raw = get("nesting_strategy") or NestingStrategy.RECURSIVE.value
    try:
        nesting_strategy = NestingStrategy(nesting_raw).value
    except ValueError:
        errors["nesting_strategy"] = "請選擇一個有效的巢狀群組展開方式。"
        nesting_strategy = NestingStrategy.RECURSIVE.value

    scope_raw = get("search_scope") or SearchScope.SUBTREE.value
    try:
        search_scope = SearchScope(scope_raw).value
    except ValueError:
        errors["search_scope"] = "請選擇一個有效的搜尋範圍。"
        search_scope = SearchScope.SUBTREE.value

    page_size = _as_int(data.get("page_size"), default=1000)
    if page_size is None:
        errors["page_size"] = "分頁大小必須是數字。"
    elif not 1 <= page_size <= 1000:
        errors["page_size"] = (
            f"分頁大小必須介於 1~1000，收到 {page_size}。"
            "這是 AD 端的硬性上限（MaxPageSize），填更大的值不會讓查詢變快。"
        )

    receive_timeout = _as_int(data.get("receive_timeout"), default=30)
    if receive_timeout is None:
        errors["receive_timeout"] = "逾時秒數必須是數字。"
    elif not 1 <= receive_timeout <= 600:
        errors["receive_timeout"] = (
            f"逾時秒數請介於 1~600 秒，收到 {receive_timeout}。大型群組建議設 60 秒以上。"
        )

    # ---- 額外屬性（白名單）----
    raw_attributes = [a for a in (data.get("extra_attributes") or "").split(",") if a.strip()]
    extra_attributes: list[str] = []
    try:
        extra_attributes = validate_attributes([a.strip() for a in raw_attributes])
    except Exception as exc:
        errors["extra_attributes"] = getattr(exc, "message", str(exc))

    if errors:
        raise FormValidationError(errors)

    return LdapSourceForm(
        name=name,
        description=get("description"),
        is_authoritative=_as_bool(data.get("is_authoritative")),
        is_active=_as_bool(data.get("is_active")),
        host=host,
        port=port,  # type: ignore[arg-type]
        use_ssl=use_ssl,
        use_start_tls=use_start_tls,
        verify_cert=verify_cert,
        ca_cert_file=ca_cert_file,
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        template_key=template_key,
        template_parameters=template_parameters,
        group_dn=group_dn,
        nesting_strategy=nesting_strategy,
        search_scope=search_scope,
        page_size=page_size,  # type: ignore[arg-type]
        receive_timeout=receive_timeout,  # type: ignore[arg-type]
        extra_attributes=extra_attributes,
    )


def config_to_form_values(config: dict) -> dict:
    """把已儲存的 ``config_json`` 攤平成表單欄位值，供編輯頁回填。

    **不回填密碼**——密文無法還原成明文，且即使可以也不該送回瀏覽器。
    表單以「留空 = 不變更」處理這件事。
    """
    values = {
        "host": config.get("host", ""),
        "port": config.get("port", 636),
        "use_ssl": config.get("use_ssl", True),
        "use_start_tls": config.get("use_start_tls", False),
        "verify_cert": config.get("verify_cert", True),
        "ca_cert_file": config.get("ca_cert_file", ""),
        "base_dn": config.get("base_dn", ""),
        "bind_dn": config.get("bind_dn", ""),
        "template_key": config.get("template_key", DEFAULT_TEMPLATE_KEY),
        "group_dn": config.get("group_dn", ""),
        "nesting_strategy": config.get("nesting_strategy", NestingStrategy.RECURSIVE.value),
        "search_scope": config.get("search_scope", SearchScope.SUBTREE.value),
        "page_size": config.get("page_size", 1000),
        "receive_timeout": config.get("receive_timeout", 30),
        "extra_attributes": config.get("extra_attributes", []),
    }

    # 範本參數攤平成 param_<key>，讓模板不必知道巢狀結構
    for key, value in (config.get("template_parameters") or {}).items():
        values[f"param_{key}"] = value

    return values
