"""外部 URL 位址管控 — 對應 FIND-002（CWE-918 SSRF、OWASP A10:2025）。

管理者可自訂外部系統的 API URL。若不限制目標位址，這個功能會變成
內網探測工具：可存取 ``127.0.0.1`` 的內部服務、雲端 metadata 端點
（``169.254.169.254``，可取得雲端憑證），或 RFC1918 內網主機。

防護策略（縱深）：
1. **解析後檢查 IP**：拒絕 loopback、link-local、private、保留區段。
2. **可選的允許清單**：企業可設定只允許特定網域，最嚴格也最建議。
3. **逐跳驗證**：重導向的每一個目標都要重新驗證，否則允許清單會被 302 繞過。
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class UrlNotAllowed(Exception):
    """目標位址不被允許。"""

    def __init__(self, message: str, *, remediation: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """判斷 IP 是否屬於應阻擋的區段。"""
    if ip.is_loopback:
        return True, "loopback（本機）位址"
    if ip.is_link_local:
        # 169.254.169.254 是各大雲端的 metadata 端點，可取得執行個體憑證
        return True, "link-local 位址（含雲端 metadata 端點）"
    if ip.is_private:
        return True, "私有網段（RFC1918 內網）位址"
    if ip.is_reserved:
        return True, "保留位址"
    if ip.is_multicast:
        return True, "多播位址"
    if ip.is_unspecified:
        return True, "未指定位址（0.0.0.0）"

    # IPv4-mapped IPv6（::ffff:127.0.0.1）可用來繞過 IPv4 檢查
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_blocked_ip(ip.ipv4_mapped)

    # 100.64.0.0/10 CGNAT —— ipaddress 不歸類為 private，但同屬內部網段
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True, "CGNAT 共享位址網段"

    return False, ""


def validate_external_url(
    url: str,
    *,
    allowed_hosts: frozenset[str] | None = None,
    allow_private: bool = False,
) -> None:
    """驗證 URL 是否可安全地對外請求。

    Args:
        url: 要驗證的完整 URL。
        allowed_hosts: 若提供，只允許清單內的主機名稱（最嚴格，建議正式環境使用）。
        allow_private: 是否允許私有網段。**僅供測試環境**——
            企業內部系統多在內網，故保留此開關，但必須是明確的設定決定。

    Raises:
        UrlNotAllowed: 目標位址不被允許。
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise UrlNotAllowed(
            f"不支援的通訊協定：{parsed.scheme or '（未指定）'}",
            remediation="URL 必須以 http:// 或 https:// 開頭。",
        )

    hostname = parsed.hostname
    if not hostname:
        raise UrlNotAllowed("URL 缺少主機名稱")

    # 允許清單優先：命中即放行，不再做 IP 檢查
    if allowed_hosts is not None:
        if hostname.lower() not in {h.lower() for h in allowed_hosts}:
            raise UrlNotAllowed(
                f"主機「{hostname}」不在允許清單中。",
                remediation="請聯繫系統管理員將此主機加入外部來源允許清單。",
            )
        return

    if allow_private:
        return

    # 解析主機名稱為 IP。同一名稱可能對應多個 IP，全部都要檢查——
    # 只檢查第一個會被「一個公網 IP + 一個內網 IP」的 DNS 記錄繞過。
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise UrlNotAllowed(
            f"無法解析主機名稱：{hostname}",
            remediation="請確認網域名稱正確且 DNS 可解析。",
        ) from exc

    for _family, _, _, _, sockaddr in addr_info:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue

        blocked, reason = _is_blocked_ip(ip)
        if blocked:
            logger.warning(
                "拒絕外部請求（SSRF 防護）：%s 解析為 %s（%s）", hostname, raw_ip, reason
            )
            raise UrlNotAllowed(
                f"目標位址不被允許：{hostname} 解析為 {reason}。",
                remediation=(
                    "為防止伺服器端請求偽造（SSRF），系統不允許連線到內網、"
                    "本機或雲端 metadata 位址。若確實需要連線至內部系統，"
                    "請將該主機加入允許清單，或由管理員開啟內網存取設定。"
                ),
            )
