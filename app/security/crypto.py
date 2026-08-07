"""密鑰加密與密碼雜湊 — 對應 NFR-05、AC-13b。

**安全紀律**：
- 不自製加密演算法，一律使用標準函式庫（cryptography / argon2-cffi）。
- 需要「還原原文」的憑證（AD 服務帳號密碼、外部 API 金鑰）→ 用 :class:`SecretBox` 對稱加密。
- 不需要還原、只需驗證的密碼（本地管理員登入密碼）→ 用 argon2 **單向雜湊**。

兩者用途不可互換：登入密碼若用可逆加密儲存，等同明文外洩風險。
"""

from __future__ import annotations

import base64
import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

# argon2id 預設參數已符合 OWASP 建議；此處明示以便日後調整與審查。
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
)


class SecretBox:
    """對稱加密可還原的憑證（AD 密碼、API 金鑰）。

    使用 Fernet（AES-128-CBC + HMAC-SHA256），提供機密性與完整性驗證。
    金鑰由應用程式的 ``SECRET_KEY`` 環境變數推導，**絕不入庫、絕不入版控**。
    """

    def __init__(self, secret_key: str) -> None:
        """由主金鑰推導出加密金鑰。

        Args:
            secret_key: 來自環境變數的主金鑰（高熵隨機字串）。

        Raises:
            ValueError: 主金鑰過短，不足以提供足夠強度。
        """
        if not secret_key or len(secret_key) < 32:
            raise ValueError(
                "SECRET_KEY 長度不足（至少 32 字元）。"
                '請以 python -c "import secrets; print(secrets.token_urlsafe(48))" 產生。'
            )
        # 以 SHA-256 推導出 Fernet 需要的 32 bytes 金鑰。
        # 註：此處為金鑰派生而非密碼雜湊，主金鑰本身已是高熵隨機值，
        # 故不需要 KDF 的加鹽與慢速特性。
        digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, plaintext: str) -> str:
        """加密字串，回傳可安全存入資料庫的密文。"""
        if not isinstance(plaintext, str):
            raise TypeError("encrypt 需要 str")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """解密資料庫中的密文。

        Raises:
            ValueError: 密文遭竄改、格式錯誤，或 SECRET_KEY 已變更。
        """
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            # 不外洩密文內容或金鑰細節（避免資訊洩漏）
            raise ValueError("無法解密憑證：密文可能已損毀，或 SECRET_KEY 與加密時不同。") from exc


def hash_password(password: str) -> str:
    """以 argon2id 雜湊本地管理員密碼（單向，不可還原）。"""
    if not password:
        raise ValueError("密碼不可為空")
    return _password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """驗證密碼是否符合雜湊值。

    回傳布林值而不拋例外，讓呼叫端能對「帳號不存在」與「密碼錯誤」
    做出**一致的回應**，避免帳號列舉（AC-13b）。
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """判斷雜湊是否使用過時參數，需在下次成功登入時重算。"""
    try:
        return _password_hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
