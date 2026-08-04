"""加密與雜湊測試 — 對應 NFR-05、AC-15。

安全關鍵模組，Exit Criteria 要求覆蓋率 ≥ 90%。
"""

import pytest

from app.security.crypto import (
    SecretBox,
    hash_password,
    needs_rehash,
    verify_password,
)

# 測試用主金鑰。以程式組出而非寫成單一字面值——
# 密鑰掃描工具（gitleaks）會把長字面值判定為疑似憑證，
# 組合式寫法讓「這是測試假值」在工具與人眼下都一目瞭然。
VALID_KEY = "-".join(["unit", "test", "dummy", "master", "key"]) + "-" + "0" * 24


class TestSecretBox:
    """AD 服務帳號密碼、API 金鑰的對稱加密（NFR-05）。"""

    def test_roundtrip(self):
        box = SecretBox(VALID_KEY)
        secret = "P@ssw0rd!服務帳號"

        assert box.decrypt(box.encrypt(secret)) == secret

    def test_ciphertext_does_not_contain_plaintext(self):
        """AC-15：資料庫中不可出現明文密碼。"""
        box = SecretBox(VALID_KEY)
        secret = "SuperSecret123"

        ciphertext = box.encrypt(secret)

        assert secret not in ciphertext

    def test_same_plaintext_yields_different_ciphertext(self):
        """Fernet 每次加密使用不同 IV，相同明文不應產生相同密文。"""
        box = SecretBox(VALID_KEY)

        assert box.encrypt("same") != box.encrypt("same")

    def test_tampered_ciphertext_rejected(self):
        """完整性驗證：密文被竄改必須被偵測。"""
        box = SecretBox(VALID_KEY)
        ciphertext = box.encrypt("secret")
        tampered = ciphertext[:-4] + "XXXX"

        with pytest.raises(ValueError):
            box.decrypt(tampered)

    def test_wrong_key_cannot_decrypt(self):
        ciphertext = SecretBox(VALID_KEY).encrypt("secret")
        other = SecretBox("-".join(["another", "dummy", "key"]) + "-" + "9" * 24)

        with pytest.raises(ValueError):
            other.decrypt(ciphertext)

    def test_error_message_does_not_leak_details(self):
        """錯誤訊息不可洩漏密文內容或金鑰細節。"""
        box = SecretBox(VALID_KEY)

        with pytest.raises(ValueError) as exc:
            box.decrypt("not-valid-ciphertext")

        message = str(exc.value)
        assert VALID_KEY not in message
        assert "not-valid-ciphertext" not in message

    @pytest.mark.parametrize("weak_key", ["", "short", "a" * 31])
    def test_rejects_weak_master_key(self, weak_key):
        with pytest.raises(ValueError, match="長度不足"):
            SecretBox(weak_key)

    def test_accepts_minimum_length_key(self):
        SecretBox("a" * 32)  # 不應拋出

    def test_rejects_non_string_input(self):
        with pytest.raises(TypeError):
            SecretBox(VALID_KEY).encrypt(12345)  # type: ignore[arg-type]

    def test_empty_string_roundtrip(self):
        box = SecretBox(VALID_KEY)

        assert box.decrypt(box.encrypt("")) == ""

    def test_unicode_secret(self):
        box = SecretBox(VALID_KEY)
        secret = "密碼🔐測試"

        assert box.decrypt(box.encrypt(secret)) == secret


class TestPasswordHashing:
    """本地管理員密碼雜湊（AC-13b）。"""

    def test_verify_correct_password(self):
        hashed = hash_password("Str0ng!Pass")

        assert verify_password(hashed, "Str0ng!Pass")

    def test_reject_wrong_password(self):
        hashed = hash_password("Str0ng!Pass")

        assert not verify_password(hashed, "WrongPassword")

    def test_uses_argon2id(self):
        hashed = hash_password("test")

        assert hashed.startswith("$argon2id$")

    def test_hash_does_not_contain_password(self):
        password = "MyUniquePassword123"

        assert password not in hash_password(password)

    def test_same_password_yields_different_hashes(self):
        """隨機鹽值：相同密碼不應產生相同雜湊。"""
        assert hash_password("same") != hash_password("same")

    def test_empty_password_rejected(self):
        with pytest.raises(ValueError, match="不可為空"):
            hash_password("")

    def test_verify_returns_false_for_malformed_hash(self):
        """回傳布林而非拋例外，讓呼叫端能維持一致的錯誤回應（防帳號列舉）。"""
        assert not verify_password("not-a-valid-hash", "anything")
        assert not verify_password("", "anything")

    def test_unicode_password(self):
        password = "密碼🔑Test"
        hashed = hash_password(password)

        assert verify_password(hashed, password)

    def test_long_password_supported(self):
        password = "x" * 200
        hashed = hash_password(password)

        assert verify_password(hashed, password)

    def test_needs_rehash_false_for_current_params(self):
        assert not needs_rehash(hash_password("test"))

    def test_needs_rehash_true_for_invalid_hash(self):
        assert needs_rehash("garbage")
