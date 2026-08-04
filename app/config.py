"""應用程式設定 — 一律由環境變數載入，絕不硬編碼密鑰。"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """從環境變數 / .env 載入的設定。"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["development", "staging", "production"] = "development"
    secret_key: str = Field(min_length=32)
    database_url: str

    # --- AD / LDAP 預設連線 ---
    ldap_host: str = ""
    ldap_port: int = 636
    ldap_use_ssl: bool = True
    ldap_base_dn: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_verify_cert: bool = True
    ldap_ca_cert_file: str = ""

    # --- 本地管理員退路帳號 ---
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    # --- 限制 ---
    upload_max_bytes: int = 10 * 1024 * 1024  # 10MB
    upload_max_rows: int = 50_000
    ldap_page_size: int = 1000  # AD 硬性上限，不可超過（IR-03）
    external_api_timeout_seconds: float = 30.0
    external_api_max_retries: int = 3

    @field_validator("ldap_page_size")
    @classmethod
    def _validate_page_size(cls, value: int) -> int:
        """AD 單次查詢硬性上限為 1000，超過會被靜默截斷。"""
        if not 1 <= value <= 1000:
            raise ValueError("ldap_page_size 必須介於 1~1000（AD MaxPageSize 硬性限制）")
        return value

    @field_validator("ldap_ca_cert_file")
    @classmethod
    def _validate_ca_file(cls, value: str) -> str:
        if value and not Path(value).is_file():
            raise ValueError(f"LDAP_CA_CERT_FILE 指定的檔案不存在：{value}")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """取得設定單例。"""
    return Settings()  # type: ignore[call-arg]
