"""資料模型 — 對應四個核心概念：來源 → 快照 → 比對 → 標註。

刻意維持在四個概念（見 CoreMain.md），不引入第五個。
所有敏感欄位（AD 密碼、API 金鑰）以密文儲存，見 app/security/crypto.py。
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class SourceType(str, Enum):
    LDAP = "ldap"
    API = "api"
    FILE = "file"


class UserRole(str, Enum):
    ADMIN = "admin"
    """管理者：可設定來源、執行比對、填寫標註。"""

    AUDITOR = "auditor"
    """稽核者：唯讀，只能查看結果與稽核軌跡。"""


class CustomFieldType(str, Enum):
    TEXT = "text"
    SELECT = "select"
    DATE = "date"


# ---------------------------------------------------------------------------
# 使用者與稽核
# ---------------------------------------------------------------------------


class User(Base):
    """系統使用者。

    支援兩種驗證來源（FR-13、FR-13b）：
    - AD 使用者：``is_local=False``，``password_hash`` 為空，登入時以 LDAP bind 驗證。
    - 本地管理員：``is_local=True``，密碼以 argon2 雜湊儲存，作為 AD 故障時的退路。
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(32), default=UserRole.AUDITOR.value)

    is_local: Mapped[bool] = mapped_column(Boolean, default=False)
    # 僅本地帳號使用；AD 帳號一律為空（AD 密碼絕不儲存）
    password_hash: Mapped[str] = mapped_column(String(255), default="")

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value


class LoginAttempt(Base):
    """登入失敗計數 — 對應 FIND-004（CWE-307）。

    ``User.failed_login_count`` 只能保護「本地已存在」的帳號。
    AD 帳號在首次登入前本地沒有記錄，若不另外追蹤，
    攻擊者可對任意 AD 帳號無限次嘗試密碼。

    以**正規化後**的帳號名為鍵（FIND-003），避免大小寫變形繞過計數。
    """

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    identity_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    first_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    """操作稽核軌跡（FR-14、AC-14）。

    僅追加不修改。記錄誰、何時、對什麼、做了什麼。
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor_username: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(64), default="")
    target_id: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")

    __table_args__ = (Index("ix_audit_actor_time", "actor_username", "occurred_at"),)


# ---------------------------------------------------------------------------
# 概念一：資料來源
# ---------------------------------------------------------------------------


class DataSource(Base):
    """一個可重複使用的帳號來源設定（FR-01、FR-04、FR-05）。

    三種型態共用同一張表——設定細節放在 ``config_json``，
    敏感值（密碼、API 金鑰）另外加密存在 ``encrypted_secret``。
    這讓「新增一種來源型態」不需要改資料庫結構（NFR-12）。
    """

    __tablename__ = "data_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    source_type: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")

    # 非敏感設定：host、base_dn、url、欄位對應等
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # 敏感值密文（AD bind 密碼 / API 金鑰）。絕不以明文儲存（NFR-05）。
    encrypted_secret: Mapped[str] = mapped_column(Text, default="")

    is_authoritative: Mapped[bool] = mapped_column(Boolean, default=False)
    """是否為權威身分來源（AD）。決定比對時是否套用離職稽核判定。"""

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    last_fetch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    snapshots: Mapped[list[Snapshot]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# 概念二：快照
# ---------------------------------------------------------------------------


class Snapshot(Base):
    """某一時刻從某來源抓到的完整帳號清單（FR-11）。

    保存快照讓「這次 vs 上次」的變更追蹤成為可能，
    也讓比對結果可追溯——稽核時能證明當時看到的資料長什麼樣。
    """

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id", ondelete="CASCADE"))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    fetched_by: Mapped[str] = mapped_column(String(255), default="")

    account_count: Mapped[int] = mapped_column(Integer, default=0)
    # 來源回報的筆數，與 account_count 不符時代表可能有截斷（風險 R-02）
    total_reported: Mapped[int | None] = mapped_column(Integer, default=None)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)
    diagnostics_json: Mapped[dict] = mapped_column(JSON, default=dict)

    source: Mapped[DataSource] = relationship(back_populates="snapshots")
    accounts: Mapped[list[SnapshotAccount]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )

    @property
    def has_count_mismatch(self) -> bool:
        return self.total_reported is not None and self.total_reported != self.account_count


class SnapshotAccount(Base):
    """快照中的單一帳號。"""

    __tablename__ = "snapshot_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("snapshots.id", ondelete="CASCADE"), index=True
    )

    identifier: Mapped[str] = mapped_column(String(512))
    normalized_key: Mapped[str] = mapped_column(String(512), index=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    email: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    attributes_json: Mapped[dict] = mapped_column(JSON, default=dict)

    snapshot: Mapped[Snapshot] = relationship(back_populates="accounts")

    __table_args__ = (Index("ix_snapshot_key", "snapshot_id", "normalized_key"),)


# ---------------------------------------------------------------------------
# 概念三：比對
# ---------------------------------------------------------------------------


class Comparison(Base):
    """一次比對的執行紀錄（FR-06）。"""

    __tablename__ = "comparisons"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    snapshot_a_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="RESTRICT"))
    snapshot_b_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="RESTRICT"))

    compared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    compared_by: Mapped[str] = mapped_column(String(255), default="")

    source_a_label: Mapped[str] = mapped_column(String(255), default="")
    source_b_label: Mapped[str] = mapped_column(String(255), default="")
    source_a_count: Mapped[int] = mapped_column(Integer, default=0)
    source_b_count: Mapped[int] = mapped_column(Integer, default=0)

    status_counts_json: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_counts_json: Mapped[dict] = mapped_column(JSON, default=dict)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)

    rows: Mapped[list[ComparisonRowRecord]] = relationship(
        back_populates="comparison", cascade="all, delete-orphan"
    )


class ComparisonRowRecord(Base):
    """比對結果的單一列。標註（概念四）掛在這裡。"""

    __tablename__ = "comparison_rows"

    id: Mapped[int] = mapped_column(primary_key=True)
    comparison_id: Mapped[int] = mapped_column(
        ForeignKey("comparisons.id", ondelete="CASCADE"), index=True
    )

    account_key: Mapped[str] = mapped_column(String(512), index=True)
    display_identifier: Mapped[str] = mapped_column(String(512), default="")
    display_name: Mapped[str] = mapped_column(String(512), default="")

    match_status: Mapped[str] = mapped_column(String(32), index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    risk_reason: Mapped[str] = mapped_column(Text, default="")
    differences_json: Mapped[list] = mapped_column(JSON, default=list)

    account_a_json: Mapped[dict | None] = mapped_column(JSON, default=None)
    account_b_json: Mapped[dict | None] = mapped_column(JSON, default=None)

    comparison: Mapped[Comparison] = relationship(back_populates="rows")
    annotations: Mapped[list[Annotation]] = relationship(
        back_populates="row", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_row_comparison_risk", "comparison_id", "risk_level"),)


# ---------------------------------------------------------------------------
# 概念四：標註（自訂欄位）
# ---------------------------------------------------------------------------


class CustomFieldDefinition(Base):
    """管理者自行定義的欄位（FR-10、AC-10）。"""

    __tablename__ = "custom_field_definitions"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(255))
    field_type: Mapped[str] = mapped_column(String(32), default=CustomFieldType.TEXT.value)
    # SELECT 型別的選項清單
    options_json: Mapped[list] = mapped_column(JSON, default=list)
    help_text: Mapped[str] = mapped_column(String(512), default="")

    display_order: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Annotation(Base):
    """管理者對某筆比對結果填寫的自訂欄位值（FR-09、AC-09）。"""

    __tablename__ = "annotations"

    id: Mapped[int] = mapped_column(primary_key=True)
    row_id: Mapped[int] = mapped_column(
        ForeignKey("comparison_rows.id", ondelete="CASCADE"), index=True
    )
    field_key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(Text, default="")

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    updated_by: Mapped[str] = mapped_column(String(255), default="")

    row: Mapped[ComparisonRowRecord] = relationship(back_populates="annotations")

    # 一列的同一個欄位只能有一個值
    __table_args__ = (UniqueConstraint("row_id", "field_key", name="uq_annotation_row_field"),)


# ---------------------------------------------------------------------------
# 權限檢視（Round 8）：對某權限來源中某帳號的自訂註記
# ---------------------------------------------------------------------------


class EntitlementNote(Base):
    """管理者在「權限來源分頁」對某成員留下的處置註記（Round 8，規格第 6 點）。

    以（來源, 帳號正規化鍵）為鍵，與比對用的 :class:`Annotation` 分開——
    後者掛在某一次比對的某一列，本註記則跟著「來源中的帳號」持續存在。
    仍屬概念四（標註）的延伸，不新增第五個核心概念。
    """

    __tablename__ = "entitlement_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("data_sources.id", ondelete="CASCADE"), index=True
    )
    account_key: Mapped[str] = mapped_column(String(512), index=True)
    note: Mapped[str] = mapped_column(Text, default="")

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    updated_by: Mapped[str] = mapped_column(String(255), default="")

    __table_args__ = (
        UniqueConstraint("source_id", "account_key", name="uq_entnote_source_account"),
    )


class EntitlementMaintainer(Base):
    """指派某使用者為某權限來源的「維護人員」（Round 10，規格：各權限表單維護權限）。

    管理者一律可維護所有權限來源；被指派為維護人員者，可維護其負責的來源
    （填寫／修改該來源的處置註記），但不會取得其他管理者權限。
    以此達成「各權限表單分別授權維護」而不需要把人升級為管理者。
    """

    __tablename__ = "entitlement_maintainers"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("data_sources.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (UniqueConstraint("source_id", "user_id", name="uq_maintainer_source_user"),)
