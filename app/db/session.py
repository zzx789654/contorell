"""資料庫連線與 session 管理。"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.db.models import Base

_settings = get_settings()

engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,  # 連線閒置後自動重連，避免 stale connection
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """建立資料表（開發用；正式環境改用 alembic migration）。"""
    Base.metadata.create_all(engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    """交易範圍的 session，出錯自動 rollback。"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Generator[Session, None, None]:
    """FastAPI 依賴注入用的 session。

    例外時必須 rollback（FIND-006）：否則失敗的交易會殘留未提交狀態，
    在連線池重用該連線時污染後續請求。對稽核軌跡尤其重要——
    未 rollback 可能造成「操作已發生但紀錄不一致」的缺口。
    """
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
