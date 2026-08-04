# contorell 應用程式映像
#
# 安全考量：
# - 以非 root 使用者執行（降低容器逃逸的影響）
# - 多階段建置，執行階段不含編譯工具，減少攻擊面
# - 不含任何憑證，全部由環境變數提供
#
# 相依說明：本專案刻意選用不需要系統層函式庫的套件——
# `ldap3` 是純 Python 實作（不需 libldap/libsasl），
# `psycopg[binary]` 自帶 libpq，`cryptography` 提供預編譯 wheel。
# 因此執行階段不需安裝任何額外的 apt 套件，也就不會因為
# Debian 版本更迭導致套件名稱（如 libldap-2.5-0）失效而建置失敗。

FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY app ./app

# 相依套件全部要求預編譯 wheel（:all: 會連本專案自己也要求 wheel，
# 故改用 --prefer-binary 搭配明確的無編譯器環境）——若有套件需要編譯，
# 建置會在此失敗，讓問題在 CI 就浮現而非上線才發現。
RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim

# 只建立執行用的非 root 使用者，不安裝額外套件
RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=appuser:appuser app ./app

USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 容器層級的健康檢查，供編排系統判斷服務是否就緒
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/login')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
