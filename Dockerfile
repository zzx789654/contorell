# contorell 應用程式映像
#
# 安全考量：
# - 以非 root 使用者執行（降低容器逃逸的影響）
# - 多階段建置，執行階段不含編譯工具
# - 不含任何憑證，全部由環境變數提供

FROM python:3.12-slim AS builder

WORKDIR /build

# 編譯 psycopg / cryptography 需要的工具與標頭檔
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libldap2-dev \
        libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim

# 執行階段只留必要的動態函式庫
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libldap-2.5-0 \
        libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=appuser:appuser app ./app

USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
