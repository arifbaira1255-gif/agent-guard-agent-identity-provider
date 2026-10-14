# AQL-1 backend + the security libs it depends on. Build context = REPOSITORY ROOT:
#   docker build -f apps/aql/backend/Dockerfile -t aql-backend .
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/opt/platform/libs/contract:/opt/platform/libs/happy-lang \
    HAPPY_LANG_PATH=/opt/platform/libs/happy-lang

# util-linux provides `unshare` (namespaces isolation backend); curl for the healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends util-linux curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 aql && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin aql

WORKDIR /app
COPY apps/aql/backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY apps/aql/backend ./
COPY libs/contract /opt/platform/libs/contract
COPY libs/happy-lang /opt/platform/libs/happy-lang

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
