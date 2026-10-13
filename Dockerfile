FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:$PATH"
WORKDIR /app
RUN pip install --no-cache-dir uv==0.11.26
COPY pyproject.toml uv.lock .python-version ./
COPY backend ./backend
RUN uv sync --frozen --no-dev
COPY analysis/pyproject.toml analysis/uv.lock ./analysis/
RUN uv sync --directory analysis --frozen --no-dev
COPY migrations ./migrations
COPY alembic.ini ./
COPY fixtures ./fixtures
COPY rules ./rules
RUN useradd --uid 10001 --create-home repoguard
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "repoguard.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM base AS verification
USER root
RUN uv sync --frozen
COPY tests ./tests
COPY scripts ./scripts
ENV UV_NO_SYNC=1 UV_CACHE_DIR=/tmp/uv PYTEST_ADDOPTS="-p no:cacheprovider"
USER 10001:10001
CMD ["python", "scripts/verify.py", "--scope", "services"]

FROM base AS runtime
