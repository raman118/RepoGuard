FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS base
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
