FROM python:3.12-slim AS base

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first for better layer caching
COPY pyproject.toml README.md ./
COPY uv.lock* ./
RUN uv sync --no-dev --no-install-project

COPY src ./src
COPY policies ./policies
RUN uv sync --no-dev

# Run as a non-root user
RUN useradd --create-home --uid 10001 gateway
USER gateway

ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["mcp-gateway", "--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
