# Use Alpine-based Python image for smaller attack surface
FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache

# Create non-root user for security
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

WORKDIR /app

# Install uv package manager for faster dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./

# Install dependencies and clean up build tools
RUN apk add --no-cache --virtual .build-deps \
    gcc=14.2.0-r6 \
    musl-dev=1.2.5-r10 \
    libffi-dev=3.4.8-r0 \
    && uv sync --frozen --no-dev \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/* \
    && rm pyproject.toml uv.lock

COPY main.py .
COPY templates/ templates/

RUN mkdir -p /data /tmp && \
    chown -R appuser:appuser /app /data /tmp

USER appuser

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
