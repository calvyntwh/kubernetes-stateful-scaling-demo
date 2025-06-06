# Use Alpine-based Python image for smaller attack surface - updated to latest secure version
FROM python:3.13-alpine

# Set environment variables for Python and uv
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Create non-root user for security
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# Set the working directory
WORKDIR /app

# Install uv package manager for faster, more reliable dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files for dependency installation
COPY pyproject.toml requirements.txt ./

# Install system dependencies and Python packages with uv
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    && uv pip install --system --no-cache -r requirements.txt \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/* \
    && rm requirements.txt pyproject.toml

# Copy only necessary application files
COPY main.py .
COPY templates/ templates/

# Create necessary directories and set permissions
RUN mkdir -p /data /tmp && \
    chown -R appuser:appuser /app /data /tmp

# Switch to non-root user
USER appuser

# Expose the port
EXPOSE 8000

# Use exec form for better signal handling
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
