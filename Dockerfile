# socai MCP server image.
#
# Packages the MCP server (`python -m mcp_server`) — the actual product.
# There is no web frontend; the previous FastAPI/frontend build stages were
# removed. Application code is unchanged: this is packaging only.
#
# Runtime config is env-driven (see mcp_server/config.py). On Azure, supply
# secrets via Key Vault -> Container App secrets, and mount persistent state
# (cases/ registry/ sessions/ browser_sessions/ articles/) plus confidential
# config/ from an Azure Files volume — none of that lives in this image.
FROM python:3.12-slim

# Faster, quieter, no .pyc clutter; unbuffered logs for container stdout.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (state/secrets are excluded via .dockerignore and mounted
# at runtime instead).
COPY . .

# Network transport defaults. Override per-environment as needed.
ENV SOCAI_MCP_HOST=0.0.0.0 \
    SOCAI_MCP_PORT=8001 \
    SOCAI_MCP_TRANSPORT=sse

EXPOSE 8001

# Liveness/readiness: /healthz is served by the SSE transport (HealthMiddleware).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url='http://127.0.0.1:%s/healthz' % os.getenv('SOCAI_MCP_PORT','8001'); \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status==200 else 1)" || exit 1

CMD ["python", "-m", "mcp_server"]
