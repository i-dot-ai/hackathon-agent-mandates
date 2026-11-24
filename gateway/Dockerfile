FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra gateway

COPY gateway gateway
COPY tool_grants tool_grants

# the audit volume mounts here; creating it first makes the named volume start owned by appuser
RUN mkdir -p /app/gateway/audit \
    && useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8082

HEALTHCHECK CMD curl --fail http://localhost:8082/healthcheck

CMD ["uv", "run", "--no-sync", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8082"]
