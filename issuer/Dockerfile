FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra gateway

# the issuer reuses the gateway's mandate code (issuing, verifying, scope maths); it runs none of its routes
COPY gateway gateway
COPY tool_grants tool_grants
COPY issuer issuer

RUN mkdir -p /app/issuer/data \
    && useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8083

HEALTHCHECK CMD curl --fail http://localhost:8083/healthcheck

CMD ["uv", "run", "--no-sync", "uvicorn", "issuer.app:app", "--host", "0.0.0.0", "--port", "8083"]
