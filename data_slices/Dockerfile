FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra fastapi

# code only; the data is mounted read-only at /app/mcp_server/data by docker-compose.yaml
COPY data_slices data_slices
COPY tool_grants tool_grants

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8090

HEALTHCHECK CMD curl --fail http://localhost:8090/healthcheck

CMD ["uv", "run", "--no-sync", "uvicorn", "data_slices.main:app", "--host", "0.0.0.0", "--port", "8090"]
