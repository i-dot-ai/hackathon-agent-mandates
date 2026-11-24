FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra gateway

COPY gateway gateway
COPY local_view local_view

EXPOSE 8090

HEALTHCHECK CMD curl --fail http://localhost:8090/

# Root on purpose: the board issues mandates into the mounted state directory.
CMD ["uv", "run", "--no-sync", "python", "local_view/server.py"]
