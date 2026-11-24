"""One process serving the three data interfaces, each on its own path.

    /schools/mcp/    level 1
    /directory/mcp/  level 2
    /special/mcp/    level 4

Reachable only through the gateway: the container publishes no port (docker-compose.yaml).
"""

from fastapi import FastAPI
from fastmcp.utilities.lifespan import combine_lifespans

from data_slices import directory, schools, special
from tool_grants import protect

SERVERS = {"schools": schools.mcp, "directory": directory.mcp, "special": special.mcp}
apps = {name: server.http_app(path="/", stateless_http=True) for name, server in SERVERS.items()}

app = FastAPI(title="data slices", lifespan=combine_lifespans(*(a.lifespan for a in apps.values())))


@app.get("/healthcheck")
def healthcheck() -> dict:
    return {"status": "ok"}


for name, sub in apps.items():
    app.mount(f"/{name}/mcp", protect(sub, name))  # every tools/call needs a gateway tool grant
