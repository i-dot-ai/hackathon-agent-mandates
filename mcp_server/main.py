import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from fastmcp.utilities.lifespan import combine_lifespans
from mcp_server.api.routes_mcp import mcp
from tool_grants import protect

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer


import sentry_sdk
from mcp_server.api.routes import router as api_router
from shared_utils.settings import (
    get_settings,
    get_logger
)

settings = get_settings()
logger = get_logger(level="info")



@asynccontextmanager
async def lifespan(app_: FastAPI):  # noqa: ARG001
    logger.info("Starting up...")

    yield
    logger.info("Shutting down...")

if settings.SENTRY_DSN and settings.ENVIRONMENT in ["dev", "preprod", "prod"]:  # noqa: SIM102
    # Placeholder check added because of default value in SSM/secrets.tf
    if settings.SENTRY_DSN != "placeholder":
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            # Reduce these sample rates in busy environments, as quota gets eaten up fast
            traces_sample_rate=1.0,
            profiles_sample_rate=1.0,
        )


mcp_app = mcp.http_app(path="/", stateless_http=True)
app = FastAPI(lifespan=combine_lifespans(lifespan, mcp_app.lifespan))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configure CORS

origins = [settings.APP_URL]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
app.mount("/mcp", protect(mcp_app, "pupil-data"))  # every tools/call needs a gateway tool grant


# Not under /mcp: the mount above would swallow it.
@app.get("/mcp-tools", tags=["mcp"])
async def list_mcp_tools():
    """Every tool exposed at /mcp, with its input and output schemas."""
    return [t.to_mcp_tool().model_dump(by_alias=True, exclude_none=True) for t in await mcp.list_tools()]


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)  # noqa: S104
