import argparse
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from app import create_app
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from middlewares.setup_middlewares import setup_middleware
from project_lib_utils.adapters.domain.user_repository import UserRepository
from project_lib_utils.helpers.sqlalchemy_deps import run_transaction
from project_lib_utils.models.users import User
from project_lib_utils.services_layer.events import EventServices
from project_lib_utils.settings.config import settings
from project_lib_utils.settings.database import create_tables, engine, session_maker
from routers.setup_routers import setup_routers

logger = logging.getLogger(__name__)


def _prepare_db() -> None:
    logger.info("Temp solution! Add test users")
    create_tables(engine)
    run_transaction(
        session_maker,
        lambda s: UserRepository(session=s, model=User).add_test_users(),
    )
    logger.info("Test users added!")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, Any]:
    logger.info("Starting up %s(%s)..." % (settings.host_name, settings.host_ip))
    _prepare_db()
    EventServices.system_start(
        result="success",
        additional_info=f"Starting up {settings.host_name}({settings.host_ip})",
        ip_address=settings.host_ip,
    )

    yield

    logger.info("Shutting down %s..." % settings.host_name)


def find_cert_files() -> tuple[str, str]:
    certfile = settings.client_tls_cert
    keyfile = settings.client_tls_key
    if certfile and keyfile:
        return certfile, keyfile
    else:
        raise FileNotFoundError("Matching certificate files not found in the directory")


app = create_app(lifespan=lifespan)

setup_middleware(app=app)
setup_routers(app=app)

app.mount("/static", StaticFiles(directory="./static"), name="static")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the FastAPI application.")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Run the server with HTTP.",
    )
    args = parser.parse_args()
    if not args.insecure:
        certfile, keyfile = find_cert_files()
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=5000,
            ssl_keyfile=keyfile,
            ssl_certfile=certfile,
            log_config="settings/logging_config.yaml",
        )
    else:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=5000,
            log_config="settings/logging_config.yaml",
        )
