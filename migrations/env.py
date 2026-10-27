"""Alembic environment (async). Connects as the schema OWNER via GATEWAY_DB_ADMIN_URL.

The app roles (gateway_app, gateway_audit) deliberately cannot alter the schema.
"""

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine


def _url() -> str:
    url = os.environ.get("GATEWAY_DB_ADMIN_URL")
    if not url:
        raise RuntimeError("GATEWAY_DB_ADMIN_URL is required (schema owner, not an app role)")
    return url


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


async def _main() -> None:
    engine = create_async_engine(_url())
    try:
        async with engine.connect() as conn:
            await conn.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported")
asyncio.run(_main())
