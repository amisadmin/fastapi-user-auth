from fastapi_amis_admin.utils.db import SqlalchemyAsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


def get_db(db_name: str = "test") -> SqlalchemyAsyncClient:
    engine: AsyncEngine = create_async_engine(f'sqlite+aiosqlite:///{db_name}', future=True)
    db = SqlalchemyAsyncClient(engine)
    return db
