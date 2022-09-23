import pytest

from fastapi_user_auth.auth.backends.db import DbTokenStore
from fastapi_user_auth.auth.backends.jwt import JwtTokenStore
from fastapi_user_auth.auth.schemas import BaseTokenData

token_data = BaseTokenData(id=1, username="test")


@pytest.mark.asyncio
async def test_jwt_token_store():
    store = JwtTokenStore(secret_key="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
    token = await store.write_token(token_data)
    assert token
    data = await store.read_token(token=token)
    assert data == token_data
    with pytest.raises(NotImplementedError):
        await store.destroy_token(token)


@pytest.mark.asyncio
async def test_db_token_store(db):
    store = DbTokenStore(db)
    token = await store.write_token(token_data)
    assert token
    data = await store.read_token(token=token)
    assert data == token_data
    await store.destroy_token(token=token)
    data = await store.read_token(token=token)
    assert data is None


@pytest.mark.asyncio
async def test_redis_token_store():
    pass
