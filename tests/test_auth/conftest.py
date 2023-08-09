import asyncio
from typing import Union

import pytest
from fastapi import FastAPI
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import SQLModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from fastapi_user_auth.auth.auth import Auth, AuthRouter
from fastapi_user_auth.auth.models import User
from tests.conftest import sync_db


@pytest.fixture()
def auth(db: Union[Database, AsyncDatabase]) -> Auth:
    return Auth(db=db)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def fake_auth() -> Auth:
    await sync_db.async_run_sync(SQLModel.metadata.create_all, is_session=False)
    auth = Auth(db=sync_db)
    # 创建角色
    await auth.create_role_user("admin")
    await auth.create_role_user("vip")
    await auth.create_role_user("test")
    # Reload policies
    await auth.enforcer.load_policy()
    yield auth
    await auth.db.async_run_sync(SQLModel.metadata.drop_all, is_session=False)
    await auth.db.async_close()


class UserClient:
    def __init__(self, auth: Auth, client: TestClient = None, user: User = None) -> None:
        self.auth = auth
        self.app: FastAPI = client.app
        self.client: TestClient = client
        self.user: User = user


@pytest.fixture(scope="session")
def logins(request, fake_auth: Auth) -> UserClient:
    app = FastAPI()
    app.add_middleware(BaseHTTPMiddleware, dispatch=sync_db.asgi_dispatch)
    #  注册auth基础路由
    auth_router = AuthRouter(auth=fake_auth)
    app.include_router(auth_router.router)

    user_data = {
        "admin": {"username": "admin", "password": "admin"},
        "vip": {"username": "vip", "password": "vip"},
        "test": {"username": "test", "password": "test"},
        "guest": {"username": None, "password": None},
    }

    def get_login_client(username: str = None, password: str = None) -> UserClient:
        client = TestClient(app)
        if not username or not password:
            return UserClient(fake_auth, client)
        response = client.post(
            "/auth/gettoken",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = response.json()
        assert data["data"]["access_token"]
        user = User.parse_obj(data["data"])
        assert user.is_active
        assert user.username == username
        return UserClient(fake_auth, client=client, user=user)

    return get_login_client(**user_data.get(request.param, {}))
