import asyncio
from typing import Union

import pytest
from fastapi import FastAPI
from sqlalchemy.orm import Session
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import SQLModel
from starlette.testclient import TestClient

from fastapi_user_auth.auth.auth import Auth, AuthRouter
from fastapi_user_auth.auth.models import Group, Permission, Role, User
from tests.conftest import async_db, sync_db


@pytest.fixture(params=[async_db, sync_db])
async def db(request) -> Union[Database, AsyncDatabase]:
    database = request.param
    await database.async_run_sync(SQLModel.metadata.create_all, is_session=False)
    yield database
    await database.async_run_sync(SQLModel.metadata.drop_all, is_session=False)


@pytest.fixture()
def auth(db: Union[Database, AsyncDatabase]) -> Auth:
    return Auth(db=async_db)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def fake_auth() -> Auth:
    auth = Auth(db=AsyncDatabase.create("sqlite+aiosqlite:///amisadmin.db?check_same_thread=False"))

    # noinspection PyTypeChecker
    def create_fake_users(session: Session):
        # init permission
        admin_perm = Permission(key="admin", name="admin permission")
        vip_perm = Permission(key="vip", name="vip permission")
        test_perm = Permission(key="test", name="test permission")
        session.add_all([admin_perm, vip_perm, test_perm])
        session.flush([admin_perm, vip_perm, test_perm])
        # init role
        admin_role = Role(key="admin", name="admin role", permissions=[admin_perm])
        vip_role = Role(key="vip", name="vip role", permissions=[vip_perm])
        test_role = Role(key="test", name="test role", permissions=[test_perm])
        session.add_all([admin_role, vip_role, test_role])
        session.flush([admin_role, vip_role, test_role])
        # init group
        admin_group = Group(key="admin", name="admin group", roles=[admin_role])
        vip_group = Group(key="vip", name="vip group", roles=[vip_role])
        test_group = Group(key="test", name="test group", roles=[test_role])
        session.add_all([admin_group, vip_group, test_group])
        session.flush([admin_group, vip_group, test_group])
        # init user
        admin_user = User(
            username="admin",
            password=auth.pwd_context.hash("admin"),
            email="admin@amis.work",
            roles=[admin_role],
            groups=[admin_group],
        )
        vip_user = User(
            username="vip", password=auth.pwd_context.hash("vip"), email="vip@amis.work", roles=[vip_role], groups=[vip_group]
        )
        test_user = User(
            username="test",
            password=auth.pwd_context.hash("test"),
            email="test@amis.work",
            roles=[test_role],
            groups=[test_group],
        )
        session.add_all([admin_user, vip_user, test_user])
        session.flush([admin_user, vip_user, test_user])

    await auth.db.async_run_sync(SQLModel.metadata.create_all, is_session=False)
    await auth.db.async_run_sync(create_fake_users)
    yield auth
    await auth.db.async_run_sync(SQLModel.metadata.drop_all, is_session=False)


class UserClient:
    def __init__(self, auth: Auth, client: TestClient = None, user: User = None) -> None:
        self.auth = auth
        self.app: FastAPI = client.app
        self.client: TestClient = client
        self.user: User = user


@pytest.fixture(scope="session")
def logins(request, fake_auth: Auth) -> UserClient:
    app = FastAPI()
    #  注册auth基础路由
    auth_router = AuthRouter(auth=fake_auth)
    app.include_router(auth_router.router)

    user_data = {
        "admin": {"username": "admin", "password": "admin"},
        "vip": {"username": "vip", "password": "vip"},
        "test": {"username": "test", "password": "test"},
        "guest": {"username": None, "password": None},
    }
    user = user_data.get(request.param) or {}

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

    return get_login_client(**user)
