from typing import AsyncGenerator, Dict, Union

import pytest
from fastapi import FastAPI
from fastapi_amis_admin.admin import BaseAdmin, HomeAdmin, Settings
from httpx import AsyncClient
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import SQLModel
from starlette.testclient import TestClient

from fastapi_user_auth.admin import AuthAdminSite, CasbinRuleAdmin, LoginHistoryAdmin

# sqlite
sync_db = Database.create("sqlite:///amisadmin.db?check_same_thread=False")
async_db = AsyncDatabase.create("sqlite+aiosqlite:///amisadmin.db?check_same_thread=False")


# mysql
# sync_db = Database.create('mysql+pymysql://root:123456@127.0.0.1:3306/amisadmin?charset=utf8mb4')
# async_db = AsyncDatabase.create('mysql+aiomysql://root:123456@127.0.0.1:3306/amisadmin?charset=utf8mb4')

# postgresql
# sync_db = Database.create('postgresql://postgres:root@127.0.0.1:5432/amisadmin')
# async_db = AsyncDatabase.create('postgresql+asyncpg://postgres:root@127.0.0.1:5432/amisadmin')

# oracle
# sync_db = Database.create('oracle+cx_oracle://scott:tiger@tnsname')

# SQL Server
# sync_db = Database.create('mssql+pyodbc://scott:tiger@mydsn')


@pytest.fixture(params=[async_db, sync_db])
async def db(request) -> Union[Database, AsyncDatabase]:
    database = request.param
    await database.async_run_sync(SQLModel.metadata.create_all, is_session=False)
    yield database
    await database.async_run_sync(SQLModel.metadata.drop_all, is_session=False)
    await database.async_close()


@pytest.fixture
def site(db) -> AuthAdminSite:
    return AuthAdminSite(settings=Settings(site_path=""), engine=db)


@pytest.fixture
def app(site: AuthAdminSite) -> FastAPI:
    fastapi = FastAPI()
    # 挂载后台管理系统
    site.mount_app(fastapi)

    return fastapi


# 已启动的app
@pytest.fixture
async def started_app(app: FastAPI, site: AuthAdminSite) -> FastAPI:
    await site.db.async_run_sync(SQLModel.metadata.create_all, is_session=False)
    # 运行后台管理系统启动事件
    await site.fastapi.router.startup()
    return app


@pytest.fixture
def admin_instances(site: AuthAdminSite) -> Dict[str, BaseAdmin]:
    user_auth_app = site.get_admin_or_create(site.UserAuthApp)
    return {
        "user_auth_app": user_auth_app,
        "home_admin": site.get_admin_or_create(HomeAdmin),
        "user_admin": user_auth_app.get_admin_or_create(user_auth_app.UserAdmin),
        "role_admin": user_auth_app.get_admin_or_create(user_auth_app.RoleAdmin),
        "login_history_admin": user_auth_app.get_admin_or_create(LoginHistoryAdmin),
        "casbin_rule_admin": site.get_admin_or_create(CasbinRuleAdmin),
    }


@pytest.fixture
def client(site: AuthAdminSite) -> TestClient:
    with TestClient(app=site.fastapi, base_url="http://testserver") as c:
        yield c


@pytest.fixture
async def async_client(site: AuthAdminSite) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=site.fastapi, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def session():
    with sync_db.session_maker() as session:
        yield session


@pytest.fixture
async def async_session():
    async with async_db.session_maker() as session:
        yield session


@pytest.fixture(autouse=True)
def _setup_sync_db() -> Database:
    yield sync_db
    # Free connection pool resources
    sync_db.close()  # type: ignore


@pytest.fixture(autouse=True)
async def _setup_async_db() -> AsyncDatabase:
    yield async_db
    await async_db.async_close()  # Free connection pool resources
