from fastapi import FastAPI
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_user_auth.auth.auth import Auth, AuthRouter
from fastapi_user_auth.auth.models import Role, Permission, Group, User
from tests.test_auth.db import get_db

app = FastAPI()

#  创建auth实例


auth = Auth(db=get_db())

#  注册auth基础路由
auth_router = AuthRouter(auth=auth)
app.include_router(auth_router.router)


# 创建初始化数据库表
@app.on_event("startup")
async def startup():
    async with auth.db.engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    async with auth.db.session_maker() as session:
        await create_fake_data(session)


async def create_fake_data(session: AsyncSession):
    # init permission
    admin_perm = Permission(key='admin', name='admin permission')
    vip_perm = Permission(key='vip', name='vip permission')
    test_perm = Permission(key='test', name='test permission')
    session.add_all([admin_perm, vip_perm, test_perm])
    await session.commit()
    await session.flush([admin_perm, vip_perm, test_perm])
    # init role
    admin_role = Role(key='admin', name='admin role', permissions=[admin_perm])
    vip_role = Role(key='vip', name='vip role', permissions=[vip_perm])
    test_role = Role(key='test', name='test role', permissions=[test_perm])
    session.add_all([admin_role, vip_role, test_role])
    await session.commit()
    await session.flush([admin_role, vip_role, test_role])
    # init group
    admin_group = Group(key='admin', name='admin group', roles=[admin_role])
    vip_group = Group(key='vip', name='vip group', roles=[vip_role])
    test_group = Group(key='test', name='test group', roles=[test_role])
    session.add_all([admin_group, vip_group, test_group])
    await session.commit()
    await session.flush([admin_group, vip_group, test_group])
    # init user
    admin_user = User(username='admin', password=auth.pwd_context.hash('admin'), email='admin@amis.work',
                      roles=[admin_role], groups=[admin_group])
    vip_user = User(username='vip', password=auth.pwd_context.hash('vip'), email='vip@amis.work', roles=[vip_role],
                    groups=[vip_group])
    test_user = User(username='test', password=auth.pwd_context.hash('test'), email='test@amis.work', roles=[test_role],
                     groups=[test_group])
    session.add_all([admin_user, vip_user, test_user])
    await session.commit()
    await session.flush([admin_user, vip_user, test_user])
