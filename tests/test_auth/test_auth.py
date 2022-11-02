from sqlalchemy import select
from sqlalchemy.orm import selectinload

from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import User


async def test_create_role_user(auth: Auth):
    user = await auth.create_role_user("admin2")
    await auth.db.async_refresh(user)
    assert user.username == "admin2"
    # test user roles
    stmt = select(User).options(selectinload(User.roles)).where(User.username == "admin2")
    result = await auth.db.async_scalar(stmt)
    role = result.roles[0]
    assert role.key == "admin2"


async def test_authenticate_user(fake_auth: Auth):
    # error
    user = await fake_auth.authenticate_user("admin", "admin1")
    assert user is None

    # admin
    user = await fake_auth.authenticate_user("admin", "admin")
    assert user.username == "admin"
