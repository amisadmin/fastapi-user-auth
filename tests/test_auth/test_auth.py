from fastapi_user_auth.auth import Auth


async def test_create_role_user(auth: Auth):
    user = await auth.create_role_user("admin2")
    await auth.db.async_refresh(user)
    assert user.username == "admin2"
    # test user roles
    result = auth.has_role_for_user(user.username, roles="admin2")
    assert result


async def test_authenticate_user(fake_auth: Auth):
    # error
    user = await fake_auth.authenticate_user("admin", "admin1")
    assert user is None

    # admin
    user = await fake_auth.authenticate_user("admin", "admin")
    assert user.username == "admin"
