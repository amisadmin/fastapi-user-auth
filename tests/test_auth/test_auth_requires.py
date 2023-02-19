from typing import Tuple, Union

import pytest
from fastapi import Depends, HTTPException
from starlette.requests import Request
from starlette.responses import Response

from fastapi_user_auth.auth.auth import Auth
from fastapi_user_auth.auth.models import User
from tests.test_auth.conftest import UserClient


@pytest.fixture(autouse=True)
def setup(logins: UserClient):
    app = logins.app
    auth = logins.auth

    # auth decorator
    @app.get("/auth/user")
    @auth.requires()
    def user(request: Request):
        return request.user

    @app.get("/auth/admin_roles")
    @auth.requires("admin")
    def admin_roles(request: Request):
        return request.user

    @app.get("/auth/vip_roles")
    @auth.requires(["vip"])
    def vip_roles(request: Request):
        return request.user

    @app.get("/auth/admin_or_vip_roles")
    @auth.requires(roles=["admin", "vip"])
    def admin_or_vip_roles(request: Request):
        return request.user

    # auth async decorator
    @app.get("/auth/admin_roles_async")
    @auth.requires("admin")
    async def admin_roles_async(request: Request):
        return request.user

    # auth depend

    @app.get("/auth/user_1", dependencies=[Depends(auth.backend.authenticate)])
    def user_1(request: Request):
        if request.user:
            return request.user
        else:
            raise HTTPException(status_code=403)

    @app.get("/auth/user_2")
    def user_2(request: Request, auth_result: Tuple[Auth, User] = Depends(auth.backend.authenticate)):
        if request.user:
            return request.user
        else:
            raise HTTPException(status_code=403)

    @app.get("/auth/user_3")
    async def user_3(request: Request):
        if await auth.requires()(request):
            return request.user

    @app.get("/auth/user_4")
    async def user_4(request: Request, user: User = Depends(auth.get_current_user)):
        if user is None:
            raise HTTPException(status_code=403)
        return request.user

    @app.get("/auth/admin_roles_depend_1", dependencies=[Depends(auth.requires("admin")())])
    def admin_roles_1(request: Request):
        return request.user

    @app.get("/auth/admin_roles_depend_2")
    def admin_roles_2(request: Request, auth_result: Union[bool, Response] = Depends(auth.requires("admin")())):
        return request.user


@pytest.mark.parametrize("logins", ["guest"], indirect=True)
def test_router_token(logins: UserClient):
    response = logins.client.post(
        "/auth/gettoken",
        data={"username": "admin", "password": "Incorrect"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    data = response.json()
    assert data["data"] is None


@pytest.mark.parametrize("logins", ["admin", "vip", "test", "guest"], indirect=True)
def test_router_userinfo(logins: UserClient):
    response = logins.client.get("/auth/userinfo")
    data = response.json()
    if logins.user:
        assert data["data"]["id"] == logins.user.id
        assert data["data"]["username"] == logins.user.username
    else:
        assert data["detail"] == "Forbidden"


path_all = {
    "/auth/user",
    "/auth/user_1",
    "/auth/user_2",
    "/auth/user_3",
    "/auth/user_4",
    # auth role
    "/auth/admin_roles",
    "/auth/vip_roles",
    "/auth/admin_or_vip_roles",
    # auth depend
    "/auth/admin_roles_depend_1",
    "/auth/admin_roles_depend_2",
}
path_admin_auth = {
    "/auth/user",
    "/auth/user_1",
    "/auth/user_2",
    "/auth/user_3",
    "/auth/user_4",
    "/auth/admin_roles",
    "/auth/admin_or_vip_roles",
    "/auth/admin_roles_depend_1",
    "/auth/admin_roles_depend_2",
    "/auth/admin_roles_async",
}

path_vip_auth = {
    "/auth/user",
    "/auth/user_1",
    "/auth/user_2",
    "/auth/user_3",
    "/auth/user_4",
    "/auth/vip_roles",
    "/auth/admin_or_vip_roles",
}
path_test_auth = {
    "/auth/user",
    "/auth/user_1",
    "/auth/user_2",
    "/auth/user_3",
    "/auth/user_4",
}


@pytest.mark.parametrize("logins", ["admin"], indirect=True)
@pytest.mark.parametrize("path", list(path_admin_auth))
def test_admin_auth(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["id"] == logins.user.id
    assert data["username"] == logins.user.username


@pytest.mark.parametrize("logins", ["admin"], indirect=True)
@pytest.mark.parametrize("path", list(path_all - path_admin_auth))
def test_admin_forbidden(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["detail"] == "Forbidden"


@pytest.mark.parametrize("logins", ["vip"], indirect=True)
@pytest.mark.parametrize("path", list(path_vip_auth))
def test_vip_auth(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["id"] == logins.user.id
    assert data["username"] == logins.user.username


@pytest.mark.parametrize("logins", ["vip"], indirect=True)
@pytest.mark.parametrize("path", list(path_all - path_vip_auth))
def test_vip_forbidden(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["detail"] == "Forbidden"


@pytest.mark.parametrize("logins", ["test"], indirect=True)
@pytest.mark.parametrize("path", list(path_test_auth))
def test_test_auth(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["id"] == logins.user.id
    assert data["username"] == logins.user.username


@pytest.mark.parametrize("logins", ["guest"], indirect=True)
@pytest.mark.parametrize("path", list(path_all))
def test_guest_forbidden(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data["detail"] == "Forbidden"
