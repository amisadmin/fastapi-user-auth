import pytest
from fastapi import FastAPI, HTTPException, Depends
from starlette.requests import Request

from tests.test_auth.conftest import UserClient
from tests.test_auth.main import app, auth

subapp1 = FastAPI()
app.mount('/subapp1', subapp1)

subapp2 = FastAPI()
app.mount('/subapp2', subapp2)
auth.backend.attach_middleware(subapp2)

subapp3 = FastAPI(dependencies=[Depends(auth.requires('admin')())])
app.mount('/subapp3', subapp3)



# auth decorator
@subapp1.get("/auth/user")
@auth.requires()
def user(request: Request):
    return request.user

@subapp2.get("/auth/user")
def user(request: Request):
    if request.user:
        return request.user
    else:
        raise HTTPException(status_code=403)


@subapp3.get("/auth/user")
@auth.requires()
def user(request: Request):
    return request.user


path_admin_auth = {
    "/subapp1/auth/user",
    "/subapp2/auth/user",
    "/subapp3/auth/user",
}


@pytest.mark.parametrize("logins", ['admin'], indirect=True)
@pytest.mark.parametrize("path", list(path_admin_auth))
def test_admin_auth(logins: UserClient, path):
    response = logins.client.get(path)
    data = response.json()
    assert data['id'] == logins.user.id
    assert data['username'] == logins.user.username
