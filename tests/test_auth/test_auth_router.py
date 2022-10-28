import pytest

from tests.test_auth.conftest import UserClient


@pytest.mark.parametrize("logins", ["admin"], indirect=True)
def test_route_userinfo(logins: UserClient):
    res = logins.client.get("/auth/userinfo")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["id"] == logins.user.id
    assert data["username"] == logins.user.username
    assert "password" not in data


@pytest.mark.skip("The UserClient is global, We can skip it to avoid affecting other tests")
@pytest.mark.parametrize("logins", ["admin"], indirect=True)
def test_route_logout(logins: UserClient):
    res = logins.client.get("/auth/logout", allow_redirects=False)
    assert res.status_code == 307
    assert res.headers["location"] == "/"
    assert res.headers["set-cookie"].find('Authorization=""') != -1

    res = logins.client.get("/auth/userinfo")
    assert res.status_code == 403
    assert res.json()["detail"] == "Forbidden"
