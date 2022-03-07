import pytest
from starlette.testclient import TestClient
from fastapi_user_auth.auth.models import User
from tests.test_auth.main import app


class UserClient:
    def __init__(self, client: TestClient = None, user: User = None) -> None:
        self.client: TestClient = client or TestClient(app)
        self.user: User = user


def get_login_client(username: str = None, password: str = None) -> UserClient:
    client = TestClient(app)
    if not username or not password:
        return UserClient()
    response = client.post('/auth/gettoken',
                           data={'username': username, 'password': password},
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    data = response.json()
    assert data['data']['access_token']
    user = User.parse_obj(data['data'])
    assert user.is_active
    assert user.username == username
    return UserClient(client=client, user=user)


@pytest.fixture(scope='session')
def logins(request) -> UserClient:
    user_data = {
        'admin': {"username": "admin", "password": "admin"},
        'vip': {"username": "vip", "password": "vip"},
        'test': {"username": "test", "password": "test"},
        'guest': {"username": None, "password": None},
    }
    user = user_data.get(request.param) or {}
    return get_login_client(**user)


@pytest.fixture(scope='session', autouse=True)
def startup():
    import asyncio
    asyncio.run(app.router.startup())
