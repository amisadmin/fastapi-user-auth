from datetime import date
from typing import Optional

import pytest
from fastapi import Depends
from fastapi_amis_admin.models import Field

from fastapi_user_auth.auth.models import BaseUser


# 自定义`User`模型,继承`User`
class MyUser(BaseUser, table=True):
    point: float = Field(default=0, title="积分", description="用户积分")
    phone: str = Field("", title="手机号", max_length=15)
    parent_id: Optional[int] = Field(None, title="上级", foreign_key="auth_user.id")
    birthday: Optional[date] = Field(None, title="出生日期")
    location: str = Field("", title="位置")


@pytest.mark.parametrize("logins", ["admin"], indirect=True)
async def test_custom_user_model(fake_auth, logins):
    # 使用自定义的`User`模型,创建auth对象
    fake_auth.user_model = MyUser
    app = logins.app
    client = logins.client

    #  注册auth用户管理路由
    @app.get("/get_user")
    async def get_user(user: MyUser = Depends(fake_auth.get_current_user)):
        assert isinstance(user, MyUser)
        user.point = 100
        user.phone = "123456789"
        return user

    response = client.get("/get_user")
    data = response.json()
    assert "parent_id" in data
    assert data["point"] == 100
    assert data["phone"] == "123456789"
