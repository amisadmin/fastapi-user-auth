from typing import Type

from fastapi_amis_admin import globals as g

from fastapi_user_auth.admin import AuthAdminSite
from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import User

site: AuthAdminSite

auth: Auth

# 自定义用户ORM模型
UserModel: Type[User]


def __getattr__(name: str):
    if name == "auth":
        return g.site.auth
    elif name == "UserModel" and not hasattr(g, name):
        return g.site.auth.user_model
    return getattr(g, name)
