from typing import Annotated, Optional, Type

from fastapi import Depends

from fastapi_user_auth.auth.exceptions import AuthError, ErrorCode
from fastapi_user_auth.auth.models import User
from fastapi_user_auth.globals._sites import auth

# 自定义用户ORM模型
UserModel: Type[User] = auth.user_model
# 获取当前登录的用户
get_user_or_none = auth.get_current_user

CurrentUserOrNone = Annotated[Optional[UserModel], Depends(get_user_or_none)]


def get_user_or_error(user: CurrentUserOrNone):
    """获取当前登录用户,如果未登录则抛出异常"""
    if not user:
        raise AuthError(status=ErrorCode.USER_IS_NOT_LOGIN, msg="用户未登录")
    return user


CurrentUser = Annotated[UserModel, Depends(get_user_or_error)]
