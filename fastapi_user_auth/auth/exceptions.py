from typing import Any, Dict, Optional

from fastapi import HTTPException
from fastapi_amis_admin.crud import BaseApiOut
from fastapi_amis_admin.models import IntegerChoices


class ErrorCode(IntegerChoices):
    """常用错误码"""

    SUCCESS = (0, "Success")  # 成功
    FAIL = (1, "Fail")  # 失败
    PARAMS_ERROR = (2, "Parameter error")  # 参数错误
    RETRY = (10, "Retry")  # 重试
    RETRY_LATER = (11, "Try again later")  # 稍后重试
    # 用户相关错误
    USER_NOT_FOUND = (40100, "User does not exist")  # 用户不存在
    USER_PASSWORD_ERROR = (40101, "Username or password is incorrect")  # 用户名或者密码错误
    USER_IS_EXIST = (40102, "User already exists")  # 用户已存在
    USER_NAME_IS_EXIST = (40103, "Username already exists")  # 用户名已存在
    USER_MOBILE_IS_EXIST = (40104, "User mobile phone number already exists")  # 用户手机号已存在
    USER_EMAIL_IS_EXIST = (40105, "User mailbox already exists")  # 用户邮箱已存在

    # 用户权限相关
    USER_IS_NOT_LOGIN = (40200, "User is not logged in")  # 用户未登录
    USER_IS_NOT_ACTIVE = (40201, "User is not activated")  # 用户未激活
    USER_PERMISSION_DENIED = (40203, "Insufficient user rights")  # 用户权限不足
    USER_IS_NOT_ADMIN = (40204, "User is not an administrator")  # 用户不是管理员
    # 系统错误
    SYSTEM_ERROR = (50000, "System error")  # 系统错误
    SYSTEM_BUSY = (50001, "The system is busy")  # 系统繁忙


class ApiException(HTTPException):
    def __init__(
            self,
            detail: Any,
            status_code: int = 200,
            content: Any = None,
            headers: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.content = content
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class ApiError(ApiException):
    """API异常基类"""

    def __init__(
            self,
            status: int = ErrorCode.FAIL,
            msg: str = "",
            headers: Optional[Dict[str, Any]] = None,
            **extra,
    ):
        self.status = status
        self.extra = extra
        super().__init__(
            detail=msg,
            content=BaseApiOut(status=status, msg=msg, **extra).dict(),
            headers=headers,
        )


class AuthError(ApiError):
    """认证异常"""

    pass
