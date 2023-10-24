from typing import Any, Dict, Optional

from fastapi import HTTPException
from fastapi_amis_admin.crud import BaseApiOut
from fastapi_amis_admin.models import IntegerChoices
from fastapi_amis_admin.utils.translation import i18n as _


class ErrorCode(IntegerChoices):
    """Common Error Codes"""

    SUCCESS = (0, _("Success"))
    FAIL = (1, _("Failure"))
    PARAMS_ERROR = (2, _("Parameter error"))
    RETRY = (10, _("Retry"))
    RETRY_LATER = (11, _("Retry later"))

    # User-related errors
    USER_NOT_FOUND = (40100, _("User not found"))
    USER_PASSWORD_ERROR = (40101, _("Username or password is incorrect"))
    USER_IS_EXIST = (40102, _("User already exists"))
    USER_NAME_IS_EXIST = (40103, _("Username already exists"))
    USER_MOBILE_IS_EXIST = (40104, _("User mobile number already exists"))
    USER_EMAIL_IS_EXIST = (40105, _("User email already exists"))

    # User permission related
    USER_IS_NOT_LOGIN = (40200, _("User is not logged in"))
    USER_IS_NOT_ACTIVE = (40201, _("User is not activated"))
    USER_PERMISSION_DENIED = (40203, _("Insufficient user permissions"))
    USER_IS_NOT_ADMIN = (40204, _("User is not an administrator"))

    # System errors
    SYSTEM_ERROR = (50000, _("System error"))
    SYSTEM_BUSY = (50001, _("System busy"))


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
    """API exception base class"""

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
    """Authentication exception"""

    pass
