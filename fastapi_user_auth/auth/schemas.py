from enum import Enum
from typing import Optional

from fastapi_amis_admin.utils.pydantic import PYDANTIC_V2
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel, SecretStr
from sqlmodel import Field

from .models import BaseUser, EmailMixin, PasswordMixin, UsernameMixin


class BaseTokenData(BaseModel):
    id: int
    username: str


class UserLoginOut(BaseUser):
    """用户登录返回信息"""

    token_type: str = "bearer"
    access_token: Optional[str] = None
    password: Optional[SecretStr] = None


class UserRegIn(UsernameMixin, PasswordMixin, EmailMixin):
    """用户注册"""

    password2: str = Field(title=_("Confirm Password"), max_length=128)

    if PYDANTIC_V2:
        from pydantic import model_validator

        @model_validator(mode="after")
        def check_passwords_match(self):
            if self.password is not None and self.password.get_secret_value() != self.password2:
                raise ValueError("passwords do not match!")
            return self

    else:
        from pydantic import validator

        @validator("password2")
        def passwords_match_(cls, v, values, **kwargs):
            if "password" in values and v != values["password"]:
                raise ValueError("passwords do not match!")
            return v


# 默认保留的用户
class SystemUserEnum(str, Enum):
    ROOT = "root"
    ADMIN = "admin"
    GUEST = "guest"
