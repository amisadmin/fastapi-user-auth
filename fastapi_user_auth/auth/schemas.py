from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel, SecretStr, validator
from sqlmodel import Field

from .models import BaseUser, EmailMixin, PasswordMixin, UsernameMixin


class BaseTokenData(BaseModel):
    id: int
    username: str


class UserLoginOut(BaseUser):
    """用户登录返回信息"""

    token_type: str = "bearer"
    access_token: str = None
    password: SecretStr = None


class UserRegIn(UsernameMixin, PasswordMixin, EmailMixin):
    """用户注册"""

    password2: str = Field(title=_("Confirm Password"), max_length=128)

    @validator("password2")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("passwords do not match!")
        return v
