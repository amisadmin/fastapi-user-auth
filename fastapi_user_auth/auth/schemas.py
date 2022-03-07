from pydantic import validator, SecretStr, BaseModel
from sqlmodel import Field
from .models import UserUsername, UserPassword, UserEmail, BaseUser


class BaseTokenData(BaseModel):
    id: int
    username: str


class UserLoginOut(BaseUser):
    """用户登录返回信息"""
    token_type: str = 'bearer'
    access_token: str = None
    password: SecretStr = None


class UserRegIn(UserUsername, UserPassword, UserEmail):
    """用户注册"""
    password2: str = Field(title='重复密码', max_length=128)

    @validator('password2')
    def passwords_match(cls, v, values, **kwargs):
        print(v, values)
        if 'password' in values and v != values['password']:
            raise ValueError('passwords do not match!')
        return v
