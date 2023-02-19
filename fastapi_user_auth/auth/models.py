from datetime import datetime
from typing import List, Optional

from fastapi_amis_admin.amis.components import ColumnImage, InputImage
from fastapi_amis_admin.models.fields import Field
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import EmailStr, SecretStr
from sqlalchemy import func
from sqlalchemy.schema import ForeignKey
from sqlmodel import Relationship

try:
    from sqlmodelx import SQLModel
except ImportError:
    from sqlmodel import SQLModel


class PkMixin(SQLModel):
    id: int = Field(default=None, primary_key=True, nullable=False)


class CreateTimeMixin(SQLModel):
    create_time: datetime = Field(default_factory=datetime.now, title=_("Create Time"))


class UpdateTimeMixin(SQLModel):
    update_time: Optional[datetime] = Field(
        default_factory=datetime.now,
        title=_("Update Time"),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )


class UsernameMixin(SQLModel):
    username: str = Field(title=_("Username"), max_length=32, unique=True, index=True, nullable=False)


class PasswordStr(SecretStr, str):
    pass


class PasswordMixin(SQLModel):
    password: PasswordStr = Field(title=_("Password"), max_length=128, nullable=False, amis_form_item="input-password")


class EmailMixin(SQLModel):
    """If you need to define the email field as unique, you can achieve it by adding the following parameters in the subclass:
    __table_args__ = (UniqueConstraint("email", name="email"),)
    """

    email: EmailStr = Field(None, title=_("Email"), index=True, nullable=True, amis_form_item="input-email")


class UserRoleLink(SQLModel, table=True):  # todo: remove
    __tablename__ = "auth_user_roles"
    user_id: int = Field(
        primary_key=True,
        sa_column_args=(
            ForeignKey(
                "auth_user.id",
                ondelete="CASCADE",
            ),
        ),
    )
    role_id: int = Field(
        primary_key=True,
        sa_column_args=(
            ForeignKey(
                "auth_role.id",
                ondelete="CASCADE",
            ),
        ),
    )


class BaseUser(PkMixin, UsernameMixin, PasswordMixin, EmailMixin, CreateTimeMixin):
    __tablename__ = "auth_user"
    is_active: bool = Field(default=True, title=_("Is Active"))
    nickname: str = Field(None, title=_("Nickname"), max_length=40)
    avatar: str = Field(
        None,
        title=_("Avatar"),
        max_length=255,
        amis_form_item=InputImage(maxLength=1, maxSize=2 * 1024 * 1024),
        amis_table_column=ColumnImage(width=50, height=50, enlargeAble=True),
    )

    @property
    def is_authenticated(self) -> bool:
        return self.is_active

    @property
    def display_name(self) -> str:
        return self.nickname or self.username

    @property
    def identity(self) -> str:
        return self.username


class User(BaseUser, table=True):
    """用户"""

    roles: List["Role"] = Relationship(link_model=UserRoleLink)


class Role(PkMixin, table=True):
    """角色"""

    __tablename__ = "auth_role"

    key: str = Field(title=_("Identify"), max_length=40, unique=True, index=True, nullable=False)
    name: str = Field(default="", title=_("Name"), max_length=40)
    desc: str = Field(default="", title=_("Description"), max_length=400, amis_form_item="textarea")


class CasbinRule(PkMixin, table=True):  # type: ignore

    __tablename__ = "casbin_rule"

    ptype: str = Field(title="Policy Type")
    v0: str = Field(title="Subject")
    v1: str = Field(title="Object")
    v2: str = Field(None, title="Action")
    v3: str = Field(None)
    v4: str = Field(None)
    v5: str = Field(None)

    def __str__(self) -> str:
        arr = [self.ptype]
        # pylint: disable=invalid-name
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self) -> str:
        return f'<CasbinRule {self.id}: "{str(self)}">'
