from datetime import datetime
from typing import Optional

from fastapi_amis_admin.models import Field, SQLModel
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import EmailStr, SecretStr
from sqlalchemy import func
from sqlmodel import AutoString

from fastapi_user_auth.utils.sqltypes import SecretStrType


class PkMixin(SQLModel):
    id: Optional[int] = Field(
        default=None, title="ID", primary_key=True, nullable=False, sa_column_kwargs={"autoincrement": True}
    )


class CreateTimeMixin(SQLModel):
    create_time: datetime = Field(default_factory=datetime.now, title=_("Create Time"), index=True)


class UpdateTimeMixin(SQLModel):
    update_time: Optional[datetime] = Field(
        default_factory=datetime.now,
        title=_("Update Time"),
        index=True,
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )


class DeleteTimeMixin(SQLModel):
    delete_time: Optional[datetime] = Field(None, title=_("Delete Time"))


class CUDTimeMixin(CreateTimeMixin, UpdateTimeMixin, DeleteTimeMixin):
    """Create, Update, Delete Time Mixin"""

    pass


class UsernameMixin(SQLModel):
    username: str = Field(title=_("Username"), max_length=32, unique=True, index=True, nullable=False)


class PasswordMixin(SQLModel):
    password: SecretStr = Field(
        title=_("Password"), max_length=128, sa_type=SecretStrType, nullable=False, amis_form_item="input-password"
    )


class EmailMixin(SQLModel):
    """If you need to define the email field as unique, you can achieve it by adding the following parameters in the subclass:
    __table_args__ = (UniqueConstraint("email", name="email"),)
    """

    email: Optional[EmailStr] = Field(
        None, title=_("Email"), sa_type=AutoString, index=True, nullable=True, amis_form_item="input-email"
    )
