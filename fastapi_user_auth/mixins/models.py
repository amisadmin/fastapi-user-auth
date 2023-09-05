from datetime import datetime
from typing import Optional

from fastapi_amis_admin.models.fields import Field
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import EmailStr, SecretStr
from sqlalchemy import func

try:
    from sqlmodelx import SQLModel
except ImportError:
    from sqlmodel import SQLModel


class PkMixin(SQLModel):
    id: int = Field(default=None, title="ID", primary_key=True, nullable=False)


class CreateTimeMixin(SQLModel):
    create_time: datetime = Field(default_factory=datetime.now, title=_("Create Time"))


class UpdateTimeMixin(SQLModel):
    update_time: Optional[datetime] = Field(
        default_factory=datetime.now,
        title=_("Update Time"),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )


class DeleteTimeMixin(SQLModel):
    delete_time: Optional[datetime] = Field(None, title=_("Delete Time"))


class CUDTimeMixin(CreateTimeMixin, UpdateTimeMixin, DeleteTimeMixin):
    """Create, Update, Delete Time Mixin"""

    pass


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
