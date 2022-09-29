from datetime import datetime
from typing import Any, List, Optional, Sequence, Union

from fastapi_amis_admin.amis.components import ColumnImage, InputImage
from fastapi_amis_admin.models.fields import Field
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import EmailStr, SecretStr
from sqlalchemy import and_, func
from sqlalchemy.orm import Session
from sqlalchemy.sql.selectable import Exists
from sqlmodel import Relationship, select

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
    email: EmailStr = Field(None, title=_("Email"), unique=True, index=True, nullable=True, amis_form_item="input-email")


class UserRoleLink(SQLModel, table=True):
    __tablename__ = "auth_user_roles"
    user_id: Optional[int] = Field(default=None, foreign_key="auth_user.id", primary_key=True, nullable=False)
    role_id: Optional[int] = Field(default=None, foreign_key="auth_role.id", primary_key=True, nullable=False)


class UserGroupLink(SQLModel, table=True):
    __tablename__ = "auth_user_groups"
    user_id: Optional[int] = Field(default=None, foreign_key="auth_user.id", primary_key=True, nullable=False)
    group_id: Optional[int] = Field(default=None, foreign_key="auth_group.id", primary_key=True, nullable=False)


class GroupRoleLink(SQLModel, table=True):
    __tablename__ = "auth_group_roles"
    group_id: Optional[int] = Field(default=None, foreign_key="auth_group.id", primary_key=True, nullable=False)
    role_id: Optional[int] = Field(default=None, foreign_key="auth_role.id", primary_key=True, nullable=False)


class RolePermissionLink(SQLModel, table=True):
    __tablename__ = "auth_role_permissions"
    role_id: Optional[int] = Field(default=None, foreign_key="auth_role.id", primary_key=True, nullable=False)
    permission_id: Optional[int] = Field(default=None, foreign_key="auth_permission.id", primary_key=True, nullable=False)


class BaseUser(PkMixin, UsernameMixin, PasswordMixin, EmailMixin, CreateTimeMixin):
    __tablename__ = "auth_user"
    __table_args__ = {"extend_existing": True}
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

    def _exists_role(self, *role_whereclause: Any) -> Exists:
        # check user role
        user_role_ids = (
            select(Role.id)
            .join(UserRoleLink, (UserRoleLink.user_id == self.id) & (UserRoleLink.role_id == Role.id))
            .where(*role_whereclause)
        )
        # check user group
        role_group_ids = select(GroupRoleLink.group_id).join(Role, and_(*role_whereclause, Role.id == GroupRoleLink.role_id))
        group_user_ids = (
            select(UserGroupLink.user_id)
            .where(UserGroupLink.user_id == self.id)
            .where(UserGroupLink.group_id.in_(role_group_ids))
        )
        return user_role_ids.exists() | group_user_ids.exists()

    def _exists_roles(self, roles: List[str]) -> Exists:
        """
        检查用户是否属于指定用户角色,或属于包含指定用户角色的用户组
        Args:
            roles:

        Returns:

        """
        return self._exists_role(Role.key.in_(roles))

    def _exists_groups(self, groups: List[str]) -> Exists:
        """
        检查用户是否属于指定用户组
        Args:
            groups:

        Returns:

        """
        group_ids = (
            select(Group.id)
            .join(UserGroupLink, (UserGroupLink.user_id == self.id) & (UserGroupLink.group_id == Group.id))
            .where(Group.key.in_(groups))
        )
        return group_ids.exists()

    def _exists_permissions(self, permissions: List[str]) -> Exists:
        """
        检查用户是否属于拥有指定权限的用户角色
        Args:
            permissions:

        Returns:

        """
        role_ids = select(RolePermissionLink.role_id).join(
            Permission, Permission.key.in_(permissions) & (Permission.id == RolePermissionLink.permission_id)
        )
        return self._exists_role(Role.id.in_(role_ids))

    def has_requires(
        self,
        session: Session,
        *,
        roles: Union[str, Sequence[str]] = None,
        groups: Union[str, Sequence[str]] = None,
        permissions: Union[str, Sequence[str]] = None,
    ) -> bool:
        """
        检查用户是否属于拥有指定的RBAC权限
        Args:
            session: sqlalchemy `Session`;异步`AsyncSession`,请使用`run_sync`方法.
            roles: 角色列表
            groups: 用户组列表
            permissions: 权限列表

        Returns:
            检测成功返回`True`
        """
        stmt = select(1)
        if groups:
            groups_list = [groups] if isinstance(groups, str) else list(groups)
            stmt = stmt.where(self._exists_groups(groups_list))
        if roles:
            roles_list = [roles] if isinstance(roles, str) else list(roles)
            stmt = stmt.where(self._exists_roles(roles_list))
        if permissions:
            permissions_list = [permissions] if isinstance(permissions, str) else list(permissions)
            stmt = stmt.where(self._exists_permissions(permissions_list))
        return bool(session.scalar(stmt))


class User(BaseUser, table=True):
    """用户"""

    roles: List["Role"] = Relationship(link_model=UserRoleLink)
    groups: List["Group"] = Relationship(link_model=UserGroupLink)


class BaseRBAC(PkMixin):
    __table_args__ = {"extend_existing": True}
    key: str = Field(..., title=_("Identify"), max_length=20, unique=True, index=True, nullable=False)
    name: str = Field(..., title=_("Name"), max_length=20)
    desc: str = Field(default="", title=_("Description"), max_length=400, amis_form_item="textarea")


class Role(BaseRBAC, table=True):
    """角色"""

    __tablename__ = "auth_role"
    groups: List["Group"] = Relationship(back_populates="roles", link_model=GroupRoleLink)
    permissions: List["Permission"] = Relationship(back_populates="roles", link_model=RolePermissionLink)


class BaseGroup(BaseRBAC):
    __tablename__ = "auth_group"
    parent_id: int = Field(None, title=_("Parent"), foreign_key="auth_group.id")


class Group(BaseGroup, table=True):
    """用户组"""

    roles: List["Role"] = Relationship(back_populates="groups", link_model=GroupRoleLink)


class Permission(BaseRBAC, table=True):
    """权限"""

    __tablename__ = "auth_permission"
    roles: List["Role"] = Relationship(back_populates="permissions", link_model=RolePermissionLink)
