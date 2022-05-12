from datetime import datetime
from typing import Optional, List, Any
from fastapi_amis_admin.amis.components import InputImage, ColumnImage
from fastapi_amis_admin.models.fields import Field
from pydantic import EmailStr, SecretStr
from sqlalchemy import Column, String, and_
from sqlmodel import SQLModel, Relationship, select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel.sql.expression import SelectOfScalar

SelectOfScalar.inherit_cache = True


class SQLModelTable(SQLModel):
    id: int = Field(default=None, primary_key=True, nullable=False)


class UserRoleLink(SQLModel, table=True):
    __tablename__ = 'auth_user_roles'
    user_id: Optional[int] = Field(
        default=None, foreign_key="auth_user.id", primary_key=True, nullable=False
    )
    role_id: Optional[int] = Field(
        default=None, foreign_key="auth_role.id", primary_key=True, nullable=False
    )


class UserGroupLink(SQLModel, table=True):
    __tablename__ = 'auth_user_groups'
    user_id: Optional[int] = Field(
        default=None, foreign_key="auth_user.id", primary_key=True, nullable=False
    )
    group_id: Optional[int] = Field(
        default=None, foreign_key="auth_group.id", primary_key=True, nullable=False
    )


class GroupRoleLink(SQLModel, table=True):
    __tablename__ = 'auth_group_roles'
    group_id: Optional[int] = Field(
        default=None, foreign_key="auth_group.id", primary_key=True, nullable=False
    )
    role_id: Optional[int] = Field(
        default=None, foreign_key="auth_role.id", primary_key=True, nullable=False
    )


class RolePermissionLink(SQLModel, table=True):
    __tablename__ = 'auth_role_permissions'
    role_id: Optional[int] = Field(
        default=None, foreign_key="auth_role.id", primary_key=True, nullable=False
    )
    permission_id: Optional[int] = Field(
        default=None, foreign_key="auth_permission.id", primary_key=True, nullable=False
    )


class UserUsername(SQLModel):
    username: str = Field(
        title='用户名', max_length=32,
        sa_column=Column(String(32), unique=True, index=True, nullable=False)
    )


class PasswordStr(SecretStr, str):
    pass


class UserPassword(SQLModel):
    password: PasswordStr = Field(
        title='密码', max_length=128,
        sa_column=Column(String(128), nullable=False),
        amis_form_item='input-password'
    )


class UserEmail(SQLModel):
    email: EmailStr = Field(
        title='邮箱',
        sa_column=Column(String(50), unique=True, index=True, nullable=False),
        amis_form_item='input-email'
    )


class BaseUser(UserEmail, UserPassword, UserUsername, SQLModelTable):
    is_active: bool = Field(default=True, title='是否激活')
    nickname: str = Field(None, title='昵称', max_length=32)
    avatar: str = Field(None, title='头像', max_length=100,
                        amis_form_item=InputImage(maxLength=1, maxSize=2 * 1024 * 1024,
                                                  receiver='post:/admin/file/upload'),
                        amis_table_column=ColumnImage(width=50, height=50, enlargeAble=True))
    point: float = Field(default=0, title='点数')
    create_time: datetime = Field(default_factory=datetime.utcnow, title='创建时间')

    class Config:
        use_enum_values = True

    @property
    def is_authenticated(self) -> bool:
        return self.is_active

    @property
    def display_name(self) -> str:
        return self.nickname or self.username

    @property
    def identity(self) -> str:
        return self.username

    def _stmt_exists_role(self, *role_whereclause: Any) -> SelectOfScalar[int]:
        # check user role
        user_role_ids = select(Role.id).join(
            UserRoleLink, (UserRoleLink.user_id == self.id) & (UserRoleLink.role_id == Role.id)
        ).where(*role_whereclause)
        # check user group
        role_group_ids = select(GroupRoleLink.group_id).join(
            Role, and_(*role_whereclause, Role.id == GroupRoleLink.role_id))
        group_user_ids = select(UserGroupLink.user_id).where(UserGroupLink.user_id == self.id).where(
            UserGroupLink.group_id.in_(role_group_ids))
        return select(1).where(user_role_ids.exists() | group_user_ids.exists())

    async def has_role(self, roles: List[str], session: AsyncSession) -> bool:
        """
        检查用户是否属于指定用户角色,或属于包含指定用户角色的用户组
        @param roles:
        @param session:
        @return:
        """
        stmt = self._stmt_exists_role(Role.key.in_(roles))
        result = await session.execute(stmt)
        return result.one_or_none() is not None

    async def has_group(self, groups: List[str], session: AsyncSession) -> bool:
        """
        检查用户是否属于指定用户组
        @param groups:
        @param session:
        @return:
        """
        group_ids = select(Group.id).join(
            UserGroupLink, (UserGroupLink.user_id == self.id) & (UserGroupLink.group_id == Group.id)
        ).where(Group.key.in_(groups))
        stmt = select(1).where(group_ids.exists())
        result = await session.execute(stmt)
        return result.one_or_none() is not None

    async def has_permission(self, permissions: List[str], session: AsyncSession) -> bool:
        """
        检查用户是否属于拥有指定权限的用户角色
        @param permissions:
        @param session:
        @return:
        """
        role_ids = select(RolePermissionLink.role_id).join(
            Permission, Permission.key.in_(permissions) & (Permission.id == RolePermissionLink.permission_id))
        stmt = self._stmt_exists_role(Role.id.in_(role_ids))
        result = await session.execute(stmt)
        return result.one_or_none() is not None


class User(BaseUser, table=True):
    """用户"""
    __tablename__ = 'auth_user'
    phone: str = Field(None, title='手机号', max_length=15)
    parent_id: int = Field(None, title='父级', foreign_key="auth_user.id")
    # parent: Optional["User"] = Relationship()  # todo 自身关联问题
    # children: List["User"]= Relationship(back_populates="parent")
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRoleLink)
    groups: List["Group"] = Relationship(back_populates="users", link_model=UserGroupLink)


class BaseRBAC(SQLModelTable):
    key: str = Field(..., title='标识', max_length=20,
                     sa_column=Column(String(20), unique=True, index=True, nullable=False))
    name: str = Field(..., title='名称', max_length=20)
    desc: str = Field(default='', title='描述', max_length=400, amis_form_item='textarea')


class Role(BaseRBAC, table=True):
    """角色"""
    __tablename__ = 'auth_role'
    users: List[User] = Relationship(back_populates="roles", link_model=UserRoleLink)
    groups: List["Group"] = Relationship(back_populates="roles", link_model=GroupRoleLink)
    permissions: List["Permission"] = Relationship(back_populates="roles", link_model=RolePermissionLink)


class Group(BaseRBAC, table=True):
    """用户组"""
    __tablename__ = 'auth_group'
    parent_id: int = Field(None, title='父级', foreign_key="auth_group.id")
    users: List[User] = Relationship(back_populates="groups", link_model=UserGroupLink)
    roles: List["Role"] = Relationship(back_populates="groups", link_model=GroupRoleLink)


class Permission(BaseRBAC, table=True):
    """权限"""
    __tablename__ = 'auth_permission'
    roles: List["Role"] = Relationship(back_populates="permissions", link_model=RolePermissionLink)
