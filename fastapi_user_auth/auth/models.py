from typing import Optional

from fastapi_amis_admin.amis.components import ColumnImage, InputImage
from fastapi_amis_admin.crud.parser import LabelField
from fastapi_amis_admin.models import Field
from fastapi_amis_admin.utils.translation import i18n as _
from sqlalchemy import func, select

from fastapi_user_auth.mixins.models import (  # noqa F401
    CreateTimeMixin,
    CUDTimeMixin,
    DeleteTimeMixin,
    EmailMixin,
    PasswordMixin,
    PkMixin,
    UpdateTimeMixin,
    UsernameMixin,
)


class BaseUser(PkMixin, CUDTimeMixin, UsernameMixin, PasswordMixin, EmailMixin):
    __tablename__ = "auth_user"
    is_active: bool = Field(default=True, title=_("Is Active"))
    nickname: Optional[str] = Field("", title=_("Nickname"), max_length=40)
    avatar: Optional[str] = Field(
        "",
        title=_("Avatar"),
        max_length=255,
        amis_form_item=InputImage(maxLength=1, maxSize=2 * 1024 * 1024),
        amis_table_column=ColumnImage(width=50, height=50, enlargeAble=True),
    )

    @property
    def is_authenticated(self) -> bool:
        return not self.delete_time and self.is_active

    @property
    def display_name(self) -> str:
        return self.nickname or self.username

    @property
    def identity(self) -> str:
        return self.username


class User(BaseUser, table=True):
    """用户"""

    pass


class BaseRole(PkMixin, CUDTimeMixin):
    __tablename__ = "auth_role"

    key: str = Field(title=_("Role ID"), max_length=40, unique=True, index=True, nullable=False)  # 角色标识
    name: str = Field(default="", title=_("Role Name"), max_length=40)  # 角色名称
    desc: str = Field(default="", title=_("Role description"), max_length=400, amis_form_item="textarea")  # 角色描述


class Role(BaseRole, table=True):
    """角色"""

    pass


class CasbinRule(PkMixin, table=True):
    __tablename__ = "auth_casbin_rule"

    ptype: str = Field(title="Policy Type")
    v0: str = Field(title="Subject")
    v1: str = Field(title="Object")
    v2: Optional[str] = Field(None, title="Action")
    v3: Optional[str] = Field(None, title="Group")
    v4: Optional[str] = Field(None, title="Effect")
    v5: Optional[str] = Field(None)

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


"""
SELECT v0, GROUP_CONCAT(t.name) as roles, GROUP_CONCAT(t.key) as role_keys
FROM (select v0, auth_role.name, auth_role.key
      from auth_casbin_rule
               left join auth_role on casbin_rule.v1 = concat('r:', auth_role.key)
      where auth_casbin_rule.ptype = 'g') as t
GROUP BY v0;
"""
# casbin主体拥有的角色列表,使用','分隔.
CasbinSubjectRolesQuery = (
    select(
        CasbinRule.v0.label("subject"),
        func.group_concat(Role.name).label("role_names"),
        func.group_concat(Role.key).label("role_keys"),
    )
    .where(CasbinRule.ptype == "g")
    .outerjoin(Role, CasbinRule.v1 == "r:" + Role.key)  # sqlalchemy#5275
    .group_by(CasbinRule.v0)
    .subquery()
)

UserRoleNameLabel = LabelField(
    CasbinSubjectRolesQuery.c.role_names.label("role_names"),
    field=Field("", title=_("Permission role")),  # 权限角色
)


class LoginHistory(PkMixin, CreateTimeMixin, table=True):
    """用户登录记录"""

    __tablename__ = "auth_login_history"

    user_id: Optional[int] = Field(None, title=_("User ID"))  # 用户ID
    login_name: str = Field("", title=_("Login name"), max_length=20)  # 登录名
    ip: str = Field("", title=_("User IP"), max_length=20)  # 登录IP
    ip_info: str = Field("", title=_("IP information"), max_length=255)  # IP信息
    client: str = Field("", title=_("Client"), max_length=20)  # 客户端
    user_agent: str = Field("", title=_("User-agent"), max_length=400)  # 浏览器
    login_type: str = Field("", title=_("Login type"), max_length=20)  # 登录类型
    login_status: str = Field(
        _("Successful login"),
        title=_("Login status"),
        max_length=20,
        description=_("Successful login, incorrect password, account locked, etc."),
    )  # 登录成功,
    # 登录成功,密码错误,账号被锁定等
    forwarded_for: str = Field("", title=_("Forward IP"), max_length=60)  # 转发IP
