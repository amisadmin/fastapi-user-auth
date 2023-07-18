from typing import List, Union

from sqlalchemy import select
from sqlalchemy.sql.selectable import ScalarSelect
from sqlalchemy_database import AsyncDatabase, Database

from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import CasbinRule, Role, User
from fastapi_user_auth.utils import casbin_get_subject_permissions, casbin_permission_encode


async def casbin_get_subject_permissions_by_db(
    db: Union[AsyncDatabase, Database], subject: Union[str, ScalarSelect]
) -> List[str]:
    """根据指定subject主体获取casbin规则"""
    permissions = await db.async_scalars(select(CasbinRule).where(CasbinRule.ptype == "p", CasbinRule.v0 == subject))
    return [casbin_permission_encode(rule.v1, rule.v2, rule.v3, rule.v4, rule.v5) for rule in permissions]


async def casbin_get_permissions_by_role_id(auth: Auth, role_id: str, implicit: bool = False) -> List[str]:
    """根据角色id获取casbin规则,是否包含隐式权限"""
    role_key = await auth.db.async_scalar(select(Role.key).where(Role.id == role_id))
    return await casbin_get_subject_permissions(auth.enforcer, "r:" + role_key, implicit=implicit)


async def casbin_get_permissions_by_user_id(auth: Auth, user_id: str, implicit: bool = False) -> List[str]:
    """根据用户id获取casbin规则,是否包含隐式权限"""
    username = await auth.db.async_scalar(select(User.username).where(User.id == user_id))
    return await casbin_get_subject_permissions(auth.enforcer, "u:" + username, implicit=implicit)
