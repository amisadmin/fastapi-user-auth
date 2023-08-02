from typing import List, Union

from sqlalchemy import select, text
from sqlalchemy.sql.selectable import ScalarSelect
from sqlalchemy_database import AsyncDatabase, Database

from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import CasbinRule, Role, User
from fastapi_user_auth.utils import casbin_get_subject_page_permissions, casbin_permission_encode


async def casbin_get_subject_permissions_by_db(
    db: Union[AsyncDatabase, Database], subject: Union[str, ScalarSelect]
) -> List[str]:
    """根据指定subject主体获取casbin规则"""
    permissions = await db.async_scalars(select(CasbinRule).where(CasbinRule.ptype == "p", CasbinRule.v0 == subject))
    return [casbin_permission_encode(rule.v1, rule.v2, rule.v3, rule.v4, rule.v5) for rule in permissions]


async def casbin_get_permissions_by_role_id(auth: Auth, role_id: str, implicit: bool = False) -> List[str]:
    """根据角色id获取casbin规则,是否包含隐式权限"""
    role_key = await auth.db.async_scalar(select(Role.key).where(Role.id == role_id))
    return casbin_get_subject_page_permissions(auth.enforcer, subject="r:" + role_key, implicit=implicit)


async def casbin_get_permissions_by_user_id(auth: Auth, user_id: str, implicit: bool = False) -> List[str]:
    """根据用户id获取casbin规则,是否包含隐式权限"""
    username = await auth.db.async_scalar(select(User.username).where(User.id == user_id))
    return casbin_get_subject_page_permissions(auth.enforcer, subject="u:" + username, implicit=implicit)


async def casbin_delete_duplicate_rule(auth: Auth):
    """删除重复的casbin规则,只保留一条"""
    stmt = text(
        f"""DELETE FROM {CasbinRule.__tablename__}
            WHERE id NOT IN (
                SELECT id
                FROM (
                    SELECT MIN(id) AS id
                    FROM {CasbinRule.__tablename__}
                    GROUP BY ptype, v0, v1, v2, v3, v4, v5
                ) AS unique_rule_id
            );
        """
    )
    await auth.db.async_execute(stmt)
    await auth.db.async_commit()
