from typing import Any, Dict, List

from casbin import AsyncEnforcer
from sqlalchemy import text
from sqlalchemy.orm import Session

from fastapi_user_auth.auth.models import CasbinRule
from fastapi_user_auth.auth.schemas import SystemUserEnum


# 执行casbin字符串规则
def permission_enforce(enforcer: AsyncEnforcer, subject: str, permission: str) -> bool:
    values = permission_decode(permission)
    return enforcer.enforce(subject, *values)


# 将casbin规则转化为字符串
def permission_encode(*field_values: str) -> str:
    """将casbin规则转化为字符串,从v1开始"""
    return "#".join(val for val in field_values if val is not None)


# 将字符串转化为casbin规则
def permission_decode(permission: str) -> List[str]:
    """将字符串转化为casbin规则"""
    return permission.strip("#").split("#")


async def get_subject_page_permissions(enforcer: AsyncEnforcer, *, subject: str, implicit: bool = False) -> List[str]:
    """根据指定subject主体获取casbin规则"""
    if implicit:
        permissions = await enforcer.get_implicit_permissions_for_user(subject)
        permissions = [perm for perm in permissions if perm[-2] == "page"]  # 只获取page权限
    else:
        permissions = enforcer.get_filtered_policy(0, subject, "", "", "page")
    return [permission_encode(*permission[1:]) for permission in permissions]


async def update_subject_roles(enforcer: AsyncEnforcer, *, subject: str, role_keys: List[str]):
    """更新casbin主体权限角色"""
    # todo 避免角色链循环
    new_roles = {(subject, role) for role in role_keys if role and role != subject}
    await enforcer.delete_roles_for_user(subject)
    if new_roles:
        await enforcer.add_grouping_policies(new_roles)


async def update_subject_page_permissions(
    enforcer: AsyncEnforcer,
    *,
    subject: str,
    permissions: List[str],
) -> List[str]:
    """根据指定subject主体更新casbin规则,会删除旧的规则,添加新的规则"""
    # 获取主体的页面权限
    old_rules = enforcer.get_filtered_policy(0, subject, "", "", "page")
    old_rules = {tuple(i) for i in old_rules}
    # 添加新的权限
    new_rules = set()
    for permission in permissions:
        perm = permission_decode(permission)
        if len(perm) == 3:  # 默认为allow
            perm.append("allow")
        new_rules.add((subject, *perm))
    remove_rules = old_rules - new_rules
    add_rules = new_rules - old_rules
    if remove_rules:
        # 删除旧的权限
        # 注意casbin缓存的是list,不能是tuple,否则无法删除.
        # 可能存在不存在的rule,导致批量删除失败. 例如站点页面
        # 如果存在重复的rule,则会导致批量删除失败.
        # todo 这个api有bug, 更换其他api
        await enforcer.remove_policies([list(rule) for rule in remove_rules])
    if add_rules:
        await enforcer.add_policies(add_rules)
    return permissions


def get_subject_policy_matrix(
    enforcer: AsyncEnforcer,
    *,
    subject: str,
    permission: str,
    rows: List[Dict[str, Any]],
):
    """体字段权限配置,存在allow,deny,default(未设置)"""
    default_, allow_, deny_ = [], [], []
    # bfc1eec773c2b331#page:list#page
    v1, v2, v3 = permission_decode(permission)
    v2 = "page:select" if v2 == "page" else v2
    rules = enforcer.get_filtered_policy(0, subject, v1, "", v2, "")
    allow_rule = set()
    deny_rule = set()
    for rule in rules:
        effect = rule[-1]
        perm = permission_encode(*rule[1:-1])
        if effect == "allow":
            allow_rule.add(perm)
        else:
            deny_rule.add(perm)
    for row in rows:
        perm = row["rol"]
        reverse = row.get("reverse", False)
        allow_item = deny_item = default_item = {"checked": False, **row}
        if reverse ^ (perm in allow_rule):
            allow_item = {"checked": True, **row}
        elif reverse ^ (perm in deny_rule):
            deny_item = {"checked": True, **row}
        else:
            default_item = {"checked": True, **row}
        default_.append(default_item)
        allow_.append(allow_item)
        deny_.append(deny_item)
    return [default_, allow_, deny_]


def get_subject_effect_matrix(
    enforcer: AsyncEnforcer,
    *,
    subject: str,
    rows: List[Dict[str, Any]],
):
    """主体字段权限执行结果,只有allow和deny两种情况"""
    allow_, deny_ = [], []
    for row in rows:
        v1, v2, v3 = permission_decode(row["rol"])
        eff = enforcer.enforce(subject, v1, v2, v3)
        reverse = row.get("reverse", False)
        allow_item = deny_item = {"checked": False, **row}
        if reverse ^ eff:
            allow_item = {"checked": True, **row}
        else:
            deny_item = {"checked": True, **row}
        allow_.append(allow_item)
        deny_.append(deny_item)
    return [allow_, deny_]


async def update_subject_data_permissions(
    enforcer: AsyncEnforcer,
    *,
    subject: str,
    permission: str,
    policy_matrix: List[List[Dict[str, Any]]],
    super_subject: str = "u:root",
) -> str:
    """更新casbin数据字段权限或数据集权限"""
    # [[{'label': '默认', 'rol': 'page:list:uid', 'col': 'default', 'checked': True}]]
    if not policy_matrix:
        return "success"
    remove_, allow_, deny_ = policy_matrix
    # 删除旧的权限
    # bfc1eec773c2b331#page:list#page
    v1, v2, v3 = permission_decode(permission)
    if super_subject != "u:" + SystemUserEnum.ROOT:
        #  检查当前用户是否有对应的权限,只有自己拥有的权限才能分配给其他主体
        eff = enforcer.enforce(super_subject, v1, v2, v3)
        if not eff:
            return "没有更新权限"

    def to_rules(items: List[dict], is_allow: bool = True) -> set:
        rules = set()
        for item in items:
            if not item["checked"]:
                continue
            reverse = item.get("reverse", False)
            # 检查当前用户是否有对应的权限,只有自己拥有的权限才能分配给其他主体
            perm = permission_decode(item["rol"])
            if super_subject != "u:" + SystemUserEnum.ROOT and (reverse ^ enforcer.enforce(super_subject, *perm)):
                continue
            effect = "allow" if is_allow ^ reverse else "deny"
            rules.add((subject, *perm, effect))
        return rules

    add_rules = to_rules(allow_, is_allow=True) | to_rules(deny_, is_allow=False)
    # 删除旧的权限.注意必须在添加新的权限之前删除旧的权限,否则会导致重复的权限
    v2 = "page:select" if v2 == "page" else v2
    await enforcer.remove_filtered_policy(0, subject, v1, "", v2, "")
    if add_rules:
        await enforcer.add_policies(add_rules)
    return "success"


def delete_duplicate_rule(session: Session):
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
    session.execute(stmt)
    session.commit()
