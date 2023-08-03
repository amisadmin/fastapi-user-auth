from copy import copy
from functools import lru_cache
from typing import Any, Callable, Dict, List, Sequence, Tuple, Type

from casbin import Enforcer
from fastapi_amis_admin.admin import FormAdmin, ModelAdmin, PageSchemaAdmin
from fastapi_amis_admin.admin.admin import AdminGroup, BaseActionAdmin, BaseAdminSite
from fastapi_amis_admin.utils.pydantic import model_fields
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from fastapi_user_auth.auth.models import CasbinRule
from fastapi_user_auth.auth.schemas import SystemUserEnum


@lru_cache()
def get_admin_action_options(
    group: AdminGroup,
) -> List[Dict[str, Any]]:
    """获取全部页面权限,用于amis组件"""
    options = []
    for admin in group:  # 这里已经同步了数据库,所以只从这里配置权限就行了
        admin: PageSchemaAdmin
        if not admin.page_schema:
            continue
        item = {
            "label": admin.page_schema.label,
            "value": casbin_permission_encode(admin.unique_id, "page", "page"),
            "sort": admin.page_schema.sort,
        }
        if isinstance(admin, BaseActionAdmin):
            item["children"] = []
            if isinstance(admin, ModelAdmin):
                item["children"].append(
                    {"label": "查看列表", "value": casbin_permission_encode(admin.unique_id, "page:list", "page")}
                )
                item["children"].append(
                    {"label": "筛选列表", "value": casbin_permission_encode(admin.unique_id, "page:filter", "page")}
                )
            elif isinstance(admin, FormAdmin) and "submit" not in admin.registered_admin_actions:
                item["children"].append(
                    {"label": "提交", "value": casbin_permission_encode(admin.unique_id, "page:submit", "page")}
                )
            for admin_action in admin.registered_admin_actions.values():
                # todo admin_action 下可能有多个action,需要遍历
                item["children"].append(
                    {
                        "label": admin_action.label,
                        "value": casbin_permission_encode(admin.unique_id, f"page:{admin_action.name}", "page"),
                    }
                )
        elif isinstance(admin, AdminGroup):
            item["children"] = get_admin_action_options(admin)
        options.append(item)
    if options:
        options.sort(key=lambda p: p["sort"] or 0, reverse=True)
    return options


def filter_options(options: List[Dict[str, Any]], filter_func: Callable[[Dict[str, Any]], bool]) -> List[Dict[str, Any]]:
    """过滤选项,包含子选项.如果选项的children为空,则删除该选项"""
    result = []
    for option in options:
        if not filter_func(option):
            continue
        option = copy(option)  # 防止children被修改
        if option.get("children"):
            option["children"] = filter_options(option["children"], filter_func)
        result.append(option)
    return result


def get_schema_fields_name_label(
    schema: Type[BaseModel],
    *,
    prefix: str = "",
    exclude_required: bool = False,
    exclude: Sequence[str] = None,
) -> Dict[str, str]:
    """获取schema字段名和标签"""
    if not schema:
        return {}
    fields = {}
    for field in model_fields(schema).values():
        if exclude_required and field.required:
            continue
        name = field.alias or field.name
        if exclude and name in exclude:
            continue
        label = field.field_info.title or field.name
        fields[name] = prefix + label
    return fields


def get_admin_action_options_by_subject(
    enforcer: Enforcer,
    subject: str,
    group: AdminGroup,
):
    """获取指定subject主体的页面权限,用于amis组件"""
    # 获取全部页面权限
    options = get_admin_action_options(group)
    # 获取当前登录用户的权限
    if subject != "u:" + SystemUserEnum.ROOT:  # Root用户拥有全部权限
        # 过滤掉没有权限的页面
        options = filter_options(options, filter_func=lambda item: casbin_permission_enforce(enforcer, subject, item["value"]))
    return options


# 获取全部admin上下级关系
def get_admin_grouping(group: AdminGroup) -> List[Tuple[str, str]]:
    children = []
    for admin in group:
        if admin is admin.app:
            continue
        children.append((admin.app.unique_id, admin.unique_id))
        if isinstance(admin, AdminGroup):
            children.extend(get_admin_grouping(admin))
    return children


# 更新casbin admin资源角色关系
def casbin_update_site_grouping(enforcer: Enforcer, site: BaseAdminSite):
    """更新casbin admin资源角色关系"""
    roles = enforcer.get_filtered_named_grouping_policy("g2", 0)
    old_roles = {tuple(role) for role in roles}
    new_roles = set(get_admin_grouping(site))
    remove_roles = old_roles - new_roles
    add_roles = new_roles - old_roles
    if remove_roles:  # 删除旧的资源角色
        enforcer.remove_named_grouping_policies("g2", [list(role) for role in remove_roles])
    if add_roles:  # 添加新的资源角色
        enforcer.add_named_grouping_policies("g2", add_roles)


# 执行casbin字符串规则
def casbin_permission_enforce(enforcer: Enforcer, subject: str, permission: str) -> bool:
    values = casbin_permission_decode(permission)
    return enforcer.enforce(subject, *values)


# 将casbin规则转化为字符串
def casbin_permission_encode(*field_values: str) -> str:
    """将casbin规则转化为字符串,从v1开始"""
    return "#".join(val for val in field_values if val is not None)


# 将字符串转化为casbin规则
def casbin_permission_decode(permission: str) -> List[str]:
    """将字符串转化为casbin规则"""
    return permission.strip("#").split("#")


def casbin_get_subject_page_permissions(enforcer: Enforcer, *, subject: str, implicit: bool = False) -> List[str]:
    """根据指定subject主体获取casbin规则"""
    if implicit:
        permissions = enforcer.get_implicit_permissions_for_user(subject)
        permissions = [perm for perm in permissions if perm[-2] == "page"]  # 只获取page权限
    else:
        permissions = enforcer.get_filtered_policy(0, subject, "", "", "page")
    return [casbin_permission_encode(*permission[1:]) for permission in permissions]


def casbin_update_subject_roles(enforcer: Enforcer, *, subject: str, role_keys: List[str]):
    """更新casbin主体权限角色"""
    # todo 避免角色链循环
    new_roles = {(subject, role) for role in role_keys if role and role != subject}
    enforcer.delete_roles_for_user(subject)
    if new_roles:
        enforcer.add_grouping_policies(new_roles)


def casbin_update_subject_page_permissions(
    enforcer: Enforcer,
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
        perm = casbin_permission_decode(permission)
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
        enforcer.remove_policies([list(rule) for rule in remove_rules])
    if add_rules:
        enforcer.add_policies(add_rules)
    return permissions


def casbin_get_subject_field_policy_matrix(
    enforcer: Enforcer,
    *,
    subject: str,
    permission: str,
    rows: List[Dict[str, Any]],
):
    """体字段权限配置,存在allow,deny,default(未设置)"""
    default_, allow_, deny_ = [], [], []
    # bfc1eec773c2b331#page:list#page
    v1, v2, v3 = casbin_permission_decode(permission)
    rules = enforcer.get_filtered_policy(0, subject, v1, "", v2, "")
    allow_rule = set()
    deny_rule = set()
    for rule in rules:
        effect = rule[-1]
        perm = casbin_permission_encode(*rule[1:-1])
        if effect == "allow":
            allow_rule.add(perm)
        else:
            deny_rule.add(perm)
    for row in rows:
        perm = row["rol"]
        allow_item = deny_item = default_item = {"checked": False, **row}
        if perm in allow_rule:
            allow_item = {"checked": True, **row}
        elif perm in deny_rule:
            deny_item = {"checked": True, **row}
        else:
            default_item = {"checked": True, **row}
        default_.append(default_item)
        allow_.append(allow_item)
        deny_.append(deny_item)
    return [default_, allow_, deny_]


def casbin_get_subject_field_effect_matrix(
    enforcer: Enforcer,
    *,
    subject: str,
    rows: List[Dict[str, Any]],
):
    """主体字段权限执行结果,只有allow和deny两种情况"""
    allow_, deny_ = [], []
    for row in rows:
        v1, v2, v3 = casbin_permission_decode(row["rol"])
        eff = enforcer.enforce(subject, v1, v2, v3)
        allow_item = deny_item = {"checked": False, **row}
        if eff:
            allow_item = {"checked": True, **row}
        else:
            deny_item = {"checked": True, **row}
        allow_.append(allow_item)
        deny_.append(deny_item)
    return [allow_, deny_]


def casbin_update_subject_field_permissions(
    enforcer: Enforcer,
    *,
    subject: str,
    permission: str,
    field_policy_matrix: List[Dict[str, Any]],
    super_subject: str = "u:root",
) -> str:
    """更新casbin字段权限"""
    # [[{'label': '默认', 'rol': 'page:list:uid', 'col': 'default', 'checked': True}]]
    if not field_policy_matrix:
        return "success"
    remove_, allow_, deny_ = field_policy_matrix
    # 删除旧的权限
    # bfc1eec773c2b331#page:list#page
    v1, v2, v3 = casbin_permission_decode(permission)
    if super_subject != "u:" + SystemUserEnum.ROOT:
        #  检查当前用户是否有对应的权限,只有自己拥有的权限才能分配给其他主体
        eff = enforcer.enforce(super_subject, v1, v2, v3)
        if not eff:
            return "没有更新权限"

    def item_check(item: dict):
        if not item["checked"]:
            return False
        if super_subject == "u:" + SystemUserEnum.ROOT:
            return True
        return enforcer.enforce(super_subject, *casbin_permission_decode(item["rol"]))

    allow_rules = {(subject, *casbin_permission_decode(item["rol"]), "allow") for item in allow_ if item_check(item)}
    deny_rules = {(subject, *casbin_permission_decode(item["rol"]), "deny") for item in deny_ if item_check(item)}
    add_rules = allow_rules | deny_rules
    # 删除旧的权限.注意必须在添加新的权限之前删除旧的权限,否则会导致重复的权限
    enforcer.remove_filtered_policy(0, subject, v1, "", v2, "")
    # if remove_rules:
    #
    #     enforcer.remove_policies(remove_rules)
    if add_rules:
        enforcer.add_policies(add_rules)
    return "success"


def casbin_delete_duplicate_rule(session: Session):
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
