from functools import lru_cache
from typing import Any, Callable, Dict, List, Type

from casbin import Enforcer
from fastapi_amis_admin.admin import FormAdmin, ModelAdmin, PageSchemaAdmin
from fastapi_amis_admin.admin.admin import AdminGroup, BaseActionAdmin
from fastapi_amis_admin.utils.pydantic import model_fields
from pydantic import BaseModel

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
            "value": casbin_permission_encode(admin.unique_id, "admin:page"),
            "sort": admin.page_schema.sort,
        }
        if isinstance(admin, BaseActionAdmin):
            item["children"] = []
            if isinstance(admin, ModelAdmin):
                item["children"].append({"label": "查看列表", "value": casbin_permission_encode(admin.unique_id, "admin:list")})
            elif isinstance(admin, FormAdmin) and "submit" not in admin.registered_admin_actions:
                item["children"].append({"label": "提交", "value": casbin_permission_encode(admin.unique_id, "admin:submit")})
            for admin_action in admin.registered_admin_actions.values():
                item["children"].append(
                    {
                        "label": admin_action.label,
                        "value": casbin_permission_encode(admin.unique_id, f"admin:{admin_action.name}"),
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
        if option.get("children"):
            option["children"] = filter_options(option["children"], filter_func)
        result.append(option)
    return result


def admin_schema_fields_rows(
    admin: PageSchemaAdmin,
    schema: Type[BaseModel],
    action: str,
) -> List[Dict[str, Any]]:
    """解析schema字段,用于amis组件"""
    rows = []
    if not schema:
        return rows
    for field in model_fields(schema).values():
        label = field.field_info.title or field.name
        alias = field.alias or field.name
        label_prefix = {
            "list": "列表展示",
            "filter": "列表筛选",
            "update": "更新",
            "bulk_update": "批量更新",
            "create": "新增",
            "bulk_create": "批量新增",
            "read": "查看",
        }.get(action, "")
        label = f"{label_prefix}-{label}" if label_prefix else label
        rows.append(
            {
                "label": label,
                "rol": f"{action}:{alias}",
            }
        )
    return rows


def get_admin_action_fields_rows(
    admin: PageSchemaAdmin,
    action: str,
) -> List[Dict[str, Any]]:
    """获取指定页面权限的字段权限,用于amis组件"""
    rows = []
    if isinstance(admin, ModelAdmin):  # 模型管理
        if action in {"list"}:
            rows.extend(admin_schema_fields_rows(admin, admin.schema_list, "list"))  # 列表展示模型
            rows.extend(admin_schema_fields_rows(admin, admin.schema_filter, "filter"))  # 列表筛选模型
        elif action in {"update", "bulk_update"}:
            rows = admin_schema_fields_rows(admin, admin.schema_update, action)  # 更新模型
        elif action in {"create", "bulk_create"}:
            rows = admin_schema_fields_rows(admin, admin.schema_create, action)  # 创建模型
        elif action in {"read"}:
            rows = admin_schema_fields_rows(admin, admin.schema_read, action)  # 详情模型
    elif isinstance(admin, FormAdmin):  # 表单管理
        if action in {"submit"}:  # 表单提交模型
            rows = admin_schema_fields_rows(admin, admin.schema, action)
    return rows


async def get_admin_action_options_by_subject(
    enforcer: Enforcer,
    subject: str,
    group: AdminGroup,
):
    """获取指定subject主体的页面权限,用于amis组件"""
    # 获取全部页面权限
    options = get_admin_action_options(group)
    # 获取当前登录用户的权限
    if subject != "u:" + SystemUserEnum.ROOT:  # Root用户拥有全部权限
        permissions = await casbin_get_subject_permissions(enforcer, subject=subject, implicit=True)
        # 过滤掉没有权限的页面
        options = filter_options(options, filter_func=lambda item: item["value"] in permissions)
    return options


# 将casbin规则转化为字符串
def casbin_permission_encode(*field_values: str) -> str:
    """将casbin规则转化为字符串,从v1开始"""
    return "#".join(field_values)


# 将字符串转化为casbin规则
def casbin_permission_decode(permission: str) -> List[str]:
    """将字符串转化为casbin规则"""
    field_values = permission.split("#")
    # 如果长度少于5,则补充为5个
    if len(field_values) < 5:
        field_values.extend([""] * (5 - len(field_values)))
    return field_values


async def casbin_get_subject_permissions(enforcer: Enforcer, subject: str, implicit: bool = False) -> List[str]:
    """根据指定subject主体获取casbin规则"""
    if implicit:
        permissions = await enforcer.get_implicit_permissions_for_user(subject)
    else:
        permissions = await enforcer.get_permissions_for_user(subject)
    return [casbin_permission_encode(*permission[1:]) for permission in permissions]


async def casbin_update_subject_roles(enforcer: Enforcer, subject: str, role_keys: str = None):
    """更新casbin主体权限角色"""
    # 删除旧的角色
    await enforcer.remove_filtered_grouping_policy(0, subject)
    # 添加新的角色
    if role_keys:
        await enforcer.add_grouping_policies([(subject, "r:" + role) for role in role_keys.split(",") if role])


async def casbin_update_subject_permissions(enforcer: Enforcer, subject: str, permissions: List[str]) -> List[str]:
    """根据指定subject主体更新casbin规则,会删除旧的规则,添加新的规则"""
    # 删除旧的权限
    await enforcer.remove_filtered_policy(0, subject)
    # 添加新的权限
    await enforcer.add_policies([(subject, v1, v2) for v1, v2 in [permission.split("#") for permission in permissions]])
    # 返回动作处理结果
    return permissions


# print("get_roles_for_user",await enforcer.get_roles_for_user(subject))
# print("get_permissions_for_user", await enforcer.get_permissions_for_user(subject))
# print("get_implicit_permissions_for_user", await enforcer.get_implicit_permissions_for_user(subject))
# print("get_implicit_roles_for_user", await enforcer.get_implicit_roles_for_user(subject))
