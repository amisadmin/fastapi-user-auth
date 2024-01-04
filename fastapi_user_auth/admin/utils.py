from copy import copy
from functools import lru_cache
from typing import Any, Callable, Dict, List, Tuple

from casbin import AsyncEnforcer
from fastapi_amis_admin.admin import FormAdmin, ModelAdmin, PageSchemaAdmin
from fastapi_amis_admin.admin.admin import AdminGroup, BaseActionAdmin, BaseAdminSite

from fastapi_user_auth.auth.schemas import SystemUserEnum
from fastapi_user_auth.utils.casbin import permission_encode, permission_enforce


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
            "value": permission_encode(admin.unique_id, "page", "page"),
            "sort": admin.page_schema.sort,
        }
        if isinstance(admin, BaseActionAdmin):
            item["children"] = []
            if isinstance(admin, ModelAdmin):
                item["children"].append({"label": "查看列表", "value": permission_encode(admin.unique_id, "page:list", "page")})
                item["children"].append({"label": "筛选列表", "value": permission_encode(admin.unique_id, "page:filter", "page")})
            elif isinstance(admin, FormAdmin) and "submit" not in admin.registered_admin_actions:
                item["children"].append({"label": "提交", "value": permission_encode(admin.unique_id, "page:submit", "page")})
            for admin_action in admin.registered_admin_actions.values():
                # todo admin_action 下可能有多个action,需要遍历
                item["children"].append(
                    {
                        "label": admin_action.label,
                        "value": permission_encode(admin.unique_id, f"page:{admin_action.name}", "page"),
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
        option = copy(option)  # 防止children被修改
        has_children = False
        if option.get("children"):
            option["children"] = filter_options(option["children"], filter_func)
            has_children = bool(option["children"])
        if not filter_func(option) and not has_children:  # 没有父级权限,并且没有子级权限
            continue
        result.append(option)
    return result


def get_admin_action_options_by_subject(
    enforcer: AsyncEnforcer,
    subject: str,
    group: AdminGroup,
):
    """获取指定subject主体的页面权限,用于amis组件"""
    # 获取全部页面权限
    options = get_admin_action_options(group)
    # 获取当前登录用户的权限
    if subject != "u:" + SystemUserEnum.ROOT:  # Root用户拥有全部权限
        # 过滤掉没有权限的页面
        options = filter_options(options, filter_func=lambda item: permission_enforce(enforcer, subject, item["value"]))
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
async def update_casbin_site_grouping(enforcer: AsyncEnforcer, site: BaseAdminSite):
    """更新casbin admin资源角色关系"""
    roles = enforcer.get_filtered_named_grouping_policy("g2", 0)
    old_roles = {tuple(role) for role in roles}
    new_roles = set(get_admin_grouping(site))
    remove_roles = old_roles - new_roles
    add_roles = new_roles - old_roles
    if remove_roles:  # 删除旧的资源角色
        await enforcer.remove_named_grouping_policies("g2", [list(role) for role in remove_roles])
    if add_roles:  # 添加新的资源角色
        await enforcer.add_named_grouping_policies("g2", add_roles)
