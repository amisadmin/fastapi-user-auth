import pytest
from casbin import AsyncEnforcer
from sqlalchemy import delete

from fastapi_user_auth.admin import AuthAdminSite
from fastapi_user_auth.admin.utils import update_casbin_site_grouping
from fastapi_user_auth.auth.models import CasbinRule
from fastapi_user_auth.utils.casbin import (
    get_subject_page_permissions,
    update_subject_page_permissions,
    update_subject_roles,
)


@pytest.fixture
def enforcer(site: AuthAdminSite) -> AsyncEnforcer:
    return site.auth.enforcer


@pytest.fixture
async def fake_data(db, site, admin_instances, enforcer: AsyncEnforcer):
    # 清空数据
    await db.async_execute(delete(CasbinRule))
    home_admin_unique_id = admin_instances["home_admin"].unique_id
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    admin_user_rules = [
        CasbinRule(ptype="g", v0="u:admin", v1="r:admin"),
        CasbinRule(ptype="p", v0="r:admin", v1=home_admin_unique_id, v2="page", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:list", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:filter", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:create", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:update", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:delete", v3="page", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:bulk_delete", v3="page", v4="allow"),
        CasbinRule(
            ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:update_subject_page_permissions", v3="page", v4="allow"
        ),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:list:email", v3="page:list", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:filter:email", v3="page:filter", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:create:email", v3="page:create", v4="allow"),
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:update:email", v3="page:update", v4="allow"),
    ]
    test_user_rules = [
        CasbinRule(ptype="g", v0="u:test", v1="r:test"),
        CasbinRule(ptype="p", v0="r:test", v1=home_admin_unique_id, v2="page", v3="page", v4="allow"),
    ]
    db.add_all(admin_user_rules)
    db.add_all(test_user_rules)
    await db.async_commit()
    # 加载页面分组
    await update_casbin_site_grouping(enforcer, site)
    # 重新加载权限
    await enforcer.load_policy()


async def test_casbin_get_subject_page_permissions(enforcer: AsyncEnforcer, admin_instances: dict, fake_data):
    permissions = await get_subject_page_permissions(enforcer, subject="u:admin", implicit=False)
    assert not permissions
    permissions = await get_subject_page_permissions(enforcer, subject="u:admin", implicit=True)
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    assert f"{user_admin_unique_id}#page#page#allow" in permissions
    assert f"{user_admin_unique_id}#page:list#page#allow" in permissions
    assert f"{user_admin_unique_id}#page:list:email#page:list#allow" not in permissions
    assert permissions
    permissions2 = await get_subject_page_permissions(enforcer, subject="r:admin", implicit=False)
    assert permissions2 == permissions


async def test_casbin_update_subject_roles(enforcer: AsyncEnforcer, admin_instances: dict, fake_data):
    admin_roles = await enforcer.get_implicit_roles_for_user("u:admin")
    assert "r:admin" in admin_roles
    await update_subject_roles(enforcer, subject="u:admin", role_keys=["r:test"])
    admin_roles = await enforcer.get_implicit_roles_for_user("u:admin")
    assert "r:admin" not in admin_roles
    assert "r:test" in admin_roles


async def test_casbin_update_subject_page_permissions(enforcer: AsyncEnforcer, admin_instances: dict, fake_data):
    permissions = await get_subject_page_permissions(enforcer, subject="r:admin", implicit=True)
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    casbin_rule_admin_unique_id = admin_instances["casbin_rule_admin"].unique_id
    assert f"{user_admin_unique_id}#page#page#allow" in permissions
    assert f"{casbin_rule_admin_unique_id}#page#page#allow" not in permissions
    await update_subject_page_permissions(
        enforcer,
        subject="r:admin",
        permissions=[
            f"{casbin_rule_admin_unique_id}#page#page",  # v1,v2,v3. 默认v4=allow
            f"{casbin_rule_admin_unique_id}#page:list#page#allow",  # v1,v2,v3,v4
        ],
    )
    permissions = await get_subject_page_permissions(enforcer, subject="r:admin", implicit=True)
    # 原来的page权限应该被删除
    assert f"{user_admin_unique_id}#page#page#allow" not in permissions
    # 新的page权限应该被添加
    assert f"{casbin_rule_admin_unique_id}#page#page#allow" in permissions
    assert f"{casbin_rule_admin_unique_id}#page:list#page#allow" in permissions
    # 非page权限应该保留
    assert enforcer.has_policy("r:admin", user_admin_unique_id, "page:list:email", "page:list", "allow")
    assert enforcer.has_policy("r:admin", user_admin_unique_id, "page:filter:email", "page:filter", "allow")
