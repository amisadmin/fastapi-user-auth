import pytest
from casbin import Enforcer
from sqlalchemy import delete

from fastapi_user_auth.auth.models import CasbinRule
from fastapi_user_auth.site import AuthAdminSite
from fastapi_user_auth.utils import (
    casbin_get_subject_page_permissions,
    casbin_update_site_grouping,
    casbin_update_subject_page_permissions,
    casbin_update_subject_roles,
    get_admin_action_options,
    get_admin_action_options_by_subject,
    get_admin_grouping,
)


@pytest.fixture
def enforcer(site: AuthAdminSite) -> Enforcer:
    return site.auth.enforcer


@pytest.fixture
async def fake_data(db, site, admin_instances, enforcer: Enforcer):
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
        CasbinRule(ptype="p", v0="r:admin", v1=user_admin_unique_id, v2="page:update_subject_permissions", v3="page", v4="allow"),
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
    await casbin_update_site_grouping(enforcer, site)
    # 重新加载权限
    await enforcer.load_policy()


def test_get_admin_action_options(site: AuthAdminSite, admin_instances: dict):
    options = get_admin_action_options(site)
    print(options)
    assert len(options) == 3
    assert options[0]["value"] == admin_instances["home_admin"].unique_id + "#page#page"
    assert options[1]["value"] == admin_instances["user_auth_app"].unique_id + "#page#page"
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    assert options[1]["children"][0]["value"] == user_admin_unique_id + "#page#page"
    children = options[1]["children"][0]["children"]
    assert children[0]["value"] == user_admin_unique_id + "#page:list#page"
    assert children[1]["value"] == user_admin_unique_id + "#page:filter#page"
    assert children[2]["value"] == user_admin_unique_id + "#page:create#page"
    assert children[3]["value"] == user_admin_unique_id + "#page:update#page"
    assert children[4]["value"] == user_admin_unique_id + "#page:delete#page"
    assert children[5]["value"] == user_admin_unique_id + "#page:bulk_delete#page"
    assert children[6]["value"] == user_admin_unique_id + "#page:update_subject_permissions#page"
    assert options[-1]["value"] == admin_instances["casbin_rule_admin"].unique_id + "#page#page"
    options2 = get_admin_action_options(site)
    assert options is options2  # test cache


def test_get_admin_action_options_by_subject(site: AuthAdminSite, admin_instances: dict, fake_data):
    options = get_admin_action_options_by_subject(site.auth.enforcer, "u:admin", site)
    assert site.auth.enforcer.enforce("u:admin", admin_instances["user_auth_app"].unique_id, "page", "page")
    assert len(options) == 2
    assert options[0]["value"] == admin_instances["home_admin"].unique_id + "#page#page"
    assert options[1]["value"] == admin_instances["user_auth_app"].unique_id + "#page#page"
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    assert options[1]["children"][0]["value"] == user_admin_unique_id + "#page#page"
    children = options[1]["children"][0]["children"]
    assert children[0]["value"] == user_admin_unique_id + "#page:list#page"
    assert children[1]["value"] == user_admin_unique_id + "#page:filter#page"
    assert children[2]["value"] == user_admin_unique_id + "#page:create#page"
    assert children[3]["value"] == user_admin_unique_id + "#page:update#page"
    assert children[4]["value"] == user_admin_unique_id + "#page:delete#page"
    assert children[5]["value"] == user_admin_unique_id + "#page:bulk_delete#page"
    assert children[6]["value"] == user_admin_unique_id + "#page:update_subject_permissions#page"
    assert options[-1]["value"] != admin_instances["casbin_rule_admin"].unique_id + "#page#page"


def test_get_admin_grouping(site: AuthAdminSite, admin_instances: dict):
    grouping = get_admin_grouping(site)
    assert (site.unique_id, admin_instances["home_admin"].unique_id) in grouping
    assert (site.unique_id, admin_instances["user_auth_app"].unique_id) in grouping
    assert (admin_instances["user_auth_app"].unique_id, admin_instances["user_admin"].unique_id) in grouping


async def test_casbin_update_site_grouping(site: AuthAdminSite, admin_instances: dict):
    await casbin_update_site_grouping(site.auth.enforcer, site)
    grouping = await site.auth.enforcer.get_named_grouping_policy("g2")
    assert (site.unique_id, admin_instances["home_admin"].unique_id) in grouping
    assert (site.unique_id, admin_instances["user_auth_app"].unique_id) in grouping
    assert (admin_instances["user_auth_app"].unique_id, admin_instances["user_admin"].unique_id) in grouping


async def test_casbin_get_subject_page_permissions(enforcer: Enforcer, admin_instances: dict, fake_data):
    permissions = await casbin_get_subject_page_permissions(enforcer, subject="u:admin", implicit=False)
    assert not permissions
    permissions = await casbin_get_subject_page_permissions(enforcer, subject="u:admin", implicit=True)
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    assert f"{user_admin_unique_id}#page#page#allow" in permissions
    assert f"{user_admin_unique_id}#page:list#page#allow" in permissions
    assert f"{user_admin_unique_id}#page:list:email#page:list#allow" not in permissions
    assert permissions
    permissions2 = await casbin_get_subject_page_permissions(enforcer, subject="r:admin", implicit=False)
    assert permissions2 == permissions


async def test_casbin_update_subject_roles(enforcer: Enforcer, admin_instances: dict, fake_data):
    admin_roles = await enforcer.get_implicit_roles_for_user("u:admin")
    assert "r:admin" in admin_roles
    await casbin_update_subject_roles(enforcer, subject="u:admin", role_keys=["r:test"])
    admin_roles = await enforcer.get_implicit_roles_for_user("u:admin")
    assert "r:admin" not in admin_roles
    assert "r:test" in admin_roles


async def test_casbin_update_subject_page_permissions(enforcer: Enforcer, admin_instances: dict, fake_data):
    permissions = await casbin_get_subject_page_permissions(enforcer, subject="r:admin", implicit=True)
    user_admin_unique_id = admin_instances["user_admin"].unique_id
    casbin_rule_admin_unique_id = admin_instances["casbin_rule_admin"].unique_id
    assert f"{user_admin_unique_id}#page#page#allow" in permissions
    assert f"{casbin_rule_admin_unique_id}#page#page#allow" not in permissions
    await casbin_update_subject_page_permissions(
        enforcer,
        subject="r:admin",
        permissions=[
            f"{casbin_rule_admin_unique_id}#page#page",  # v1,v2,v3. 默认v4=allow
            f"{casbin_rule_admin_unique_id}#page:list#page#allow",  # v1,v2,v3,v4
        ],
    )
    permissions = await casbin_get_subject_page_permissions(enforcer, subject="r:admin", implicit=True)
    # 原来的page权限应该被删除
    assert f"{user_admin_unique_id}#page#page#allow" not in permissions
    # 新的page权限应该被添加
    assert f"{casbin_rule_admin_unique_id}#page#page#allow" in permissions
    assert f"{casbin_rule_admin_unique_id}#page:list#page#allow" in permissions
    # 非page权限应该保留
    assert await enforcer.has_policy("r:admin", user_admin_unique_id, "page:list:email", "page:list", "allow")
    assert await enforcer.has_policy("r:admin", user_admin_unique_id, "page:filter:email", "page:filter", "allow")
