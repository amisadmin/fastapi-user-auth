import pytest
from casbin import AsyncEnforcer
from sqlalchemy import delete

from fastapi_user_auth.admin import AuthAdminSite
from fastapi_user_auth.admin.utils import (
    get_admin_action_options,
    get_admin_action_options_by_subject,
    get_admin_grouping,
    update_casbin_site_grouping,
)
from fastapi_user_auth.auth.models import CasbinRule


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


def test_get_admin_action_options(site: AuthAdminSite, admin_instances: dict):
    options = get_admin_action_options(site)
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
    assert children[6]["value"] == user_admin_unique_id + "#page:update_subject_page_permissions#page"
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
    assert children[6]["value"] == user_admin_unique_id + "#page:update_subject_page_permissions#page"
    assert options[-1]["value"] != admin_instances["casbin_rule_admin"].unique_id + "#page#page"


def test_get_admin_grouping(site: AuthAdminSite, admin_instances: dict):
    grouping = get_admin_grouping(site)
    assert (site.unique_id, admin_instances["home_admin"].unique_id) in grouping
    assert (site.unique_id, admin_instances["user_auth_app"].unique_id) in grouping
    assert (admin_instances["user_auth_app"].unique_id, admin_instances["user_admin"].unique_id) in grouping


async def test_casbin_update_site_grouping(site: AuthAdminSite, admin_instances: dict):
    await update_casbin_site_grouping(site.auth.enforcer, site)
    grouping = site.auth.enforcer.get_named_grouping_policy("g2")
    assert (site.unique_id, admin_instances["home_admin"].unique_id) in grouping
    assert (site.unique_id, admin_instances["user_auth_app"].unique_id) in grouping
    assert (admin_instances["user_auth_app"].unique_id, admin_instances["user_admin"].unique_id) in grouping
