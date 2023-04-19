from typing import Any, List, Union

from casbin import Enforcer
from fastapi_amis_admin import amis
from fastapi_amis_admin.admin import AdminAction, ModelAction
from fastapi_amis_admin.amis import SchemaNode
from fastapi_amis_admin.amis.components import Action, ActionType, FormItem
from fastapi_amis_admin.amis.constants import LevelEnum
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.models import Field
from pydantic import BaseModel
from pydantic.fields import ModelField
from sqlalchemy import select
from starlette.requests import Request

from fastapi_user_auth.auth.models import Role
from fastapi_user_auth.utils import get_admin_action_options


class CasbinUpdateRoleAction(AdminAction):
    async def get_action(self, request: Request, **kwargs) -> Action:
        from fastapi_user_auth.admin import RoleAdmin  # 防止循环导入

        role_admin = self.admin.app.get_admin_or_create(RoleAdmin)
        if not role_admin:
            return None
        return amis.Service(
            label="权限角色",
            schemaApi={
                "url": role_admin.router_path,
                "method": "post",
                "data": {},
                "cache": 300000,
                "responseData": {
                    "body": [
                        {
                            "type": "picker",
                            "name": "role_keys",
                            "size": "full",
                            "source": {
                                "url": "${body.api.url}",
                                "method": "post",
                                "data": "${body.api.data}",
                            },
                            "multiple": True,
                            "labelField": "name",
                            "valueField": "key",
                            "modalMode": "dialog",
                            "pickerSchema": {"type": "crud", "&": "${body}"},
                            "onEvent": {
                                "change": {
                                    "actions": [
                                        {
                                            "args": {
                                                "options": {},
                                                "api": {
                                                    "url": self.admin.router_path + "/update_subject_roles",
                                                    "method": "post",
                                                    "dataType": "json",
                                                    "data": {
                                                        "data": "${body.api.data}"
                                                        # "&": "${body.api.__rendererData}"
                                                    },
                                                },
                                            },
                                            "actionType": "ajax",
                                        }
                                    ]
                                }
                            },
                        }
                    ]
                },
            },
        )


class CasbinUpdateRoleRuleAction(ModelAction):
    """更新角色Casbin规则"""

    form_init = True
    # 配置动作基本信息
    # action = ActionType.Drawer(icon="fa fa-gavel", tooltip="权限配置", drawer=amis.Drawer(), level=LevelEnum.warning)
    action = ActionType.Dialog(
        icon="fa fa-gavel",
        label="权限配置",
        tooltip="权限配置",
        dialog=amis.Dialog(),
        level=LevelEnum.warning,
    )

    # 创建动作表单数据模型
    class schema(BaseModel):
        rules: str = Field(
            None,
            title="权限列表",
            amis_form_item=amis.InputTree(
                multiple=True,
                source="",
                searchable=True,
                showOutline=True,
                autoCheckChildren=False,
            ),
        )

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        # 从数据库获取角色的权限列表
        item_id = request.query_params.get("item_id")
        if not item_id:
            return BaseApiOut(data=self.schema())
        role_key = await self.admin.db.async_scalar(select(Role.key).where(Role.id == item_id))
        enforcer: Enforcer = self.site.auth.enforcer
        rules = await enforcer.get_filtered_policy(0, "r:" + role_key)
        rules = ",".join([f"{rule[1]}#{rule[2]}" for rule in rules])
        return BaseApiOut(data=self.schema(rules=rules))

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        if item.name == "rules":
            item.source = f"{self.router_path}/get_admin_action_options"
        return item

    # 动作处理
    async def handle(self, request: Request, item_id: List[str], data: schema, **kwargs):
        # 从数据库获取用户选择的数据列表
        items = await self.admin.fetch_items(*item_id)
        role_key = "r:" + items[0].key
        enforcer: Enforcer = self.site.auth.enforcer
        # 删除旧的权限
        await enforcer.remove_filtered_policy(0, role_key)
        # 添加新的权限
        rules = [rule for rule in data.rules.split(",") if rule]  # 分割权限列表,去除空值
        site_rule = f"{self.site.unique_id}#admin:page"
        if rules and site_rule not in rules:  # 添加后台站点默认权限
            rules.append(site_rule)
        await enforcer.add_policies([(role_key, v1, v2) for v1, v2 in [rule.split("#") for rule in rules]])
        # 返回动作处理结果
        return BaseApiOut(data="success")

    def register_router(self):
        super().register_router()

        # 获取全部页面权限
        @self.router.get("/get_admin_action_options", response_model=BaseApiOut)
        async def _get_admin_action_options():
            return BaseApiOut(data=get_admin_action_options(self.site))

        return self
