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
from starlette.requests import Request

from fastapi_user_auth.auth.crud import (
    casbin_get_permissions_by_role_id,
    casbin_get_permissions_by_user_id,
)
from fastapi_user_auth.auth.models import Role, User
from fastapi_user_auth.utils import (
    casbin_update_subject_permissions,
    get_admin_action_options,
)


class CasbinUpdateSubjectRolesAction(AdminAction):
    """更新用户拥有的角色或者更新角色拥有的子角色"""

    async def get_action(self, request: Request, **kwargs) -> Action:
        from fastapi_user_auth.admin import RoleAdmin  # 防止循环导入

        role_admin = self.admin.app.get_admin_or_create(RoleAdmin)
        if not role_admin:
            return None
        return amis.Service(  # type: ignore
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


class CasbinViewSubjectPermissionsAction(ModelAction):
    """查看主体Casbin权限,暂时不支持单个主体的权限可视化配置"""

    _implicit: bool = True
    form_init = True
    # 配置动作基本信息
    # action = ActionType.Drawer(
    #     name="view_subject_permissions",
    #     icon="fa fa-check",
    #     tooltip="查看权限",
    #     drawer=amis.Drawer(),
    #     level=LevelEnum.warning
    # )

    action = ActionType.Dialog(
        name="view_subject_permissions",
        icon="fa fa-check",
        tooltip="查看权限",
        dialog=amis.Dialog(),
        level=LevelEnum.warning,
    )

    # 创建动作表单数据模型
    class schema(BaseModel):
        permissions: str = Field(
            None,
            title="权限列表",
            amis_form_item=amis.InputTree(
                multiple=True,
                source="",
                searchable=True,
                showOutline=True,
                autoCheckChildren=False,
                heightAuto=True,
            ),
            # amis_form_item=amis.Transfer(
            #     selectMode="tree", # chained
            #     searchResultMode="tree",
            #     sortable=True,
            #     source="",
            #     searchable=True,
            #     resultListModeFollowSelect=True,
            #     resultSearchable=True,
            # ),
        )

    def __init__(self, admin, **kwargs):
        super().__init__(admin, **kwargs)
        if self.admin.model.__table__.name == Role.__tablename__:
            self._subject = "r"
        elif self.admin.model.__table__.name == User.__tablename__:
            self._subject = "u"
        else:
            raise Exception("暂不支持的模型")

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        if item.name == "permissions":  # 为角色树形选择器数据指定API源
            item.source = f"{self.router_path}/get_admin_action_options"
        return item

    def register_router(self):
        super().register_router()

        # 获取全部页面权限
        @self.router.get("/get_admin_action_options", response_model=BaseApiOut)
        async def _get_admin_action_options():
            return BaseApiOut(data=get_admin_action_options(self.site))

        return self

    async def get_subject_by_id(self, item_id: str) -> str:
        # 从数据库获取用户选择的数据列表
        items = await self.admin.fetch_items(item_id)
        if self._subject == "r":  # 角色管理
            return "r:" + items[0].key
        elif self._subject == "u":  # 用户管理
            return "u:" + items[0].username
        else:  # 其他管理
            return ""

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        # 从数据库获取角色的权限列表
        item_id = request.query_params.get("item_id")
        if not item_id:
            return BaseApiOut(data=self.schema())
        if self._subject == "r":  # 角色管理
            permissions = await casbin_get_permissions_by_role_id(self.site.auth, item_id, implicit=self._implicit)
        elif self._subject == "u":  # 用户管理
            permissions = await casbin_get_permissions_by_user_id(self.site.auth, item_id, implicit=self._implicit)
        else:  # 其他管理
            permissions = []
        return BaseApiOut(data=self.schema(permissions=",".join(permissions)))

    async def handle(self, request: Request, item_id: List[str], data: BaseModel, **kwargs):
        return BaseApiOut(status=1, msg="请通过的【设置权限】更新设置!")


class CasbinUpdateSubjectPermissionsAction(CasbinViewSubjectPermissionsAction):
    """更新角色Casbin权限"""

    _implicit: bool = False
    action = ActionType.Dialog(
        name="update_subject_permissions",
        icon="fa fa-gavel",
        tooltip="设置权限",
        dialog=amis.Dialog(),
        level=LevelEnum.warning,
    )

    async def handle(self, request: Request, item_id: List[str], data: BaseModel, **kwargs):
        """更新角色Casbin权限"""
        subject = await self.get_subject_by_id(item_id[0])
        if not subject:
            return BaseApiOut(status=0, msg="暂不支持的模型")
        # 权限列表
        permissions = [rule for rule in data.permissions.split(",") if rule]  # 分割权限列表,去除空值
        site_rule = f"{self.site.unique_id}#admin:page"
        if permissions and site_rule not in permissions:  # 添加后台站点默认权限
            permissions.append(site_rule)
        enforcer: Enforcer = self.site.auth.enforcer
        await casbin_update_subject_permissions(enforcer, subject, permissions)  # 更新角色权限
        # 返回动作处理结果
        return BaseApiOut(data="success")
