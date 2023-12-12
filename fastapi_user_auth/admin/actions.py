from functools import lru_cache
from typing import Any, Dict, List, Union

from casbin import AsyncEnforcer
from fastapi_amis_admin import amis
from fastapi_amis_admin.admin import FormAdmin, ModelAction, PageSchemaAdmin
from fastapi_amis_admin.amis import SchemaNode
from fastapi_amis_admin.amis.components import ActionType, FormItem
from fastapi_amis_admin.amis.constants import LevelEnum
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.models import Field
from fastapi_amis_admin.utils.pydantic import ModelField
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_user_auth.admin.utils import get_admin_action_options_by_subject
from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import Role, User
from fastapi_user_auth.auth.schemas import SystemUserEnum
from fastapi_user_auth.mixins.admin import AuthFieldModelAdmin, AuthSelectModelAdmin
from fastapi_user_auth.mixins.models import PkMixin, UsernameMixin
from fastapi_user_auth.utils.casbin import (
    get_subject_effect_matrix,
    get_subject_page_permissions,
    get_subject_policy_matrix,
    permission_decode,
    update_subject_data_permissions,
    update_subject_page_permissions,
    update_subject_roles,
)


@lru_cache()
def get_admin_select_permission_rows(admin: PageSchemaAdmin) -> List[Dict[str, Any]]:
    rows = []
    if not isinstance(admin, AuthSelectModelAdmin):
        return rows
    for perm in admin.select_permissions:
        rows.append(
            {
                "label": "仅限数据-" + perm.label,
                "rol": f"{admin.unique_id}#page:select:{perm.name}#page:select",
                "reverse": perm.reverse,
            }
        )
    return rows


@lru_cache()
def get_admin_field_permission_rows(admin: PageSchemaAdmin, action: str) -> List[Dict[str, Any]]:
    """获取指定页面权限的字段权限,用于amis组件"""
    rows = []
    fields = {}
    if isinstance(admin, AuthFieldModelAdmin):  # 模型管理
        if action == "list":  # 列表展示模型
            fields = admin.list_permission_fields
        elif action == "filter":  # 列表筛选模型
            fields = admin.filter_permission_fields
        elif action == "create":  # 创建模型
            fields = admin.create_permission_fields
        elif action == "update":  # 更新模型
            fields = admin.update_permission_fields
        elif action == "read":  # 详情模型
            fields = admin.read_permission_fields
        else:
            pass
        if not fields:
            return []
        rows.append(
            {
                "label": "全部",
                "rol": f"{admin.unique_id}#page:{action}:*#page:{action}",
            }
        )
        rows.extend(
            {
                "label": label,
                "rol": f"{admin.unique_id}#page:{action}:{name}#page:{action}",
            }
            for name, label in fields.items()
        )
    elif isinstance(admin, FormAdmin):  # todo 表单管理
        pass
    return rows


class BaseSubAction(ModelAction):
    def __init__(self, admin, **kwargs):
        super().__init__(admin, **kwargs)
        if self.admin.model.__table__.name == Role.__tablename__:
            self._subject = "r"
        elif self.admin.model.__table__.name == User.__tablename__:
            self._subject = "u"
        else:
            raise Exception("暂不支持的主体模型")

    async def get_subject_by_id(self, item_id: str) -> str:
        # 从数据库获取用户选择的数据列表
        items = await self.admin.fetch_items(item_id)
        if not items:
            return ""
        if self._subject == "r":  # 角色管理
            return "r:" + items[0].key
        elif self._subject == "u":  # 用户管理
            return "u:" + items[0].username
        else:  # 其他管理
            return ""


class UpdateSubRolesAction(BaseSubAction):
    """主体Casbin角色基类"""

    _implicit: bool = True
    form_init = True

    action = ActionType.Dialog(
        name="update_subject_roles",
        icon="fa fa-check",
        tooltip="设置角色",
        dialog=amis.Dialog(),
        level=LevelEnum.warning,
    )

    class schema(BaseModel):
        role_keys: str = Field(
            "",
            title="角色列表",
            amis_form_item=amis.Transfer(
                selectMode="table",
                resultListModeFollowSelect=True,
                columns=[
                    # {"name": "key", "label": "角色标识"},
                    {"name": "name", "label": "角色名称"},
                    {"name": "desc", "label": "角色描述"},
                    {"name": "role_names", "label": "子角色"},
                ],
                source="",
                valueField="key",
            ),
        )

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        from fastapi_user_auth.admin import RoleAdmin  # 防止循环导入

        # role_admin = self.admin.app.get_admin_or_create(RoleAdmin)
        role_admin, _ = self.admin.app.get_page_schema_child(unique_id=RoleAdmin.unique_id)
        if item.name == "role_keys":  # 为角色树形选择器数据指定API源
            # value
            item.source = f"post:{role_admin.router_path}/list?page=1&perPage=100"
        return item

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        # 从数据库获取角色的权限列表
        item_id = request.query_params.get("item_id")
        if not item_id:
            return BaseApiOut(data=self.schema())
        subject = await self.get_subject_by_id(item_id)
        if not subject:
            return BaseApiOut(status=0, msg="暂不支持的模型")
        role_keys = await self.site.auth.enforcer.get_roles_for_user(subject)
        return BaseApiOut(data=self.schema(role_keys=",".join(role_keys).replace("r:", "")))

    async def handle(self, request: Request, item_id: List[str], data: schema, **kwargs):
        """更新角色Casbin权限"""
        subject = await self.get_subject_by_id(item_id[0])
        if not subject:
            return BaseApiOut(status=0, msg="暂不支持的模型")
        identity = await self.site.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
        if subject == "u:" + identity:
            return BaseApiOut(status=0, msg="不能修改自己的权限")
        enforcer: AsyncEnforcer = self.site.auth.enforcer
        role_keys = [f"r:{role}" for role in data.role_keys.split(",") if role]
        if role_keys and identity not in [SystemUserEnum.ROOT, SystemUserEnum.ADMIN]:
            # 检查当前用户是否有对应的角色,只有自己拥有的角色才能分配给其他主体
            user_role_keys = await self.site.auth.enforcer.get_implicit_roles_for_user("u:" + identity)
            role_keys = [role for role in role_keys if role in user_role_keys]  # 过滤掉当前用户的角色
        # 更新角色列表
        await update_subject_roles(enforcer, subject=subject, role_keys=role_keys)
        return BaseApiOut(msg="success")


class BaseSubPermAction(BaseSubAction):
    """主体Casbin权限基类"""

    _implicit: bool = True
    form_init = False
    # 配置动作基本信息
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
            "",
            title="权限列表",
            amis_form_item=amis.InputTree(
                multiple=True,
                source="",
                searchable=True,
                showOutline=True,
                cascade=True,
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

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        if item.name == "permissions":  # 为角色树形选择器数据指定API源
            item.source = f"{self.site.settings.site_path}/auth/site_admin_actions_options"
        return item


class ViewSubPagePermAction(BaseSubPermAction):
    """查看主体Casbin权限,暂时不支持单个主体的权限可视化配置"""

    _implicit: bool = True
    form_init = True

    action = ActionType.Dialog(
        name="view_subject_page_permissions",
        icon="fa fa-check",
        tooltip="查看页面权限",
        dialog=amis.Dialog(actions=[]),
        level=LevelEnum.warning,
    )

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        if item.name == "permissions":  # 为角色树形选择器数据指定API源
            item.multiple = True
        return item

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        # 从数据库获取角色的权限列表
        item_id = request.query_params.get("item_id")
        if not item_id:
            return BaseApiOut(data=self.schema())
        subject = await self.get_subject_by_id(item_id)
        if not subject:
            return BaseApiOut(status=0, msg="暂不支持的模型")
        permissions = await get_subject_page_permissions(self.site.auth.enforcer, subject=subject, implicit=self._implicit)
        permissions = [perm.replace("#allow", "") for perm in permissions if perm.endswith("#allow")]
        return BaseApiOut(data=self.schema(permissions=",".join(permissions)))

    async def handle(self, request: Request, item_id: List[str], data: BaseModel, **kwargs):
        return BaseApiOut(status=1, msg="请通过的【设置权限】更新设置!")


class UpdateSubDataPermAction(BaseSubPermAction):
    """更新主体Casbin权限,字段权限+数据集权限"""

    _implicit: bool = True

    action = ActionType.Dialog(
        name="update_subject_data_permissions",
        icon="fa fa-gavel",
        tooltip="更新数据权限",
        dialog=amis.Dialog(actions=[amis.Action(actionType="submit", label="保存", close=False, primary=True)]),
        level=LevelEnum.warning,
    )

    # 创建动作表单数据模型
    class schema(BaseSubPermAction.schema):
        effect_matrix: list = Field(
            [],
            title="当前权限",
            amis_form_item=amis.MatrixCheckboxes(
                rowLabel="权限名称",
                multiple=False,
                singleSelectMode="row",
                source="",
                disabled=True,
            ),
        )
        policy_matrix: list = Field(
            [],
            title="权限配置",
            amis_form_item=amis.MatrixCheckboxes(
                rowLabel="名称",
                multiple=False,
                singleSelectMode="row",
                yCheckAll=True,
                source="",
            ),
        )

    async def get_form_item(self, request: Request, modelfield: ModelField) -> Union[FormItem, SchemaNode]:
        item = await super().get_form_item(request, modelfield)
        if item.name == "permissions":  # 为角色树形选择器数据指定API源
            item.multiple = False
            item.source = f"{self.router_path}/get_admin_action_options?item_id=$id"  # 获取对方权限列表
        elif item.name == "policy_matrix":
            item.source = f"{self.router_path}/get_admin_action_perm_options?type=policy&permission=$permissions&item_id=$id"
        elif item.name == "effect_matrix":
            item.source = f"{self.router_path}/get_admin_action_perm_options?type=effect&permission=$permissions&item_id=$id"
        return item

    def register_router(self):
        super().register_router()

        # 获取全部页面权限
        @self.router.get("/get_admin_action_options", response_model=BaseApiOut)
        async def _get_admin_action_options(request: Request, item_id: str):
            # 获取对方权限列表
            subject = await self.get_subject_by_id(item_id)
            options = []
            options = get_admin_action_options_by_subject(self.site.auth.enforcer, subject, self.site)
            return BaseApiOut(data=options)

        @self.router.get("/get_admin_action_perm_options", response_model=BaseApiOut)
        async def get_admin_action_perm_options(
            request: Request,
            permission: str = "",
            item_id: str = "",
            type: str = "policy",
        ):
            columns = [
                {
                    "label": "默认",
                    "col": "default",
                },
                {
                    "label": "是",
                    "col": "allow",
                },
                {
                    "label": "否",
                    "col": "deny",
                },
            ]
            if type == "effect":
                columns = columns[1:]
            out = BaseApiOut(
                data={
                    "columns": columns,
                    "rows": [],
                }
            )
            if not permission:
                return out
            unique_id, action, *_ = permission_decode(permission)
            admin, parent = self.site.get_page_schema_child(unique_id)
            if not admin:
                return out
            if action == "page":  # select权限
                rows = get_admin_select_permission_rows(admin)
            else:  # 字段权限
                action = action.replace("page:", "")
                rows = get_admin_field_permission_rows(admin, action)
            out.data["rows"] = rows
            if not item_id:
                return out
            # 设置初始值
            subject = await self.get_subject_by_id(item_id)
            if type == "effect":
                value = get_subject_effect_matrix(self.site.auth.enforcer, subject=subject, rows=rows)
            else:
                value = get_subject_policy_matrix(
                    self.site.auth.enforcer,
                    subject=subject,
                    permission=permission,
                    rows=rows,
                )
            out.data["value"] = value
            return out

        return self

    async def get_form(self, request: Request) -> amis.Form:
        form = await super().get_form(request)
        form.body = amis.Grid(columns=form.body)
        return form

    async def handle(self, request: Request, item_id: List[str], data: BaseModel, **kwargs):
        subject = await self.get_subject_by_id(item_id[0])
        identity = await self.site.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
        if subject == "u:" + identity:
            return BaseApiOut(status=0, msg="不能修改自己的权限")
        msg = await update_subject_data_permissions(
            self.site.auth.enforcer,
            subject=subject,
            permission=data.permissions,
            policy_matrix=data.policy_matrix,
            super_subject="u:" + identity,
        )
        return BaseApiOut(msg=msg)


class UpdateSubPagePermsAction(ViewSubPagePermAction):
    """更新主体Casbin权限"""

    _implicit: bool = False
    action = ActionType.Dialog(
        name="update_subject_page_permissions",
        icon="fa fa-gavel",
        tooltip="更新页面权限",
        dialog=amis.Dialog(),
        level=LevelEnum.warning,
    )

    async def handle(self, request: Request, item_id: List[str], data: BaseModel, **kwargs):
        """更新角色Casbin权限"""
        subject = await self.get_subject_by_id(item_id[0])
        if not subject:
            return BaseApiOut(status=0, msg="暂不支持的模型")
        identity = await self.site.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
        if subject == "u:" + identity:
            return BaseApiOut(status=0, msg="不能修改自己的权限")
        # 权限列表
        permissions = [perm for perm in data.permissions.split(",") if perm and perm.endswith("#page")]  # 分割权限列表,去除空值
        enforcer: AsyncEnforcer = self.site.auth.enforcer
        if permissions and identity != SystemUserEnum.ROOT:
            #  检查当前用户是否有对应的权限,只有自己拥有的权限才能分配给其他主体
            permissions = [perm for perm in permissions if enforcer.enforce("u:" + identity, *permission_decode(perm))]
        await update_subject_page_permissions(enforcer, subject=subject, permissions=permissions)  # 更新角色权限
        return BaseApiOut(msg="success")


class CopyUserAuthLinkAction(ModelAction):
    """复制用户免登录链接"""

    action = amis.ActionType.Dialog(
        name="copy_user_auth_link",
        icon="fa fa-link",
        tooltip="用户免登录链接",
        level=amis.LevelEnum.danger,
        dialog=amis.Dialog(
            size=amis.SizeEnum.md,
            title="用户免登录链接",
        ),
    )
    form_init = True
    form = amis.Form(static=True, disabled=True)  # type: ignore # 禁用表单

    class schema(UsernameMixin, PkMixin):
        auth_url: str = Field(
            title="授权链接",
            description="复制链接到浏览器打开即可免登录",
            amis_form_item=amis.Static(
                copyable=True,
            ),
        )

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        """复制用户免登录链接"""
        item_id = request.query_params.get("item_id")
        items = await self.admin.fetch_items(item_id)
        user: User = items[0]
        auth: Auth = request.auth
        token_data = {
            "id": user.id,
            "username": user.username,
        }
        token = await auth.backend.token_store.write_token(token_data)
        return BaseApiOut(
            msg="操作成功",
            data={**token_data, "auth_url": f"{str(request.base_url)[:-1]}{self.site.router_path}/login_by_token?token={token}"},
        )

    def register_router(self):
        @self.site.router.get("/login_by_token", include_in_schema=False)
        async def login_by_token(token: str):
            """通过url中的token登录"""
            response = RedirectResponse(self.site.settings.site_path)
            response.set_cookie("Authorization", f"bearer {token}")
            return response

        return super().register_router()
