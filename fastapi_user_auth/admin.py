import contextlib
from typing import Any, Callable, Dict, List, Type, Union

from casbin import Enforcer
from fastapi import Depends, HTTPException
from fastapi_amis_admin import amis
from fastapi_amis_admin.admin import AdminApp, FormAdmin, ModelAdmin, PageSchemaAdmin
from fastapi_amis_admin.admin.admin import AdminGroup, ModelAction
from fastapi_amis_admin.amis import SchemaNode
from fastapi_amis_admin.amis.components import (
    Action,
    ActionType,
    ButtonToolbar,
    Form,
    FormItem,
    Grid,
    Horizontal,
    Html,
    Page,
    PageSchema,
)
from fastapi_amis_admin.amis.constants import DisplayModeEnum, LevelEnum
from fastapi_amis_admin.crud.base import SchemaUpdateT
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.models import Field
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel
from pydantic.fields import ModelField
from sqlalchemy import select
from sqlmodel.sql.expression import Select
from starlette import status
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import NoMatchFound

from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import BaseUser, CasbinRule, Role, User
from fastapi_user_auth.auth.schemas import SystemUserEnum, UserLoginOut


def attach_page_head(page: Page) -> Page:
    desc = _("Amis is a low-code front-end framework that reduces page development effort and greatly improves efficiency")
    page.body = [
        Html(
            html=f'<div style="display: flex; justify-content: center; align-items: center; margin: 96px 0px 8px;">'
            f'<img src="https://baidu.gitee.io/amis/static/favicon_b3b0647.png" alt="logo" style="margin-right: 8px; '
            f'width: 48px;"><span style="font-size: 32px; font-weight: bold;">Amis Admin</span></div>'
            f'<div style="width: 100%; text-align: center; color: rgba(0, 0, 0, 0.45); margin-bottom: 40px;">{desc}</div>'
        ),
        Grid(columns=[{"body": [page.body], "lg": 2, "md": 4, "valign": "middle"}], align="center", valign="middle"),
    ]
    return page


class UserLoginFormAdmin(FormAdmin):
    page = Page(title=_("User Login"))
    page_path = "/login"
    page_parser_mode = "html"
    schema: Type[SchemaUpdateT] = None
    schema_submit_out: Type[UserLoginOut] = None
    page_schema = None
    page_route_kwargs = {"name": "login"}

    async def handle(self, request: Request, data: SchemaUpdateT, **kwargs) -> BaseApiOut[BaseModel]:  # self.schema_submit_out
        if request.user:
            return BaseApiOut(code=1, msg=_("User logged in!"), data=self.schema_submit_out.parse_obj(request.user))
        user = await request.auth.authenticate_user(username=data.username, password=data.password)  # type:ignore
        if not user:
            return BaseApiOut(status=-1, msg=_("Incorrect username or password!"))
        if not user.is_active:
            return BaseApiOut(status=-2, msg=_("Inactive user status!"))

        token_info = self.schema_submit_out.parse_obj(user)
        auth: Auth = request.auth
        token_info.access_token = await auth.backend.token_store.write_token(user.dict())
        return BaseApiOut(code=0, data=token_info)

    @property
    def route_submit(self):
        async def route(response: Response, result: BaseApiOut = Depends(super().route_submit)):
            if result.status == 0 and result.code == 0:  # 登录成功,设置用户信息
                response.set_cookie("Authorization", f"bearer {result.data.access_token}")
            return result

        return route

    async def get_form(self, request: Request) -> Form:
        form = await super().get_form(request)
        buttons = []
        with contextlib.suppress(NoMatchFound):
            buttons.append(
                ActionType.Link(
                    actionType="link",
                    link=f"{self.site.router_path}{self.app.router.url_path_for('reg')}",
                    label=_("Sign up"),
                )
            )
        buttons.append(Action(actionType="submit", label=_("Sign in"), level=LevelEnum.primary))
        form.body.sort(key=lambda form_item: form_item.type, reverse=True)
        form.update_from_kwargs(
            title="",
            mode=DisplayModeEnum.horizontal,
            submitText=_("Sign in"),
            actionsClassName="no-border m-none p-none",
            panelClassName="",
            wrapWithPanel=True,
            horizontal=Horizontal(left=3, right=9),
            actions=[ButtonToolbar(buttons=buttons)],
        )
        form.redirect = request.query_params.get("redirect") or "/"
        return form

    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        return attach_page_head(page)

    @property
    def route_page(self) -> Callable:
        async def route(request: Request, result=Depends(super().route_page)):
            if request.user:
                raise HTTPException(
                    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                    detail="already logged in",
                    headers={"location": request.query_params.get("redirect") or "/"},
                )
            return result

        return route

    async def has_page_permission(self, request: Request, obj: PageSchemaAdmin = None, action: str = None) -> bool:
        return True


class UserRegFormAdmin(FormAdmin):
    user_model: Type[BaseUser] = User
    page = Page(title=_("User Register"))
    page_path = "/reg"
    page_parser_mode = "html"
    schema: Type[SchemaUpdateT] = None
    schema_submit_out: Type[UserLoginOut] = None
    page_schema = None
    page_route_kwargs = {"name": "reg"}

    async def handle(self, request: Request, data: SchemaUpdateT, **kwargs) -> BaseApiOut[BaseModel]:  # self.schema_submit_out
        auth: Auth = request.auth
        if data.username.upper() in SystemUserEnum.__members__:
            return BaseApiOut(status=-1, msg=_("Username has been registered!"), data=None)
        user = await auth.db.async_scalar(select(self.user_model).where(self.user_model.username == data.username))
        if user:
            return BaseApiOut(status=-1, msg=_("Username has been registered!"), data=None)
        user = await auth.db.async_scalar(select(self.user_model).where(self.user_model.email == data.email))
        if user:
            return BaseApiOut(status=-2, msg=_("Email has been registered!"), data=None)
        values = data.dict(exclude={"id", "password"})
        values["password"] = auth.pwd_context.hash(data.password.get_secret_value())  # 密码hash保存
        user = self.user_model.parse_obj(values)
        try:
            auth.db.add(user)
            await auth.db.async_flush()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error Execute SQL：{e}",
            ) from e
        # 注册成功,设置用户信息
        token_info = self.schema_submit_out.parse_obj(user)
        token_info.access_token = await auth.backend.token_store.write_token(user.dict())
        return BaseApiOut(code=0, msg=_("Registered successfully!"), data=token_info)

    @property
    def route_submit(self):
        async def route(response: Response, result: BaseApiOut = Depends(super().route_submit)):
            if result.status == 0 and result.code == 0:  # 登录成功,设置用户信息
                response.set_cookie("Authorization", f"bearer {result.data.access_token}")
            return result

        return route

    async def get_form(self, request: Request) -> Form:
        form = await super().get_form(request)
        form.redirect = request.query_params.get("redirect") or "/"
        form.update_from_kwargs(
            title="",
            mode=DisplayModeEnum.horizontal,
            submitText=_("Sign up"),
            actionsClassName="no-border m-none p-none",
            panelClassName="",
            wrapWithPanel=True,
            horizontal=Horizontal(left=3, right=9),
            actions=[
                ButtonToolbar(
                    buttons=[
                        ActionType.Link(
                            actionType="link",
                            link=f"{self.router_path}/login",
                            label=_("Sign in"),
                        ),
                        Action(actionType="submit", label=_("Sign up"), level=LevelEnum.primary),
                    ]
                )
            ],
        )

        return form

    async def get_page(self, request: Request) -> Page:
        page = await super().get_page(request)
        return attach_page_head(page)

    async def has_page_permission(self, request: Request, obj: PageSchemaAdmin = None, action: str = None) -> bool:
        return True


class UserInfoFormAdmin(FormAdmin):
    page_schema = None
    user_model: Type[BaseUser] = User
    page = Page(title=_("User Profile"))
    page_path = "/userinfo"
    schema: Type[SchemaUpdateT] = None
    schema_submit_out: Type[BaseUser] = None
    form_init = True
    form = Form(mode=DisplayModeEnum.horizontal)
    page_route_kwargs = {"name": "userinfo"}

    async def get_init_data(self, request: Request, **kwargs) -> BaseApiOut[Any]:
        return BaseApiOut(data=request.user.dict(exclude={"password"}))

    async def get_form(self, request: Request) -> Form:
        form = await super().get_form(request)
        formitems = [
            await self.get_form_item(request, modelfield)
            for k, modelfield in self.user_model.__fields__.items()
            if k not in self.schema.__fields__
        ]
        form.body.extend(formitem.update_from_kwargs(disabled=True) for formitem in formitems if formitem)
        return form

    async def handle(self, request: Request, data: SchemaUpdateT, **kwargs) -> BaseApiOut[Any]:
        for k, v in data.dict(exclude_none=True).items():
            if k == "password":
                if not v:
                    continue
                else:
                    v = request.auth.pwd_context.hash(v)  # 密码hash保存
            setattr(request.user, k, v)
        return BaseApiOut(data=self.schema_submit_out.parse_obj(request.user))

    async def has_page_permission(self, request: Request, obj: PageSchemaAdmin = None, action: str = None) -> bool:
        return await self.site.auth.requires(response=False)(request)


class UserAdmin(ModelAdmin):
    page_schema = PageSchema(label=_("User"), icon="fa fa-user")
    model: Type[BaseUser] = None
    exclude = ["password"]
    search_fields = [User.username]

    async def on_create_pre(self, request: Request, obj, **kwargs) -> Dict[str, Any]:
        data = await super(UserAdmin, self).on_create_pre(request, obj, **kwargs)
        data["password"] = request.auth.pwd_context.hash(data["password"])  # 密码hash保存
        return data

    async def on_update_pre(self, request: Request, obj, item_id: List[int], **kwargs) -> Dict[str, Any]:
        data = await super(UserAdmin, self).on_update_pre(request, obj, item_id, **kwargs)
        password = data.get("password")
        if password:
            data["password"] = request.auth.pwd_context.hash(data["password"])  # 密码hash保存
        return data


def get_admin_action_options(group: AdminGroup) -> List[Dict[str, Any]]:
    """获取全部页面权限,用于amis组件"""
    options = []
    for admin in group:  # 这里已经同步了数据库,所以只从这里配置权限就行了
        admin: PageSchemaAdmin
        if not admin.page_schema:
            continue
        item = {"label": admin.page_schema.label, "value": f"{admin.unique_id}#admin:page"}
        if isinstance(admin, ModelAdmin):
            item["children"] = [
                {"label": "查看列表", "value": f"{admin.unique_id}#admin:list"},
                {"label": "查看详情", "value": f"{admin.unique_id}#admin:read"},
                {"label": "更新数据", "value": f"{admin.unique_id}#admin:update"},
                {"label": "创建数据", "value": f"{admin.unique_id}#admin:create"},
                {"label": "删除数据", "value": f"{admin.unique_id}#admin:delete"},
            ]  # type: ignore
        elif isinstance(admin, AdminGroup):
            item["children"] = get_admin_action_options(admin)
        options.append(item)
    return options


class UpdateRoleCasbinRuleAction(ModelAction):
    """更新角色Casbin规则"""

    form_init = True
    # 配置动作基本信息
    # action = ActionType.Drawer(icon="fa fa-gavel", tooltip="权限配置", drawer=amis.Drawer(), level=LevelEnum.warning)
    action = ActionType.Dialog(icon="fa fa-gavel", label="权限配置", tooltip="权限配置", dialog=amis.Dialog(), level=LevelEnum.warning)

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
        print("item_id", item_id)
        if not item_id:
            return BaseApiOut(data=self.schema())
        # role_key = select(Role.key).where(Role.id == item_id).scalar_subquery()
        # stmt = select(CasbinRule).where(CasbinRule.ptype == "p", CasbinRule.v0 == role_key)
        # rules = await self.admin.db.async_scalars(stmt)
        # data = ",".join([f"{rule.v1}#{rule.v2}" for rule in rules])
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
        ret = await enforcer.remove_filtered_policy(0, role_key)
        print("remove_filtered_policy", ret)
        # 添加新的权限
        rules = data.rules.split(",")
        ret = await enforcer.add_policies([(role_key, v1, v2) for v1, v2 in [rule.split("#") for rule in rules if rule]])
        print("add_policies", ret)
        # 刷新权限
        await enforcer.save_policy()
        # 返回动作处理结果
        return BaseApiOut(data="操作成功")

    def register_router(self):
        super().register_router()

        # 获取全部页面权限
        @self.router.get("/get_admin_action_options", response_model=BaseApiOut)
        async def _get_admin_action_options():
            return BaseApiOut(
                data=[
                    {"label": self.site.page_schema.label, "value": f"{self.site.unique_id}#admin:page"},
                    *get_admin_action_options(self.site),
                ]
            )

        return self


class RoleAdmin(ModelAdmin):
    page_schema = PageSchema(label=_("Role"), icon="fa fa-group")
    model = Role
    readonly_fields = ["key"]

    async def get_actions_on_item(self, request: Request) -> List[Action]:
        actions = await super().get_actions_on_item(request)
        action = await self.update_role_casbin_action.get_action(request)
        actions.append(action.copy())
        return actions

    # 注册自定义路由
    def register_router(self):
        # 注册动作路由
        super().register_router()
        self.update_role_casbin_action = UpdateRoleCasbinRuleAction(self).register_router()
        return self


class UserCasbinRuleAdmin(ModelAdmin):
    page_schema = PageSchema(label="用户角色", icon="fa fa-group")
    model = CasbinRule
    list_display = [
        User.username,
        User.nickname,
        User.is_active,
        Role.key,
        Role.name,
    ]

    async def get_select(self, request: Request) -> Select:
        select = await super().get_select(request)
        select = select.where(CasbinRule.ptype == "g")
        return select.outerjoin(Role, "r:" + Role.key == CasbinRule.v1).outerjoin(User, "u:" + User.username == CasbinRule.v0)


class CasbinRuleAdmin(ModelAdmin):
    page_schema = PageSchema(label="CasbinRule", icon="fa fa-group")
    model = CasbinRule
    list_filter = [CasbinRule.ptype, CasbinRule.v0, CasbinRule.v1, CasbinRule.v2, CasbinRule.v3, CasbinRule.v4, CasbinRule.v5]

    enforcer: Enforcer = None

    def __init__(self, app: "AdminApp"):
        assert self.enforcer, "enforcer is None"
        super().__init__(app)

        @self.site.fastapi.on_event("startup")
        async def _load_policy():
            await self.load_policy()

    @classmethod
    def bind(cls, app: AdminApp, enforcer: Enforcer = None) -> Enforcer:
        cls.enforcer = enforcer or cls.enforcer
        app.register_admin(cls)
        return cls.enforcer

    async def get_actions_on_header_toolbar(self, request: Request) -> List[Action]:
        actions = await super().get_actions_on_header_toolbar(request)
        actions.append(
            ActionType.Ajax(
                label="刷新权限",
                icon="fa fa-refresh",
                level=LevelEnum.success,
                api=f"GET:{self.router_path}/load_policy",
            )
        )
        return actions

    async def load_policy(self):
        await self.enforcer.load_policy()

    def register_router(self):
        @self.router.get("/load_policy", response_model=BaseApiOut)
        async def _load_policy():
            await self.load_policy()
            return BaseApiOut(data="刷新成功")

        return super().register_router()
