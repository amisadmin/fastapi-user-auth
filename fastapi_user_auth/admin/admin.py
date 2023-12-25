import contextlib
from typing import Any, Callable, Dict, List, Type

from fastapi import Depends, HTTPException
from fastapi_amis_admin.admin import (
    AdminAction,
    AdminApp,
    AutoTimeModelAdmin,
    FieldPermEnum,
    FootableModelAdmin,
    FormAdmin,
    PageSchemaAdmin,
    ReadOnlyModelAdmin,
    SoftDeleteModelAdmin,
)
from fastapi_amis_admin.amis.components import (
    Action,
    ActionType,
    ButtonToolbar,
    Form,
    Grid,
    Horizontal,
    Html,
    Page,
    PageSchema,
)
from fastapi_amis_admin.amis.constants import DisplayModeEnum, LevelEnum
from fastapi_amis_admin.crud.base import SchemaUpdateT
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.utils.pydantic import model_fields
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel
from sqlalchemy import select
from sqlmodel.sql.expression import Select
from starlette import status
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import NoMatchFound

from fastapi_user_auth.admin.actions import (
    CopyUserAuthLinkAction,
    UpdateSubDataPermAction,
    UpdateSubPagePermsAction,
    UpdateSubRolesAction,
)
from fastapi_user_auth.admin.utils import (
    get_admin_action_options,
    update_casbin_site_grouping,
)
from fastapi_user_auth.auth import Auth
from fastapi_user_auth.auth.models import (
    BaseUser,
    CasbinRule,
    CasbinSubjectRolesQuery,
    LoginHistory,
    Role,
    User,
    UserRoleNameLabel,
)
from fastapi_user_auth.auth.schemas import SystemUserEnum, UserLoginOut
from fastapi_user_auth.mixins.admin import AuthFieldModelAdmin, AuthSelectModelAdmin


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
    unique_id = "Auth>UserLoginFormAdmin"
    page = Page(title=_("User Login"))
    page_path = "/login"
    page_parser_mode = "html"
    schema: Type[SchemaUpdateT] = None
    schema_submit_out: Type[UserLoginOut] = None
    page_schema = None
    page_route_kwargs = {"name": "login"}

    @property
    def route_submit(self):
        async def route(request: Request, response: Response, data: self.schema):  # type: ignore
            return await request.auth.request_login(request, response, data.username, data.password)

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
    unique_id = "Auth>UserRegFormAdmin"
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
    unique_id = "Auth>UserInfoFormAdmin"
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
            for k, modelfield in model_fields(self.user_model).items()
            if k not in model_fields(self.schema).keys() | {"delete_time"}
        ]
        form.body.extend(formitem.update_from_kwargs(disabled=True) for formitem in formitems if formitem)
        return form

    async def handle(self, request: Request, data: SchemaUpdateT, **kwargs) -> BaseApiOut[Any]:
        for k, v in data.dict(exclude_none=True).items():
            if k == "password":
                if not v:
                    continue
                v = request.auth.get_password_hash(v)
            setattr(request.user, k, v)
        return BaseApiOut(data=request.user.dict(exclude={"password"}))

    async def has_page_permission(self, request: Request, obj: PageSchemaAdmin = None, action: str = None) -> bool:
        return await self.site.auth.requires(response=False)(request)


class UserAdmin(AuthFieldModelAdmin, AuthSelectModelAdmin, SoftDeleteModelAdmin, FootableModelAdmin):
    unique_id = "Auth>UserAdmin"
    page_schema = PageSchema(label=_("User"), icon="fa fa-user")
    model: Type[BaseUser] = None
    exclude = ["password"]
    ordering = [User.id.desc()]
    search_fields = [User.username]
    update_exclude = AutoTimeModelAdmin.update_exclude | {"username"}
    display_item_action_as_column = True
    admin_action_maker = [
        lambda admin: UpdateSubPagePermsAction(
            admin=admin,
            name="update_subject_page_permissions",
            tooltip="更新用户页面权限",
        ),
        lambda admin: UpdateSubDataPermAction(
            admin=admin,
            name="update_subject_data_permissions",
            tooltip="更新用户数据权限",
        ),
        lambda admin: UpdateSubRolesAction(
            admin=admin, name="update_subject_roles", tooltip="更新用户角色", icon="fa fa-user", flags="item"
        ),
        lambda admin: CopyUserAuthLinkAction(admin),
    ]
    list_display = [
        User.id,
        User.username,
        User.nickname,
        User.email,
        User.is_active,
        User.create_time,
    ]
    perm_fields_exclude = {
        FieldPermEnum.ALL: [
            "id",
            "username",
            "nickname",
            "avatar",
            "is_active",
            "create_time",
            "update_time",
            "delete_time",
        ],
    }

    async def on_create_pre(self, request: Request, obj, **kwargs) -> Dict[str, Any]:
        data = await super(UserAdmin, self).on_create_pre(request, obj, **kwargs)
        data["password"] = request.auth.get_password_hash(data["password"])
        return data

    async def on_update_pre(self, request: Request, obj, item_id: List[int], **kwargs) -> Dict[str, Any]:
        data = await super(UserAdmin, self).on_update_pre(request, obj, item_id, **kwargs)
        if data.get("password", None):
            data["password"] = request.auth.get_password_hash(data["password"])
        return data


class RoleAdmin(AutoTimeModelAdmin, FootableModelAdmin):
    unique_id = "Auth>RoleAdmin"
    page_schema = PageSchema(label=_("Role"), icon="fa fa-group")
    model = Role
    ordering = [Role.id.desc()]
    search_fields = [Role.name, UserRoleNameLabel]
    update_exclude = AutoTimeModelAdmin.update_exclude | {"key"}
    display_item_action_as_column = True
    admin_action_maker = [
        lambda admin: UpdateSubPagePermsAction(
            admin=admin,
            name="update_subject_page_permissions",
            tooltip="更新角色页面权限",
        ),
        lambda admin: UpdateSubDataPermAction(
            admin=admin,
            name="update_subject_data_permissions",
            tooltip="更新角色数据权限",
        ),
        lambda admin: UpdateSubRolesAction(
            admin=admin, name="update_subject_roles", tooltip="更新子角色", icon="fa fa-user", flags="item"
        ),
    ]

    list_display = [
        Role.id,
        Role.key,
        Role.name,
        UserRoleNameLabel,
        Role.desc,
    ]

    async def get_select(self, request: Request) -> Select:
        sel = await super().get_select(request)
        sel = sel.outerjoin(CasbinSubjectRolesQuery, CasbinSubjectRolesQuery.c.subject == "r:" + Role.key)
        return sel


class CasbinRuleAdmin(ReadOnlyModelAdmin):
    unique_id = "Auth>CasbinRuleAdmin"
    page_schema = PageSchema(label="CasbinRule", icon="fa fa-lock")
    model = CasbinRule
    list_filter = [CasbinRule.ptype, CasbinRule.v0, CasbinRule.v1, CasbinRule.v2, CasbinRule.v3, CasbinRule.v4, CasbinRule.v5]
    admin_action_maker = [
        lambda admin: AdminAction(
            admin=admin,
            action=ActionType.Ajax(
                id="refresh",
                label="刷新权限",
                icon="fa fa-refresh",
                level=LevelEnum.success,
                api=f"GET:{admin.router_path}/load_policy",
            ),
            flags=["toolbar"],
        ),
    ]

    def __init__(self, app: "AdminApp"):
        super().__init__(app)

        @self.site.router.on_event("startup")
        async def _load_policy():
            await self.load_policy()

    async def load_policy(self):
        await self.site.auth.enforcer.load_policy()
        # 更新站点资源分组
        await update_casbin_site_grouping(self.site.auth.enforcer, self.site)

    def register_router(self):
        @self.router.get("/load_policy", response_model=BaseApiOut)
        async def _load_policy():
            await self.load_policy()
            get_admin_action_options.cache_clear()  # 清除系统菜单缓存
            return BaseApiOut(data="刷新成功")

        return super().register_router()


class LoginHistoryAdmin(ReadOnlyModelAdmin):
    unique_id = "Auth>LoginHistoryAdmin"
    page_schema = PageSchema(label="登录历史", icon="fa fa-history")
    model = LoginHistory
    search_fields = [LoginHistory.login_name, LoginHistory.ip, LoginHistory.login_status, LoginHistory.user_agent]
    list_display = [
        User.nickname,
        LoginHistory.login_name,
        LoginHistory.ip,
        LoginHistory.login_status,
        LoginHistory.create_time,
        LoginHistory.user_agent,
        LoginHistory.forwarded_for,
        LoginHistory.ip_info,
    ]
    ordering = [LoginHistory.create_time.desc()]

    async def get_select(self, request: Request) -> Select:
        sel = await super().get_select(request)
        sel = sel.outerjoin(User, User.id == LoginHistory.user_id)
        return sel
