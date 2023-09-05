from typing import Type

from fastapi_amis_admin.admin import AdminApp, ModelAdmin
from fastapi_amis_admin.amis.components import PageSchema
from fastapi_amis_admin.crud import BaseApiOut
from fastapi_amis_admin.utils.pydantic import create_model_by_model
from fastapi_amis_admin.utils.translation import i18n as _
from starlette.requests import Request

from fastapi_user_auth.admin import CasbinRuleAdmin
from fastapi_user_auth.admin import LoginHistoryAdmin as DefaultLoginHistoryAdmin
from fastapi_user_auth.admin import RoleAdmin as DefaultRoleAdmin
from fastapi_user_auth.admin import UserAdmin as DefaultUserAdmin
from fastapi_user_auth.admin import UserInfoFormAdmin as DefaultUserInfoFormAdmin
from fastapi_user_auth.admin import UserLoginFormAdmin as DefaultUserLoginFormAdmin
from fastapi_user_auth.admin import UserRegFormAdmin as DefaultUserRegFormAdmin
from fastapi_user_auth.admin.utils import get_admin_action_options_by_subject
from fastapi_user_auth.auth import AuthRouter
from fastapi_user_auth.auth.schemas import SystemUserEnum


class UserAuthApp(AdminApp, AuthRouter):
    unique_id = "Auth>UserAuthApp"
    page_schema = PageSchema(label=_("User Authentication"), icon="fa fa-lock", sort=99)
    router_prefix = "/auth"
    # default admin
    UserLoginFormAdmin: Type[DefaultUserLoginFormAdmin] = DefaultUserLoginFormAdmin
    UserRegFormAdmin: Type[DefaultUserRegFormAdmin] = DefaultUserRegFormAdmin
    UserInfoFormAdmin: Type[DefaultUserInfoFormAdmin] = DefaultUserInfoFormAdmin
    UserAdmin: Type[DefaultUserAdmin] = DefaultUserAdmin
    RoleAdmin: Type[ModelAdmin] = DefaultRoleAdmin
    LoginHistoryAdmin: Type[ModelAdmin] = DefaultLoginHistoryAdmin

    def __init__(self, app: "AdminApp"):
        AdminApp.__init__(self, app)
        self.auth = self.auth or self.site.auth
        AuthRouter.__init__(self)
        self.UserAdmin.model = self.UserAdmin.model or self.auth.user_model
        self.UserLoginFormAdmin.schema = self.UserLoginFormAdmin.schema or create_model_by_model(
            self.auth.user_model, "UserLoginIn", include={"username", "password"}
        )
        self.UserLoginFormAdmin.schema_submit_out = self.UserLoginFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserRegFormAdmin.schema = self.UserRegFormAdmin.schema or create_model_by_model(
            self.auth.user_model, "UserRegIn", include={"username", "password", "email"}
        )
        self.UserRegFormAdmin.schema_submit_out = self.UserRegFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserInfoFormAdmin.user_model = self.auth.user_model
        self.UserInfoFormAdmin.schema = self.UserInfoFormAdmin.schema or create_model_by_model(
            self.auth.user_model,
            "UserInfoForm",
            include={"nickname", "password", "avatar", "email"},
            set_none=True,
        )
        self.UserInfoFormAdmin.schema_submit_out = self.UserInfoFormAdmin.schema_submit_out or self.schema_user_info
        # register admin
        self.register_admin(
            self.UserLoginFormAdmin,
            self.UserRegFormAdmin,
            self.UserInfoFormAdmin,
            self.UserAdmin,
            self.RoleAdmin,
            self.LoginHistoryAdmin,
            CasbinRuleAdmin,
        )

    def register_router(self):
        super().register_router()

        @self.router.get("/site_admin_actions_options", response_model=BaseApiOut)
        async def site_admin_actions_options(request: Request):
            # 获取当前登录用户的权限
            username = await self.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
            # 获取当前用户的权限列表
            options = get_admin_action_options_by_subject(enforcer=self.auth.enforcer, subject="u:" + username, group=self.site)
            return BaseApiOut(data=options)

        return self
