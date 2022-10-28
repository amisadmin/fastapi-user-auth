from typing import Type

from fastapi_amis_admin.admin import AdminApp, ModelAdmin
from fastapi_amis_admin.amis.components import PageSchema
from fastapi_amis_admin.crud.utils import schema_create_by_schema
from fastapi_amis_admin.utils.translation import i18n as _
from starlette.requests import Request

from fastapi_user_auth.admin import GroupAdmin as DefaultGroupAdmin
from fastapi_user_auth.admin import PermissionAdmin as DefaultPermissionAdmin
from fastapi_user_auth.admin import RoleAdmin as DefaultRoleAdmin
from fastapi_user_auth.admin import UserAdmin as DefaultUserAdmin
from fastapi_user_auth.admin import UserInfoFormAdmin as DefaultUserInfoFormAdmin
from fastapi_user_auth.admin import UserLoginFormAdmin as DefaultUserLoginFormAdmin
from fastapi_user_auth.admin import UserRegFormAdmin as DefaultUserRegFormAdmin
from fastapi_user_auth.auth import AuthRouter


class UserAuthApp(AdminApp, AuthRouter):
    page_schema = PageSchema(label=_("User Authentication"), icon="fa fa-lock", sort=99)
    router_prefix = "/auth"
    # default admin
    UserLoginFormAdmin: Type[DefaultUserLoginFormAdmin] = DefaultUserLoginFormAdmin
    UserRegFormAdmin: Type[DefaultUserRegFormAdmin] = DefaultUserRegFormAdmin
    UserInfoFormAdmin: Type[DefaultUserInfoFormAdmin] = DefaultUserInfoFormAdmin
    UserAdmin: Type[DefaultUserAdmin] = DefaultUserAdmin
    RoleAdmin: Type[ModelAdmin] = DefaultRoleAdmin
    GroupAdmin: Type[ModelAdmin] = DefaultGroupAdmin
    PermissionAdmin: Type[ModelAdmin] = DefaultPermissionAdmin

    def __init__(self, app: "AdminApp"):
        AdminApp.__init__(self, app)
        self.auth = self.auth or self.site.auth
        AuthRouter.__init__(self)
        self.UserAdmin.model = self.UserAdmin.model or self.auth.user_model
        self.UserLoginFormAdmin.schema = self.UserLoginFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model, "UserLoginIn", include={"username", "password"}
        )
        self.UserLoginFormAdmin.schema_submit_out = self.UserLoginFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserRegFormAdmin.schema = self.UserRegFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model, "UserRegIn", include={"username", "password", "email"}
        )
        self.UserRegFormAdmin.schema_submit_out = self.UserRegFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserInfoFormAdmin.user_model = self.auth.user_model
        self.UserInfoFormAdmin.schema = self.UserInfoFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model,
            "UserInfoForm",
            exclude={"id", "username", "password", "is_active", "create_time"},
        )
        self.UserInfoFormAdmin.schema_submit_out = self.UserInfoFormAdmin.schema_submit_out or self.schema_user_info
        # register admin
        self.register_admin(
            self.UserLoginFormAdmin,
            self.UserRegFormAdmin,
            self.UserInfoFormAdmin,
            self.UserAdmin,
            self.RoleAdmin,
            self.GroupAdmin,
            self.PermissionAdmin,
        )

    async def has_page_permission(self, request: Request) -> bool:
        return await super().has_page_permission(request) and await request.auth.requires(roles="admin", response=False)(request)
