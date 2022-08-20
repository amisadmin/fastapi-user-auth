from typing import Type

from fastapi_amis_admin.amis.components import PageSchema
from fastapi_amis_admin.admin import AdminApp, ModelAdmin
from fastapi_amis_admin.crud.utils import schema_create_by_schema
from fastapi_amis_admin.utils.translation import i18n as _
from starlette.requests import Request

from fastapi_user_auth.admin import UserLoginFormAdmin, GroupAdmin, PermissionAdmin, UserAdmin, \
    UserRegFormAdmin, RoleAdmin, UserInfoFormAdmin  # noqa F401
from fastapi_user_auth.auth import AuthRouter

class UserAuthApp(AdminApp, AuthRouter):
    page_schema = PageSchema(label = _('User Authentication'), icon = 'fa fa-lock', sort = 99)
    router_prefix = '/auth'
    # default admin
    UserLoginFormAdmin: Type[UserLoginFormAdmin] = UserLoginFormAdmin
    UserRegFormAdmin: Type[UserRegFormAdmin] = UserRegFormAdmin
    UserInfoFormAdmin: Type[UserInfoFormAdmin] = UserInfoFormAdmin
    UserAdmin: Type[UserAdmin] = UserAdmin
    RoleAdmin: Type[ModelAdmin] = RoleAdmin
    GroupAdmin: Type[ModelAdmin] = GroupAdmin
    PermissionAdmin: Type[ModelAdmin] = PermissionAdmin

    def __init__(self, app: "AdminApp"):
        AdminApp.__init__(self, app)
        AuthRouter.__init__(self)
        self.UserAdmin.model = self.UserAdmin.model or self.auth.user_model
        self.UserLoginFormAdmin.schema = self.UserLoginFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model, 'UserLoginIn', include = {'username', 'password'}
        )
        self.UserLoginFormAdmin.schema_submit_out = self.UserLoginFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserRegFormAdmin.schema = self.UserRegFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model, 'UserRegIn', include = {'username', 'password', 'email'}
        )
        self.UserRegFormAdmin.schema_submit_out = self.UserRegFormAdmin.schema_submit_out or self.schema_user_login_out
        self.UserInfoFormAdmin.schema = self.UserInfoFormAdmin.schema or schema_create_by_schema(
            self.auth.user_model, 'UserInfoForm',
            exclude = {'id', 'username', 'password', 'is_active', 'parent_id', 'point', 'create_time'}
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
            self.PermissionAdmin
        )

    async def has_page_permission(self, request: Request) -> bool:
        return (await super().has_page_permission(request)
                and await request.auth.requires(roles = 'admin', response = False)(request))
