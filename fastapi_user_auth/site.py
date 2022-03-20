from typing import Type
from fastapi import FastAPI
from fastapi_amis_admin.amis.components import Flex, App, Service, ActionType, Dialog
from fastapi_amis_admin.amis.constants import SizeEnum
from fastapi_amis_admin.amis.types import AmisAPI
from fastapi_amis_admin.amis_admin.settings import Settings
from fastapi_amis_admin.amis_admin.site import AdminSite
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.requests import Request
from fastapi_user_auth.app import UserAuthApp
from fastapi_user_auth.auth import Auth


class AuthAdminSite(AdminSite):
    auth: Auth = None
    UserAuthApp: Type[UserAuthApp] = UserAuthApp

    def __init__(
            self,
            settings: Settings,
            fastapi: FastAPI = None,
            engine: AsyncEngine = None,
            auth: Auth = None
    ):
        super().__init__(settings, fastapi, engine)
        self.auth = auth or self.auth or Auth(db=self.db)
        self.UserAuthApp.auth = self.auth
        self.register_admin(self.UserAuthApp)

    async def get_page(self, request: Request) -> App:
        app = await super().get_page(request)
        user_auth_app = self.create_admin_instance(self.UserAuthApp)
        app.header = Flex(className="w-full", justify='flex-end', alignItems='flex-end', items=[app.header, {
            "type": "dropdown-button",
            "label": f"{request.user.username}",
            "trigger": "hover",
            "icon": "fa fa-user",
            "buttons": [
                ActionType.Dialog(label='个人信息',
                                  dialog=Dialog(title='个人信息', actions=[], size=SizeEnum.lg,
                                                body=Service(
                                                    schemaApi=AmisAPI(method='get',
                                                                      url=f"{user_auth_app.router_path}/form/userinfo",
                                                                      cache=20000,
                                                                      responseData={'&': '${body}'})))),
                ActionType.Url(label='退出登录',
                               url=f"{user_auth_app.router_path}/logout")
            ]
        }])
        return app

    async def has_page_permission(self, request: Request) -> bool:
        return await self.auth.requires(response=False)(request)
