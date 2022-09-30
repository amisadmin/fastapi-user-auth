from typing import Type

from fastapi import FastAPI
from fastapi_amis_admin.admin import AdminSite, Settings
from fastapi_amis_admin.amis.components import ActionType, App, Dialog, Flex, Service
from fastapi_amis_admin.amis.constants import SizeEnum
from fastapi_amis_admin.amis.types import AmisAPI
from fastapi_amis_admin.crud.utils import SqlalchemyDatabase
from fastapi_amis_admin.utils.translation import i18n as _
from starlette.requests import Request

from fastapi_user_auth.app import UserAuthApp as DefaultUserAuthApp
from fastapi_user_auth.auth import Auth


class AuthAdminSite(AdminSite):
    auth: Auth = None
    UserAuthApp: Type[DefaultUserAuthApp] = DefaultUserAuthApp

    def __init__(self, settings: Settings, fastapi: FastAPI = None, engine: SqlalchemyDatabase = None, auth: Auth = None):
        super().__init__(settings, fastapi, engine)
        self.auth = auth or self.auth or Auth(db=self.db)
        self.register_admin(self.UserAuthApp)

    async def get_page(self, request: Request) -> App:
        app = await super().get_page(request)
        user_auth_app = self.get_admin_or_create(self.UserAuthApp)
        app.header = Flex(
            className="w-full",
            justify="flex-end",
            alignItems="flex-end",
            items=[
                app.header,
                {
                    "type": "dropdown-button",
                    "label": f"{request.user.username}",
                    "trigger": "hover",
                    "icon": "fa fa-user",
                    "buttons": [
                        ActionType.Dialog(
                            label=_("User Profile"),
                            dialog=Dialog(
                                title=_("User Profile"),
                                actions=[],
                                size=SizeEnum.lg,
                                body=Service(
                                    schemaApi=AmisAPI(
                                        method="post",
                                        url=f"{user_auth_app.router_path}/form/userinfo",
                                        cache=600000,
                                        responseData={"&": "${body}"},
                                    )
                                ),
                            ),
                        ),
                        ActionType.Url(label=_("Sign out"), url=f"{user_auth_app.router_path}/logout"),
                    ],
                },
            ],
        )
        return app

    async def has_page_permission(self, request: Request) -> bool:
        return await self.auth.requires(response=False)(request)
