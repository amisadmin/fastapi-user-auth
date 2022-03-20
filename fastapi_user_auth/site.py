import fastapi_amis_admin
from fastapi import FastAPI
from fastapi_amis_admin.amis.components import Flex, Tpl
from fastapi_amis_admin.amis_admin.settings import Settings
from fastapi_amis_admin.amis_admin.site import AdminSite
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.requests import Request
from fastapi_user_auth.app import UserAuthApp
from fastapi_user_auth.auth import Auth


class AuthAdminSite(AdminSite):
    auth: Auth = None

    def __init__(
            self,
            settings: Settings,
            fastapi: FastAPI = None,
            engine: AsyncEngine = None,
            auth: Auth = None
    ):
        super().__init__(settings, fastapi, engine)
        self.auth = auth or self.auth or Auth(db=self.db)
        UserAuthApp.auth = self.auth
        self.register_admin(UserAuthApp)
    
    async def get_page(self, request: Request) -> App:
        app = await super().get_page(request)
        user_items = {
            "type": "dropdown-button",
            "label": f"{request.user.username}",
            "trigger": "hover",
            "icon": "fa fa-user",
            "buttons": [
                {
                    "type": "button",
                    "label": "个人信息"
                },
                {
                    "type": "button",
                    "label": "退出登录"
                }
            ]
        }
        copyright_info = Tpl(style={"margin-left": 5},
                             tpl=f"""
                                     <div class="flex justify-between">
                                        <div>
                                            <a href="{fastapi_amis_admin.__url__}" target="_blank"'title="版权信息,不可删除!">
                                                <i class="fa fa-github fa-2x"></i>
                                            </a>
                                        </div>
                                    </div>
                                  """
                             )
        app.header = Flex(className="w-full", justify='flex-end', alignItems='flex-end', items=[user_items, copyright_info])

    async def has_page_permission(self, request: Request) -> bool:
        return await self.auth.requires(response=False)(request)
