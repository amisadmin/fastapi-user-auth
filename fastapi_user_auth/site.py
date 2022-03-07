from fastapi import FastAPI
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

    async def has_page_permission(self, request: Request) -> bool:
        return await self.auth.requires(response=False)(request)
