from fastapi_amis_admin.admin import BaseAuthFieldModelAdmin, BaseAuthSelectModelAdmin
from sqlalchemy.sql import Select
from starlette.requests import Request

from fastapi_user_auth.auth.schemas import SystemUserEnum


class AuthFieldModelAdmin(BaseAuthFieldModelAdmin):
    async def has_field_permission(self, request: Request, field: str, action: str = "") -> bool:
        """判断用户是否有字段权限"""
        subject = await self.site.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
        action += ""
        effect = self.site.auth.enforcer.enforce("u:" + subject, self.unique_id, f"page:{action}:{field}", f"page:{action}")
        return effect


class AuthSelectModelAdmin(BaseAuthSelectModelAdmin):
    async def has_select_permission(self, request: Request, name: str) -> bool:
        """判断用户是否有数据集权限"""
        subject = await self.site.auth.get_current_user_identity(request) or SystemUserEnum.GUEST
        effect = self.site.auth.enforcer.enforce("u:" + subject, self.unique_id, f"page:select:{name}", "page:select")
        return effect

    async def filter_select(self, request: Request, sel: Select) -> Select:
        """在sel中添加权限过滤条件"""
        subject = await self.site.auth.get_current_user_identity(request)
        if subject == SystemUserEnum.ROOT:
            return sel
        return await super().filter_select(request, sel)
