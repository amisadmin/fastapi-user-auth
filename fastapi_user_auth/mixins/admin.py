from datetime import datetime
from functools import cached_property
from typing import Dict, List

from fastapi_amis_admin import admin
from fastapi_amis_admin.admin import AdminAction, AdminApp
from fastapi_amis_admin.amis import TableCRUD
from fastapi_amis_admin.crud.base import SchemaModelT, SchemaUpdateT
from starlette.requests import Request


class ReadOnlyModelAdmin(admin.ModelAdmin):
    """只读模型管理Mixin
    移除了创建,更新,删除等操作
    """

    @cached_property
    def registered_admin_actions(self) -> Dict[str, "AdminAction"]:
        actions = super().registered_admin_actions
        return {
            key: action
            for key, action in actions.items()
            if key not in {"create", "update", "delete", "bulk_delete", "bulk_update", "bulk_create"}
        }

    async def has_create_permission(self, request: Request, data: SchemaUpdateT, **kwargs) -> bool:
        return False

    async def has_update_permission(
        self,
        request: Request,
        item_id: List[str],
        data: SchemaUpdateT,
        **kwargs,
    ) -> bool:
        return False

    async def has_delete_permission(self, request: Request, item_id: List[str], **kwargs) -> bool:
        return False


class AutoTimeModelAdmin(admin.ModelAdmin):
    """禁止修改时间Mixin,没有Id,创建时间,更新时间,删除时间等字段的创建和更新"""

    create_exclude = {
        "id",
        "create_time",
        "update_time",
        "delete_time",
    }
    update_exclude = {
        "id",
        "create_time",
        "update_time",
        "delete_time",
    }


class SoftDeleteModelAdmin(AutoTimeModelAdmin):
    """软删除模型Mixin.
    - 需要在模型中定义delete_time字段.如果delete_time字段为None,则表示未删除.
    """

    def __init__(self, app: "AdminApp"):
        super().__init__(app)
        assert hasattr(self.model, "delete_time"), "SoftDeleteAdminMixin需要在模型中定义delete_time字段"

    async def get_select(self, request: Request):
        sel = await super().get_select(request)
        return sel.where(self.model.delete_time == None)  # noqa E711

    def delete_item(self, obj: SchemaModelT) -> None:
        obj.delete_time = datetime.now()


class FootableModelAdmin(admin.ModelAdmin):
    """为模型管理Amis表格添加底部展示(Footable)属性"""

    async def get_list_table(self, request: Request) -> TableCRUD:
        table = await super().get_list_table(request)
        table.footable = True
        return table
