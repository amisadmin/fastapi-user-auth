from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Awaitable, Callable, List, Optional, Sequence, Union

from fastapi_amis_admin.admin import ModelAdmin
from sqlalchemy.sql import Select
from starlette.requests import Request


@dataclass
class PermFieldsExclude:
    all: Optional[Sequence[str]] = None
    list: Optional[Sequence[str]] = None
    filter: Optional[Sequence[str]] = None
    create: Optional[Sequence[str]] = None
    read: Optional[Sequence[str]] = None
    update: Optional[Sequence[str]] = None


SelectPermCallable = Callable[[ModelAdmin, Request, Select], Union[Select, Awaitable[Select]]]


@dataclass
class SelectPerm:
    name: str
    label: str
    reverse: bool = False
    call: SelectPermCallable = None

    def __post_init__(self):
        if self.call is None and hasattr(self, "_call"):
            self.call = self._call
        assert self.call is not None, "call must be set"


@dataclass
class RecentTimeSelectPerm(SelectPerm):
    """最近时间选择数据集"""

    td: Union[int, timedelta] = 60 * 60 * 24 * 7
    time_column: str = "create_time"

    def __post_init__(self):
        # 如果td为int,则表示秒数
        self.td = timedelta(seconds=self.td) if isinstance(self.td, int) else self.td

    async def _call(self, admin: ModelAdmin, request: Request, sel: Select) -> Select:
        column = getattr(admin.model, self.time_column)
        return sel.where(column > datetime.now() - self.td)


@dataclass
class UserSelectPerm(SelectPerm):
    """所属用户选择数据集,只能选择匹配当前用户的数据"""

    user_column: str = "user_id"

    async def _call(self, admin: ModelAdmin, request: Request, sel: Select) -> Select:
        user_id = await admin.site.auth.get_current_user_identity(request, name="id")
        if not user_id:  # 未登录
            return sel.where(False)
        column = getattr(admin.model, self.user_column)
        return sel.where(column == user_id)


@dataclass
class SimpleSelectPerm(SelectPerm):
    """简单列选择数据集"""

    values: Union[List[str], List[int]] = None
    column: str = "status"

    async def _call(self, admin: ModelAdmin, request: Request, sel: Select) -> Select:
        if not self.values:
            return sel
        column = getattr(admin.model, self.column)
        if len(self.values) == 1:
            return sel.where(column == self.values[0])
        return sel.where(column.in_(self.values))


@dataclass
class FilterSelectPerm(SelectPerm):
    """filter(where)子句选择数据集"""

    filters: list = None

    async def _call(self, admin: ModelAdmin, request: Request, sel: Select) -> Select:
        if not self.filters:
            return sel
        return sel.filter(*self.filters)
