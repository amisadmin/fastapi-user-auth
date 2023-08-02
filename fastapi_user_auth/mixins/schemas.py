from datetime import datetime, timedelta
from typing import Awaitable, Callable, Optional, Sequence, Union

from fastapi_amis_admin.admin import ModelAdmin
from sqlalchemy.sql import Select
from starlette.requests import Request
from typing_extensions import TypedDict


class PermissionExcludeDict(TypedDict):
    all: Optional[Sequence[str]]
    list: Optional[Sequence[str]]
    filter: Optional[Sequence[str]]
    create: Optional[Sequence[str]]
    read: Optional[Sequence[str]]
    update: Optional[Sequence[str]]


SelectPermCallable = Callable[[ModelAdmin, Request, Select], Union[Select, Awaitable[Select]]]


class SelectPerm:
    def __init__(
        self,
        *,
        name: str,
        label: str,
        call: SelectPermCallable,
        reverse: bool = False,
    ):
        self.name = name
        self.label = label
        self.reverse = reverse
        self.call = call


class RecentTimeSelectPerm(SelectPerm):
    """最近时间选择数据集权限控制"""

    def __init__(
        self,
        *,
        name: str,
        label: str,
        call: SelectPermCallable = None,
        reverse: bool = False,
        td: Union[int, timedelta] = 60 * 60 * 24 * 7,
        time_column: str = "create_time",
    ):
        # 如果td为int,则表示秒数
        if isinstance(td, int):
            td = timedelta(seconds=td)
        self.td = td
        self.time_column = time_column
        super().__init__(name=name, label=label, call=call or self._call, reverse=reverse)

    async def _call(self, admin: ModelAdmin, request: Request, sel: Select) -> Select:
        column = getattr(admin.model, self.time_column)
        return sel.where(column > datetime.now() - self.td)
