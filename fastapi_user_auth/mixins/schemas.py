from typing import Optional, Sequence

from typing_extensions import TypedDict


class PermissionExcludeDict(TypedDict):
    all: Optional[Sequence[str]]
    list: Optional[Sequence[str]]
    filter: Optional[Sequence[str]]
    create: Optional[Sequence[str]]
    read: Optional[Sequence[str]]
    update: Optional[Sequence[str]]
