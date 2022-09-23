from typing import Generic, Optional, TypeVar, Union

from fastapi_user_auth.auth.schemas import BaseTokenData

_TokenDataSchemaT = TypeVar("_TokenDataSchemaT", bound=BaseTokenData)


class BaseTokenStore(Generic[_TokenDataSchemaT]):
    TokenDataSchema: _TokenDataSchemaT

    def __init__(self, expire_seconds: Optional[int] = 60 * 60 * 24 * 3, TokenDataSchema: _TokenDataSchemaT = None) -> None:
        self.TokenDataSchema = TokenDataSchema or BaseTokenData
        self.expire_seconds = expire_seconds

    async def read_token(self, token: Optional[str]) -> Optional[_TokenDataSchemaT]:
        raise NotImplementedError

    async def write_token(self, token_data: Union[_TokenDataSchemaT, dict]) -> str:
        raise NotImplementedError

    async def destroy_token(self, token: str) -> None:
        raise NotImplementedError
