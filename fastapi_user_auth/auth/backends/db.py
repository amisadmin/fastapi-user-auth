import secrets
from datetime import datetime, timedelta
from typing import Optional, Union

from sqlalchemy import Column, String, delete
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import Field, select

from ..backends.base import BaseTokenStore, _TokenDataSchemaT
from ..models import CreateTimeMixin, PkMixin


class TokenStoreModel(PkMixin, CreateTimeMixin, table=True):
    __tablename__ = "auth_token"
    token: str = Field(..., max_length=48, sa_column=Column(String(48), unique=True, index=True, nullable=False))
    data: str = Field(default="")


class DbTokenStore(BaseTokenStore):
    def __init__(
        self,
        db: Union[AsyncDatabase, Database],
        expire_seconds: Optional[int] = 60 * 60 * 24 * 3,
        TokenDataSchema: _TokenDataSchemaT = None,
    ):
        super().__init__(expire_seconds, TokenDataSchema)
        self.db = db

    async def read_token(self, token: str) -> Optional[_TokenDataSchemaT]:
        stmt = select(TokenStoreModel).where(TokenStoreModel.token == token)
        obj: TokenStoreModel = await self.db.async_scalar(stmt)
        if obj is None:
            return None
        # expire
        if obj.create_time < datetime.now() - timedelta(seconds=self.expire_seconds):
            await self.destroy_token(token=token)
            return None
        return self.TokenDataSchema.parse_raw(obj.data)

    async def write_token(self, token_data: Union[_TokenDataSchemaT, dict]) -> str:
        obj = self.TokenDataSchema.parse_obj(token_data) if isinstance(token_data, dict) else token_data
        token = secrets.token_urlsafe()
        model = TokenStoreModel(token=token, data=obj.json())
        self.db.add(model)
        await self.db.async_flush()
        return token

    async def destroy_token(self, token: str) -> None:
        stmt = delete(TokenStoreModel).where(TokenStoreModel.token == token)
        await self.db.async_execute(stmt)
        await self.db.async_flush()
