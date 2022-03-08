import secrets
from datetime import datetime, timedelta
from typing import Optional, Union

from fastapi_amis_admin.utils.db import SqlalchemyAsyncClient
from sqlalchemy import Column, String, delete, insert
from sqlmodel import Field, select

from ..backends.base import BaseTokenStore, _TokenDataSchemaT
from ..models import SQLModelTable


class TokenStoreModel(SQLModelTable, table=True):
    __tablename__ = 'auth_token'
    token: str = Field(..., max_length=48, sa_column=Column(String(48), unique=True, index=True, nullable=False))
    data: str = Field(default='')
    create_time: datetime = Field(default_factory=datetime.utcnow)



class DbTokenStore(BaseTokenStore):
    def __init__(self, db: SqlalchemyAsyncClient,
                 expire_seconds: Optional[int] = 60 * 60 * 24 * 3,
                 TokenDataSchema: _TokenDataSchemaT = None):
        super().__init__(expire_seconds, TokenDataSchema)
        self.db = db

    async def read_token(self, token: str) -> Optional[_TokenDataSchemaT]:
        async with self.db.session_maker() as session:
            obj: TokenStoreModel = await session.scalar(select(TokenStoreModel).where(TokenStoreModel.token == token))
        if obj is None:
            return None
        # expire
        if obj.create_time < datetime.utcnow() - timedelta(seconds=self.expire_seconds):
            await self.destroy_token(token=token)
            return None
        return self.TokenDataSchema.parse_raw(obj.data)

    async def write_token(self, token_data: Union[_TokenDataSchemaT, dict]) -> str:
        obj = self.TokenDataSchema.parse_obj(token_data) if isinstance(token_data, dict) else token_data
        token = secrets.token_urlsafe()
        async with self.db.session_maker() as session:
            await session.execute(insert(TokenStoreModel).values(dict(token=token, data=obj.json())))
            await session.commit()
        return token

    async def destroy_token(self, token: str) -> None:
        async with self.db.session_maker() as session:
            await session.execute(delete(TokenStoreModel).where(TokenStoreModel.token == token))
            await session.commit()
