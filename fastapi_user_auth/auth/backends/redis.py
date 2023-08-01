import secrets
from typing import Optional, Union

from redis.asyncio import Redis

from ..backends.base import BaseTokenStore, _TokenDataSchemaT


class RedisTokenStore(BaseTokenStore):
    def __init__(self, redis: Redis, expire_seconds: Optional[int] = 60 * 60 * 24 * 3, TokenDataSchema: _TokenDataSchemaT = None):
        super().__init__(expire_seconds, TokenDataSchema)
        self.redis = redis

    async def read_token(self, token: str) -> Optional[_TokenDataSchemaT]:
        data = await self.redis.get(self.get_key(token))
        if data is None:
            return None
        return self.TokenDataSchema.parse_raw(data)

    async def write_token(self, token_data: Union[_TokenDataSchemaT, dict]) -> str:
        obj = self.TokenDataSchema.parse_obj(token_data) if isinstance(token_data, dict) else token_data
        token = secrets.token_urlsafe()
        await self.redis.set(self.get_key(token), obj.json(), ex=self.expire_seconds)
        return token

    async def destroy_token(self, token: str) -> None:
        await self.redis.delete(self.get_key(token))

    def get_key(self, token: str):
        return f"auth:token:{token}"
