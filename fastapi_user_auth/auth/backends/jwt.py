from datetime import timedelta, datetime
from typing import Optional, Union

from jose import jwt, JWTError

from ..backends.base import BaseTokenStore, _TokenDataSchemaT


class JwtTokenStore(BaseTokenStore):

    def __init__(
            self,
            secret_key: str,
            algorithm: str = "HS256",
            expire_seconds: Optional[int] = 60 * 60 * 24 * 3,
            TokenDataSchema: _TokenDataSchemaT = None
    ):
        super().__init__(expire_seconds, TokenDataSchema)
        self.secret_key = secret_key
        self.algorithm = algorithm

    async def read_token(self, token: str) -> Optional[_TokenDataSchemaT]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=self.algorithm)
            return self.TokenDataSchema.parse_obj(payload)
        except JWTError:
            return None

    async def write_token(self, token_data: Union[_TokenDataSchemaT, dict]) -> str:
        obj = self.TokenDataSchema.parse_obj(token_data) if isinstance(token_data, dict) else token_data
        data = obj.dict()
        expire = datetime.utcnow() + timedelta(seconds=self.expire_seconds)
        data.update({"exp": expire})
        return jwt.encode(data, self.secret_key, algorithm=self.algorithm)

    async def destroy_token(self, token: str) -> None:
        raise NotImplementedError
