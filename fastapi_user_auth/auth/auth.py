import asyncio
import contextlib
import functools
import inspect
from collections.abc import Coroutine
from typing import (
    Any,
    Callable,
    Generic,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from fastapi import Depends, FastAPI, Form, HTTPException, params
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi_amis_admin.crud.base import RouterMixin
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.crud.utils import schema_create_by_schema
from fastapi_amis_admin.utils.functools import cached_property
from fastapi_amis_admin.utils.translation import i18n as _
from passlib.context import CryptContext
from pydantic import BaseModel, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import select
from starlette.authentication import AuthenticationBackend
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.websockets import WebSocket

from .backends.base import BaseTokenStore
from .backends.db import DbTokenStore
from .models import BaseUser, Role, User, UserRoleLink
from .schemas import UserLoginOut

_UserModelT = TypeVar("_UserModelT", bound=BaseUser)


class AuthBackend(AuthenticationBackend, Generic[_UserModelT]):
    def __init__(self, auth: "Auth", token_store: BaseTokenStore):
        self.auth = auth
        self.token_store = token_store

    @staticmethod
    def get_user_token(request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization") or request.cookies.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            return None
        return token

    async def authenticate(self, request: Request) -> Tuple["Auth", Optional[_UserModelT]]:
        return self.auth, await self.auth.get_current_user(request)

    def attach_middleware(self, app: FastAPI):
        app.add_middleware(AuthenticationMiddleware, backend=self)  # 添加auth中间件


class Auth(Generic[_UserModelT]):
    user_model: Type[_UserModelT] = None
    db: Union[AsyncDatabase, Database] = None
    backend: AuthBackend[_UserModelT] = None

    def __init__(
        self,
        db: Union[AsyncDatabase, Database],
        token_store: BaseTokenStore = None,
        user_model: Type[_UserModelT] = User,
        pwd_context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto"),
    ):
        self.user_model = user_model or self.user_model
        assert self.user_model, "user_model is None"
        self.db = db or self.db
        self.backend = self.backend or AuthBackend(self, token_store or DbTokenStore(self.db))
        self.pwd_context = pwd_context

    async def authenticate_user(self, username: str, password: Union[str, SecretStr]) -> Optional[_UserModelT]:
        user = await self.db.async_scalar(select(self.user_model).where(self.user_model.username == username))
        if user:
            pwd = password.get_secret_value() if isinstance(password, SecretStr) else password
            pwd2 = user.password.get_secret_value() if isinstance(user.password, SecretStr) else user.password
            if self.pwd_context.verify(pwd, pwd2):  # 用户存在 且 密码验证通过
                return user
        return None

    @cached_property
    def get_current_user(self):
        async def _get_current_user(
            request: Request, session: Union[Session, AsyncSession, None] = Depends(self.db.session_generator)
        ) -> Optional[_UserModelT]:
            if request.scope.get("auth"):  # 防止重复授权
                return request.scope.get("user")
            request.scope["auth"], request.scope["user"] = self, None
            token = self.backend.get_user_token(request)
            if not token:
                return None
            token_data = await self.backend.token_store.read_token(token)
            if token_data is not None:
                request.scope["user"]: _UserModelT = await self.db.async_get(self.user_model, token_data.id, session=session)
            return request.user

        return _get_current_user

    def requires(
        self,
        roles: Union[str, Sequence[str]] = None,
        groups: Union[str, Sequence[str]] = None,
        permissions: Union[str, Sequence[str]] = None,
        status_code: int = 403,
        redirect: str = None,
        response: Union[bool, Response] = None,
    ) -> Callable:  # sourcery no-metrics
        async def has_requires(user: _UserModelT) -> bool:
            return user and await self.db.async_run_sync(
                user.has_requires, roles=roles, groups=groups, permissions=permissions, commit=False
            )

        async def depend(
            request: Request,
            user: _UserModelT = Depends(self.get_current_user),
        ) -> Union[bool, Response]:
            if isinstance(user, params.Depends):
                user = await self.get_current_user(request)
            if not await has_requires(user):
                if response is not None:
                    return response
                code, headers = status_code, {}
                if redirect is not None:
                    code = 307
                    headers = {"location": request.url_for(redirect)}
                raise HTTPException(status_code=code, headers=headers)
            return True

        def decorator(func: Callable = None) -> Union[Callable, Coroutine]:
            if func is None:
                return depend
            if isinstance(func, Request):
                return depend(func)
            sig = inspect.signature(func)
            for idx, parameter in enumerate(sig.parameters.values()):  # noqa: B007
                if parameter.name == "request" or parameter.name == "websocket":
                    type_ = parameter.name
                    break
            else:
                raise Exception(f'No "request" or "websocket" argument on function "{func}"')

            if type_ == "websocket":
                # Handle websocket functions. (Always async)
                @functools.wraps(func)
                async def websocket_wrapper(*args: Any, **kwargs: Any) -> None:
                    websocket = kwargs.get("websocket", args[idx] if args else None)
                    assert isinstance(websocket, WebSocket)
                    user = await self.get_current_user(websocket)  # type: ignore
                    if not await has_requires(user):
                        await websocket.close()
                    else:
                        await func(*args, **kwargs)

                return websocket_wrapper

            elif asyncio.iscoroutinefunction(func):
                # Handle async request/response functions.
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Response:
                    request = kwargs.get("request", args[idx] if args else None)
                    assert isinstance(request, Request)
                    response = await depend(request)
                    if response is True:
                        return await func(*args, **kwargs)
                    return response

                return async_wrapper

            else:
                # Handle sync request/response functions.
                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Response:
                    request = kwargs.get("request", args[idx] if args else None)
                    assert isinstance(request, Request)
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    response = loop.run_until_complete(loop.create_task(depend(request)))
                    if response is True:
                        return func(*args, **kwargs)
                    return response

                return sync_wrapper

        return decorator

    def _create_role_user_sync(self, session: Session, role_key: str = "admin") -> User:
        # create admin role
        role = session.scalar(select(Role).where(Role.key == role_key))
        if not role:
            role = Role(key=role_key, name=f"{role_key} role")
            session.add(role)
            session.flush()

        # create admin user
        user = session.scalar(
            select(self.user_model)
            .join(UserRoleLink, UserRoleLink.user_id == self.user_model.id)
            .where(UserRoleLink.role_id == role.id)
        )
        if not user:
            user = self.user_model(
                username=role_key,
                password=self.pwd_context.hash(role_key),
                email=f"{role_key}@amis.work",  # type:ignore
                roles=[role],
            )
            session.add(user)
            session.flush()

        return user

    async def create_role_user(self, role_key: str = "admin") -> User:
        return await self.db.async_run_sync(self._create_role_user_sync, role_key, on_close_pre=lambda user: User.parse_obj(user))


class AuthRouter(RouterMixin):
    auth: Auth = None
    schema_user_login_out: Type[UserLoginOut] = UserLoginOut
    router_prefix = "/auth"
    schema_user_info: Type[BaseModel] = None

    def __init__(self, auth: Auth = None):
        self.auth = auth or self.auth
        assert self.auth, "auth is None"
        RouterMixin.__init__(self)
        self.router.dependencies.insert(0, Depends(self.auth.backend.authenticate))
        self.schema_user_info = self.schema_user_info or schema_create_by_schema(
            self.auth.user_model, "UserInfo", exclude={"password"}
        )

        self.router.add_api_route(
            "/userinfo",
            self.route_userinfo,
            methods=["GET"],
            description=_("User Profile"),
            dependencies=None,
            response_model=BaseApiOut[self.schema_user_info],
        )
        self.router.add_api_route(
            "/logout", self.route_logout, methods=["GET"], description=_("Sign out"), dependencies=None, response_model=BaseApiOut
        )
        # oauth2
        self.router.dependencies.append(Depends(self.OAuth2(tokenUrl=f"{self.router_path}/gettoken", auto_error=False)))
        self.router.add_api_route(
            "/gettoken",
            self.route_gettoken,
            methods=["POST"],
            description="OAuth2 Token",
            response_model=BaseApiOut[self.schema_user_login_out],
        )

    @cached_property
    def router_path(self) -> str:
        return self.router.prefix

    @property
    def route_userinfo(self):
        @self.auth.requires()
        async def userinfo(request: Request):
            return BaseApiOut(data=request.user)

        return userinfo

    @property
    def route_logout(self):
        @self.auth.requires()
        async def user_logout(request: Request):
            token_value = request.auth.backend.get_user_token(request=request)
            with contextlib.suppress(Exception):
                await self.auth.backend.token_store.destroy_token(token=token_value)
            response = RedirectResponse(url="/")
            response.delete_cookie("Authorization")
            return response

        return user_logout

    @property
    def route_gettoken(self):
        async def oauth_token(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
            if request.scope.get("user") is None:
                request.scope["user"] = await request.auth.authenticate_user(username=username, password=password)
            if request.scope.get("user") is None:
                return BaseApiOut(status=-1, msg=_("Incorrect username or password!"))
            token_info = self.schema_user_login_out.parse_obj(request.user)
            token_info.access_token = await request.auth.backend.token_store.write_token(request.user.dict())
            response.set_cookie("Authorization", f"bearer {token_info.access_token}")
            return BaseApiOut(data=token_info)

        return oauth_token

    class OAuth2(OAuth2PasswordBearer):
        async def __call__(self, request: Request) -> Optional[str]:
            return request.auth.backend.get_user_token(request)
