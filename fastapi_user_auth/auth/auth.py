import asyncio
import contextlib
import functools
import inspect
from collections.abc import Coroutine
from pathlib import Path
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

from casbin import AsyncEnforcer
from fastapi import Depends, FastAPI, Form, HTTPException, params
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi_amis_admin.admin import BaseAdminSite
from fastapi_amis_admin.crud.base import RouterMixin
from fastapi_amis_admin.crud.schema import BaseApiOut
from fastapi_amis_admin.utils.functools import cached_property
from fastapi_amis_admin.utils.pydantic import create_model_by_model
from fastapi_amis_admin.utils.translation import i18n as _
from passlib.context import CryptContext
from pydantic import BaseModel, SecretStr
from sqlalchemy.orm import Session
from sqlalchemy_database import AsyncDatabase, Database
from sqlmodel import select
from starlette.authentication import AuthenticationBackend
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.websockets import WebSocket

from ..utils.sqlachemy_adapter import Adapter
from .backends.base import BaseTokenStore
from .backends.db import DbTokenStore
from .models import BaseUser, CasbinRule, LoginHistory, Role, User
from .schemas import BaseTokenData, UserLoginOut

UserModelT = TypeVar("UserModelT", bound=BaseUser)


class AuthBackend(AuthenticationBackend, Generic[UserModelT]):
    def __init__(self, auth: "Auth", token_store: BaseTokenStore):
        self.auth = auth
        self.token_store = token_store

    @staticmethod
    def get_user_token(request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization") or request.cookies.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)
        return None if not authorization or scheme.lower() != "bearer" else token

    async def authenticate(self, request: Request) -> Tuple["Auth", Optional[UserModelT]]:
        return self.auth, await self.auth.get_current_user(request)

    def attach_middleware(self, app: FastAPI):
        app.add_middleware(AuthenticationMiddleware, backend=self)  # 添加auth中间件


class Auth(Generic[UserModelT]):
    user_model: Type[UserModelT] = None
    db: Union[AsyncDatabase, Database] = None
    backend: AuthBackend[UserModelT] = None

    def __init__(
        self,
        db: Union[AsyncDatabase, Database],
        *,
        token_store: BaseTokenStore = None,
        user_model: Type[UserModelT] = User,
        pwd_context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto"),
        enforcer: AsyncEnforcer = None,
    ):
        self.user_model = user_model or self.user_model
        assert self.user_model, "user_model is None"
        self.db = db or self.db
        self.backend = self.backend or AuthBackend(self, token_store or DbTokenStore(self.db))
        self.pwd_context = pwd_context
        self._enforcer = enforcer

    @cached_property
    def enforcer(self) -> AsyncEnforcer:
        if self._enforcer is not None:
            return self._enforcer
        enforcer = AsyncEnforcer(
            model=str(Path(__file__).parent / "model.conf"),
            adapter=Adapter(
                db=self.db,
                db_class=CasbinRule,
            ),
        )
        return enforcer

    async def authenticate_user(self, username: str, password: Union[str, SecretStr]) -> Optional[UserModelT]:
        user = await self.db.async_scalar(
            select(self.user_model).where(
                self.user_model.username == username,
                self.user_model.is_active == True,  # noqa E712
                self.user_model.delete_time == None,  # noqa E711
            )
        )
        if user:
            pwd = password.get_secret_value() if isinstance(password, SecretStr) else password
            pwd2 = user.password.get_secret_value() if isinstance(user.password, SecretStr) else user.password
            if self.pwd_context.verify(pwd, pwd2):  # 用户存在 且 密码验证通过
                return user
        return None

    async def _get_token_info(self, request: Request) -> Optional[BaseTokenData]:
        if "user_token_info" in request.scope:  # 防止重复授权
            return request.scope["user_token_info"]
        request.scope["auth"] = self  # 为了在token_store中使用
        token = self.backend.get_user_token(request)
        request.scope["user_token_info"] = await self.backend.token_store.read_token(token) if token else None
        return request.scope["user_token_info"]

    async def get_current_user_identity(self, request: Request, name: str = None) -> str:
        token_info = await self._get_token_info(request)
        name = name or "username"
        user_identity = getattr(token_info, name, "") if token_info else ""
        return user_identity

    async def has_role_for_user(self, identity: str, roles: Union[str, Sequence[str]], is_any: bool = True) -> bool:
        identity = "u:" + identity
        if isinstance(roles, str):
            roles = [roles]
        if identity == "u:root" and "root" in roles:  # 默认root用户拥有root角色
            return True
        for role in roles:
            if not role:
                continue
            ret = await self.enforcer.has_role_for_user(identity, "r:" + role)
            if is_any and ret:
                return True
            elif not is_any and not ret:
                return False
        return not is_any

    async def has_role(self, request: Request, *, roles: Union[str, Sequence[str]]) -> bool:
        """判断当前用户是否拥有指定角色,拥有任意一个角色即返回True"""
        identity = await self.get_current_user_identity(request)
        return await self.has_role_for_user(identity, roles, is_any=True)

    async def get_current_user(self, request: Request) -> Optional[UserModelT]:
        if "user" in request.scope:  # 防止重复授权
            return request.scope["user"]
        token_info = await self._get_token_info(request)
        request.scope["user"]: UserModelT = await self.db.async_get(self.user_model, token_info.id) if token_info else None
        return request.scope["user"]

    def requires(
        self,
        roles: Union[str, Sequence[str]] = None,
        status_code: int = 403,
        redirect: str = None,
        response: Union[bool, Response] = None,
    ) -> Callable:  # sourcery no-metrics
        # todo 优化
        roles_ = (roles,) if not roles or isinstance(roles, str) else tuple(roles)

        async def has_requires(user: UserModelT) -> bool:
            if not user:
                return False
            if roles_ == (None,):
                return True
            return await self.has_role_for_user(user.username, roles_)

        async def depend(
            request: Request,
            user: UserModelT = Depends(self.get_current_user),
        ) -> Union[bool, Response]:
            user_auth = request.scope.get("__user_auth__", None)
            if user_auth is None:
                request.scope["__user_auth__"] = {}
            cache_key = (roles_,)
            if cache_key not in request.scope["__user_auth__"]:  # 防止重复授权
                if isinstance(user, params.Depends):
                    user = await self.get_current_user(request)
                result = await has_requires(user)
                request.scope["__user_auth__"][cache_key] = result
            if not request.scope["__user_auth__"][cache_key]:
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
                if parameter.name in ["request", "websocket"]:
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

    def _create_role_user_sync(self, session: Session, role_key: str = "root") -> User:
        # create admin role
        role = session.scalar(select(Role).where(Role.key == role_key))
        if not role:
            role = Role(key=role_key, name=f"{role_key} role")
            session.add(role)
            session.flush()

        # create admin user
        user = session.scalar(select(self.user_model).where(self.user_model.username == role_key))
        if not user:
            user = self.user_model(
                username=role_key,
                password=self.pwd_context.hash(role_key),
            )
            session.add(user)
            session.flush()
        # create casbin rule
        rule = session.scalar(
            select(CasbinRule).where(
                CasbinRule.ptype == "g",
                CasbinRule.v0 == "u:" + role_key,
                CasbinRule.v1 == "r:" + role_key,
            )
        )
        if not rule:
            rule = CasbinRule(ptype="g", v0="u:" + role_key, v1="r:" + role_key)
            session.add(rule)
            session.flush()
        return user

    async def create_role_user(self, role_key: str = "root", commit: bool = True) -> User:
        user = await self.db.async_run_sync(self._create_role_user_sync, role_key)
        if commit:
            await self.db.async_commit()
        return user

    async def request_login(self, request: Request, response: Response, username: str, password: str) -> BaseApiOut[UserLoginOut]:
        if request.scope.get("user"):
            return BaseApiOut(code=1, msg=_("User logged in!"), data=UserLoginOut.parse_obj(request.user))
        user = await request.auth.authenticate_user(username=username, password=password)
        # 保存登录记录
        ip = request.client.host  # 获取真实ip
        # 获取代理ip
        ips = [request.headers.get(key, "").strip() for key in ["x-forwarded-for", "x-real-ip", "x-client-ip", "remote-host"]]
        forwarded_for = ",".join([i for i in set(ips) if i and i != ip])
        history = LoginHistory(
            user_id=user.id if user else None,
            login_name=username,
            ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
            login_status="登录成功",
            forwarded_for=forwarded_for,
        )
        self.db.add(history)
        if not user:
            history.login_status = "密码错误"
            return BaseApiOut(status=-1, msg=_("Incorrect username or password!"))
        if not user.is_active:
            history.login_status = "用户未激活"
            return BaseApiOut(status=-2, msg=_("Inactive user status!"))
        request.scope["user"] = user
        token_info = UserLoginOut.parse_obj(request.user)
        token_info.access_token = await request.auth.backend.token_store.write_token(request.user.dict())
        response.set_cookie("Authorization", f"bearer {token_info.access_token}")
        return BaseApiOut(code=0, data=token_info)

    def get_password_hash(self, password: Union[str, SecretStr]) -> str:
        if isinstance(password, SecretStr):
            password = password.get_secret_value()
        return self.pwd_context.hash(password) if password else ""


class AuthRouter(RouterMixin):
    auth: Auth = None
    schema_user_login_out: Type[UserLoginOut] = UserLoginOut
    router_prefix = "/auth"
    schema_user_info: Type[BaseModel] = None
    site: BaseAdminSite = None

    def __init__(self, auth: Auth = None):
        self.auth = auth or self.auth
        assert self.auth, "auth is None"
        RouterMixin.__init__(self)
        self.router.dependencies.insert(0, Depends(self.auth.backend.authenticate))
        self.schema_user_info = self.schema_user_info or create_model_by_model(
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
            "/logout",
            self.route_logout,
            methods=["GET"],
            description=_("Sign out"),
            dependencies=None,
            response_model=BaseApiOut,
        )
        # oauth2
        if self.route_gettoken:
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
            response = RedirectResponse(url=self.site.settings.site_path)
            response.delete_cookie("Authorization")
            return response

        return user_logout

    @property
    def route_gettoken(self):
        async def oauth_token(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
            return await self.auth.request_login(request, response, username, password)

        return oauth_token

    class OAuth2(OAuth2PasswordBearer):
        async def __call__(self, request: Request) -> Optional[str]:
            return request.auth.backend.get_user_token(request)
