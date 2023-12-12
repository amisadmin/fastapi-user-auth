# 项目介绍

<h2 align="center">
  FastAPI-User-Auth
</h2>
<p align="center">
    <em>FastAPI-User-Auth是一个基于Casbin简单而强大的FastAPI用户认证与授权库.</em><br/>
    <em>基于FastAPI-Amis-Admin并提供可自由拓展的可视化管理界面.</em>
</p>
<p align="center">
    <a href="https://github.com/amisadmin/fastapi_amis_admin/actions/workflows/pytest.yml" target="_blank">
        <img src="https://github.com/amisadmin/fastapi_amis_admin/actions/workflows/pytest.yml/badge.svg" alt="Pytest">
    </a>
    <a href="https://pypi.org/project/fastapi_user_auth" target="_blank">
        <img src="https://badgen.net/pypi/v/fastapi-user-auth?color=blue" alt="Package version">
    </a>
    <a href="https://pepy.tech/project/fastapi-user-auth" target="_blank">
        <img src="https://pepy.tech/badge/fastapi-user-auth" alt="Downloads">
    </a>
    <a href="https://gitter.im/amisadmin/fastapi-amis-admin">
        <img src="https://badges.gitter.im/amisadmin/fastapi-amis-admin.svg" alt="Chat on Gitter"/>
    </a>
    <a href="https://jq.qq.com/?_wv=1027&k=U4Dv6x8W" target="_blank">
        <img src="https://badgen.net/badge/qq%E7%BE%A4/229036692/orange" alt="229036692">
    </a>
</p>
<p align="center">
  <a href="https://github.com/amisadmin/fastapi_user_auth" target="_blank">源码</a>
  ·
  <a href="http://user-auth.demo.amis.work/" target="_blank">在线演示</a>
  ·
  <a href="http://docs.amis.work" target="_blank">文档</a>
  ·
  <a href="http://docs.gh.amis.work" target="_blank">文档打不开？</a>
</p>

------

`FastAPI-User-Auth`是一个基于 [FastAPI-Amis-Admin](https://github.com/amisadmin/fastapi_amis_admin)
的应用插件,与`FastAPI-Amis-Admin`深度结合,为其提供用户认证与授权.
基于Casbin的RBAC权限管理,支持多种验证方式,支持多种数据库,支持多种颗粒度的权限控制.

### 权限类型

- **页面权限**: 控制用户是否可以访问某个菜单页面.如不可访问,则菜单不会显示,并且页面下的所有路由都不可访问.
- **动作权限**: 控制用户是否可以执行某个动作,按钮是否显示.如: 新增,更新,删除等.
- **字段权限**: 控制用户是否可以操作某个字段.如:列表展示字段,筛选字段,新增字段,更新字段等.
- **数据权限**: 控制用户可以操作的数据范围.如:只能操作自己创建的数据,只能操作最近7天的数据等.

## 安装

```bash
pip install fastapi-user-auth
```

## 简单示例

```python
from fastapi import FastAPI
from fastapi_amis_admin.admin.settings import Settings
from fastapi_user_auth.site import AuthAdminSite
from starlette.requests import Request
from sqlmodel import SQLModel

# 创建FastAPI应用
app = FastAPI()

# 创建AdminSite实例
site = AuthAdminSite(settings=Settings(database_url='sqlite:///amisadmin.db?check_same_thread=False'))
auth = site.auth
# 挂载后台管理系统
site.mount_app(app)


# 创建初始化数据库表
@app.on_event("startup")
async def startup():
    await site.db.async_run_sync(SQLModel.metadata.create_all, is_session=False)
        # 创建默认管理员,用户名: admin,密码: admin, 请及时修改密码!!!
    await auth.create_role_user("admin")
    # 创建默认超级管理员,用户名: root,密码: root, 请及时修改密码!!!
    await auth.create_role_user("root")
    # 运行site的startup方法,加载casbin策略等
    await site.router.startup()
    # 添加一条默认的casbin规则
    if not auth.enforcer.enforce("u:admin", site.unique_id, "page", "page"):
        await auth.enforcer.add_policy("u:admin", site.unique_id, "page", "page", "allow")


# 要求: 用户必须登录
@app.get("/auth/get_user")
@auth.requires()
def get_user(request: Request):
    return request.user


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app)

```

## 验证方式

### 装饰器

- 推荐场景: 单个路由.支持同步/异步路由.

```python
# 要求: 用户必须登录
@app.get("/auth/user")
@auth.requires()
def user(request: Request):
    return request.user  # 当前请求用户对象.


# 验证路由: 用户拥有admin角色
@app.get("/auth/admin_roles")
@auth.requires('admin')
def admin_roles(request: Request):
    return request.user


# 要求: 用户拥有vip角色
# 支持同步/异步路由
@app.get("/auth/vip_roles")
@auth.requires(['vip'])
async def vip_roles(request: Request):
    return request.user


# 要求: 用户拥有admin角色 或 vip角色
@app.get("/auth/admin_or_vip_roles")
@auth.requires(roles=['admin', 'vip'])
def admin_or_vip_roles(request: Request):
    return request.user

```

### 依赖项(推荐)

- 推荐场景: 单个路由,路由集合,FastAPI应用.

```python
from fastapi import Depends
from fastapi_user_auth.auth.models import User


# 路由参数依赖项, 推荐使用此方式
@app.get("/auth/admin_roles_depend_1")
def admin_roles(user: User = Depends(auth.get_current_user)):
    return user  # or request.user


# 路径操作装饰器依赖项
@app.get("/auth/admin_roles_depend_2", dependencies=[Depends(auth.requires('admin')())])
def admin_roles(request: Request):
    return request.user


# 全局依赖项
# 在app应用下全部请求都要求拥有admin角色
app = FastAPI(dependencies=[Depends(auth.requires('admin')())])


@app.get("/auth/admin_roles_depend_3")
def admin_roles(request: Request):
    return request.user

```

### 中间件

- 推荐场景: FastAPI应用

```python
app = FastAPI()
# 在app应用下每条请求处理之前都附加`request.auth`和`request.user`对象
auth.backend.attach_middleware(app)

```

### 直接调用

- 推荐场景: 非路由方法

```python
from fastapi_user_auth.auth.models import User


async def get_request_user(request: Request) -> Optional[User]:
    # user= await auth.get_current_user(request)
    if await auth.requires('admin', response=False)(request):
        return request.user
    else:
        return None

```

## Token存储后端

`fastapi-user-auth` 支持多种token存储方式.默认为: `DbTokenStore`, 建议自定义修改为: `JwtTokenStore`

### JwtTokenStore

- pip install fastapi-user-auth[jwt]

```python
from fastapi_user_auth.auth.backends.jwt import JwtTokenStore
from sqlalchemy_database import Database
from fastapi_user_auth.auth import Auth
from fastapi_amis_admin.admin.site import AuthAdminSite

# 创建同步数据库引擎
db = Database.create(url="sqlite:///amisadmin.db?check_same_thread=False")

# 使用`JwtTokenStore`创建auth对象
auth = Auth(
    db=db,
    token_store=JwtTokenStore(secret_key='09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7')
)

# 将auth对象传入AdminSite
site = AuthAdminSite(
    settings=Settings(),
    db=db,
    auth=auth
)

```

### DbTokenStore

```python
# 使用`DbTokenStore`创建auth对象
from fastapi_user_auth.auth.backends.db import DbTokenStore

auth = Auth(
    db=db,
    token_store=DbTokenStore(db=db)
)
```

### RedisTokenStore

- pip install fastapi-user-auth[redis]

```python
# 使用`RedisTokenStore`创建auth对象
from fastapi_user_auth.auth.backends.redis import RedisTokenStore
from redis.asyncio import Redis

auth = Auth(
    db=db,
    token_store=RedisTokenStore(redis=Redis.from_url('redis://localhost?db=0'))
)
```

## RBAC模型

本系统采用的`Casbin RBAC`模型,并运行基于角色的优先级策略.

- 权限可分配给角色,或者直接分配给用户.
- 用户可拥有多个角色.
- 角色可拥有多个子角色.
- 用户拥有的权限策略优先级高于所拥有角色的权限策略.

```mermaid
flowchart LR
    User -. m:n .-> Role
    User -. m:n .-> CasbinRule
    Role -. m:n .-> Role
    Role -. m:n .-> CasbinRule 
```

## 高级拓展

### 拓展`User`模型

```python
from datetime import date

from fastapi_amis_admin.models.fields import Field
from fastapi_user_auth.auth.models import BaseUser

# 自定义`User`模型,继承`BaseUser`
class MyUser(BaseUser, table = True):
    point: float = Field(default = 0, title = '积分', description = '用户积分')
    phone: str = Field(None, title = '手机号', max_length = 15)
    parent_id: int = Field(None, title = "上级", foreign_key = "auth_user.id")
    birthday: date = Field(None, title = "出生日期")
    location: str = Field(None, title = "位置")

# 使用自定义的`User`模型,创建auth对象
auth = Auth(db = AsyncDatabase(engine), user_model = MyUser)
```

### 拓展`Role`模型

```python
from fastapi_amis_admin.models.fields import Field
from fastapi_user_auth.auth.models import Role


# 自定义`Role`模型,继承`Role`;
class MyRole(Role, table=True):
    icon: str = Field(None, title='图标')
    is_active: bool = Field(default=True, title="是否激活")

```

### 自定义`UserAuthApp`默认管理类

默认管理类均可通过继承重写替换.
例如: `UserLoginFormAdmin`,`UserRegFormAdmin`,`UserInfoFormAdmin`,
`UserAdmin`,`RoleAdmin`

```python
# 自定义模型管理类,继承重写对应的默认管理类
class MyRoleAdmin(admin.ModelAdmin):
    page_schema = PageSchema(label='用户组管理', icon='fa fa-group')
    model = MyRole
    readonly_fields = ['key']


# 自定义用户认证应用,继承重写默认的用户认证应用
class MyUserAuthApp(UserAuthApp):
    RoleAdmin = MyRoleAdmin


# 自定义用户管理站点,继承重写默认的用户管理站点
class MyAuthAdminSite(AuthAdminSite):
    UserAuthApp = MyUserAuthApp


# 使用自定义的`AuthAdminSite`类,创建site对象
site = MyAuthAdminSite(settings, auth=auth)
```

## ModelAdmin权限控制

### 字段权限

- 继承`AuthFieldModelAdmin`类,即可实现字段权限控制.通过在后台分配用户和角色权限.

- `perm_fields_exclude`: 指定不需要权限控制的字段.

```python
from fastapi_user_auth.mixins.admin import AuthFieldModelAdmin
from fastapi_amis_admin.amis import PageSchema
from fastapi_amis_admin.admin import FieldPermEnum

class AuthFieldArticleAdmin(AuthFieldModelAdmin):
    page_schema = PageSchema(label="文章管理")
    model = Article
    # 指定不需要权限控制的字段. 
    perm_fields_exclude = {
        FieldPermEnum.CREATE: ["title", "description", "content"],
    }
```

### 数据权限

- 继承`AuthSelectModelAdmin`类,即可实现数据权限控制.通过在后台分配用户和角色权限.
- `select_permisions`: 指定查询数据权限.

```python
from fastapi_user_auth.mixins.admin import AuthSelectModelAdmin
from fastapi_amis_admin.amis import PageSchema
from fastapi_amis_admin.admin import RecentTimeSelectPerm, UserSelectPerm, SimpleSelectPerm


class AuthSelectArticleAdmin(AuthSelectModelAdmin):
    page_schema = PageSchema(label="数据集控制文章管理")
    model = Article
    select_permissions = [
        # 最近7天创建的数据. reverse=True表示反向选择,即默认选择最近7天之内的数据
        RecentTimeSelectPerm(name="recent7_create", label="最近7天创建", td=60 * 60 * 24 * 7, reverse=True),
        # 最近30天创建的数据
        RecentTimeSelectPerm(name="recent30_create", label="最近30天创建", td=60 * 60 * 24 * 30),
        # 最近3天更新的数据
        RecentTimeSelectPerm(name="recent3_update", label="最近3天更新", td=60 * 60 * 24 * 3, time_column="update_time"),
        # 只能选择自己创建的数据, reverse=True表示反向选择,即默认选择自己创建的数据
        UserSelectPerm(name="self_create", label="自己创建", user_column="user_id", reverse=True),
        # # 只能选择自己更新的数据
        # UserSelectPerm(name="self_update", label="自己更新", user_column="update_by"),
        # 只能选择已发布的数据
        SimpleSelectPerm(name="published", label="已发布", column="is_published", values=[True]),
        # 只能选择状态为[1,2,3]的数据
        SimpleSelectPerm(name="status_1_2_3", label="状态为1_2_3", column="status", values=[1, 2, 3]),
    ]
```

## 界面预览

- Open `http://127.0.0.1:8000/admin/auth/form/login` in your browser:

![Login](https://s2.loli.net/2022/03/20/SZy6sjaVlBT8gin.png)

- Open `http://127.0.0.1:8000/admin/` in your browser:

![ModelAdmin](https://s2.loli.net/2022/03/20/ItgFYGUONm1jCz5.png)

- Open `http://127.0.0.1:8000/admin/docs` in your browser:

![Docs](https://s2.loli.net/2022/03/20/1GcCiPdmXayxrbH.png)

## 许可协议

- `fastapi-amis-admin`基于`Apache2.0`开源免费使用，可以免费用于商业用途，但请在展示界面中明确显示关于FastAPI-Amis-Admin的版权信息.

## 鸣谢

感谢以下开发者对 FastAPI-User-Auth 作出的贡献：

<a href="https://github.com/amisadmin/fastapi_user_auth/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=amisadmin/fastapi_user_auth"  alt=""/>
</a>

