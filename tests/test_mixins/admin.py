from typing import List, Optional

from fastapi_amis_admin import admin
from fastapi_amis_admin.admin import FieldPermEnum, RecentTimeSelectPerm, SelectPerm, SimpleSelectPerm, UserSelectPerm
from fastapi_amis_admin.amis import PageSchema
from fastapi_amis_admin.models import Field
from sqlalchemy import Column, Text

from fastapi_user_auth.mixins.admin import AuthFieldModelAdmin, AuthSelectModelAdmin
from fastapi_user_auth.mixins.models import CUDTimeMixin, PkMixin


class Article(PkMixin, CUDTimeMixin, table=True):
    title: str = Field(title="ArticleTitle", max_length=200)
    description: str = Field(default="", title="ArticleDescription", sa_column=Column(Text))
    status: int = Field(None, title="status")
    category_id: Optional[int] = Field(default=None, title="CategoryId")
    user_id: Optional[int] = Field(default=None, foreign_key="auth_user.id", title="Author")
    content: str = Field(title="ArticleContent", sa_column=Column(Text, default=""))
    is_published: bool = Field(default=False, title="IsPublished")


class AuthFieldArticleAdmin(AuthFieldModelAdmin, admin.ModelAdmin):
    page_schema = PageSchema(label="字段控制文章管理")
    model = Article
    perm_fields_exclude = {
        FieldPermEnum.CREATE: ["title", "description", "content"],
    }


class AuthSelectArticleAdmin(AuthSelectModelAdmin, admin.ModelAdmin):
    page_schema = PageSchema(label="数据集控制文章管理")
    model = Article
    select_permissions: List[SelectPerm] = [
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
