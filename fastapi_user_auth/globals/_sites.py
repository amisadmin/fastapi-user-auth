from fastapi_amis_admin.globals import get_site
from lazy_object_proxy import Proxy

from fastapi_user_auth.admin import AuthAdminSite
from fastapi_user_auth.auth import Auth

site: AuthAdminSite = Proxy(get_site)

auth: Auth = Proxy(lambda: site.auth)
