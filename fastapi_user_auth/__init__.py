__version__ = "0.2.4"
__url__ = "https://github.com/amisadmin/fastapi_user_auth"

import gettext
import os

from fastapi_amis_admin import i18n

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

i18n.load_translations(
    {"zh_CN": gettext.translation(domain="messages", localedir=os.path.join(BASE_DIR, "locale"), languages=["zh_CN"])}
)
