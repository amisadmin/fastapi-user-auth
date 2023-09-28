__version__ = "0.6.2"
__url__ = "https://github.com/amisadmin/fastapi_user_auth"

import gettext
from pathlib import Path

from fastapi_amis_admin import i18n

BASE_DIR = Path(__file__).resolve().parent

i18n.load_translations(
    {
        "zh_CN": gettext.translation(
            domain="messages",
            localedir=BASE_DIR / "locale",
            languages=["zh_CN"],
        ),
    }
)
