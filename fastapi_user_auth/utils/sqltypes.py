from typing import cast

from pydantic import SecretStr
from sqlalchemy import String, types
from sqlalchemy.engine import Dialect


class SecretStrType(types.TypeDecorator):
    impl = String
    cache_ok = True
    mysql_default_length = 255

    @property
    def python_type(self):
        return self.impl.python_type

    def load_dialect_impl(self, dialect: Dialect):
        impl = cast(types.String, self.impl)
        if impl.length is None and dialect.name == "mysql":
            return dialect.type_descriptor(types.String(self.mysql_default_length))
        return super().load_dialect_impl(dialect)

    def process_bind_param(self, value, dialect):
        if value and isinstance(value, SecretStr):
            return value.get_secret_value()
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return SecretStr(value)
        return value
