from typing import Any, Iterable, List, Optional, Tuple, Union

from casbin import Model, persist
from casbin.persist import Adapter as BaseAdapter
from casbin.persist.adapters.update_adapter import UpdateAdapter
from sqlalchemy import Column, Integer, String, and_, delete, insert, or_, select
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import Select
from sqlalchemy.sql.dml import Delete
from sqlalchemy_database import AsyncDatabase, Database

Base = declarative_base()


class DefaultCasbinRule(Base):
    __tablename__ = "auth_casbin_rule"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


class AdapterException(Exception):
    """AdapterException"""


class Filter:  # pylint: disable=too-few-public-methods
    """
    Filter class for SQLModel-based Casbin adapter.
    """

    ptype: List[str] = []
    v0: List[str] = []
    v1: List[str] = []
    v2: List[str] = []
    v3: List[str] = []
    v4: List[str] = []
    v5: List[str] = []


class Adapter(BaseAdapter, UpdateAdapter):
    """
    Adapter class for ormar-based Casbin adapter.
    """

    cols = ["ptype"] + [f"v{i}" for i in range(6)]

    def __init__(
        self,
        db: Union[Database, AsyncDatabase],
        db_class: Optional[Any] = None,
        filtered: bool = False,
    ):
        self.db = db
        if db_class is None:
            db_class = DefaultCasbinRule
        else:
            for attr in (
                "id",
                "ptype",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
            ):  # id attr was used by filter
                if not hasattr(db_class, attr):
                    raise AdapterException(f"{attr} not found in custom DatabaseClass.")

        self._db_class = db_class
        self._filtered: bool = filtered

    async def load_policy(self, model: Model) -> None:
        """loads all policy rules from the storage."""
        result = await self.db.async_scalars(select(self._db_class))
        for line in result:
            persist.load_policy_line(str(line), model)

    def is_filtered(self) -> bool:
        """returns whether the adapter is filtered or not."""

        return self._filtered

    async def load_filtered_policy(self, model: Model, filter_: Filter) -> None:
        """loads all policy rules from the storage."""

        query: Select = select(self._db_class)
        filters = self.filter_query(query, filter_)
        result = await self.db.async_scalars(filters)
        for line in result:
            persist.load_policy_line(str(line), model)
        self._filtered = True

    def filter_query(self, querydb: Select, filter_: Filter) -> Select:
        """filters the query based on the filter_."""

        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            if len(getattr(filter_, attr)) > 0:
                querydb = querydb.filter(getattr(self._db_class, attr).in_(getattr(filter_, attr)))
        return querydb.order_by(self._db_class.id)

    def parse_rule(self, ptype: str, rule: Iterable[str]):
        line = self._db_class(ptype=ptype)
        for i, v in enumerate(rule):  # pylint: disable=invalid-name
            setattr(line, f"v{i}", v)
        return line

    async def save_policy(self, model: Model) -> bool:
        """saves all policy rules to the storage."""
        await self.db.async_execute(delete(self._db_class))  # delete all
        values = []
        for sec in ["p", "g"]:
            if sec not in model.model.keys():  # pragma: no cover
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    values.append(self.parse_rule(ptype, rule).dict())
        if values:
            await self.db.async_execute(insert(self._db_class).values(values))
        await self.db.async_commit()
        return True

    async def add_policy(self, sec: str, ptype: str, rule: List[str]) -> None:
        """adds a policy rule to the storage."""
        obj = self.parse_rule(ptype, rule)
        self.db.add(obj)
        await self.db.async_commit()

    async def add_policies(self, sec: str, ptype: str, rules: Iterable[Tuple[str]]) -> None:
        """adds a policy rules to the storage."""
        values = []
        for rule in rules:
            values.append(self.parse_rule(ptype, rule).dict())
        if not values:
            return
        await self.db.async_execute(insert(self._db_class).values(values))
        await self.db.async_commit()

    # pylint: disable=unused-argument
    async def remove_policy(self, sec: str, ptype: str, rule: Iterable[str]) -> bool:
        """removes a policy rule from the storage."""

        query: Delete = delete(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        for i, v in enumerate(rule):  # pylint: disable=invalid-name
            if not v:
                continue
            query = query.filter(getattr(self._db_class, f"v{i}") == v)
        res = (await self.db.async_execute(query)).rowcount  # type: ignore
        await self.db.async_commit()
        return res > 0  # pragma: no cover

    async def remove_policies(self, sec: str, ptype: str, rules: List[Tuple[str]]) -> None:
        """remove policy rules from the storage."""
        if not rules:  # pragma: no cover
            return
        if len(rules) == 1:
            await self.remove_policy(sec, ptype, rules[0])
            return
        query: Delete = delete(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        _rules = []
        for rule in rules:
            _rules.append(and_(*(getattr(self._db_class, f"v{i}") == v for i, v in enumerate(rule) if v)))
        query = query.filter(or_(*_rules))
        await self.db.async_execute(query)
        await self.db.async_commit()

    async def remove_filtered_policy(self, sec: str, ptype: str, field_index: int, *field_values: Tuple[str]) -> bool:
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """

        query: Delete = delete(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)

        if not 0 <= field_index <= 5:  # pragma: no cover
            return False
        if not 1 <= field_index + len(field_values) <= 6:  # pragma: no cover
            return False
        for i, v in enumerate(field_values):  # pylint: disable=invalid-name
            if v != "":
                v_value = getattr(self._db_class, f"v{field_index + i}")
                query = query.filter(v_value == v)
        res = (await self.db.async_execute(query)).rowcount  # type: ignore
        await self.db.async_commit()
        return res > 0

    async def update_policy(self, sec: str, ptype: str, old_rule: List[str], new_rule: List[str]) -> None:
        """
        Update the old_rule with the new_rule in the database (storage).
        :param sec: section type
        :param ptype: policy type
        :param old_rule: the old rule that needs to be modified
        :param new_rule: the new rule to replace the old rule
        :return: None
        """

        query: Select = select(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)

        # locate the old rule
        for index, value in enumerate(old_rule):
            v_value = getattr(self._db_class, f"v{index}")
            query = query.filter(v_value == value)

        # need the length of the longest_rule to perform overwrite
        longest_rule = old_rule if len(old_rule) > len(new_rule) else new_rule
        old_rule_line = await self.db.async_scalar(query)
        # overwrite the old rule with the new rule
        for index in range(len(longest_rule)):
            if index < len(new_rule):
                setattr(old_rule_line, f"v{index}", new_rule[index])
            else:  # pragma: no cover
                setattr(old_rule_line, f"v{index}", None)
        await self.db.async_commit()

    async def update_policies(
        self,
        sec: str,
        ptype: str,
        old_rules: List[List[str]],
        new_rules: List[List[str]],
    ) -> None:
        """
        Update the old_rules with the new_rules in the database (storage).
        :param sec: section type
        :param ptype: policy type
        :param old_rules: the old rules that need to be modified
        :param new_rules: the new rules to replace the old rules
        :return: None
        """
        if len(old_rules) != len(new_rules):
            raise ValueError("Invalid request, old and new rules must be of the same length")
        for i, rule in enumerate(old_rules):  # todo optimize
            await self.update_policy(sec, ptype, rule, new_rules[i])

    async def update_filtered_policies(
        self, sec: str, ptype: str, new_rules: Iterable[Tuple[str]], field_index: int, *field_values: Tuple[str]
    ) -> List[Tuple[str]]:
        """update_filtered_policies updates all the policies on the basis of the filter."""

        filter_ = Filter()
        filter_.ptype = [ptype]

        # Creating Filter from the field_index & field_values provided
        for i in range(len(field_values)):
            if field_index <= i < field_index + len(field_values):
                setattr(filter_, f"v{i}", [field_values[i - field_index]])
            else:
                break

        return await self._update_filtered_policies(new_rules, filter_)

    async def _update_filtered_policies(self, new_rules: Iterable[Tuple[str]], filter_: Filter) -> List[Tuple[str]]:
        """_update_filtered_policies updates all the policies on the basis of the filter."""
        query = select(self._db_class).filter(self._db_class.ptype == filter_.ptype)
        self.filter_query(query, filter_)
        old_rules = (await self.db.async_scalars(query)).all()
        # Delete old policies
        await self.remove_policies("p", filter_.ptype[0], old_rules)
        # Insert new policies
        await self.add_policies("p", filter_.ptype[0], new_rules)
        # return deleted rules
        await self.db.async_commit()
        return old_rules
