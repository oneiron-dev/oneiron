"""LangGraph long-term BaseStore, not a checkpoint saver or another ingress."""
from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from itertools import islice
from typing import Any
from uuid import uuid4

from langgraph.store.base import (
    BaseStore, GetOp, Item, ListNamespacesOp, Op, PutOp, Result, SearchItem, SearchOp,
)

__all__ = ["OneironStore"]


def _namespace(value: tuple[str, ...], *, empty: bool = False) -> list[str]:
    if not isinstance(value, tuple) or (not value and not empty) or len(value) > 32:
        raise ValueError("namespace must contain 1..32 exact string segments")
    if any(not isinstance(part, str) or not part or "\0" in part or part == "*" for part in value):
        raise ValueError("namespace segments must be nonempty strings, without wildcard or NUL")
    if sum(len(part.encode("utf-8")) for part in value) > 4096:
        raise ValueError("namespace exceeds 4096 UTF-8 bytes")
    return list(value)


def _address(namespace: tuple[str, ...], key: str) -> dict[str, Any]:
    if not isinstance(key, str) or not key or "\0" in key or len(key.encode("utf-8")) > 4096:
        raise ValueError("key must be a nonempty bounded string")
    return {"namespace": _namespace(namespace), "key": key}


def _page(limit: int, offset: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer between 1 and 1000")
    if type(offset) is not int or not 0 <= offset <= 1_000_000:
        raise ValueError("offset must be an integer between 0 and 1000000")


def _json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("value must be a JSON mapping")
    # json.dumps otherwise coerces integer keys into strings. Validate every
    # nested object before crossing the SDK's plain JSON DTO boundary.
    def check(node: Any) -> None:
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                raise TypeError("JSON object keys must be strings")
            for child in node.values():
                check(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                check(child)
    plain = dict(value)
    check(plain)
    encoded = json.dumps(plain, allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("value exceeds the keyed payload ceiling")
    return json.loads(encoded)


def _item(value: dict[str, Any], *, search: bool = False) -> Item:
    fields = dict(namespace=tuple(value["namespace"]), key=value["key"], value=value["value"],
                  created_at=datetime.fromtimestamp(value["created_at"], timezone.utc),
                  updated_at=datetime.fromtimestamp(value["updated_at"], timezone.utc))
    return SearchItem(**fields, score=None) if search else Item(**fields)


class OneironStore(BaseStore):
    """Adapt one already actor-bound SDK handle. Never opens/rebinds a vault.

    Operations execute in input order, including writes before later reads.
    A batch is NOT atomic: engine failure leaves earlier successful operations
    committed and stops later ones. All adapter capability/shape checks run
    before the first call. No TTL, vector search, wildcard namespaces, or
    operator filters are advertised. Exact top-level filter equality works.
    """
    supports_ttl = False

    def __init__(self, memory: Any, *, source: str = "generated") -> None:
        if source not in {"generated", "inferred", "observed", "user_stated", "tool_output", "imported"}:
            raise ValueError("source must be a canonical claim source")
        self._memory = memory
        self._source = source

    def _prepare(self, op: Op) -> tuple[str, dict[str, Any]]:
        if isinstance(op, GetOp):
            return "key_value_get", _address(op.namespace, op.key)
        if isinstance(op, PutOp):
            request = _address(op.namespace, op.key)
            if op.ttl is not None:
                raise NotImplementedError("OneironStore has no TTL support")
            if op.index is not None and op.index is not False:
                raise NotImplementedError("OneironStore has no vector index configuration")
            if op.value is None:
                return "key_value_delete", request
            return "key_value_put", {**request, "value": _json_object(op.value),
                "request_id": uuid4().hex, "source": self._source}
        if isinstance(op, SearchOp):
            _page(op.limit, op.offset)
            if op.query is not None:
                raise NotImplementedError("OneironStore search is exact namespace/value search, not semantic recall")
            filters = _json_object(op.filter) if op.filter is not None else None
            if filters and any(isinstance(value, dict) and any(key.startswith("$") for key in value)
                               for value in filters.values()):
                raise NotImplementedError("OneironStore supports exact field equality, not operator filters")
            return "key_value_search", {"namespace_prefix": _namespace(op.namespace_prefix, empty=True),
                "filter": filters, "limit": op.limit, "offset": op.offset}
        if isinstance(op, ListNamespacesOp):
            _page(op.limit, op.offset)
            if op.max_depth is not None and (type(op.max_depth) is not int or not 1 <= op.max_depth <= 32):
                raise ValueError("max_depth must be an integer between 1 and 32")
            patterns: dict[str, list[str]] = {"prefix": [], "suffix": []}
            incompatible = False
            for condition in op.match_conditions or ():
                if condition.match_type not in patterns:
                    raise ValueError("namespace condition must be prefix or suffix")
                path = _namespace(condition.path, empty=True)
                old = patterns[condition.match_type]
                short, long = sorted((old, path), key=len)
                match = long[:len(short)] == short if condition.match_type == "prefix" else (not short or long[-len(short):] == short)
                incompatible |= not match
                patterns[condition.match_type] = long
            return ("empty" if incompatible else "key_value_namespaces"), {
                **patterns, "max_depth": op.max_depth, "limit": op.limit, "offset": op.offset}
        raise TypeError("unsupported LangGraph store operation")

    def batch(self, ops: Iterable[Op]) -> list[Result]:
        operations = list(islice(ops, 10001))
        if len(operations) > 10000:
            raise ValueError("batch exceeds 10000 operations")
        prepared = [self._prepare(op) for op in operations]
        results: list[Result] = []
        for verb, request in prepared:
            if verb == "empty":
                results.append([])
                continue
            result = getattr(self._memory, verb)(request)
            if verb == "key_value_get":
                results.append(None if result is None else _item(result))
            elif verb == "key_value_search":
                results.append([_item(item, search=True) for item in result])
            elif verb == "key_value_namespaces":
                results.append([tuple(namespace) for namespace in result])
            else:
                # The keyed SDK's strict transactional write contract returns
                # only committed puts/retractions. Proposed claims raise; no
                # pending approval is converted into BaseStore's success None.
                results.append(None)
        return results

    async def abatch(self, ops: Iterable[Op]) -> list[Result]:
        # One worker for the entire ordered batch. Cancellation does not roll
        # back a native call that already started; callers must re-read state.
        return await asyncio.to_thread(self.batch, ops)
