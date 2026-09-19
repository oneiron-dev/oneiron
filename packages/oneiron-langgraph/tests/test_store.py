from __future__ import annotations

import asyncio
from datetime import timezone

import pytest
from langgraph.store.base import BaseStore, GetOp, PutOp, SearchOp, ListNamespacesOp, MatchCondition, SearchItem
from oneiron_langgraph import OneironStore


ROW = {"namespace": ["users", "a"], "key": "preference", "value": {"color": "blue"},
       "created_at": 100, "updated_at": 101, "revision": "a" * 32}


class Client:
    def __init__(self, responses=()):
        self.calls = []
        self.responses = iter(responses)

    def __getattr__(self, name):
        assert name.startswith("key_value_")
        def call(request):
            self.calls.append((name, request))
            response = next(self.responses)
            if isinstance(response, Exception):
                raise response
            return response
        return call


def test_real_abstract_surface_and_ordered_put_get_delete_get():
    client = Client([{"item": ROW, "replayed": False, "receipt_ref": "gate:x"}, ROW, {"existed": True}, None])
    store = OneironStore(client)
    assert isinstance(store, BaseStore)
    result = store.batch(iter([
        PutOp(("users", "a"), "preference", {"color": "blue"}),
        GetOp(("users", "a"), "preference"),
        PutOp(("users", "a"), "preference", None),
        GetOp(("users", "a"), "preference"),
    ]))
    assert [call[0] for call in client.calls] == ["key_value_put", "key_value_get", "key_value_delete", "key_value_get"]
    assert result[0] is result[2] is result[3] is None
    assert result[1].namespace == ("users", "a")
    assert result[1].value == {"color": "blue"}
    assert result[1].created_at.tzinfo is timezone.utc
    assert client.calls[0][1]["source"] == "generated"
    assert client.calls[0][1]["request_id"]


def test_inherited_conveniences_and_exact_search_namespace_arguments():
    client = Client([ROW, [ROW], [["users", "a"]]])
    store = OneironStore(client)
    assert store.get(("users", "a"), "preference").key == "preference"
    hits = store.search(("users",), filter={"color": "blue"}, limit=1, offset=2)
    assert isinstance(hits[0], SearchItem)
    assert hits[0].score is None
    assert client.calls[1] == ("key_value_search", {"namespace_prefix": ["users"], "filter": {"color": "blue"}, "limit": 1, "offset": 2})
    assert store.list_namespaces(prefix=("users",), suffix=("a",), max_depth=2) == [("users", "a")]


@pytest.mark.parametrize("invalid", [
    PutOp(("n",), "k", {}, ttl=10),
    PutOp(("n",), "k", {}, index=["text"]),
    SearchOp(("n",), query="semantic"),
    SearchOp(("n",), filter={"n": {"$gt": 1}}),
    ListNamespacesOp(match_conditions=(MatchCondition("prefix", ("*",)),)),
    GetOp(("n",), ""),
    PutOp(("n",), "k", {"nested": {1: "invalid"}}),
    PutOp(("n",), "k", {"bad": float("nan")}),
    SearchOp(("n",), limit=True),
])
def test_preflight_refuses_whole_batch_before_any_write(invalid):
    client = Client()
    store = OneironStore(client)
    with pytest.raises((ValueError, TypeError, NotImplementedError)):
        store.batch([PutOp(("n",), "before", {}), invalid])
    assert client.calls == []


def test_base_class_ttl_rejection_and_direct_batch_ttl_rejection():
    store = OneironStore(Client())
    assert store.supports_ttl is False
    with pytest.raises(NotImplementedError):
        store.put(("n",), "k", {}, ttl=1)
    with pytest.raises(NotImplementedError):
        store.batch([PutOp(("n",), "k", {}, ttl=0)])


def test_typed_engine_refusal_is_not_swallowed_and_stops_later_ops():
    refusal = RuntimeError("typed native refusal sentinel")
    client = Client([refusal])
    store = OneironStore(client)
    with pytest.raises(RuntimeError) as caught:
        store.batch([PutOp(("n",), "k", {}), GetOp(("n",), "k")])
    assert caught.value is refusal
    assert len(client.calls) == 1


def test_async_batch_preserves_order_and_inherited_async_convenience():
    client = Client([{"item": ROW}, ROW, ROW])
    store = OneironStore(client)
    async def run():
        result = await store.abatch([PutOp(("users", "a"), "preference", {}), GetOp(("users", "a"), "preference")])
        assert result[0] is None
        assert result[1].key == "preference"
        assert (await store.aget(("users", "a"), "preference")).namespace == ("users", "a")
    asyncio.run(run())
    assert [name for name, _ in client.calls] == ["key_value_put", "key_value_get", "key_value_get"]


def test_incompatible_exact_conditions_return_empty_without_ingress():
    client = Client()
    assert OneironStore(client).batch([ListNamespacesOp(match_conditions=(
        MatchCondition("prefix", ("a",)), MatchCondition("prefix", ("ab",))))]) == [[]]
    assert not client.calls
