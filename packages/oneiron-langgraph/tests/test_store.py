from __future__ import annotations


import pytest
from langgraph.store.base import GetOp, PutOp, SearchOp, ListNamespacesOp, MatchCondition
from oneiron_langgraph import OneironStore


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
