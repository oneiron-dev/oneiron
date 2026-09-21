"""A real StateGraph with the installed native SDK, not a mock store."""
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.store.base import BaseStore
from oneiron import Oneiron
from oneiron_langgraph import OneironStore


class State(TypedDict):
    user_preference: str
    previous: str | None
    current: str


def test_graph_reads_and_writes_native_long_term_memory(tmp_path):
    # The test input is an explicit user statement, not generated model output.
    store = OneironStore(Oneiron.open(tmp_path / "vault"), source="user_stated")

    def remember(state: State, *, store: BaseStore):
        old = store.get(("preferences", "user"), "style")
        store.put(("preferences", "user"), "style", {"style": state["user_preference"]})
        current = store.get(("preferences", "user"), "style")
        assert current is not None
        return {"previous": None if old is None else old.value["style"],
                "current": current.value["style"]}

    builder = StateGraph(State)
    builder.add_node("remember", remember)
    builder.add_edge(START, "remember")
    builder.add_edge("remember", END)
    graph = builder.compile(store=store)
    first = graph.invoke({"user_preference": "brief", "previous": None, "current": ""})
    assert first["previous"] is None
    assert first["current"] == "brief"
    second = graph.invoke({"user_preference": "detailed", "previous": None, "current": ""})
    assert second["previous"] == "brief"
    assert second["current"] == "detailed"
    assert [item.key for item in store.search(("preferences",), filter={"style": "detailed"})] == ["style"]
    assert store.list_namespaces(prefix=("preferences",)) == [("preferences", "user")]
    store.delete(("preferences", "user"), "style")
    assert store.get(("preferences", "user"), "style") is None
    assert store.list_namespaces(prefix=("preferences",)) == []
