# oneiron-langgraph

A thin LangGraph **long-term `BaseStore`** over an already actor-bound Oneiron
SDK handle. This is not a checkpoint saver. It does not open a vault, rebind an
actor, issue HTTP, implement recall, or grant deletion authority.

```sh
python -m pip install oneiron oneiron-langgraph langgraph
```

## Runnable graph

```python
from typing import TypedDict
from oneiron import Oneiron
from oneiron_langgraph import OneironStore
from langgraph.graph import StateGraph, START, END

memory = Oneiron.open()
# This value was explicitly stated by the user. Do not label model output
# user_stated: use the default generated source and the real policy gate.
store = OneironStore(memory, source="user_stated")
store.put(("preferences",), "format", {"style": "brief"})

class State(TypedDict):
    answer: str

def respond(state: State, *, store: OneironStore):
    item = store.get(("preferences",), "format")
    return {"answer": f"Saved style: {item.value['style'] if item else 'unset'}"}

builder = StateGraph(State)
builder.add_node("respond", respond)
builder.add_edge(START, "respond")
builder.add_edge("respond", END)
graph = builder.compile(store=store)
print(graph.invoke({"answer": ""}))
print(store.search(("preferences",), filter={"style": "brief"}))
print(store.list_namespaces(prefix=("preferences",)))
store.delete(("preferences",), "format")
assert store.get(("preferences",), "format") is None
```

For a remote handle, replace only construction:

```python
import os
from oneiron import Oneiron
from oneiron_langgraph import OneironStore

memory = Oneiron.connect(os.environ["ONEIRON_URL"], os.environ["ONEIRON_KEY"])
store = OneironStore(memory)  # generated provenance; policy may refuse writes
```

The credential's slip must carry `principal_ref`, `actor_class`, and the needed
core scopes. Neither the adapter nor the SDK reads the slip's claims or supplies
another actor.

## Semantics

- `batch` / `abatch` implement the real abstract API. Inherited `get`, `put`,
  `delete`, `search`, `list_namespaces`, and async conveniences use those doors.
- Batches execute sequentially in input order. They are not atomic. Adapter
  validation runs before the first call. An engine error stops the batch and
  preserves the original exception; earlier operations may already have committed.
- `abatch` runs the whole ordered batch in one worker thread. Cancellation
  cannot undo a native call that already started. Re-read state before retrying.
- Identity is vault + actor id + actor class + worldless namespace tuple + key.
  Namespaces are literal segments, not path strings, actor selectors, or worlds.
  The adapter cannot read another actor's namespaces. The API intentionally
  does not include world-scoped memory yet; omission never means all worlds.
- Search is exact namespace-prefix plus exact top-level JSON-field equality.
  Number equality follows the engine's JSON representation: integer `2` and
  floating `2.0` differ. Large integers are compared exactly, never converted to
  `f64`. Each SDK can only preserve numbers its host JSON encoder represents;
  JavaScript cannot distinguish `2` from `2.0` or represent every large integer.
  Results sort by namespace then key. Offset applies after filtering.
  Namespace listing supports exact prefix/suffix, truncation, deduplication, and
  pagination. Empty namespaces disappear when the last live key is withdrawn.
- Pages are live snapshots, not a cross-request snapshot cursor. Concurrent
  writes can shift offsets. Each page is internally consistent.
- TTL, wildcard patterns, semantic queries, operator filters and explicit vector
  index fields are rejected, including in direct `batch` calls. `refresh_ttl`
  is ignored because the store has no expiry. `supports_ttl` is false.
- A put submits a real CLAIM candidate. Its source defaults to `generated`.
  A policy that requires review returns the engine's typed error and rolls back
  the whole put. It does **not** report a proposed claim as a successful write.
  Use the ordinary claim workflow for reviewable facts, or have the owner
  configure the applicable actor/source policy. Never relabel source to evade it.
- Replacement is source-sensitive. Generated output cannot supersede a
  user-stated head, even for the same actor and key and even if a policy permits
  generated writes. The engine returns `INVALID_STATE` and preserves the old
  value and history. Keep the true source; use a separate key for generated
  output. Only a genuine new user statement may replace a user-stated value
  as `user_stated`. Never relabel model output as `user_stated`, or delete then put to evade this
  protection. Same-source replacements still pass the normal policy gate.
- Keyed bodies are excluded from generic recall, context packs, scoped hydration,
  and generic claim/entity/history views, including the owner's views. Read them
  only through the actor/class-bound keyed API. Privileged raw Vault/batch systems
  APIs are not an actor isolation boundary.
- Erased shells and malformed rows are not live keyed heads. Scans skip them;
  unrelated keys stay available. Readers never fall back to superseded history.
  A replay against an erased/malformed revision refuses instead of recreating it.
  Competing valid live heads still fail loudly; no arbitrary winner is selected.
- SDK callers may reuse a `request_id` for an identical retry. It cannot change
  payload/source, replay a superseded revision, or resurrect a deleted key.
  Each BaseStore put is a new operation and receives a fresh request ID.
- Delete retracts only the bound actor/class's current claim. It preserves
  historical claims and gate receipts. It is not physical deletion, GDPR
  erasure, or `safe_delete`, and grants no cross-actor owner authority.

No external application cutover is performed by installing this satellite.
Existing external migrations remain held.

## Tests

Install this package and its `test` extra in the test environment, then run
`python -m pytest packages/oneiron-langgraph/tests`. Tests use the actual
LangGraph `BaseStore` classes, not replacement abstract classes.
