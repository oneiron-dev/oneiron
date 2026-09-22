# Memory Wire facade census

This is the complete **shipped SDK facade**, in manifest order. It is
not a claim that every engine-internal method is a public SDK verb.
`scripts/sdk/agent-verbs.json` owns this list.
Names are stable: a new export or rename must update the engine catalog,
both bindings and their export-census tests in one reviewed change.

- `witness`
- `claim_upsert`
- `recall`
- `receipts`
- `key_value_get`
- `key_value_put`
- `key_value_delete`
- `key_value_search`
- `key_value_namespaces`
- `tasks.ask`
- `tasks.wait`
- `tasks.answer`
- `tasks.outcomes`
- `rooms.list`
- `rooms.messages`
- `rooms.claim`
- `rooms.speak`
