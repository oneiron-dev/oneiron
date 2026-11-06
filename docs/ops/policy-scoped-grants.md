# Typed policy scoped grants

The existing `vault.gate.policy.get`, `vault.gate.policy.put` and
`vault.gate.policy.propose` surfaces include `manifest.scoped_grants`.
There is no second grant store or row-level grant API.

An omitted `scoped_grants` field preserves the stored table when editing.
An explicit list replaces the table; `[]` clears it. A new contribution with
this field omitted has no scoped-grant table. Editing still requires the
existing exact body hash, authenticated writer and manifest trust checks.
A proposal remains an untrusted contribution under the existing resolver.

Each row names optional `actor_class` and `actor_ref`, its `effector`, the
required authority `scope`, optional purpose-specific `selectors` and `budget`,
and an explicit `receipt_required` boolean. Arbitrary effector strings and all
native selector and budget values remain supported. The native decoder and
current consumers decide what a row does; the typed door adds no grant or
permission of its own. Other policy tables are preserved as MessagePack values.

Selectors and budgets use the tagged `PolicyGrantValue` representation:

- `nil`, `boolean`, `integer` (decimal text), and `string`.
- `float32` and `float64`: four or eight big-endian bytes of the float's bits.
- `binary`: byte array; `array`: values; `map`: ordered `{key, value}` entries.
- `extension`: `{tag, data}`; `raw_string`: exactly one encoded MessagePack
  string, including its header, for a string that is not valid UTF-8.

The `kind` field chooses the variant and `value` carries its data; `nil` has
no data. This preserves wide integers, float width and non-finite bits,
binary and extension values, non-string or duplicate map keys, and invalid
UTF-8 strings without a lossy JSON conversion. A present `{kind: "nil"}`
value is distinct from omitting selectors or budget.

For example, `note.edit` selectors naming an entity are:

```json
{"kind":"map","value":[{"key":{"kind":"string","value":"entity_refs"},"value":{"kind":"array","value":[{"kind":"string","value":"0123456789abcdef0123456789abcdef"}]}}]}
```

This change adds no migration, old-format reader, new cap, policy default,
or automatic narrowing rule. It does not change the existing read/note
consumers' scope, budget or receipt checks.
