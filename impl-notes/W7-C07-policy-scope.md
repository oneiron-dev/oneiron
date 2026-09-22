# W7-C07 policy Scope storage handoff

Historical implementation handoff. Final acceptance and remaining-work status are recorded in [W7-C07.md](W7-C07.md) and supersede pending statements below.

Status: implementation handoff retained for design detail. Integration and current validation are tracked in [W7-C07.md](W7-C07.md).

## Storage decision

`POLICY_SCHEMA_VERSION` is now **"1.2"**. Version **"1.1"** is explicit migration input only; it is not interpreted as live Scope authority by the reader.

- In schema 1.1, grant `scope` meant purpose-specific selectors (for example `world_ref`, `entity_types`, `channel`). An absent, null, or empty old selector had the old unbounded preset meaning.
- In schema 1.2, every scoped grant requires `scope`, which is the canonical six-axis `federation::Scope`. Purpose-specific constraints live in a separate optional `selectors` field. `budget` and `receipt_required` remain separate, conjunctive constraints.
- New `scope: {}` becomes `Scope::default()` (Bottom). Partial current scopes keep missing axes Bottom. Missing the entire field, null Scope, invalid axis values, duplicate fields, and unknown scoped-grant fields fail manifest decoding. No shape guessing can lift a new empty object into a read/effect preset.
- The new named `gate/decode/policy_scope_migration.rs` owns normalization. Only an explicit 1.1 envelope may lift old selectors to an explicit read/effect Scope. Both `core:read` and the real alias `oneiron.read` choose the read preset. New-axis keys inside a 1.1 selector cannot acquire a preset. Selectors remain present and narrow the generic Scope.
- Valid admitted writes normalize BEFORE body comparison, short-id planning, row staging, and digest-bound stamp creation. Normalization is not only an in-memory decoder default. Explicit 1.1 input at the internal write door is lifted once to a stored 1.2 row; ordinary live reads never repeat that conversion. Replay authorization remains the parent's existing refusal in `base_apply.rs`, unchanged here.
- Invalid, unsupported, and malformed manifests retain their original bytes. The resolver keeps its malformed/unsupported diagnostics, and default reseeding cannot replace them with permissive policy. The normalizer never falls back to a default manifest.
- `default_policy_manifest()` follows the version constant; its defaults, rule table, actor ceilings, trust table, signatures, and lack of read grants are otherwise unchanged.

Example stored schema 1.2 grant:

```json
{
  "actor_ref": "reader",
  "effector": "core:read",
  "scope": {
    "worlds": {"kind": "all"},
    "facets": {"kind": "all"},
    "bands": {"kind": "all"},
    "audience": {"kind": "all"},
    "verbs": {"kind": "some", "values": ["read"]},
    "sensitivity": {"kind": "at_most", "value": "restricted"}
  },
  "selectors": {"entity_types": [1]},
  "receipt_required": false
}
```

## Open migration

The existing atomic scope sweep has an independent `scope:policy-manifest:v1.2` marker. It still migrates policy grants when `scope:claim-codec:v2` was already set. Valid old policy rows are rewritten, stamped, and committed with the marker. A second open does not rewrite the row. Malformed policy bytes remain in storage and fail closed; they do not abort the whole vault open or trigger default replacement.

The sweep previously called `short_id_prefix(...)?` for ACCESS_GRANT/FEDERATION_GRANT/OUTBOUND_GRANT, although maintenance grant kinds can have no prefix. Both that existing grant arm and the policy arm now plan a short ID only when the kind has one. This prevents the policy addition from inheriting the same open failure.

## Authorization integration

- `gate/grants.rs` preserves the parent's `external_effect_grant_matches` conjunct: the stored Scope must admit the conservative `effect_preset()` record position because this adapter has no stamped resource context. A restricted world/audience/kind/sensitivity is not silently ignored.
- Non-claim scoped readers now enforce the retained selector floor AND the stored generic Scope. This is necessary because a schema-1.2 author can provide `Scope::top()` and narrower selectors independently; only checking the generic Scope would discard selectors. Unsupported selector shapes remain denied.
- Existing CLAIM selectors and mask relevance are untouched. `Scope::admits` facet semantics are untouched. Budgets stay outside Scope and retain the existing enforcement/fail-closed behavior.

## Focused tests added

All tests are under `gate::decode::policy_scope_migration::tests::`:

1. `empty_and_partial_new_scopes_persist_bottom_and_deny_real_reads_and_effects`: real internal policy write and actual stored six-axis object; positive reader/effect control, followed by empty/partial Scope read denial and effect Pending.
2. `legacy_policy_grants_migrate_on_write_and_once_on_open_with_selectors_and_budget`: actual write normalization, legacy raw stored row, real reopen migration despite an already-finished claim sweep, byte-stable second reopen, real read/effect decisions, selector and budget preservation. Other default-envelope fields must remain equal.
3. `current_selectors_and_budget_only_narrow_stored_scope`: non-claim reader selector narrowing, effect budget conjunction, and conservative adapter denial of a resource-bounded Scope.
4. `malformed_manifest_is_not_replaced_or_migrated_to_permissive_defaults`: absent/null/invalid new Scope and new axes in an old envelope preserve bytes and fail closed through write, sweep, and reopen.

No compiler or runtime success is claimed. Parent should run its assigned-host scoped filter above after integration. Old fixtures that write the CURRENT version while using old selectors under `scope` must now move those selectors to `selectors` and emit an explicit Scope. Raw test store writes do not run migration by design. Changing the decoder to guess those old shapes would reintroduce the security bug.

## Integration follow-up

Canonical `grant.authority_scope` is now included in `gate/resolution/frontier_hash.rs`, with a Scope-only narrowing regression. Positive raw policy fixtures emit current Scopes and separate selectors. Final runtime validation remains tracked in the main implementation note.

## Exact frozen files

- `crates/oneiron/src/gate/constants.rs`
- `crates/oneiron/src/gate/decode/mod.rs`
- `crates/oneiron/src/gate/decode/decode_policy_tables.rs`
- `crates/oneiron/src/gate/decode/policy_scope_migration.rs` (new)
- `crates/oneiron/src/gate/decode/policy_scope_migration/tests.rs` (new)
- `crates/oneiron/src/gate/mod.rs` (normalizer re-export only)
- `crates/oneiron/src/gate/grants.rs` (selector comment and non-claim conjunct only; parent's effect guard preserved)
- `crates/oneiron/src/batch/person_substrate.rs`
- `crates/oneiron/src/batch/put_apply/apply.rs` (normalizer before materialization only)

No authority, server, claim, base_apply, retrieval_filter, or other worker file was edited.

## Canon correction

The earlier `.w7/scope-implementation.md` claim that all four grant envelopes already persisted Scope was not true for policy manifests: live decode derived presets from selector shape and treated `{}` as legacy. The docs should describe schema 1.2's required stored Scope, separate selectors/budgets, explicit versioned migration, and independent open marker. No docs-repo file was edited.
