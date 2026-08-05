# ONE-1606 — Unified consent-mode — bounded standing grants

Worktree `/Volumes/Cinema/w5-lt/gov-1606` · branch `ONE-1606` · base `e9d9e9a`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/GOV-CONSENT/ONE-1606.md`
Claims: `/Users/olety/.claude-wave5/blueprints/GOV-CONSENT/CLAIMS.md`
Acceptance authority: DEC-0006 nine-invariant table (exact, not illustrative).

## Decisions taken (seg0)

- **No new entity type / type byte.** Standing rows live as strict versioned
  MessagePack under a `consent.grant.v1` `vault_meta` prefix owned by `consent.rs`.
  `store.rs` is NOT claimed, so `consent.rs` reads/writes `self.store.vault_meta`
  directly — precedent: `identity_topology.rs:2388/2413/2433` does exactly this.
  No store.rs edit is needed and none is taken.
- **Receipt projection, not a second ledger.** `ConsentReceipt` projects into
  `GateDecisionRecord` (`diff_handle` = effect/bound digest, `grant_ref` joins
  standing use), appended with `Store::append_gate_decision_in_txn` in the SAME
  wtxn as the grant row. Idiom copied from `inbox.rs:1066`.
- **Digest is engine-computed.** `EffectDigest` is derived by domain-separated
  BLAKE3 over the normalized bounds + facts inside `ComposedEffect`; there is no
  public constructor taking caller bytes on the ask path, and no `reversible`
  field anywhere in a caller-supplied struct (invariant 6).
- **Domain axis vs lifetime axis stay separate.** `ConsentGrant` = lifetime
  (`ApproveOnce` | `Standing`); `StandingConsentGrant` = domain
  (`Disclosure` | `Action`). `GrantBound` constructors reject crossed triples so
  a caller cannot reinterpret one domain as the other (invariant 4).
- **Fail-safe direction (invariant 8)** is taken on CLASSIFICATION FAILURE, not
  on ordinary non-containment: a malformed/absent-facts disclosure resolves
  `Hide`, a malformed/absent-facts write resolves `Ask`. An ordinary
  non-contained candidate `Ask`s in both domains (Shape line 16).
- **Adapters, not migrations.** `AccessGrant` / `StandingOutboundGrant` /
  `PolicyScopedGrant` / `DisclosureScope` fold through `From`-style adapters in
  `consent.rs`; their bytes, status vocabulary and codecs are untouched.
  `PolicyScopedGrant` is `pub(crate)`, so its adapter is `pub(crate)` too.

## Ordering / carve-out posture

- `receipt.rs` + `receipt/tests.rs`: MS ONE-1747's arming owns these earlier per
  the blueprint ordering clause. This lane's receipt touch is the consent-registry
  projection only (additive, function-level disjoint).
- `tests/merge_split_oracle.rs`: additive only — arm `count_standing_grants` +
  un-ignore `ms06_streak_offers_standing_grant_never_auto_grants`; never weaken an
  MS-armed test.
- `gate.rs` develops in parallel with ONE-1728/P4a per CLAIMS; rebase before push.

## Next-step INTENT

1. `consent.rs` — types, bound normalization/containment, catastrophe floor,
   classifier, evaluator, Vault doors, registry projection, adapters. [in flight]
2. `consent/tests.rs` — the nine named invariant tests + adapter tests.
3. `error.rs` additive variants + `lib.rs` mod/re-exports.
4. `gate.rs` write-side residual: new pending reason codes; `Critical` stops
   minting an unconditional `PendingCriticalityFloor` and becomes a composed-effect
   signal. Watch: `inbox.rs:` (UNCLAIMED) string-matches
   `GateReasonCode::PendingCriticalityFloor.as_str()` — the VARIANT must survive.
5. Arming: `genui.rs` action ids, `edit_settle.rs::settle_standing_grant_authorizes`,
   `merge_split_oracle.rs`, `receipt.rs` lens compat projection, `disclosure.rs`
   adapter seam.
