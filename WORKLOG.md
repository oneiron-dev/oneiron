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

## Later decisions (same segment)

- **`ActorBound` name collision.** `crate::vault::ActorBound` (the engine-internal
  write handle) already owns that name at the crate root, and `vault.rs` is NOT in
  this lane's claims. `consent::ActorBound` is therefore deliberately NOT
  re-exported from `lib.rs`; the pinned downstream import path is
  `oneiron::consent::ActorBound`. Every other contract name IS re-exported. A
  rename of either type would be a cross-lane change, so the module path is the
  cheap correct answer. Noted in the `lib.rs` re-export block.
- **`facade.rs` NOT touched — deliberately.** Blueprint line 27 requires that
  `facade.rs` route actor-bound write verbs through the one Gate; it already does
  (3 gate call sites). Editing a file contended with w4 S-AUTH3, L1-ENTITY E1/E2,
  spine 1889, RET 208/1486/1487 and FED 1414 to add nothing would buy pure
  serialization cost. **This drops `facade.rs` from the lane's effective packet.**
- **`disclosure.rs` NOT touched — deliberately.** The `DisclosureScope` adapter
  lives in `consent.rs` per the blueprint's adapter table, so the w4
  S-DISC1/2/4-contended file needs no edit. Same reasoning as `facade.rs`.
- **Each consent act mints its OWN `GateDecisionId`.** First implementation reused
  `AuthenticatedOwner::decision_id` for every receipt; the ledger rejected the
  second one (`gate decision id collision`) and 4 tests caught it. The
  authentication's id now rides the grant row's owner stamp as provenance only.
- **`PendingCriticalityFloor` survives as a variant.** UNCLAIMED `inbox.rs:593`
  string-matches its `as_str()`. `Critical` now only mints it when NO consent
  context was composed, so doors not yet on the DEC-0006 path keep their
  pre-existing behaviour instead of silently losing a gate.
- **`brief_ref` is used VERBATIM in the settle bound.** First implementation
  re-prefixed it to `brief:{ref}`, minting a bound no grant could match; the
  done-means test caught it.
- **Confirm trio is asserted as an OUTCOME mapping.** genui emits
  `approve_once` / `decline` / N bound-naming `escalate_*` ids, so "exactly three
  outcomes" is `ConsentConfirmOutcome::from_action_id` covering every emitted id,
  not a literal 3-string list. Each `escalate_*` id names ONE bound, which is what
  makes approve-and-stop-asking an owner act on a row rather than an inference.

## State: seg0 COMPLETE — cheap gate GREEN

- `cargo fmt --all` clean · `cargo clippy --workspace --all-targets --all-features`
  clean for this lane (only pre-existing `oneiron-seal` sha1 deprecation remains)
  · `cargo test -p oneiron --all-features` = **3169 passed, 0 failed** plus all
  integration binaries green.
- Files touched (all inside Claims): `consent.rs` (new) · `consent/tests.rs` (new)
  · `lib.rs` · `error.rs` · `gate.rs` · `gate/tests.rs` · `genui.rs` ·
  `edit_settle.rs` · `edit_settle/tests.rs` · `receipt.rs` ·
  `tests/merge_split_oracle.rs`. `Cargo.lock` untouched.

## SIMPLIFY pass (seg1) — verdict + delta

Deletion-biased review of the full lane diff (4786+/43−), one pass, cheap gate
re-green. The seg0 implementer already wrote lean: the pass is a **1-line net
deletion**, and "kept" items below were individually re-checked against the
deletion bias rather than left by default.

- **DELETED** a dead `let _ = catastrophe;` binding inside the catastrophe
  mint-reject in `create_standing_grant` — a leftover from a first draft that
  named the binding; the arm discards the match. `consent.rs` 2603 → 2602.
- **Kept: `ActorBound::new` + `with_actor_class`** (no `actor(&str, Option)` arg
  collapse). A two-arg constructor reads class-optics as a permission expansion,
  which is why the GET flavor + builder-with-tightener shape is the
  deliberate, common one in this codebase's bound types.
- **Kept: `ConsentGateContext::evaluate` + `consent_gate_reason_codes` wrappers**
  in gate.rs. They are the pin that says the Gate composes `consent.rs`'s
  evaluator ONCE, rather than each door re-implementing the ladder. That
  docstring is the contract, not scaffolding.
- **Kept: strict `validate_keys` + the `required_value` chain on the row codec.**
  This is the persisted-MessagePack bodycontract — the one place the
  envelope-discipline cost is load-bearing. Weakening it (e.g. `serde(default)`)
  would admit crossed/mislabeled rows, which the invariant-8 fail-safe
  explicitly guards against.
- **Kept: `evaluate_consent`'s three-step ladder as-is.** Catastrophe →
  approve-once/standing → reversibility is the DEC-0006 pin order; folding the
  "uncovered+irreversible ≠ write hides" nuance any further collapses the
  domain fail-safe back into a single verdict and re-opens invariant 8.
- **Kept: `ActionEnvelope`'s 4 Option/bool fields.** Model, not speculative
  generality: each (`selectors`, `target`, `budget`, `receipt_required`) has an
  invariant-bearing containment rule; a presence check confirmed all four are
  set or matched in the lane's own tests.
- Checked the three wrapper-shaped items one-by-one (`ConsentEvaluation` →
  reason-codes, `ConsentRegistryRow::from_row`, `append_consent_receipt_in_txn`
  → `append_consent_gate_decision_in_txn`): all earn their layer as named
  seams in the "projection, not a second ledger" contract, NOT "for safety"
  scaffolding.
- No test file, no public-API signature, no `GateDecisionRecord` field was
  touched. `Cargo.lock` untouched.

Net lane delta from this pass: **+0 / −1** (the dead binding). Cheap gate below.

### Cheap gate, tail of pass

- `cargo check -p oneiron -j6` — clean; the one warning is the pre-existing,
  untemplated `batch.rs` dead-code marker (`facet_of_endpoints_provably_off_table`),
  present on the base template too (its warning count = 1 there, same file).
- `cargo clippy -p oneiron -j6` — clean, same baseline warning only.
- `cargo test -p oneiron --lib consent::` — **40 passed, 0 failed**.

RELAY-ONE-1606-simplify-seg0 — committed as `79d7764`.

## Next-step INTENT

1. **Rebase on post-1728 `gate.rs`** before any push (CLAIMS §gate.rs seam) and
   re-run the cheap gate. The `GateEvaluatorInput.consent` field and the
   `GateMetricReasonClass::Consent` arm are the likely conflict points.
2. Confirm the w4 same-file carve-outs at dispatch WITH THE DIFF CITED for
   `gate.rs`/`gate/tests.rs` (E-A + E-B), `genui.rs`/tests (S-DISC3/4),
   `edit_settle.rs`/tests + `receipt.rs` (E-F), `receipt/tests.rs` (E-A AND E-F),
   `error.rs` (S-AUTH1/S-AUTH4/S-DISC1/S-DISC2/E-L). All this lane's hunks are
   additive and function-level disjoint. `facade.rs` and `disclosure.rs` carve-outs
   are MOOT — not touched.
3. Verify the MS ONE-1747 ordering clause on `receipt.rs` before opening the PR;
   this lane's receipt touch is one additive re-export method
   (`consent_registry_lens`).
4. SECURITY-CORE RIDER: owner/cross-vendor review is a merge condition. A green
   implement/simplify/finder/verdict stack does NOT authorize merge.

## FIX leg (K3, post-verdict on 62ddae1)

Nine P1s from the verdict on commit `62ddae1`. Each closes as its own
commit, cheap gate green per commit; full-workspace sweep lands next.

- **FIX1 — gate chokepoint** (`15d0017`): both gate-input builders now take
  `Option<ConsentGateContext>`; the legislated `Some` door
  (`evaluate_external_effect_policy`) composes the ladder from host-observed
  effect facts inside its own write txn and folds three remembered-state
  sources that were ALREADY verified on that txn (active consent grants,
  scope-matched `StandingOutboundGrant` through the pinned adapter,
  budget-free policy-scoped matches echoed as covering grants). An
  unauthorized IRREVERSIBLE send now surfaces
  `gate.pending.consent.irreversible_effect` ahead of the authority code —
  the three updated exact-vec reason pins in `gate/tests.rs` are the behavior
  change made legible, not weakened coverage.
- **FIX2 — owner-auth** (`08e4c85`): `authenticate_owner` additionally
  validates the principal ref through `ActorBound` (shape check), requires
  the actor's identity-topology lifecycle be ACTIVE (merged/split shells are
  redirects, not owners), and fails a hex principal ref that decodes to a
  DIFFERENT actor. Not in scope: distinguishing "the owner PERSON" from other
  PERSON entities — the store has no owner-of-vault table; that is what the
  principal-authentication handshake carries.
- **FIX3 — approve-once** (`ce528fb`): `approve_once` claims a
  `consent.once.v1:` spend marker keyed by the effect digest in the SAME
  write txn as the receipt, so a re-mint of the same digest is refused with
  `ConsentApproveOnceSpent`. The marker value is the approving
  `GateDecisionId` — evidence on a contested spend, not a tombstone. The
  evaluator's Auto arm on a matched digest is unchanged in shape; what
  changed is that the RECEIPT it honors cannot be minted twice.
- **FIX4 — reversibility** (`7676515`): the coverage arm now fires only when
  the op carries a requirement to cover; a requirement-free irreversible op
  falls through to the classifier and Asks (was: `is_none_or` over two
  `None`s short-circuited Auto). A requirement-free REVERSIBLE op still
  auto-runs — invariant 6's permissive bias is preserved where the invariant
  says to preserve it.
- **FIX5 — revocation TOCTOU** (`f5d456d`): both settle paths resolve
  standing-grant authority INSIDE the settle's own write txn
  (`authorize_settle_in_txn`). LMDB serializes writers, so a revocation is
  either committed before the settle's txn opens (the grant reads Revoked and
  the settle refuses) or lands after the settle commits (its read was live at
  authorize time). The pre-txn `authorize_settle` call stays as the
  early-error contract; the in-txn one is the atomicity pin. Test simulates
  the race shape at the reader level (LMDB has one writer; a second writer's
  commit is by definition serialized) plus the end-to-end revoke→settle
  refusal.
- **FIX6/7/8** (`a60232f`): test pins only — the catastrophe floor's mint
  rejection + exact closed-set always-gate was already covered by the
  invariant-7 test; this commit extends invariant 9's registry test with the
  owner audit-dump assertions (subject/class/selectors/status per row,
  revoked retained under the audit flag) and invariant 3's bound test with
  the envelope-mismatch axis (different selector set, superset drift → Ask,
  never inherit).
- **FIX9 — cross-vendor pin** (`a43f7d4`): pins that actor-class admission is
  a typed `ConsentActorIdentity` variant check, not a free-text claim — one
  ask card, same payload, pinned `SurfaceActor` admits what an unverified
  `VoicePath` turns into `NoopNonPrincipal`.

State: cheap gate green per fix commit. Claims audit: lane diff touches ONLY
files inside the fix list's allowed surface (consent.rs, consent/tests.rs,
gate.rs, gate/tests.rs, edit_settle.rs, edit_settle/tests.rs, error.rs,
genui.rs, genui/tests.rs, lib.rs, receipt.rs, merge_split_oracle.rs). No
facade.rs, no Cargo.lock, no out-of-packet writes.

RELAY-ONE-1606-fix-seg0
