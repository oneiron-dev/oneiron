# WORKLOG — ONE-1438 [SURF-ENG-05] universal select-to-agent

Branch `ONE-1438` off `929b7ba73` (main tip, #592 = ONE-1436 already merged, so the
1436→1438 seam serialization is satisfied by main rather than by a stacked base).

Diff: `crates/oneiron/src/lens.rs`, `crates/oneiron/src/lens/tests.rs` — exactly the
ONE-1438 rows of `SURFACES-WIRE/CLAIMS.md`. No `lib.rs` re-export was needed: nothing
outside `lens` consumes the new types yet, so the packet stayed closed.

## What landed

### 1. Selection input never carries a target

`LensAtomSelectionRequest { card_id, atom_id, handle }` — `deny_unknown_fields`,
`camelCase`. Three names, nothing else: no `entityId`, body, screenshot, write token,
authority, query string, short ref, or role is expressible. The engine looks the node up
in the exact `GeneratedUiRender` it emitted.

### 2. One resolution path

`LensRenderFrame::select_atom` validates in order: acting principal's selected read key →
render belongs to this frame → request card id equals the render's → node exists → node
declares the named handle **exactly once** → declared role converts to a read reach →
frame's host backing row exists for that handle **at the same role** →
`resolve_backing_ref_token` (host-minted + same render + `ensure_target_readable` under
the principal). The returned token is copied off the host row; nothing is synthesized
from client data.

### 3. A distinct read-reach type

`LensReadHandle` — `Serialize` only, no `Deserialize`, no public constructor, private
fields with `#[must_use]` accessors. Carries `renderId`, `atomId`, `reach`, `targetKind`,
`shortRef`, `backingToken` and nothing else. `LensReadReach` is `LensHandleRole` minus
`ActionTarget`; `TryFrom<LensHandleRole>` is the only way in and it rejects `ActionTarget`,
so an action-target binding cannot be laundered into a selection handle.

`resolve_read_handle` repeats the whole proof against the *current* render and scope:
switched principal, target that stopped hydrating, a render revision that dropped the
binding, moved it to another atom, or relabelled its role. The stale-short-ref case is
tested end to end through the new door — the fixture re-puts the target entity with a
different body, the stored `content_hash` moves, `ensure_target_readable` stops hydrating
the handle's `short_id`, and a handle that resolved a moment earlier now fails instead of
following the entity forward onto content it was never issued against.

### 4. Selection stays separate from approval

No conversion to `LensApprovedAction` / `LensHostMediatedWrite` /
`LensGateWriteChokepoint` exists on `LensReadHandle`. `GeneratedUiAgentCallback` gained
`selected_context: Vec<LensReadHandle>`, populated only through
`LensRenderFrame::with_selected_context`, which re-resolves every handle and requires the
callback to come from this frame. The callback itself remains non-`Deserialize`, so it is
still an engine-to-agent output, never a client-submittable authority path.

### 5. Fuzz / property coverage

`generated_ui_fuzz_rejects_extra_atom_selection_fields` (proptest over arbitrary JSON
field names/values) plus deterministic sweeps for arbitrary ids, duplicate node bindings,
cross-render tokens, role swaps, alternate principals, and missing fields. The short ref
IS asserted present in the encoded handle (a locator under `ScopedRead`); the encoded key
set is pinned to exactly the six metadata fields and asserted free of the body bytes and
the target entity id.

## ONE-1436 banked P3 — per-control `$bind`/patch conformance

The chokepoint: the `$bind` half of `validate_generated_ui_interactivity` was extracted
into `validate_generated_ui_state_bindings(elements, state)` and is now called from **two**
places — card/render assembly (as before) and `validate_action_event` immediately after
`apply_generated_ui_state_patch`. One validator, both doors.

The new rule is `SelfUiControl::accepts_bound_value`: type agreement was never the whole
conformance story.

- `Select` / `Segmented` + `Selected`: the token must be one of that control's own options
  (reuses the existing `validate_selected_option`).
- `Slider` + `Value`: the number must satisfy `SliderControl::admits` — inside `[min, max]`
  and on the `step` grid, residual measured against `SLIDER_STEP_TOLERANCE` (1e-6 of one
  step) so decimal steps like `0.5`/`0.1` survive binary rounding. Non-finite quotients
  (subnormal `step`) reject rather than silently pass.
- `Slider` + `Value` + non-number: rejected outright.
- Every other (control, property) pair is fully described by its type → `Ok`.

The grid tolerance is deliberately **absolute** (a fraction of one step), not
absolute-plus-relative. At magnitudes where `f64` spacing exceeds the step, a relative
epsilon term would exceed the step itself and admit every value; the absolute form
rejects instead. A validator should fail closed on inputs whose grid is not representable.

`SliderControl::validate` now routes its own declared `value` through the same `admits`
helper, so the domain a slider enforces on a client patch is literally the domain it
declares for itself. Existing fixtures (`min 0, max 10, step 0.5, value 5.0`) stay green.

**Consequence worth naming (falls out of the single chokepoint, not a separate decision):**
a patch that `Remove`s a `$state` key a control is bound to is now rejected — the render
would otherwise be left with a `$bind` pointing at a missing key, a shape assembly already
refuses. Tested.

## Blueprint deltas (small, deliberate)

1. **`camelCase` on the new wire types.** The blueprint skeleton showed bare
   `deny_unknown_fields`. Every sibling generated-ui wire type (`GeneratedUiActionEvent`,
   `GeneratedUiNode`, `SelfUiBinding`) is `camelCase`; snake_case here would have made
   `cardId` fail on a surface where every other field is `cardId`.
2. **No `#[serde(default)]` on `selected_context`.** `GeneratedUiAgentCallback` has no
   serde derive at all (it is a host-side type, deliberately). A serde attribute there
   would not compile, and the blueprint's own rule — "do not make that callback shape a
   client-submittable authority path" — is better served by it having no `Deserialize`.
3. **No tautology guards in `resolve_read_handle`.** `handle.render_id`, `reach`,
   `target_kind`, and `short_ref` are all copied from the same immutable host row the
   token identifies, so re-comparing them at resolve is unreachable-branch defence. The
   checks that can actually fail are the ones implemented: principal, token provenance,
   target hydration (this is the stale-short-ref path), render ownership, and the node's
   currently-declared role. Called out here because a reviewer will reasonably ask.
4. **`ensure_render_is_ours`** extracted — `validate_action_event` carried a byte-identical
   inline check; the three selection entry points now share it.

## Gates

- `cargo check -p oneiron --all-features` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — **zero** findings in `lens.rs`
  or `lens/tests.rs`.
- `cargo fmt` — clean on both claimed files.
- `cargo test -p oneiron --all-features --lib lens::` — 52/52 green.
- `cargo check --workspace --all-features` — clean (the new `GeneratedUiAgentCallback`
  field has no external constructor: `GeneratedUiAgentCallback` is referenced nowhere
  outside `lens.rs`).
- `cargo test -p oneiron --all-features` — run 1: 3458 passed, 1 red in
  `attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
  ("cleanup span records=[]"). Run 2 (flake guard): **3459 passed, 0 failed**, that test
  included. It also passes in isolation and captures with
  `tracing::subscriber::with_default` (thread-local), so it is scheduling-dependent — a
  latent base flake this lane's added test count perturbed, not a lane failure. Nothing in
  this diff touches tracing, `attempt_queue`, or any shared subscriber.

### Mutation verification

Nine mutations applied to the new guards, each reverted after; **all nine were caught** by
the new tests:

| Mutation | Caught by |
|---|---|
| drop `select_atom` node-role vs host-row match | `selection_proves_one_resolution_path` |
| drop duplicate-node-binding rejection | `selection_proves_one_resolution_path` |
| make `ActionTarget` convert to a read reach | `action_target_bindings_never_become_read_handles` |
| drop `resolve_read_handle` role re-proof | `read_handles_reresolve_and_never_widen` |
| drop post-patch `$bind` revalidation | `bound_control_values_stay_inside_their_declared_domain` |
| drop per-control domain check | `bound_control_values_stay_inside_their_declared_domain` |
| make the slider step grid always admit | `bound_control_values_stay_inside_their_declared_domain` |
| drop the `with_selected_context` re-proof loop | `selected_read_context_rides_a_callback_without_becoming_approval` |
| drop the `with_selected_context` frame-ownership check | `selected_read_context_rides_a_callback_without_becoming_approval` |

## Base defects NOT touched (other lane's)

`crates/oneiron/src/surface_event/tests.rs:733` (fmt) and
`crates/oneiron/src/identity_topology/tests.rs:4203` (clippy `redundant_clone`) are red on
the base and out of this packet. Gates were scoped around them.

## Known holes / banked

None opened. Selection is read-only by construction and the write path is unchanged: any
mutation still names a gated verb and resolves its own action target through the action
backchannel.

## K3 simplify pass (tip 532418859)

Verdict: **NO EDIT WARRANTED.**

Candidates walked, each rejected with a grounding:

- `accepts_bound_value`'s `(Slider, Value, non-Number)` arm looks defensive but is
  reachable: `SelfUiBindableProperty::Value::accepts` admits `Number | Text`, so a
  Text-valued `$state` bound to a slider's `value` passes type agreement and lands
  exactly on that arm. Not dead.
- Folding `row.role != role` into the `find` predicate in `select_atom` would conflate
  two distinct rejections ("not host-bound" vs "role mismatch") — conflation, not
  simplification.
- `find` (not exactly-once) on the backing rows is sound: `mint_backing_ref` rejects a
  duplicate handle per frame at the mint chokepoint, so uniqueness is a frame invariant,
  not something `select_atom` must re-prove.
- Routing `select_atom` through `resolve_read_handle` would double-resolve the token —
  more work, not less.
- `with_selected_context` is beyond the blueprint skeleton but is the only re-proving
  population path for `selected_context` (documented blueprint delta 2); removing it is
  a design change, outside simplify scope.
- Helpers are all multi-use (`ensure_render_is_ours` ×3, `validate_generated_ui_state_bindings`
  ×2, `SliderControl::admits` ×2, `declared_binding_role` ×2) — the dedup was already done
  build-side. No layers, no speculative generality, no untouched-test desire.

Gates at verdict: `cargo clippy -p oneiron --all-features --lib -- -D warnings` clean;
`cargo test -p oneiron --all-features --lib lens::` 52/52; `cargo fmt --check -p oneiron`
clean on both claimed files (only the pre-existing `surface_event/tests.rs` base defect
shows, out of packet).

## VERDICT-FIX (from tip fb1350bcf)

One verdict-verified REAL P1. Commits `501e6f542` + `ecc69d85c`.

### F1 — stale handles laundered onto a later frame's row (P1, closed)

`LensBackingRefToken` is `(render_id, ref_id)` and nothing else. Render ids derive
deterministically from card ids, so re-rendering a card produces a *second frame with the
same render id*; `mint_backing_ref` names rows `ref-{len}`, so every frame's first mint is
`ref-0`. Two frames over one card therefore mint **byte-identical tokens** over completely
unrelated targets — the token cannot distinguish them, and only the issued handle's own
recorded metadata can.

`resolve_read_handle` never looked at that metadata. It proved `token.render_id ==
frame.render_id`, that `ref_id` was present in the *current* table, that the target still
hydrates, and that the *current* render declares the row's handle at the row's role — then
returned the current row. The handle's recorded `short_ref`, `target_kind`, and `reach`
were carried for the client's benefit and never re-proved. So frame B's `ref-0` answered
frame A's handle: a read handle silently relocated onto a different entity, and when both
the twin row and the current render said `ActionTarget`, the role check passed by agreeing
with itself and a **read-only handle resolved to an action-target backing ref** — the exact
launder `LensReadReach`'s missing variant exists to prevent (blueprint §2, §3, done-means).

The stale doc comment named the defect out loud: *"Reach is fixed by that row, so
re-proving the role covers the whole read-reach claim."* Reach is fixed by *whichever* row
currently sits at `ref-0`, which is precisely what an attacker chooses.

**Fix — one derivation, not three comparisons.** Issuance and re-resolution now share
`LensRenderFrame::issue_read_handle`: the handle that selecting `atom_id` onto a resolved
row proves *right now*. `select_atom` returns it; `resolve_read_handle` re-derives it and
honors the presented handle only if the two are **equal whole**:

```rust
let resolved = self.resolve_backing_ref_token(scoped_read, &handle.backing_token)?;
if self.issue_read_handle(render, &handle.atom_id, &resolved)? != *handle { ... }
```

Chosen over three ad-hoc field comparisons deliberately:

- It is the *whole* invariant, stated once — "an issued handle is honored iff re-issuing it
  now reproduces it" — instead of a checklist that a future field can silently escape.
- Reach is re-derived through `LensReadReach::try_from`, which has **no action-target
  variant**. An action-target row now yields no handle at all rather than a read handle
  over it; §3 is enforced by the type, at the same chokepoint, on both paths.
- `target_kind`, `render_id`, and `atom_id` come along for free in the struct equality, so
  no provably-unreachable branch had to be written to cover them (see M5 below).

The role-vs-host-row check moved into `issue_read_handle` unchanged, which also removes the
one place the two paths had diverged (`select_atom` looked the role up from the *request's*
handle name, re-resolution from the *host row's*). The prior simplify pass rejected
"routing `select_atom` through `resolve_read_handle`" as double-resolution — correctly;
this is the other direction (a shared derivation both callers reach with a row already in
hand), so no token is resolved twice. That pass's note about folding `row.role != role`
into the `find` predicate is now moot: the check lives in the shared helper.

**The twin-frame test was vacuous.** `read_handles_reresolve_and_never_widen` built its
twin with `LensRenderFrame::new(...)` and left the backing table **empty**, so it only ever
proved "a token absent from the table does not resolve" — it never reached the metadata
gap. It is kept (that case is still worth pinning) and the real case is now
`stale_handles_never_launder_onto_a_later_frames_row`, which populates the twin with a
same-named `ref-0` and asserts up front that

```rust
assert_eq!(&token, frame.backing_refs()[0].token(), ...)
```

— the twin's first mint *collides* with the token the issued handle carries. Without that
assertion the test could rot back into vacuity. Three orthogonal twins follow, each
isolating one leg: a different entity at the same role (short-ref re-proof), the **same**
entity rebound as `ActionTarget` (reach derivation — same short ref and kind, so only the
missing variant can reject it), and the same entity at `Timeline` (reach comparison). A
positive control closes it: reach a twin issues itself resolves through that twin and
points at the twin's own target, so the three rejections are the re-proof's doing and not a
broken fixture.

### Mutation verification (this fix)

Each re-proof leg stripped in turn, tests re-run, source restored (`git diff` clean after):

| Mutation | Result |
|---|---|
| M1 drop the whole metadata re-proof | **RED** — `stale_handles_never_launder_onto_a_later_frames_row` |
| M2 drop role == host-row role | **RED** — `selection_proves_one_resolution_path` |
| M3 omit `short_ref` from the re-proof | **RED** — `stale_handles_…_later_frames_row` |
| M4 omit `reach` from the re-proof | **RED** — `stale_handles_…_later_frames_row` |
| M5 omit `target_kind` from the re-proof | **still green — subsumed, reported honestly** |
| M6 let an action-target row carry read reach | **RED** — `action_target_bindings_never_become_read_handles` + `stale_handles_…_later_frames_row` |

M5 is not a coverage hole and no test was invented to manufacture one. `short_ref` is
`short_id:content_hash`, which `hydrate_short_id` resolves to exactly one entity, and
`ensure_target_readable` pins `Claim`↔`ENTITY_TYPE_CLAIM` and `Entity`↔not-claim against
that entity's stored type. A target whose kind differs while its short ref matches
therefore cannot survive `resolve_backing_ref_token` at all, so the `target_kind` term is
unfalsifiable *given* the other two — it is carried by struct equality at zero cost and
zero dead code, and would only become load-bearing if short refs ever stopped determining
the row's kind. Writing a defensive branch for it would have been the gold-plating the
doctrine header rejects; deriving why it cannot fire is the alternative.

### Gates (per commit)

`rustfmt --check` clean on both claimed files; `cargo clippy -p oneiron --lib
--all-features --all-targets` — **0** findings in `lens.rs` / `lens/tests.rs`;
`cargo test -p oneiron --all-features --lib lens` — **56/56 green** (52 → 56: three twin
cases run inside one new test plus the sharpening commit).

Diff stays inside the packet: `crates/oneiron/src/lens.rs`,
`crates/oneiron/src/lens/tests.rs`, this worklog. No `Cargo.toml` / `Cargo.lock` touched.
The pre-existing `surface_event/tests.rs:733` fmt defect is still red on the base, still
another lane's, still untouched.
