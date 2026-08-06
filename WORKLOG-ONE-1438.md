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
switched principal, target that stopped hydrating (this is where a rotated short ref
dies — `ensure_target_readable` hydrates `short_id` + `content_hash`), a render revision
that dropped the binding, moved it to another atom, or relabelled its role.

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
