# WORKLOG — ONE-1436 [SURF-ENG-01C] Typed action/event backchannel + card lifecycle states

branch: `ONE-1436` cut off `f5fce02` (current `origin/main` at dispatch)
worktree: `/Volumes/Cinema/w5-lt/surfaces-wire`
blueprint: `/Users/olety/.claude-wave5/blueprints/SURFACES-WIRE/ONE-1436.md`

## Packet (claims) — verified `git diff --name-only f5fce02`

- `crates/oneiron/src/lens.rs` (edit)
- `crates/oneiron/src/lens/tests.rs` (edit)

Nothing else. `lib.rs` deliberately NOT touched: it is reserved to ONE-1926 by the
CLAIMS amendment, and `pub mod lens;` already makes every new type reachable as
`oneiron::lens::…`. Re-exports are a one-line additive follow-on whenever a
consumer needs them.

One incident worth recording: `cargo fmt -p oneiron` reformatted a *pre-existing*
unformatted line in `crates/oneiron/src/surface_event/tests.rs:736` (ONE-1259's
file). Reverted — packet discipline beats drive-by formatting. That line is still
unformatted on main and will trip a repo-wide `cargo fmt --check`.

## Shape as built

**Wire version.** `GENERATED_UI_WIRE_VERSION` 1 → 2; `LENS_ATOM_KIT_VERSION` stays 2.
The tree/prebuilt/catalog shapes landed by 01A/01B are untouched.

**Declare server-side, accept client-side.** `GeneratedUiCard` gains `actions`
(engine-authored `GeneratedUiActionDeclaration` manifest) and `$state`
(`GeneratedUiStateSnapshot`). `render_for_surface` carries both into
`GeneratedUiRender` and on into the `GeneratedUiDataModel` inside
`card_state_update`, so the manifest is *serialized*, never ambient host state.

`GeneratedUiActionEvent` names only `cardId`/`elementId`/`actionId`/`patch`/
`occurredAt` under `deny_unknown_fields`. There is no field on the wire for a
command, actor, source, approval, or authority — forging one is a parse error,
not a policy check.

**Validation chokepoint.** `LensRenderFrame::validate_action_event` is the single
door. It proves, in order: the read key is the principal's selected key; the
`emitter` argument *is* this frame's binding; the render belongs to this frame;
the event names this render's card; the card is not archived; the element exists;
the action id is declared exactly once; the declaration is for that element; the
element is a `self_ui` control whose embedded `SelfUiAction` equals the manifest
entry; and the patch satisfies the declared state schema. Only then is a trigger
returned.

**Three ruled tiers (ARCH-0048 G2).** `local` returns only a new state snapshot.
`deterministic_tool` returns a `LensApprovedAction` — a trigger that still has to
be routed through `into_host_mediated_write` + `GatedActorWrite`; nothing here
executes. `model_round_trip` returns exactly
`{action_name, resolved_params, source_card_id, source_element_id}` for the next
agent turn. Handle arguments resolve through the existing `approve_action`, so
the host backing table and role check are unchanged.

Two closed-shape rules make "no tier auto-forwards" structural rather than
aspirational: a `local` declaration may not carry `SelfUiValue::Handle` args (it
has no path to the backing table, so a handle there would only *look* like
authority), and a non-local event may not carry a `$state` patch (trigger args come
from the engine's declaration alone). A toggle-then-submit flow is two events,
which is the ARCH-0048 shape anyway.

**Declarative `$state`/`$bind`, no evaluator.** `$state` serializes as the map
itself — `{"$state":{"remind":{"type":"bool","value":false}}}` — via a hand-written
`Serialize`/`Deserialize` on `GeneratedUiStateSnapshot`. No `values` wrapper, so
`/$state/<key>` addresses an entry directly.

`SelfUiStateKey` is a `lens_token_type!` (ASCII alnum, `.`, `_`, `-`). That is a
deliberate strengthening of the blueprint's `#[serde(transparent)] String`, and it
buys the whole pointer story for free: a key can never contain `/` or `~`, so
"exact escaped `/$state/<key>` path, no `/values/` segment, no healing" collapses
into one `strip_prefix` + `SelfUiStateKey::new`. `/$state/values/remind`,
`/$state/remind/nested`, and `/$state/` all die there.

`$bind` descriptors bind one state key to one of four closed control properties.
The property→type table is closed (`checked`→bool, `selected`→token, `text`→text,
`value`→number|text), bindings only ride `self_ui` atoms, and each property binds
at most once per node. No `$computed`, expressions, scripts, or URLs exist as
fields, so they fail at parse.

**Lifecycle.** `generating → active → responded → archived`, with `completed`/
`expired`/`dismissed`/`superseded` as archive *reasons*. `GeneratedUiCardPhase`
derives `Ord` in declaration order, so `transition` is one comparison —
`next <= self.phase` rejects backwards moves, self-loops, and every edge out of
`archived` (terminal) in a single rule, and the revision advances via `checked_add`.
A reason is required on `archived` and forbidden elsewhere, on the wire too.
`render_for_surface` mints `active`/rev 0, which is what the initial completed tree
emits in `card_state_update`.

**Hand-written seams widened** (serde attributes on the public structs are inert
on these paths, per the blueprint):

- `GeneratedUiCardWire` — `actions`, `$state`
- `GeneratedUiRenderWire` — `actions`, `$state`, `lifecycle`
- `GeneratedUiDataModelWire` — `actions`, `$state`, `lifecycle`
- `LensNodeSeed` — literal `$bind` in the `Field` identifier, the map arm, the
  **sequence** arm (position 5, so positional msgpack still round-trips; the
  over-length check moved 5 → 6), the construction, and the accepted-field list
- `GeneratedUiRender::segments()` — the `GeneratedUiDataModel` literal now carries
  actions, flattened `$state`, and lifecycle instead of only root/nodeCount/catalog
- `GeneratedUiRender::from_segments` — reconstructs them back off `card_state_update`

The three new data-model fields deserialize with `#[serde(default)]`, so the
pre-existing JSON literals in the segment-stream and raw-URL tests stay valid.

## Deviations from the blueprint

1. **`SelfUiStateKey` is a validated lens token, not a transparent `String`.**
   Strictly stronger, house idiom, and it is what makes the JSON-Pointer rules
   enforceable by construction rather than by string surgery.

2. **Added `GeneratedUiCard::interactive(card_id, tree, actions, state)` beside the
   pinned `with_interactivity(self, actions, state)`.** Forced, not cosmetic: a
   tree carrying `$bind` cannot pass through a stateless intermediate card, because
   a card with `$bind` and no `$state` has dangling bindings and *should* be
   rejected. `with_interactivity` is retained (it delegates) for the manifest-only
   flow where the tree has no `$bind`. `new`/`card` also delegate — one validation
   path, three entry points.

3. **`GeneratedUiValidatedAction::ModelRoundTrip.action_name` is the declaration's
   `action.command`, not its `action_id`.** `action_name` is paired with
   `resolved_params` exactly as `LensApprovedAction` pairs `command` with `args`;
   the callable verb is what the next turn needs. The manifest key stays
   recoverable from `source_card_id` + `source_element_id`.

4. **Two scope calls made explicitly, both narrow:** archived cards reject action
   events (terminal means terminal — the one place where accepting would be a real
   defect), and `render_for_surface` drops manifest entries and `$bind` descriptors
   for elements the surface degraded to fallback text (a control that cannot render
   cannot be actuated; an event for it then finds no declaration).

## Tests — `crates/oneiron/src/lens/tests.rs`

The five named in Done-means, all with positive controls so no assertion is
vacuous:

- `typed_action_event_matches_declared_set` — valid event resolves; unknown action
  id, foreign element, ghost element, and wrong card all fail; duplicate
  declarations fail at card construction; manifest drift fails **and** the pristine
  render still succeeds (proving the drift is what bit); degraded surface offers no
  manifest.
- `forged_action_and_actor_are_rejected` — honest event JSON parses (control), then
  actor/authority/command/approval/emitter/source/script/url each fail to parse;
  patch ops reject smuggled fields; wrong emitter and wrong read key fail; a
  foreign frame cannot adjudicate; five bad `$state` paths fail; type change fails;
  remove-then-replace fails; archived card refuses events; the validated action
  carries the frame's emitter.
- `local_state_bind_round_trip` — `$state` is the flattened map with no `values`
  key; `$bind` is literal on both tree and flat nodes; card → render → segments →
  `from_segments` round-trips actions/state/lifecycle; msgpack named **and
  positional** round-trip through the `LensNodeSeed`; dangling and mistyped
  bindings fail; `$bind` on a non-control fails; baseline card decodes while
  `$computed`/`$expr`/`$script` do not.
- `action_tiers_do_not_auto_forward` — local moves only state; deterministic yields
  an approved action whose handle arg resolved to the host backing ref and which
  still needs an explicit gate chokepoint; model yields exactly the four callback
  fields; trigger tiers reject patches; a local declaration with a handle arg fails.
- `card_lifecycle_transition_table` — full forward table with revision counting,
  expiry/completion as reasons, archived terminal against all four phases,
  backwards and self transitions, reason required/forbidden, the same table on the
  wire, and the revision observable in `card_state_update`.

Existing generated-UI stream, capability-lowering, raw-URL, principal-key, and
host-backing-ref tests are unchanged and green. Three struct literals needed the
new fields added (`generated_ui_node`, the aggregate-budget data model, the
depth-budget node) — mechanical, no assertion touched.

## Gates

- `cargo check -p oneiron --all-features --lib` — clean
- `cargo clippy -p oneiron --all-features --lib --tests` — clean **for this diff**.
  One pre-existing `-D clippy::redundant-clone` error survives at
  `crates/oneiron/src/identity_topology/tests.rs:4203`; that file is untouched here
  (`git diff --name-only` = my two files), has no lens references, and is red on
  `f5fce02` itself. Main defect, not this lane's.
- `cargo test -p oneiron --all-features` — **green**: 3450 lib tests passed
  (46 in `lens::tests`, up from 41), 0 failed, every integration binary and doctest
  green.

## Known holes / follow-ons

- Card state is reset-to-initial across process restart, as the ticket scopes it.
  Durable card-state persistence is later work.
- New public types are reachable as `oneiron::lens::…` but are not in the
  `crates/oneiron/src/lib.rs` re-export block — that file belongs to ONE-1926.
  Additive one-liner when a consumer lands.
- ONE-1438 is layer 2 on this same `lens.rs`/`lens/tests.rs` stack and must rebase
  on this branch.
