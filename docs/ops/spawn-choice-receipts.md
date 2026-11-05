# Owner choices on spawn plan receipts

Live spawn planning records the owner choice rows that supplied fields of the
receipt's `asked` need. Both a leased parent's plan and an owner's root plan
carry `owner_choices` alongside the effective need, resolved plan and reasons.

Each entry names:

- `key`: `model`, `width`, `pattern` or `budget`.
- `mode`: `seed` or `pin`.
- `scope`: `goal`, `project`, `task_type` or `vault`.
- `scope_ref`: the goal or project id in hex, or the task type node. Vault
  rows omit it. A task type row applies at every tree version.
- `at`: the selected row's stored timestamp in Unix seconds.

The entry is captured in the same read that selected the value. It is not a
later lookup of the current row. The effective value and any seed weight are
already in `asked`; the setter and the row's free-text reason are not copied.
A timestamp is not a content hash or a new authority proof.

Only an owner row that actually supplies a field appears. A call's pin keeps
precedence and names no owner row. Skipped seeds and incompatible pins do not
appear. Existing pin-before-seed, narrowest-scope and pattern-before-width
rules do not change. The planner still learns and ranks under those choices.

A plan with no applied owner row omits `owner_choices`. The value-only planner
has no owner-row lookup, and top-shapes advice returns quotes, not receipts.
The metadata does not certify the plan's complete decision-source set, change
admission, or change the meaning of the receipt's other fields.

## Native dispatch model pins

A fresh, unplanned native dispatch also reads the owner's model pin at its
actual project and placed task type. An absent project still permits the
type and vault rows; it is not replaced with a guessed project. Pins follow
the same narrowest-scope order as planning.

An explicit seat override or a direct call's model pin takes precedence.
This does not newly apply a direct call's model request that its receipt
marks unapplied. Such a call keeps its existing behavior rather than taking
an owner default. A call's model seed is not a pin.

The owner pin uses the existing model-seat admission path. The model must
still satisfy the agent's list, model catalog, route, capabilities, context
window, facet, worlds and currently served set. An unavailable fixed model
is not replaced with another model.

An existing run resumes its stored seat before any fresh-birth owner lookup.
Changing an owner row does not repick that run or change its durable task
identity. Planned and continued seats keep their explicit model. The old
seatless path is unchanged.

The native model-seat receipt records the model that actually runs. It is
not a spawn plan receipt and gains no `owner_choices` metadata. Owner model
seeds, width and pattern defaults, and reader-spawn choice transport are not
added by this native pin path.

## Task-type tree root lookup

Live leased and owner-root plans also record `type_tree_root_lookup` when the
task-type tree root consults a live default hub. It contains the actual hub id,
`skills/team-shape` alias and pin used by that lookup, captured in the same
transaction as the tree read. No later pin lookup fills it.

A recorded lookup does not assert that an installed holder matched. If none
matched, the receipt still names the consulted alias while the existing seeded
tree fallback stays unchanged. An absent or deleted hub consults no alias, so
the field is omitted. The value-only planner does not consult a hub and also
omits it. This field names the initial task-type tree root lookup, not every
hub read a planner or donor may make.

The lookup travels with the frozen planned-intent receipt and its existing
launch-integrity comparison. It is audit metadata, not a read grant, a new
freshness check, or the plan's complete entity-source set. Planned-intent erase
removes it with the rest of the plan; other existing receipt retention rules
are unchanged.
