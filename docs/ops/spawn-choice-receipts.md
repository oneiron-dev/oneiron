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
