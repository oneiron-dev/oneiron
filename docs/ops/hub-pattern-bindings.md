# Hub coordination-pattern bindings

A workflow skill can include `pattern.json` at its package root, beside `SKILL.md`:

```json
{
  "pattern": "committee",
  "default_axis": "converge",
  "works_well_for": "researching what exists; refining",
  "works_well_for_types": ["research", "refine"]
}
```

`pattern` uses the existing `TeamPattern` tokens: `ceo_decides`, `committee`,
`vote`, `market`, or `rotation`. `default_axis` is `converge` or `diverge`.
The line and node IDs follow the native pattern binder's existing validation.
An empty type list is valid. The engine does not infer node IDs from prose or
invent executor names. A matching node uses the current tree version at read time.

## Import and sync

Hub import and an applied hub sync attempt the binding in the same writer that
persists the package. The helper only creates a missing binding. An existing
host or hub binding is never replaced by package bytes. A host can still rebind
explicitly with `team::register_pattern_skill`; that door is unchanged.

A missing, malformed, unknown-field, or invalid `pattern.json` leaves the skill
unbound. A non-workflow skill stays unbound too. These cases do not refuse the
skill import or update. Storage errors still abort the original transaction.
A proposed or rejected sync does not retain a new binding from its rolled-back
update. The file does not grant approval or activate a skill. The planner keeps
its existing loadability checks.

The import helper writes no learning priors. It only records the existing
`PatternSkill` shape under the actual imported skill entity, with the import's
`learned_at` timestamp. Existing stored priors and learned evidence remain intact.
The binding's line is available to the normal planner; the separate pattern-prior
reader can use it as the weakest default for an exact matching type node.

## Publication

Publish the workflow's instructions and explicit sidecar through the hub. Do not
add the five coordination patterns back to the engine's bootstrap file list.
The package's ordinary content hash covers both files. No record, package, storage
ABI, permission, or wire schema changes are needed for the sidecar.

The engine consumer does not itself publish, import, admit, or enable any first-party
skill. First-party availability still requires a released hub commit and an explicit
import through the existing hub doors. Revised metadata does not overwrite an
existing binding; use the explicit host rebind door when that change is wanted.
