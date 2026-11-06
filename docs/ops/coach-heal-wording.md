# Coach heal-route and health-draft wording

Two host instructions are configurable in `[models.dreamer.wording]`:

| Inline setting | File setting | Consumer |
| --- | --- | --- |
| `coach_heal_route_prompt` | `coach_heal_route_prompt_file` | The existing heal-route question for a failure case or blocked report. |
| `coach_health_draft_prompt` | `coach_health_draft_prompt_file` | The system instruction for a health-card proposal. |

Set the inline text or the file path for a piece, not both. An omitted or
blank piece uses its shipped text in `crates/oneiron-server/prompts/`:
`coach-heal-route.md` or `coach-health-draft.md`. Both defaults are exactly
the previous runtime instructions, with no added newline. An unreadable
file is a configuration error. Relative paths resolve beside the config
file. Managed vaults apply their existing owner-path containment rules.

The host resolves these pieces when it loads its configuration. A host
without `[models]` uses the same defaults. No live reload mechanism is added.

The route question still uses the existing Choice options. The health draft
still uses the existing JSON fields, parser and skill/version binding.
The data, source rows, grants, admission, proposed-only behavior, model
roles, budgets, worker cadence and settlement do not change. A custom
instruction must still request the answer shape its existing consumer reads.
