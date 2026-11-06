# Coach skill-author wording

Four pieces are configurable in `[models.dreamer.wording]`:

| Inline setting | File setting | Consumer |
| --- | --- | --- |
| `coach_skill_workflow_answer_prompt` | `coach_skill_workflow_answer_prompt_file` | Answer instructions appended to the loaded `skill-optimize` workflow. |
| `coach_skill_draft_prompt` | `coach_skill_draft_prompt_file` | The fallback skill-edit instruction and the first part of a heal repair's instruction. |
| `coach_skill_cause_prompt` | `coach_skill_cause_prompt_file` | The second part of a heal repair's instruction, explaining its cause-context data. |
| `coach_producer_fix_prompt` | `coach_producer_fix_prompt_file` | The instruction for a proposed policy-manifest or configuration fix. |

Set inline text or a file for each piece, not both. Missing or blank values
use the shipped files in `crates/oneiron-server/prompts/`: respectively
`coach-skill-workflow-answer.md`, `coach-skill-draft.md`,
`coach-skill-cause.md` and `coach-producer-fix.md`. Those files preserve the
previous runtime text exactly, with no added newline. Unreadable files are
configuration errors. Relative paths resolve beside the configuration file;
managed vaults apply the existing owner-path containment rules.

The host resolves these pieces when it loads configuration. Hosts without
`[models]` use the same defaults. No live reload mechanism is added.

The loaded workflow remains the instruction prefix, followed by two newlines
and its answer piece. A heal repair uses its draft and cause pieces separated
by one space. The existing fallback branches, workflow loading, attempt pins,
DEV evidence, held-out evaluation, admission gates, data/source rows, model
roles, budgets and parsers do not change. Custom wording must still request
the existing JSON answer shape. Proposed edits and fixes remain proposals;
this configuration does not apply them.
