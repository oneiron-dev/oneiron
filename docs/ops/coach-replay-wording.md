# Coach replay and invented-example questions

The code-fix host reads three questions from `[models.dreamer.wording]`:

| Inline setting | File setting | Question |
| --- | --- | --- |
| `code_fix_reproduced_prompt` | `code_fix_reproduced_prompt_file` | Does a replay reproduce the failure? |
| `code_fix_fixed_prompt` | `code_fix_fixed_prompt_file` | Does the reply after the fix no longer fail that way? |
| `code_fix_export_safe_prompt` | `code_fix_export_safe_prompt_file` | Is the invented example free of real private details? |

Set either the inline text or the file path for each question, not both.
An omitted or blank value uses the shipped text in
`crates/oneiron-server/prompts/code-fix-{reproduced,fixed,export-safe}.md`.
Those defaults are exactly the questions used before these settings existed.
An unreadable file is a configuration error. Relative paths resolve against
the configuration file's directory. Managed vaults apply their existing
owner-path containment rules to all three file settings.

The host resolves the text when it loads the configuration. A host without
`[models]` uses the same defaults. This adds no live reload mechanism.

The configured text goes to the existing `reproduced`, `fixed` and
`export_safe` questions on the decision ladder. The yes/no answer contract,
state, evidence and verdict mapping do not change. The replay, grants,
consent and export checks still run as before. These settings do not change
the failure-class question or the prompt that drafts the invented example.
