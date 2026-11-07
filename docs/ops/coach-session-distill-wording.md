# Coach session-distill wording

The Coach's session distiller uses the instruction resolved from
`[models.dreamer.wording]`:

```toml
[models.dreamer.wording]
coach_session_distill_prompt_file = "prompts/my-session-distill.md"
```

`coach_session_distill_prompt` supplies the instruction inline instead. Choose
one form, not both. File paths resolve relative to the configuration file through
the existing prompt loader. Managed settings also apply the existing owner-path
rules to this file setting. With neither setting, the host uses
`crates/oneiron-server/prompts/coach-session-distill.md`, byte for byte the previous
instruction. The resolved wording is held by the server's AI handle, including
its model-free defaults; each session distiller uses that host's wording.

This replaces only the system instruction. The sitting remains a separate data
message. Speaker resolution, source-row capture, model routing, budgets, note
parsing, and the existing distill schedule are unchanged. An override does not
change the engine's accepted answer format or grant access to a sitting.
