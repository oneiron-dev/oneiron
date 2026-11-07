# Coach failure-class wording

The Coach asks a typed failure-class question before drafting a code fix.
A host can replace that question's wording through the existing model config:

```toml
[models.dreamer.wording]
code_fix_class_prompt = "Classify this failure using the supplied Choice options."
```

Or supply a UTF-8 file instead:

```toml
[models.dreamer.wording]
code_fix_class_prompt_file = "/vault/config/coach-class.md"
```

Use the inline field or the file field, not both. Relative file paths resolve
beside the config file. A missing setting or blank text uses the shipped wording
in `crates/oneiron-server/prompts/code-fix-class.md`. An unreadable file is a
configuration error. Managed vaults apply their existing owner-path containment
rule to the file field.

The wording resolves when the server loads its model config. Once that config is
loaded, subsequent code-fix runs use its text. Hosts without `[models]` use the
same shipped default. This adds no new reload mechanism.

Only the failure-class question text changes. The nine Choice options, answer
parsing, evidence, decision ladder, budgets, draft instruction, and replay checks
are unchanged. The default text is byte-identical to the former Rust constant.
No code-mode prompt package is needed. This setting does not add a stored source
revision or claim that the question wording has a witnessed entity source.
