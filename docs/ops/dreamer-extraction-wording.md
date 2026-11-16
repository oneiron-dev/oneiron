# Dreamer extraction prompt and consolidation wording

The Dreamer asks a model to extract claims from each conversation slice and
each NOTE it reviews, then asks typed questions about what it extracted: how a
conflict resolves, which identity a merge keeps, which listed claim a candidate
corrects, how a sieve span reads, whether two claims of one night state the same
thing, and whether an Arc's cited turn should be opened. A host can word both
through the existing model config:

```toml
[models.dreamer.wording]
extraction_prompt_file = "/vault/config/dreamer-extraction.json"
consolidation_wording_file = "/vault/config/dreamer-questions.json"
```

`extraction_prompt_file` holds the whole extraction prompt in the shipped
prompt's shape, `crates/oneiron/src/dreamer_consolidation/executor/extraction_prompt.json`:

```json
{
  "system": "Extract durable memory claims from the conversation transcript ...",
  "examples": [
    { "user": "an example transcript", "assistant": "{\"candidates\": [], \"persons\": []}" }
  ]
}
```

The system text goes first, then each example as a user turn and the
assistant's answer, then the transcript. `examples` may be empty. The file
replaces the shipped prompt as a whole.

`consolidation_wording_file` names any of the questions of the shipped
`crates/oneiron/src/dreamer_consolidation/executor/decision_wording.json`:
`resolution`, `identity`, `correction`, `sieve_novelty`, `sieve_kind`,
`sieve_entity`, `sieve_confidence`, `nightly_link` and `arc_open`. Each question
it names asks in its words; each one it leaves out keeps the shipped wording.

```json
{ "resolution": "Several values were extracted for one claim identity. How do they resolve?" }
```

Relative file paths resolve beside the config file. A missing setting or a blank
file uses the shipped text. A file that does not read, is not that JSON shape,
names another key, or leaves the system text, an example's turn or a question
blank is a configuration error at load. Managed vaults apply their existing
owner-path containment rule to both file fields.

Only the words change. The reply contract and its check, the candidate decode,
each question's options and answer kinds, the decision ladder and its bands, and
the budgets stay the engine's. A reply the engine cannot read under its contract
is refused as before, so a prompt that asks for another reply shape gets no
claims.
