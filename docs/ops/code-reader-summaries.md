# Code-reader summary prompts

Code-mode `summarize` uses the executor's configured `models.code_mode.prompt_package`.
The package may override `blocks/code-reader-summary.md`. If that block is absent,
the engine uses the shipped summary text in `crates/oneiron/prompts/blocks/`.
Existing packages do not need a new file to keep summaries working.

The optional block is a text template. It supports the ordinary package `@include`
resolver and these placeholders:

- `{{version}}`: the summary recipe version.
- `{{effort}}`: `low`, `medium`, or `high`.
- `{{length}}`: the shipped length instruction for that effort.

A package can omit any placeholder and supply its own instructions. Text and
whitespace in a configured block are kept. An invalid configured block or include
reports the ordinary package-resolution error; it is not silently replaced.

The recording host resolves and renders the block after the existing member-read
and taint checks, before the summary memo lookup. It freezes the rendered text in
the queued recipe. The memo hashes those same words, and the worker uses them
without reading a newer package. Changing the package therefore changes a new
summary's memo identity, but not a summary already queued.

The REPL and pinned-program entry both pass the active executor package to their
recording host. Direct native callers can use `SummarizeRecipe::from_prompt_package`.
`SummarizeRecipe::new` selects the shipped default. The between-turn attached-skill
surface still has no reader-spawn binding and gains no summary capability here.

Source admission, result withholding, member order, model selection, budgets,
window checks, waits and summary receipts are unchanged. The recipe keeps its
existing version and effort; the default prompt's words are unchanged.
