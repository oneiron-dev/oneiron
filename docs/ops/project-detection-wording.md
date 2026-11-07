# Configure the house mind's project question

The host installs the project detector when it attaches its workflow pump.
Its question asks whether a message describes work worth tracking as a
project. Override that question in the model configuration:

```toml
[models.dreamer.wording]
project_detection_prompt_file = "project-question.md"
```

On a self-hosted server, a relative file path resolves beside the config
file. Managed settings require an absolute owner path inside an allowed
vault or settings directory, under the existing owner-path rules.
Alternatively, set `project_detection_prompt` to the question text inline.
Do not set both fields. A missing or whitespace-only value uses the shipped
default. Nonempty text is kept as written. An unreadable file is a config
error.

The wording is resolved at start and copied into the existing project
detector. Restart to use a changed value; this adds no live reload. With
neither setting, the shipped question is byte-for-byte the prior question,
including its lack of a trailing newline. Its source is
`crates/oneiron-server/prompts/project-detection.md`.

Only the wording changes. The detector still asks the
`conversation.project_proposal` Noul question, with the original source
message as evidence, Big ceiling, bands, reversible-read classification,
and 20-second budget. The decision question's identity includes its exact
wording, so an explicit override has its own question identity and bands.
It does not change source admission, proposal drafting, answer handling,
or whether the workflow pump starts.
