# Executor reply evidence

A step keeps the provider's complete message as untrusted reply evidence at
`executor/repl/<sequence>.reply.json`. It is separate from the post-hook text
that the executor heals and runs. Post-turn hooks run before evidence capture.

Capture uses the run's existing custody and PERSON snapshot. When that snapshot
has no PERSON prints, the message is serialized straight into the ordinary
custody-sweeping body sink. It does not first encode a second whole-message byte
buffer to search for PERSON spans.

When PERSON prints exist, capture keeps the full original JSON encoding so typed
Text spans can be mapped back to those bytes. Custody matches are selected over
the complete original encoding and win overlaps with PERSON matches. Non-Text
parts keep their existing custody-only treatment. A run with prints but no
surviving PERSON match still takes the ordinary custody-sweeping sink.

Publication keeps the same output path, run owner, source rows and routed
canonical or off-record storage. Neither transport selection nor model-call
admission, retries, usage settlement or the reply schema changes.

This is a body-evidence slice of FIX 448. Provider stream adapters still assemble
the complete terminal message. Replies with PERSON prints still need the full
encoded buffer for span selection. No raw transport capture or bounded-memory
completion of the whole row is claimed. There is no new configuration or limit.
