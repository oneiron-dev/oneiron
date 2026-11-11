# Route-fitness question labels

Route grading gives each candidate a canonical, versioned fitness question. Its provider
state names those questions with call-local `Q1`, `Q2`, and subsequent labels, not entity
IDs. One immutable table covers the whole grading pack and its person and paired questions.
The canonical questions, rule lookups, returned answers and receipts do not change.

`DecisionLadder::run_pack_labeled` requires the caller's table. The shared runner carries
it through first-read chunks, auxiliary questions, tournaments and later rungs. Generated
reads use the same table for request keys, reply lookup and request-identity binding.
Native reads prefix the original question and paired text with their table names. Their
rubrics, answer contracts, score scales, token labels and result positions stay unchanged.
The Big and Local-vision request builders also bind the table into their existing
`LlmRequest` identity. The remote System One rung retains its fixed single-answer wire
key and prefixes its original question instructions.

The route-fitness binding uses wire version 1 and a digest of the ordered canonical
question IDs and versions in host-only provider options. The digest is not model prompt
text. It keeps requests with different label bindings distinct without exposing IDs.
The table lasts only for its call; a label is neither a durable ID nor read authority.

Existing callers without a table retain their ordinary path. Native reads still use the
same admission, deadline, release and settlement behavior. This change adds no model,
configuration setting, numeric operating default, dependency or deployment requirement.
