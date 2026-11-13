# External provider answers for standing graph questions

A caller can prepare one explicit standing-question unit, ask an external provider,
and admit that provider's typed decision without scheduling a host ladder call.
The existing question pump, `vault.questions.backfill` and one-off `vault.graph.admit`
keep their behavior.

## Prepare before provider work

Call `vault.questions.prepare` through the host facade:

`POST /v1/core/facade/vault.questions.prepare`

The request is `QuestionPrepareRequest`: the saved question `id`, its
`expected_version`, and `input` containing one `unit` and its ordered `evidence` ids.
The question must belong to the authenticated asker and cover that unit.

The result is `QuestionPrepared`. It contains the selected typed question and dial,
the authenticated principal, the unit, the authorized logical source bodies and
their hashes, and `source_frontier`. Sources are ordered unit first, then the
requested evidence. It does not expose other question units or the saved read lane.
These are graph logical bodies, not a separate image or audio download API.
The owner gets each body as stored. Every other asker gets it as the typed Nulled
rule releases it, and empty when that rule withholds it. Each `hash` is still the
stored body's, and that hash is what admission compares.

Provider work must use this preparation. Keep its question version, source order,
hashes and frontier with the measurement. A frontier is data, not a grant. The
preparation reads under the actual credential as well as the question's frozen
principal lane and the writing holder's existing checks.

## Admit the measured decision

Call `vault.questions.admit`:

`POST /v1/core/facade/vault.questions.admit`

The request is `QuestionAdmitRequest`: the same `id`, `expected_version`, `input`
and prior `source_frontier`, plus the provider's full `TypedDecision`.

- The receipt names the prepared question/version and authenticated principal.
- `decision.evidence` equals `input.evidence` in order. The standing unit is
  recorded separately, as it is on existing standing answers.
- `decision.receipt.evidence_versions` contains every prepared source, **unit
  first**, with its exact returned body hash.
- Keep the real provider pins, probability, paired/person readings, band, clock
  and other receipt fields. Admission runs the native typed-decision and standing
  provider validation; it does not invent a provider measurement.

The same writer that lands the proposed answer rechecks the current question
version, source eligibility, frozen principal/holder checks, actual caller lane,
source frontier and all submitted body hashes. A changed or newly inaccessible
source cannot be rebound to current bytes after measurement. Prepare again and
repeat provider work if the measurement is no longer current.

A successful admission returns the native `AnswerRecord`. Its full submitted
`TypedDecision` is retained. Repeating work at an already answered question version,
unit and frontier returns the existing native answer rather than minting a second
claim. The answer remains proposed; this door does not Keep it automatically.

The verb registry generates the HTTP, MCP, code-mode and SDK projections from these
same request and response types. Use the generated SDK rather than a separate wire
shape. Matching engine and server binaries are needed when deploying these verbs;
there is no data migration or new configuration setting.
