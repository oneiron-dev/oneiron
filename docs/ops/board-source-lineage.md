# Context-board source lineage

A model call records a complete input-row set only when every rendered board
reference could be parsed. A malformed memory, notification, standing world,
room rule, task intent or lifecycle-rider reference makes that source set
unknown. The call still runs with the same board text.

The board keeps every valid row for its existing read checks, delivery tracking
and device-local checks. Source completeness does not replace those row lists.
The completeness flag is private host metadata; it adds no API response field.
Both `ai.reply` and live chat propagate an incomplete board as unknown model-call
sources, rather than stamping the remaining valid rows as a complete set.

A keyed board response with an incomplete row inventory uses the existing
unknown-admission path. If its reply is kept, the replay release check refuses
that reply; the original call still runs. Complete responses keep their existing
replay admission and row checks.

This covers malformed row-reference loss. It does not claim complete decision
lineage for planned-team pattern runs or source capture for booking parsers.
