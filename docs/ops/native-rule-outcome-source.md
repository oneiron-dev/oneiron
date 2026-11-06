# Native rule-outcome source capture

The original rule-outcome writer accepts an explicit optional
`RuleOutcomeReadPosition`. This is producer placement, not a read grant. The
ordinary health-review bridge passes `None`.

A proved new row receives its own store-clock identity when that optional mint
succeeds. Only that birth can adopt the original request's position. A replay
with the same source, win and timestamp keeps the held identity and position,
including `None`. Changed contents keep the identity but clear the position.
An unreadable held row or a failed optional identity mint leaves placement
unknown and does not add a failure before the original put. A later request
never restamps an existing row.

The new Raw map requires explicit `row_id` and `read_position` values, each
`nil` or its typed value. A missing field is a codec error. There is no
old-format reader or migration.

The ordinary scanner and canonical source scanner share one classifier. They
read the key first, then the rule row, then the plain-outcome fallback. Invalid
keys and invalid values retain their original WARN behavior. A plain outcome
is still skipped silently. Storage errors still propagate to the brief, whose
outer handler warns and cites nothing.

The typed witness records **every consulted raw row**, not only successful
rule rows: the full physical key, BLAKE3 of stored bytes and classification,
in the original iterator order, under the full table-and-skill prefix. This
includes ordinary outcomes and damaged rows. Heal re-reads that complete
prefix and compares every witness in order before re-admission.

The original Coach request persists its full-key grant clock before body pins,
the custody guard and the source read transaction. Capture runs before the
health-review-prefix and DEV filters. Each dependency must have its own native
identity and producer position, pass the existing full live-reader predicate
in that same transaction, and pass the existing body-disclosure check. A
non-rule or unreadable dependency has no such position and leaves the optional
family capture unknown. It does not refuse or change the ordinary read.

Point and scan witnesses use the existing `NativeReadSource` and
`AttemptSources` graph. They do not confer ENTITY access through a skill,
actor, receipt or hash. A native source does not become an entity-only source
projection.

This family is a partial source declaration. The complete Coach model-source
remains `None` and FACT attempt activation remains off until the other actual
families and terminal publisher compose. Ordinary/paired/amended/displaced
outcomes, substitution, preference and package reads are not certified by this
family.
