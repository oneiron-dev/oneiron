# Dreamer Gate replay coordinates

A promotion write already names its `DreamerRunContext.attempt_id` as `job_id`
beside its run name. The Gate claim door keeps that attempt in its existing
Action/Runner context link. It accepts the field only after the ordinary
Dreamer actor, runner/surface marker and non-empty run checks, and only as a
strict 16-byte attempt id. A missing or malformed field stays absent; a run
name, receipt id or content hash is never substituted.

This link is metadata, not permission. Its origin remains `Unresolved`. It
does not establish that the attempt exists, has ended, owns the write or may
retry. Gate admission, refusal, source and consent checks are unchanged.

The normal Gate receipt projects the typed Action/Runner attempt slot into
its existing `job_ref`. Clearing a decision's context also clears that
coordinate. Other receipt fields, audience filtering and policy traces keep
their original behavior.

The served receipt-window consolidation detector recognizes Gate's native
`deny` outcome. It keeps the exact Gate receipt id as evidence and uses only
that same receipt's `job_ref` as the replay coordinate. A receipt without a
job remains a diagnostic with no run to retry. The public generic point
detector, other detectors and the existing signed receipt-window witness
path are unchanged.

This coordinate is retained only when the existing transaction path durably
keeps its Gate decision. The checker batch path preserves refusal rows; a
grouped writer that discards its decision on error still has no Gate receipt.
This change adds no separate persistence path for those existing cases.

The existing sweep still requires a stored Dreamer attempt in its ended,
failed state before it can file a proposed Retry. A coordinate alone never
passes that check or runs a repair. Retry policy and the failure ladder are
unchanged. No public record field, ABI version, format migration, default,
cap or configuration option is added. Matching engine/server deployment
requires no SDK, worker or guest-image change.
