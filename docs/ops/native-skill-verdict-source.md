# Native skill-edit verdict sources

A skill-edit verdict id names a VERDICTS ledger row, not an ENTITY row.
The decoder also reads the verdict's separate displacement marker. An absent
marker is a real source result; it is not permission to ignore a later retirement.

`canonical_skill_edit_verdict_in_txn` returns the full physical primary key,
the exact stored primary bytes, the full displacement key, its stored bytes or
absence, and the value decoded from those same rows in the caller's snapshot.
It does not reserialize the ruling or infer its Scope from the proposal or SKILL.
The revision-displacement table is not read by this decoder and is not invented
as a dependency of this operation.

`verdict_rows_sourced_observed_in_txn` optionally reports those same canonical
rows at the original scan's decode positions. It retains the eager primary scan
before per-row marker reads. `ScanComplete` follows only a successful scan and
all successful native decodes. The old no-observer route uses its original
primary scan, decoder and marker getter. The legacy id-only result still answers
unknown when any decoded ruling has a displacement marker.

These witnesses are data, not grants, custody certificates or complete attempt
read sets. They are not fed into ENTITY admission, the heal source union or model
source declarations. The original Coach request/key bridge, genuine producer-owned
VERDICTS read position and native scoped admission must still compose before that
capture is activated. A missing witness does not filter ordinary candidates,
change an optimizer outcome or turn a working read into a refusal.
