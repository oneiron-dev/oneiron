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
source declarations. The original Coach request/key bridge and native scoped admission must still
compose before that capture is activated. A missing witness does not filter ordinary candidates,
change an optimizer outcome or turn a working read into a refusal.

## Producer-requested placement

The native `score_gate_skill_edit_in_cycle_positioned` entry takes an explicit
`SkillVerdictReadPosition` on the original scoring request. It runs the same gate
and writes that position only when the request creates a new ruling. A standing
ruling returned by replay is never restamped. The position carries its full Scope,
registered kind band, explicit relationship/private axes, body worlds/facets and
read anchors. The attempt, scorer, payer and supporting SKILL infer none of them.
Existing unpositioned entries record no position and keep their original encoding.

A new admission-refusal, tradeoff-resolution or deferred-approval row does not
inherit a different request's placement merely because it continues that verdict.
It is born unknown. An absent optional position means unknown; a supplied but
malformed position is a corrupt row, not a broader or default placement.

## Original Coach read request

The admitted optimizer job creates its own `Memory(Coach, System)` request after
its actual facet/Coach/stamp checks and before ranking. It retains the verified
owned read key from that original request. It does not reconstruct an absent
external caller, replace an existing credential or infer model-delivery authority.

The brief and healthy-skill path carry that key to their actual native VERDICTS
scan. Capture prepares the grant clock before the custody guard and source
snapshot. Every canonical ruling and its actual displacement row or absence must
pass that key's native admission in that snapshot. Optional opener, custody,
admission and receipt failures leave only this capture unknown. Original primary
scan and native decode failures still propagate; ordinary candidates, values and
author errors are not filtered, masked or swallowed.

The brief's native-family witness is partial data, not the complete attempt read
set or a grant to a later reader. The actual Coach job keeps the old id-only
complete-source field unknown. Activation still needs all other native families
and a typed downstream heal/source consumer, not ENTITY checks on ledger ids.
