# Owed-call reconciliation evidence

The wake-start and ended-attempt reconciliation writer keeps the original owed
row beside each known terminal-step usage contribution. After the existing
reservation settlement or unreserved charge succeeds, an optional child writer
retains that source on its already admitted native-call row. The record and the
charge commit or abort with the same parent writer. Missing or mismatched source
rows warn and leave the ordinary charge and owed-row deletion unchanged.

The source identifies the original admission, step and selected terminal claim.
Its step usage can include schema-correction replies; it is not a measurement of
one physical call's invoice. The record also keeps the unchanged reconciliation
aggregate and, when a reservation was consumed, its prior cumulative owed units
and actual settled total. Prior owed units remain aggregate context, not an
attribution of those units to this original call. Equal successful observations
are not deduplicated by their amounts or timestamps.

Live-boot rows, already charged steps and unknown terminal usage keep their
existing paths. An unreserved zero aggregate records no charge observation. A
reservation with no known owed source does not invent an admission. Evidence
failure does not hold settlement, and evidence is not payment, NET/GROSS
coverage, an exclusion, guard restoration or authority for a later recovery.
The direct native-invoice payer remains unchanged and is not enabled here.
