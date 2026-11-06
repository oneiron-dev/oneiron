# Native scoped judge-label reads

`ScopedRead::judge_label(ask_id)` reads the inline
`SKILL_OPTIMIZE_JUDGE_LABEL` row at its canonical ask key. It returns the
unchanged label and a scoped-read receipt, or `None` without a missing-versus-denied
existence count. It does not turn the label into an entity.

The original authenticated pick request can supply `JudgeLabelReadPosition`.
That position contains the label's Scope, a registered native read band,
explicit relationship and private axes, body worlds and facets, and complete
thread, room and occurred-time anchors. Placement is data, not a reader grant.
A missing position is unknown. Rubric mutations clear the old position rather
than leaving stale placement as proof.

The reader rechecks its proof, current grants, records and channel limits,
read floor, guest limits, legal use setting, relationship authority, world and
facet ceilings, room clearance and roster, private threads, own-entry windows,
every peer read, and each destination in the source snapshot. A retained
canonical value must still match the physical key and full stored bytes.

The custody guard is acquired before the source snapshot and after grant-clock
persistence. The known-value matcher reads that same snapshot; it opens no
second transaction or custody lock. The read never treats absent custody or an
unclassed side-table declaration as a secret scan. It applies the existing
release and known-value checks to the full stored value. A value requiring
secret masking is not returned through this exact-value read. Storage and
custody failures propagate.

The immutable question and the exact A/B choice are never rewritten, masked or
normalized into stand-ins. The ordinary pick, replay and raw native APIs are
unchanged. A successful native read does not itself create a Coach attempt,
source witness or permission for a later read. A Coach consumer must retain its
actual original read context and recheck each source before use.
