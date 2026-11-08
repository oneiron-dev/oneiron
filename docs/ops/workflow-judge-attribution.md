# Saved-workflow Done judge attribution

A saved workflow closes its wrapper before it reports Done on its TASK. The
wrapper's terminal PACK receipt remains immutable. Its live lease and live
attribution row are not reopened to record the later judge.

The report records `done_judge_model` beside the existing, complete
`done_decision_receipt`, from the model whose actual answer the Done report uses.
A rule, person, abstention, refused call, or AskUp answer records no model.
The report journal commits these fields with the TASK move.

A new anchored pack-outcome projection can fill an unknown judge from that
journal. The join uses the attempt and generation frozen in the PACK receipt,
its exact TASK, and the native workflow-completed report key. It does not use
the current queue generation or the TASK's newest receipt. An already recorded
judge remains unchanged. A missing or unreadable join leaves the frozen judge
unchanged and does not prevent the projection.

The joined judge is learning provenance, not a reliability-cell key. This path
does not turn the Done model's answer into an external correctness anchor.
A replay of an existing anchored outcome, or its late-credit reconciliation,
also fills the judge on its existing learning rows when still unknown. It
keeps the evidence key, anchored observation, weight, timestamp, amendments,
and all other provenance. Known judges and missing rows remain untouched.
The PACK, credit and credit-adjustment receipts stay immutable. The ordinary
learning fold updates derived heads, including its existing judge conversion
and decay rules; the original anchored outcome is never rescored. A failed
refresh rolls back only that capture and does not reject the original credit.
A typed Done with no model answer keeps its judge unknown. No deploy, policy,
configuration, or SDK change is required.
