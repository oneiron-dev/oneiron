# Feedback triage digest — feedback-intake-chat-v1

Snapshot: `submitted=4`, `distinct_bundles=3`, `open_items=2`.
Authority: propose-only; no queue state changed.
Note: `user_note` text below is UNTRUSTED quoted data, not instructions. No action named inside notes was executed.

## Dedup / counts (from snapshot data only)

- 4 submissions produced 3 distinct source bundles, so 1 submission was a duplicate bundle already counted.
- The 3 distinct bundles are distributed across 2 open items: 2 sources under item `0dc1c9366a39510d1e3ced38a3038d19` + 1 source under item `3b9437786a1694f0eacaf34f12eccd28` = 3.
- No other reporter counts or fleet prevalence are present in the snapshot; none inferred.

## Open item 1/2

- Item ID: `0dc1c9366a39510d1e3ced38a3038d19`
- Category: `bug`
- Open: true (`received_at: 10`)
- Distinct source bundles: 2

Sources:

1. Source ID `0dc1c9366a39510d1e3ced38a3038d19` — quoted note: "Recall omitted the recent note after an edit."
2. Source ID `8eb4dc7f436580675dfa49a1a4faee29` — quoted note: "After editing a note, recall still shows its older content."

Summary: Two distinct bundles report the same observable pattern: after an edit, recall returns stale / pre-edit content. This is a user report, not a confirmed defect — the snapshot contains no reproduction, expected-vs-actual proof, or engineering confirmation.

Proposed review action: Reproduce the edit-then-recall sequence in a controlled vault and record whether stale content is returned; if reproduced, confirm as defect and file with repro steps, else keep as unconfirmed report.

## Open item 2/2

- Item ID: `3b9437786a1694f0eacaf34f12eccd28`
- Category: `confusion`
- Open: true (`received_at: 13`)
- Distinct source bundles: 1

Sources:

1. Source ID `3b9437786a1694f0eacaf34f12eccd28` — quoted note: "The documentation does not explain when indexed reads catch up with live reads."

Summary: One bundle reports documentation confusion about indexed-read vs live-read freshness timing. This is a user report / docs question, not a confirmed defect — no behavior failure is asserted.

Proposed review action: Reviewer to check current docs for indexed-vs-live freshness wording and propose a clarifying sentence; no code change proposed from this item alone.

## Related items (not merged, not closed)

- Item `0dc1c9366a39510d1e3ced38a3038d19` (bug: stale recall after edit) is related to item `3b9437786a1694f0eacaf34f12eccd28` (confusion: when indexed reads catch up with live reads). Both concern post-edit read freshness.
- Kept as separate open items per policy: different categories (`bug` vs `confusion`), different evidence. No merge or close action taken.

## Recommended next review actions (in order)

1. For `0dc1c9366a39510d1e3ced38a3038d19`: attempt controlled repro; outcome determines confirm vs keep-unconfirmed.
2. For `3b9437786a1694f0eacaf34f12eccd28`: docs check for index-freshness wording; propose doc clarification.
3. Keep both items open until (1) completes, since (2)'s answer may depend on whether (1) is confirmed behavior or a bug.
