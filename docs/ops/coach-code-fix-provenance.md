# Coach code-fix candidate provenance

`Vault::code_fix_work(limit)` returns each failure's local code-fix work. Each
settled `CandidateRun` has a required `coach_own` boolean:

- `true`: the Coach drafted this candidate for this run.
- `false`: the host supplied it as a pinned publisher candidate, including a
  catch-up run for a candidate pinned after the failure settled.

The engine carries that origin beside the candidate object. A candidate id, even
one beginning with `coach.`, does not establish its origin. If a publisher uses the
same id as the Coach's draft, both candidates keep their own instruction and origin.
Publisher catch-up and retry matching do not mistake the Coach's result for a
publisher run.

This field changes neither export consent nor the replay's model judgment.
`FixOutcome::Fixed` still means the decision ladder judged the replay fixed. It is
not independent evidence of success. These records do not feed Coach reliability
learning without the separate native anchored-outcome join.

The record format requires the field. There is no old-format reader or backfill.
Deploy a matching engine/server when consuming the new result shape. No setting,
new timer, model prompt, or model worker change is required.
