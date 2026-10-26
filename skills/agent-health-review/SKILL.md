---
name: agent-health-review
description: Judge agent health from receipts with closed-form detectors and seeded dials.
---

# Agent-health review

## Input
Take one review window of call receipts, step replay capsules, attempt rows,
run coordination and sealed attempt receipts. Read no diary. Read every dial
for the project and task type of the attempt it judges.

## Detectors
- loop: identical calls in a row in one stream, with no other call and no new
  input between them, at `health.loop.repeats` or more.
- failed_check_repeat: the same tool run failing the same way
  `health.check.fails` times.
- long_wait: more than `health.wait.share` of an attempt's life spent waiting,
  not on a person, over at least `health.wait.minutes`.
- silent: a leased attempt with no activity of its own for
  `health.silent.minutes`, no open wait and no word that it is stuck.
- misalignment: an audit found a flaw in an objective the agent's confession
  called met; or `health.widen.denials` widen proposals the board has not
  approved.
- cost_spike: an attempt's own spend over `health.cost.spike` times its task
  type's p90, from at least `health.cost.min_runs` settled runs; with fewer,
  against the plan's expected spend, at low confidence.
- duplicate_work: an action another attempt ran first on the same inputs,
  unplanned, costing at least `health.dup.min_cost`.
- unsupported_done: a Done TASK whose done-means names evidence that does not
  resolve.

## Evidence rule
Each finding is one DIAGNOSTIC that cites every receipt and attempt it counted.
A finding merges into one card per agent, signal and task. A card holds refs
and numbers: the measured number and the dial it was held against. A finding
whose tone is below `health.card.floor` writes its DIAGNOSTIC and no card. A
settled card reopens only when its evidence grows past its watermark.
Counter-evidence lowers confidence; it never hides the card.

## Policy
`policy.json` carries this revision's seed for each detector dial. An owner's
seed or pin and a learned fit outrank it; a missing or invalid value falls back
to the engine's compiled seed for that dial alone.

## Output
Cards and proposed moves. The review never stops an agent, narrows a grant or
takes a move. An owner's confirmed or dismissed on a card scores this revision.
