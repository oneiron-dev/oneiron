---
name: skill-optimize
description: Improve a standard skill from observed failures and held-out evidence.
---

# Skill optimizer

## Input
Read the target skill, its governance tier, attributed outcomes, and a held-out
case set. Keep the input revision and evidence references in the proposal.

## Procedure
1. Exclude identity and alignment skills. An unknown tier needs owner resolution.
2. Identify a repeated observable failure. Do not optimize for a judge's wording.
3. Draft the smallest change that addresses that failure. Preserve the declared
   capability envelope. Fork imported content rather than overwriting it.
4. Run the candidate and the current revision on the same held-out cases.
5. Ask the judge for a structured comparison with evidence for each score.
6. Submit the candidate through skill admission. Never activate your own draft
   by changing its lifecycle field. Keep the old revision until admission passes.

## Output
Return a candidate revision, parent reference, evidence references, test results,
and any unresolved trade-off. If evidence does not show improvement, keep canon.
