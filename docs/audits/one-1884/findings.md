# ONE-1884 — verified findings ledger

**No new findings are verified by this packet.** The scope refresh is source/canon research, not an executed failure probe. The eight historic concerns in the issue remain *hypotheses*, not defects. A passed build or a source-only observation is not evidence of either a defect or complete safety.

Keep independently proven results here, never in the target list. For each new finding, record:

| Field | Required evidence |
| --- | --- |
| ID / packet probe | Stable `F-n` and source `A1`–`D2` (or `new path`) |
| Revision / feature graph | Exact commit, Cargo feature selection, host and target directory |
| Contract / reached caller | Canon line or explicit design choice; public entry, caller chain, data family |
| Reproduction / controls | Exact command and fixture, adversarial input, at least one nonfailing control |
| Observable actual vs expected | Returned value, typed error, persisted row or wire body; not logs/private counters |
| Disposition | Separate issue/PR link, owner, regression red-before/green-after and residual coverage |

Earlier September Wave 8 audits probed some neighboring surfaces. For example, [#984](https://github.com/oneiron-dev/oneiron/pull/984) merged remote/MCP fixes before this baseline. Those prior, revision-specific results are **not** counted as ONE-1884 findings, and pending audit-fix PRs must not be credited as repairs until merged. Do not copy a historical claim into this ledger without reproducing it against a named current revision.
