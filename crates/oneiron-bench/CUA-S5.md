# CUA S5: frozen drift and repair protocol

This is harness source, not a collected benchmark. The frozen matrix,
provenance checks, terminal rows, lifecycle handling and repair state machine
are implemented. FIX 8061's engine forward now exists, and PR1 writes it with
an empty egress allowlist. S5 checks the same frozen PUBLIC bind and validates
reset entries through the shared virtual-origin helper. Its live adapter still
needs the original admitted workflows' vault and attached-run continuity;
`s5_original_workflow_vault_unavailable` names that separate gap. It never
refiles an original under a replacement ID in a new scratch vault or substitutes
a fresh solve for strict replay.

## Commands (Linux build/run hosts only)

```sh
oneiron-bench cua drift --plan /srv/cua/frozen/s5.json --programs /srv/cua/submissions.json --out /srv/cua/drift
oneiron-bench cua report --in /srv/cua/drift/rows.jsonl --out /srv/cua/drift-report
```

Neither command compiles anything. `drift` refuses non-Linux execution. CLI
filters are deliberately absent: the frozen plan declares the entire selection.
Changing selection, argument bytes, evidence pins or submissions requires another
output directory, not a resume that silently changes its campaign.

## Plan: schema 1, phase S5

All fields are explicit; unknown fields are refused. File digests are BLAKE3.
An `Evidence` is `{ "path": "/srv/cua/evidence.json", "digest": "<digest>" }`.
Evidence documents are JSON. Runtime secrets stay in private deployment files.

| Field | Meaning |
|---|---|
| `schema`, `phase` | `1`, `"S5"`. |
| `base_plan` | Evidence reference to the frozen PR1 plan, not a regenerated task set. Reuses checker/fixture pins, task packets and caps. |
| `runtime_pins` | Evidence reference to PR1's deployment pin manifest. |
| `server` | Absolute prebuilt `oneiron` binary path. |
| `conditions` | Nonempty unique subset of `[3,4,5]`. Selecting 5 requires 4. |
| `authors` | Nonempty unique subset of `A1`, `A2`, `A3`, `A4`. |
| `fixtures` | Nonempty unique subset of `F1` through `F5`. |
| `drift_order` | Exactly `["v1","v5","v2","v3","v4"]`, explicitly published. |
| `recovery_arm` | Exactly `"C"`; no implicit D-funded expansion. |
| `recovery_task`, `recovery_task_digest` | Pinned deployment-supplied public recovery instructions. No oracle values or send permission. Required even when recovery is not selected. |
| `evaluations` | Map keyed by `F1-A1`, etc. Every admitted selected program needs one evaluation. Unselected evaluations are rejected. Missing/refused submissions need none. |

Each evaluation has:

- `entry_param`: the already-declared parameter used by the frozen first Open.
  That Open must name `http://127.0.0.1:8080/` with a parameterized path.
  A slot-bearing host or a hand-edited `/v0/` URL is not accepted.
- `replays`: exactly three `{seed,args}` evaluation records. Seeds are distinct
  from each other and from that source's solved and admission/qualification seeds.
- `versions`: `v0` through `v5`, each `{seed,args}`. All six have identical
  seeds/data arguments; only the reset namespace changes at execution.
- `confirmations`: `v2`, `v3`, `v4`, each with `drift` and `regression`
  `{seed,args}` records. The pair has the same seed/data and is disjoint from
  original solved/qualification, baseline drift and C3 evaluation seeds.

Every argument map exactly names the source program's parameters. Its entry
parameter is the literal `"{entry}"`. `strict_spec` replaces that value with the
relative entry from PRIVATE `/reset`, without changing stored program bytes.
The first Open's authority remains fixed. v4 uses the new reset namespace, never
an oracle-supplied relocated target route. Argument seeds and bytes are frozen;
there is no argument generator or hidden resampling during drift.

Caps remain PR1/S1's F1 420s/120, F2 60s/20, F3 300s/60, F4 120s/20,
F5 600s/60. F5 retains S1's inherited research-cap assumption. No retries,
extra action cap, independent admission reset or best-of-N repair is introduced.

## Submission references: no second program store

The `--programs` JSON object has `schema:1` and a `submissions` array. Each entry:

| Field | Meaning |
|---|---|
| `fixture`, `author` | One source per fixture/author. A4 remains the hand-written ceiling, not learned yield. |
| `outcome` | `admitted` or `refused`; absence of a selected entry produces missing-source rows. |
| `workflow` | Exact original public 32-lowercase-hex engine ID, or null for refusal. No successor resolution for baseline cells. |
| `program_hash` | BLAKE3 of RFC 8785 canonical `{subgoal,params,steps,postcondition}`, or null for refusal. |
| `proposal` | Evidence reference to the original typed engine proposal, or null. |
| `admission` | Evidence reference to public `library.propose` output. |
| `qualification` | Evidence reference to the independent checker result. |
| `author_traces` | Nonempty list of evidence references, including an explicitly labelled A4 control trace when applicable. No Coach/recorder substitute. |
| `solved_seed`, `qualification_seed` | Original fixture RNG seeds, not hub provenance. |
| `lineage` | Evidence references to original public lineage/lifecycle answers. |

The engine's closed proposal DTO validates the source. The manifest's admitted
ID must match its public admission. Qualification must have a full checker pass
with safety and complete counts. F2 may retain a state-only diagnostic source
while E6 is unavailable; this never turns into a provenance/full-rubric pass.
Admission must have held-out argument maps and a fresh replay guest receipt.
The archive stores canonical hashes, source/evidence references, arguments and
IDs, not copied program bytes, a stored JS body, direct vault copies or LMDB edits.

## Scheduling and lifecycle

All C3 cells finish before C4. All original C4 cells finish before C5 can propose.
Within each source C4 runs v1, v5, v2, v3, v4. C3 has three v0 strict assignments.
C4 has five strict assignments. Selected missing/refused sources retain all
nominal assignments; no author is substituted. With all authors/families selected,
this is 60 C3 and 100 C4 assignments, **not a claim that 160 executions ran**.

The engine owns `LibraryRunMode::Strict`, rule abstention, public retirement and
supersession. The scheduler never implements those semantics. A driver returns
raw engine run/checker/reset/lifecycle evidence. `drift` checks the exact workflow,
strict mode and reset identity before recording execution. `model_free` is read
from that receipt, never derived from strict mode. E4 is present; an explicit
library call alone does not prove whole-TASK model freedom.

A public `library.retired` answer with `drift` or `superseded:<id>` records a
lifecycle event. The scheduler remembers observed retirement solely to avoid
starting the exact retired ID again: remaining assigned cells become
`program_retired_before_case`. It never counts three generic failures, retires a
record itself, refiles/resurrects it or resolves it to a successor.

## C5 protocol

Only checked v2-v4 failures of selected A1/A4 programs are eligible. A config or
transport block is not an observed failure. Nominal chains remain visible as
`drift_failure_unobserved` if their baseline is unavailable. Each nominal chain
has one chain record and two assigned confirmation records. At full selection
there are 30 chain records and 60 confirmation records, separate from baseline
execution denominators. They are not 90 extra model runs.

The state machine makes one fresh assisted recovery/replan from the saved failure
(the original matrix already ended), then gates proposal on the independent
checker passing with no wrong effects. It accepts changed bytes only, preserves
parameter intent, requires exact `supersedes` and makes one `library.propose` call.
Only engine admission requalifies. `retired`, `linked` and `dropped` are the actual
E1 snake_case enum values; dropped/same-byte refiles are not repair success.
No fixture reset occurs inside atomic admission. Two independent fresh strict
executions confirm the admitted successor on the drift version and on v0.
Persistent repair requires both checker passes, model-free execution receipts
and clean safety. A repair never erases a baseline safety violation.

The `Engine` boundary describes these operations but has no live implementation
on this head. In particular, authenticated fresh attached-run acquisition,
recovery/checker/proposal checkpoint continuity and independent fresh guest
confirmation must be bound through the real served transport before live use.
There is no alternate direct CDP client, harness planner, restored vault or
fabricated `admitted:true` fallback behind the unavailable adapter.

## Rows, reports and known gaps

PR1 supplies the durable JSONL writer/lock, checker/fixture identity, pin validator
and measurement vocabulary. S5 adds condition/author/stage, frozen arguments,
original/successor IDs/hashes, raw engine evidence, expected direction and lineage.
All terminal rows survive resume, including failures, timeouts and unavailable
cells. An operation that started without a terminal row becomes interrupted;
it is not retried. Stale locks require operator proof of owned cleanup.

`drift-report.json` separates assigned/terminal operations, strict passes, safe
stops, safety violations, timeouts, statuses, observed medians and repair
confirmations. No success-only all-assigned median, p95 or direction score is
invented. `cua report` understands S5 archives and preserves missing assignments.

Remaining engine/integration facts:

- FIX 8061: freeze `fixture_public_bind` with `taskgen --fixture-forward` and
  match it in `browser.bench_fixture_forward`. Served vaults write the forward
  and set `ONEIRON_EGRESS_CONFIG` to a private file holding
  `{"allowed_domains": []}`. Reset entries use `http://127.0.0.1:8080` only;
  S5's parameterized first Open keeps that authority. No boolean bypass exists.
- E3 remains `unavailable_e3`; E6 remains `unavailable_e6`.
- E1, E2, E4 and E5 are present. B/C/C+/D now require `browser_planner` bindings;
  generative/chat recovery stays a separate engine role. Binding does not prove
  which role actually finished a run; receipt coverage remains separate.
- L06 FIX 7895: owned, attested routes accept the house returned identity
  `oneiron-llama/<epoch>/<manifest digest>`. The gate records both fields and maps
  that alias to the route's existing exact engine pin without rewriting the reply.
  Unrelated subscription/cash sibling names still fail the exact-ID check. This
  trusts the already-pinned deployment endpoint/weight/tokenizer attestation; it
  is not a claim that the manifest digest is the weight digest.
- Full F1 model-free harvest/output is still unavailable without an appropriate
  frozen public result-producing caller. A navigation-only library batch cannot
  produce the three required tables/files. No expected artifact is seeded.
- No complete whole-TASK model-edge ledger, GPU kernel timing, actual billing,
  learned-author yield resource accounting or N=1/5/20 amortisation is fabricated.
