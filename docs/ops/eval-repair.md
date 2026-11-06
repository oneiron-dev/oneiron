# Explicit Repair eval cases

The native facade exposes two calls for an explicitly mapped task in a linked
AG-UI capture. They use the caller's existing source-reading rights. A source
hash or task hash is a reconstruction pin, not a read grant.

## Prepare a recipe

Call `vault.evals.repair.prepare` with `EvalRepairTaskSource`: `claim_ref`,
`source_hash`, `outcome_ordinal`, `task_pointer`, and `seat`. The pointer names the
explicit task contract in the linked failure event. The source contract supplies
the response domain and the existing linked outcome supplies the grader.

The result contains only `recipe` and the actual scoped-read `receipt`. A missing
or withheld source returns `recipe: null`. An invalid task returns its typed
error, retaining the receipt of the admitted source read. This call neither
records a case nor returns task input, the expected response, or sealed members.
Preparation does not require an owner write proof.

## Record or reuse a case

The owner calls `vault.evals.repair.record` with the prepared `recipe` and an
existing family `purpose`. The writer uses the authenticated caller's original
Memory handle, not an owner-broadened source reader. It rechecks the current source
and full task digest, assigns the family before deriving the case, and reuses an
exact matching case in the same transaction.

The result contains only `case_ref` and the actual scoped-read `receipt`.
A missing or withheld source returns `case_ref: null` without authoring a family,
case, or label. A changed source or task is not silently accepted. Neither call
returns the source text, expected response, or the full case ledger.

These calls provide an explicit preparation and recording path. They do not add
automatic capture discovery, change the receipt-based authoring inventory or its
plan format, or authorize training. Existing family purposes, sealed-cohort
exposure, source erasure, and measurement release checks still apply.

## Record explicit recipes before cohort cuts

`vault.evals.repair.cohorts.setup` accepts `setup`, the existing pinned
`EvalCohortSetup`, and `repairs`, an explicit list of `EvalRepairCaseRequest`.
It first validates the inventory and applies its ordinary family/case decisions,
then records or reuses each exact Repair recipe under the same original reader,
then runs the existing scoped cut audits and cohort cuts. It does not retire
cohorts or discover captures automatically.

The result contains `authoring`, the ordinary setup report, and `repairs`, the
actual Repair case refs and receipts. The ordinary `cases_recorded` and
`cases_reused` counters count its receipt-based decisions, not Repair results;
the existing Repair writer does not distinguish a new case from a reused case
in this response. A null Repair case ref still means missing or withheld.

Each stage keeps its existing transaction. An error can follow earlier committed
stages; this call does not promise rollback of the whole setup. Existing setup
calls and the receipt-based automatic authoring plan are unchanged. The new
facade setup uses the existing owner-host admission policy; this is not a claim
of room-turn support for owner-host doors.
