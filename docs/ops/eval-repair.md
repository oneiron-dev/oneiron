# Repair eval case preparation

The native facade prepares and records explicitly mapped tasks from a linked
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

## Discover source-declared tasks

The owner-selected AG-UI import includes a required `repair_tasks` list. Each
entry names `outcome_ordinal`, a `task_pointer` into the linked failure event,
and an explicit native `seat`. An empty list declares no tasks. The declarations
are stored in the same capture and covered by its native source fingerprint.
They are data, not app-role identity, an outcome label, or training permission.
Capture does not add task validation gates; the existing compiler validates a
declared task when it is prepared. Manual pinned preparation remains available
without a declaration.

`vault.evals.repair.nominate` accepts an optional native claim-list
`subject_ref` and a required capture `limit`. A null subject searches all
ordinary admitted claims, not only one project. It uses the original Memory
handle's Recorded claim reader with the AG-UI predicate, then authenticates each
capture through the same scoped projection and binding checks as a pinned read.
The metadata read computes the native fingerprint; it does not trust a hash
recreated from a claim-list projection. Each declaration is then compiled by the
existing exact pinned Repair reader under that same handle.

The result contains the discovery receipt and one entry per selected capture.
Each entry contains a metadata result and task preparation results in declaration
order. Successful metadata contains only native pins, source time and declarations.
Missing or withheld metadata returns a null source and no task results. Each task
returns a recipe or null, with its own actual read receipt. A metadata or task
error remains an error in that entry; it does not suppress unrelated declarations
or captures. No source text, task input, expected response, case ledger or label
is returned. A discovery failure remains the call's outer error.

The capture limit retains native claim-list ordering and truncation. This is not
an exhaustive inventory or a shared snapshot across all reads. Discovery writes
no case or family, chooses no family purpose, runs no task, and grants no rights.
The owner may use the prepared recipes with the existing record/setup calls.
Receipt-based automatic authoring plans are unchanged.

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

## Native source-bound Coach jobs

The native `Memory::request_eval_repair_authoring` captures the original source
reader privately in the existing Coach job payload. It takes the same nomination
filter and an authenticated owner for the request write. Each explicit request
keeps its own job and context; it does not replace or coalesce with another
requester or the existing nightly authoring sweep.

`Vault::coach_eval_repair_authoring_source` reads the canonical `coach.host` job,
its validated Coach stamp, and its current lease owner and generation before
restoring that reader. A Coach facet string or a caller-supplied decoded payload
is not sufficient. The returned opaque source exposes metadata-only nominations,
not the stored reader or task bodies. Its `record_case` accepts only an exact
successful nomination, then rechecks the same canonical payload, stamp and lease
inside the case writer. It shares the existing source projection, full task
rebuild, family-before-case admission, and exact case reuse machinery. It does
not fabricate owner proof for a background job.

The source's native `inventory_sourced` adds successfully nominated seats to
the ordinary metadata inventory, including seats with no receipt history yet.
It retains the ordinary inventory digest and the discovered source rows; the
reads do not promise a shared batch snapshot. `apply_plan_listing` accepts an
`EvalRepairAuthoringPlan` with the ordinary `authoring` plan and explicit
`repairs`. It validates the whole ordinary plan and every selected recipe before
writing, applies the existing receipt-family/case decisions, records Repair
cases, then performs scoped cut audits and cuts, and finally retirements. Cuts
and retirements name the actual attempt and loaded Skill revision, never an
invented owner. Repair results retain their own case refs and scoped receipts;
the ordinary case counters still count only receipt-derived decisions. Actual
Repair/audit rows remain listed when a later stage fails. Stages keep their
existing separate transactions, not a whole-plan rollback.

This is a native source/write interface, not a published automatic-authoring
endpoint. The server's loaded-skill input/output and attempt read-set integration
still need a consumer for this explicit job. Existing manual owner calls and
receipt-based nightly authoring are unchanged. No new source ledger, training
permission, label, or read grant is created.
