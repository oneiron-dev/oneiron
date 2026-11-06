# Native host allocation state

`llm::run_admission::VaultAllocationLedger` is the vault-bound persistent
allocation backend. It is not installed by the current `HostAccount` constructors.
Those constructors and their run admission path still use their existing
in-memory allocation meters. `RunAdmission::with_persistent_allocation` explicitly
selects the native ledger with a required `AllocationProducer`. It uses no
reflected allocation meter for admission. The server's explicit
`with_native_usage_metering` binding selects this constructor for its
`undeclared_run` factory. When selected before `AiHost::attach`, the same
backend and observer are passed into the original model runtime before it is
shared or starts work. Startup without an explicit native selection remains
unchanged. This backend implements no Cloud wallet or host pricing policy;
conversion uses only explicitly supplied rates.

## Original host delivery

A managed supervisor can select native custody with `--allocation-fd <fd>`.
The inherited descriptor carries one
`oneiron_vault_contract::allocation::AllocationDelivery` JSON object, then EOF.
Descriptor numbers are checked for aliases before any is consumed. The object
is read before storage opens, and native usage is bound before AI attachment,
sharing the server, or starting workers. Without the flag startup stays on its
ordinary path. Omission does not revoke or replace a stored allocation.

The descriptor contains `vault_id`, an explicit opaque `usage_owner`,
`allocation: {id, generation}`, `units`, `unit`, the original ordered
`rates: [{unit, per, cost}]`, and `issued_at`. Integer amounts and clocks are
`u64`. `vault_id` is the supervisor's routing identity (`--vault-name`), not the
separate authority-genesis hex used by `VaultUsage`. The owner is the original
usage producer's input, never inferred from a financial account or vault id.
The runtime control request is `AllocationInstall { delivery }` on the existing
authenticated ctl channel. It uses the existing managed write/reap admission
and can install the first original allocation into an already-running ordinary
server. The descriptor commits before the shared future-run selection is
published. Subsequent deliveries use that same native ledger, and their owner
must match its original producer. If usage metering was already bound, the first
delivery must match that meter's owner and reuses the same meter. No owner is
inferred from an account, a reflected balance or the routing id.

Each new run snapshots the current selection. Runs constructed before that
publication keep their original backend and line, and already-admitted usage
keeps its original owner and prices. Native holds are never copied or reissued.
Reading the selection does not acquire the installation mutex or wait for its
vault writer; calls can continue on the ordinary path until publication.

`VaultAllocationLedger::install_backed` retains the original allocation and
`AllocationTerms` (owner, ordered rates and issue clock) in the native writer.
An identical original delivery is a no-op even after depletion, an explicit
close, or replacement by a newer generation. It changes no balances, pending
holds, current selection, refusal or account revision. A different descriptor
at an already recorded generation is an `AllocationConflict`; an unrecorded
older generation follows the existing `StaleGeneration` result. No restart
replays a full grant. Manual `grant` retains its existing fresh-generation
semantics and per-call conversion inputs.

A backed reservation selects its stored original ordered rates in the same
writer that selects the current allocation, not from an earlier process or
factory snapshot. Each durable hold captures the effective rates, and only
that hold's persistent settlement conversion uses them. Its original rates
survive a newer grant. The run's own budget line and in-memory allocation path
keep their existing per-offer rates. `allocations()` exposes the original terms
separately from remaining, pending and used observations.

`AllocationInstalled { allocation_installed: revision }` acknowledges native
descriptor retention at that account revision. A postcommit error does not undo
it. The reply does not prove current selection at a later read, financial
acceptance, an accepted terminal, or backing return. The hosting control plane
still owns actual spawn/VM transport and original financial receipts; this
engine interface alone is not a deployment or financial proof.

## Authority and state

Construct the backend only with a vault opened under its actual process-owner
writer lease. One opaque 16-byte acquisition identity travels with that lease,
including an under-lease restore handoff. It does not replace the live OS lock,
current-process check or descriptor-bound lock-file checks. A second backend on
the same lease uses the same identity. A later lease acquisition changes the
serving observation without resetting any allocation balance or pending hold.

The native account row has an explicit current allocation selection and a
monotonic newest-grant generation. A historical maximum or an observed balance
never selects an allocation. Each allocation keeps its own remaining, pending
and used units and original holds. Replacing or closing the current selection
stops its fresh reservations without releasing its captured holds. A late old
hold settles its original allocation, not the new grant.

The same vault writer adjudicates a reservation and its resident's pinned or
soft share. Resident charges are kept by exact original allocation reference,
including its generation. A late old-generation charge cannot reset newer
resident depletion. The existing owner presentation reports the newest charged
generation; `resident_shares_on` reads an explicitly selected allocation.
Neither presentation is admission authority.

## Producer integration contract

`reserve` takes a caller-owned-writer callback that must persist the original
admitted producer material before the reservation returns. The callback must
use only the supplied transaction and must not acquire another writer. It must
not call a void receipt sink and treat that as durability.

The required producer freeze argument includes `AllocationCallContext`: the
original run name, revision and admission clock, plus the permit's native unit,
unit cost, wide native reservation, ordered run-line conversion rates and
metered flag. The native producer keeps this context in the same canonical
admitted row and transaction, alongside its already frozen facts and financial
price snapshot. Ordinary admissions carry no context and retain their existing
serialized shape. Run-line rates remain distinct from the durable hold's
allocation conversion rates.

`NativeUsageProducer::continuation_in_write_txn` reads the original key from that
same selected producer and caller-owned transaction. It returns the current
stored, scrubbed facts and their original context without looking up new prices,
owners or wallets. This is only a material read port: it restores no guard or
lease, changes no kept-job terminal behavior, and enables no server recovery
caller. Genuine original-line restoration and media continuation remain open.

`NativeUsage::continuation_in_write_txn` reads that selected backend's original
hold and producer material under one supplied writer. It uses
`VaultAllocationLedger::hold_in_write_txn`, which observes pending writes too
and opens no transaction. A terminal hold remains readable after settlement
consumed its admitted producer; it returns no admitted material. A missing
hold returns no snapshot, not permission to mint a replacement. These reads
change no balances, reservations, selection, dispatch or terminal state. They
restore no guard and do not enable a server media recovery caller.

A caller can attach an `AllocationCallIntent` to one cloned admission handle
with `RunAdmission::with_allocation_intent`. For a native host-paid call, its
callback runs in the same reserve writer as the original admitted producer.
It receives that original receipt and hold, so it can retain the call key
without copying balances, rates or producer facts. Failure aborts both writes.
Ordinary, free and memory-work admissions do not invoke the callback.
`RunPermit::allocation_call_key` exposes only the committed original key.

`Vault::media_job_put_in_write_txn` uses the existing media key and erase fences
in the caller's supplied writer. It opens no writer and commits nothing by
itself. The ordinary media put and update wrappers are unchanged. These are
integration ports, not a restored media permit or an automatic media recovery
path; native continuation and its original pending hold still need to be wired.

The physical dispatch adapter must commit `begin_dispatch` before releasing
request bytes. A hold from another acquisition cannot start under the new
serving fence; it remains pending for original-terminal reconciliation. Admission,
a cached boolean, a provider answer, or a later observer does not prove dispatch. This backend never infers unsent
work from a false dispatch bit and never releases old pending work by timeout,
process close, mode change or grant replacement.

`settle` uses the original terminal clock, receipt digest and actual charged
units. It commits the hold terminal, resident charge and caller's staging
callback in one writer. The callback must stage the original frozen event
through the existing `UsageLedger::stage_settlement_in_write_txn`; it must not
create another usage or money outbox. Replaying the same terminal does not
charge or stage again. A different terminal cannot replace it. Actual overrun
remains used even when it exceeds the original grant.

Every mutation returns `AllocationCommit`. Once its `value` is present, the
allocation write is durable, even if `postcommit_error` reports a later vault
failure. Do not undo that operation, return its capacity or mint a new identity
because unrelated postcommit work failed. Before-commit storage or producer
errors remain errors, not exhausted-budget denials. No `HostAccount`, run, budget or
resident mutex is held while this backend acquires its writer. First live
selection serializes installations only; run factories read the once-published
selection without that installation mutex.

The new row is a LIVE restore family and is not imaged into checkpoint payloads.
Actor erase removes the stored resident attribution without releasing money or
pending work; a later terminal cannot recreate that resident row. The existing
resident-share family and its whole-row erase remain unchanged in ownership.


Before opening the native reserve writer, the issuing guard captures the open
lease's `BudgetReservationSource` under its own lock. The canonical admission
context retains that source: the opaque issuing guard ID, lease ID, reserve and
metered flag, exact matched row ordinals, and original floor/shared reservation
split. A foreign, unknown or closed token yields no source; that observation
does not refuse the ordinary admission. No actor, policy table or later row
lookup is copied into it. Row ordinals refer only to the original resolved
table: they are not a durable policy-table reference and cannot reconstruct
one. This source neither restores the program meter nor books the scoped or
unscoped job line, retains a terminal receipt, or proves payment.

### Original-key terminal preparation

`CallOutcome::charge` uses the original native unit, cost and reservation without
constructing a permit. Its run-line conversion uses the original line terms;
its native allocation conversion uses the original hold's terms. These are
separate quantities, not interchangeable booking amounts.

`VaultAllocationLedger::settle_original_with` prepares a pending original
terminal inside the existing writer and uses the same accounting body as
`settle`. The caller stages its original line booking, retained terminal receipt
and canonical producer under that supplied transaction. The API does not create
that caller ownership or activate kept-job recovery. An already selected
terminal returns `AllocationTerminalSelection::Existing` with its exact original
identity, without invoking either callback or reading a consumed producer.
Both cases retain the existing `AllocationCommit` semantics: an error after the
durable commit does not undo the selected value or justify another terminal.
Post-commit producer cleanup and notification remain the actual caller's duty.

## Runtime integration and remaining work

The opt-in run path reserves and freezes its admitted receipt in the native
writer before returning its permit. The real `RunInner::begin_dispatch` hook
commits the native start before `GatedBackend` releases bytes. Settlement builds
one original receipt and passes that same value to the native hold-terminal
transition, its producer callback and, after commitment, its receipt sink.
Native resident settlement uses only the hold's once-selected writer transition.
Storage errors have a distinct typed denial and a host-storage model error,
not an exhausted-budget or provider-health result. No native commit failure
publishes a terminal into a legacy sink that could settle it independently.

`PersistentAllocation::retry_settlements` retries each currently queued native
terminal once. A failed precommit write retains the original receipt, clock and
digest in that backend's memory, even after its caller drops the run handle.
Retries do not settle the run's line again or call a second money producer.
They clear the original ownership marker and publish the original observer
receipt only after the native write commits. Failed entries remain queued;
other calls can still make progress. No queue, run, meter or resident lock spans
the vault writer. This is memory custody, not durable terminal crash recovery.
The opt-in server binding retains the selected backend for its lifetime and
invokes this drain before the existing usage flush, including the shutdown
pass. It reuses the existing meter worker; it adds no timer, retry cap or wait
loop. Failed writes still retain memory-only terminals, not crash recovery.

The binding creates no allocation and replays no old full grant. Its
`persistent_allocation_ledger` accessor returns the same authoritative ledger
for original trusted-host grant, status and retirement operations. Actual
host-delivered allocation identity, original unit and ordered conversion rates
must arrive intact; no `HostAccount`, run meter, maximum historical generation
or reflected balance supplies them.

This is opt-in source integration, not default startup or hosted activation.
`VaultUsage::allocation_producer` creates
`NativeUsageProducer` from the original usage ledger and its same vault. Its
freeze callback stores the one original `AdmittedCall`, not a second field list
or a fake settled usage event. The separate `USAGE_ADMITTED_CALL` family is LIVE
and not imaged into checkpoint payloads. Native source/actor erasure removes
nullable source and actor associations while preserving the original owner,
rates, service cost and pending allocation custody. Writes check the same
writer's hard-erasure markers. A later terminal reads those stored facts, never
an old memory snapshot that could restore erased attribution.

The producer's typed `record_service_cost` updates that original admitted row
for a service call. A model call's frozen rate snapshot is unchanged. The web
connector's actual backend-key caller now uses the selected server factory
when it has no existing run, and its cost update selects the original permit's
native backend before settlement. Ordinary permits keep the existing memory
service-cost method. Native admission and dispatch storage failures keep their
host-storage distinction and become an internal facade error, never a spent
budget or provider-health refusal. Model raw HTTP errors retain their original
typed `HostStore` payload with an internal status and `host_store` code; role
invocation facades also keep host storage as an internal error. The model walk
classifies that new error explicitly and does not send it to another provider.

The producer retains the exact content-free provider cost before attempting
its preliminary row update. If that write fails, the terminal's same-writer
callback still merges the retained fact into the stored, scrubbed original
admission. A failed terminal retains both originals for retry. Only the native
commit acknowledgement releases the memory cost; a postcommit error does not
undo or reissue the committed event. This memory backstop does not survive a
process crash. Terminal staging
uses the existing pure event builder and `UsageLedger` pending pipeline in the
hold's writer, then removes the admission in that same commit. An undispatched
terminal removes its admission without creating served usage.

Optional model-call evidence and its NoRecord checks remain separate. This
producer does not capture a prompt, response or credential, and does not change
the existing usage path's billing or suppress settlement because an evidence
write is absent. The selected native run's sink only observes its actual
committed native admission and terminal; it does not feed those rows through
`VaultUsage::record` as an independent usage producer. Free and memory-work
calls on that factory keep the ordinary usage leg, and chosen observers and
budget-hit hooks remain attached.

The configured model runtime's undeclared, room-funded and attributed calls
now retain their original run meter, payer and attribution while selecting the
same native backend. Declared calls with no explicit host override retain
their exact declaration and line on that backend; an explicit host account
still selects its original ordinary path. Configured raw calls and the
server's injected raw backend carry that same native selection, including
both owned builder orderings for the injected backend. Existing settlement
capture, original request/source overlays and chosen observers remain attached.
The attachment passes the shared future-run binding before `Arc<ModelRuntime>`
exists. First live delivery can publish that binding later without changing
worker identity or any constructed run. An explicit startup selection still
binds native metering before attaching the AI host or starting its workers.

Media job factories, standalone House gates and direct non-runtime run
factories still need their original native binding joins. Existing kept media
jobs retain their current restore path: they are not blindly re-admitted as
new native holds on restart. Converting that path requires its actual original
hold/lease and terminal recovery, not another grant or a new refusal. The
original hosted spawn/VM delivery counterpart, durable terminal crash recovery
and accepted-terminal reconciliation remain open. A false dispatch observation is
never permission to release an old hold.

Cloud accepted-terminal identity, serving-retirement reconciliation and backing
return remain the hosted control plane's responsibility. Native revisions,
fences, local pending deletion and settlement cursors are observations, not a
Cloud acceptance frontier. No runtime, privacy, financial or full-row completion
is claimed by this source implementation.
