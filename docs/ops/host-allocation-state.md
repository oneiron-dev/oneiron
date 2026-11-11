# Native host allocation state

`llm::run_admission::VaultAllocationLedger` is the vault-bound persistent
allocation backend. It is not installed by the current `HostAccount` constructors.
Those constructors and the current run admission path still use their existing
in-memory allocation meters. No Cloud wallet or price conversion is implemented
by this backend.

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
errors remain errors, not exhausted-budget denials. No host, run, budget or
resident mutex is held while this backend acquires its writer.

The new row is a LIVE restore family and is not imaged into checkpoint payloads.
Actor erase removes the stored resident attribution without releasing money or
pending work; a later terminal cannot recreate that resident row. The existing
resident-share family and its whole-row erase remain unchanged in ownership.

## Remaining runtime work

The live `HostAccount` / `RunInner` admission, actual dispatch and terminal path
are not connected to this backend yet. The server still needs the original
`AdmittedCall` durable freeze with its actual custody/erase contract, the
original terminal producer join and the existing usage.pending drain. The
callback API alone is not evidence that those runtime joins exist.

Cloud accepted-terminal identity, serving-retirement reconciliation and backing
return remain the hosted control plane's responsibility. Native revisions,
fences, local pending deletion and settlement cursors are observations, not a
Cloud acceptance frontier. No runtime, privacy, financial or full-row completion
is claimed by this source implementation.
