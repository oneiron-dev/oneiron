//! A run's own change journal (ARCH-0040 #revert-run, REV-2): each change a
//! run writes is recorded under that run in the change's own write
//! transaction, so the engine lists a run's changes by itself and a client no
//! longer assembles them. Membership is what the run wrote, from the run
//! reference its dispatcher bound, never guessed from an actor or a time.
//! `Memory::run_changes_as_owner` is its call surface;
//! `record_run_claim_in_txn` is its claim writer,
//! `record_run_edge_in_txn` its code-run edge writer,
//! `record_run_topology_in_txn` its identity-topology writer,
//! `record_run_deletion_in_txn` its delete and erase writer,
//! `record_run_effect_in_txn` its external-effect writer and
//! `record_run_note_in_txn` its NOTE fork writer, whose landing keeps its
//! undo through `record_run_note_landing_in_txn`. A run nobody settled is
//! reverted from this journal (`journal_members_in_txn`), and each change's
//! compensation is kept on its first row.

use super::*;
use crate::claim::ClaimApprovalStatus;

/// The run whose changes are read: its job id, or its settlement's `run:` handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunChangesRequest {
    pub run_id: String,
}

/// Every change the run wrote, once each and in write order. Child jobs of a
/// run with a run id write under that same run, so their changes are here
/// too. `changes` is the set `vault.runs.review` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunChanges {
    pub run_id: String,
    pub changes: Vec<RunReviewChange>,
}

/// One journal row: the run, spelled whole beside its hashed key, and the
/// change. A change's first row keeps the owner's compensation receipt once a
/// revert took it back, and the later changes that compensation left
/// standing; rows written before the first revert hold neither. A NOTE
/// fork's first row keeps the undo its landing took, whoever landed it
/// (ruling RUNCHANGES-NOTE-UNDO = A); a fork not landed has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunChangeRow {
    run: String,
    change: RunReviewChange,
    #[serde(default)]
    compensation: Option<String>,
    #[serde(default)]
    unrestored: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note_undo: Option<crate::note::RunNoteUndo>,
}

/// A journal row's key: the run's hashed head and the change's write order.
pub(super) type JournalKey = ([u8; 16], u64);

const CHANGES: SideTable<JournalKey, RunChangeRow, Named> =
    SideTable::new(&side_table::RUN_REVIEW_CHANGE);

/// The fixed-width key head of every row of `run`.
fn run_hash(run: &str) -> [u8; 16] {
    let hash = blake3::Hasher::new_derive_key("oneiron.run-review.change.v1")
        .update(run.as_bytes())
        .finalize();
    let mut head = [0; 16];
    head.copy_from_slice(&hash.as_bytes()[..16]);
    head
}

/// Records that the run `envelope` names wrote claim `id`, in the claim's own
/// write transaction. An envelope no code run built names no run, and records
/// nothing.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_claim_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    envelope: &crate::WriteEnvelope,
    id: EntityId,
) -> crate::Result<()> {
    let Some(run) = crate::code_run::envelope_run_ref(envelope) else {
        return Ok(());
    };
    record_change_in_txn(
        store,
        txn,
        run,
        RunReviewChange::Claim {
            claim_ref: id.to_hex(),
        },
    )
}

/// Records that the run `envelope` names put an edge whose `edge.provenance`
/// Claim is `provenance`, in the edge's own write transaction (ruling
/// RUNCHANGES-EDGE-REF = A). An envelope no code run built names no run, and
/// records nothing.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_edge_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    envelope: &crate::WriteEnvelope,
    provenance: EntityId,
) -> crate::Result<()> {
    let Some(run) = crate::code_run::envelope_run_ref(envelope) else {
        return Ok(());
    };
    record_change_in_txn(
        store,
        txn,
        run,
        RunReviewChange::Edge {
            provenance_ref: provenance.to_hex(),
        },
    )
}

/// Records that `run` wrote the identity-topology event `event` (a merge,
/// split or facet judgment, applied or parked as a proposal), in the event's
/// own write transaction.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_topology_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    event: EntityId,
) -> crate::Result<()> {
    record_change_in_txn(
        store,
        txn,
        run,
        RunReviewChange::Topology {
            event_ref: event.to_hex(),
        },
    )
}

/// Records that `run` deleted `entity`, an erase when `erase`, in the write
/// that commits the deletion: the soft delete's scrub, or the erase's purge
/// beside its `dt:` marker. A revert reports the change backup-only or
/// one-way; it never undoes it.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_deletion_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    entity: &EntityId,
    erase: bool,
) -> crate::Result<()> {
    let entity_ref = entity.to_hex();
    let change = if erase {
        RunReviewChange::Erase { entity_ref }
    } else {
        RunReviewChange::Delete { entity_ref }
    };
    record_change_in_txn(store, txn, run, change)
}

/// Records that `run` asked the external effect whose gate receipt is
/// `decision`, in the receipt's own write. A receipt the run already lists is
/// not listed again, nor is a later decision on an effect whose pending
/// receipt the run lists: that pending receipt stands for the effect, and its
/// verdict follows the newest decision on it (FIX 11478). A revert never
/// replays an effect; it reports one that ran as one-way.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_effect_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    decision: crate::store::GateDecisionId,
) -> crate::Result<()> {
    let run = run.strip_prefix("run:").unwrap_or(run);
    let receipt_ref = format!("gate:{}", decision.to_hex());
    let record = store.gate_decision_in_txn(&*txn, decision)?;
    for row in CHANGES.iter_from(store, &*txn, &run_hash(run))? {
        let (_, row) = row?;
        let RunReviewChange::ExternalEffect {
            receipt_ref: listed,
        } = &row.change
        else {
            continue;
        };
        if row.run != run {
            continue;
        }
        if *listed == receipt_ref {
            return Ok(());
        }
        let Some(record) = &record else {
            continue;
        };
        let Some(listed) = listed
            .strip_prefix("gate:")
            .and_then(|hex| EntityId::from_hex(hex).ok())
        else {
            continue;
        };
        let listed = store.gate_decision_in_txn(
            &*txn,
            crate::store::GateDecisionId::from_bytes(*listed.as_bytes()),
        )?;
        if listed.is_some_and(|listed| {
            listed.outcome == "pending"
                && listed.content_kind == record.content_kind
                && !record.diff_handle.is_empty()
                && listed.diff_handle == record.diff_handle
        }) {
            return Ok(());
        }
    }
    record_change_in_txn(
        store,
        txn,
        run,
        RunReviewChange::ExternalEffect { receipt_ref },
    )
}

/// Records that `run` opened `fork` of `note`, in the fork's own write. The
/// fork lands later, or never; its landing keeps the undo on this row.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_note_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    note: EntityId,
    fork: EntityId,
) -> crate::Result<()> {
    record_change_in_txn(
        store,
        txn,
        run,
        RunReviewChange::Note {
            note_ref: note.to_hex(),
            fork_ref: fork.to_hex(),
        },
    )
}

/// Keeps `undo`, which restores the revision `run`'s fork `fork` landed
/// over, on that fork's first journal row, in the landing's own write,
/// whoever landed it (ruling RUNCHANGES-NOTE-UNDO = A). A run whose journal
/// does not list the fork lists it now, with its undo.
///
/// # Errors
/// A store failure.
pub(crate) fn record_run_note_landing_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    fork: EntityId,
    undo: &crate::note::RunNoteUndo,
) -> crate::Result<()> {
    let run = run.strip_prefix("run:").unwrap_or(run);
    let fork_ref = fork.to_hex();
    let listed = CHANGES
        .iter_from(store, &*txn, &run_hash(run))?
        .find_map(|row| match row {
            Ok((key, row)) if row.run == run && row.change.change() == fork_ref => {
                Some(Ok((key, row)))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    match listed {
        Some((key, mut row)) => {
            row.note_undo = Some(undo.clone());
            CHANGES.put(store, txn, &key, &row)
        }
        None => append_row_in_txn(
            store,
            txn,
            run,
            RunReviewChange::Note {
                note_ref: undo.note.clone(),
                fork_ref,
            },
            Some(undo.clone()),
        ),
    }
}

/// The undo the landing of `run`'s fork `fork_ref` kept on the run's
/// journal, for a settlement of a fork that landed before it.
pub(super) fn journal_note_undo_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    run: &str,
    fork_ref: &str,
) -> MemoryResult<Option<crate::note::RunNoteUndo>> {
    Ok(first_rows_in_txn(store, txn, run)?
        .into_iter()
        .find(|(_, row)| row.change.change() == fork_ref)
        .and_then(|(_, row)| row.note_undo))
}

/// Appends `change` after the run's last recorded change.
fn record_change_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    change: RunReviewChange,
) -> crate::Result<()> {
    append_row_in_txn(store, txn, run, change, None)
}

/// Appends `change`, with a NOTE landing's `note_undo`, after the run's last
/// recorded change.
fn append_row_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    change: RunReviewChange,
    note_undo: Option<crate::note::RunNoteUndo>,
) -> crate::Result<()> {
    let run = run.strip_prefix("run:").unwrap_or(run);
    let head = run_hash(run);
    let order = match CHANGES.iter_rev_from(store, &*txn, &head)?.next() {
        Some(last) => {
            let ((_, order), _) = last?;
            order.saturating_add(1)
        }
        None => 0,
    };
    CHANGES.put(
        store,
        txn,
        &(head, order),
        &RunChangeRow {
            run: run.to_owned(),
            change,
            compensation: None,
            unrestored: Vec::new(),
            note_undo,
        },
    )
}

/// The run's rows in write order, each change at its first row: a change the
/// run wrote again keeps its first place.
fn first_rows_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    run: &str,
) -> MemoryResult<Vec<(JournalKey, RunChangeRow)>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for row in CHANGES.iter_from(store, txn, &run_hash(run))? {
        let (key, row) = row?;
        if row.run == run && seen.insert(row.change.change().to_owned()) {
            rows.push((key, row));
        }
    }
    Ok(rows)
}

/// The run's changes in write order, each once.
pub(super) fn run_changes_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    run: &str,
) -> MemoryResult<Vec<RunReviewChange>> {
    Ok(first_rows_in_txn(store, txn, run)?
        .into_iter()
        .map(|(_, row)| row.change)
        .collect())
}

/// The run's journal as revert members, for a run nobody settled (ARCH-0040
/// #revert-run; ruling RUNCHANGES-REVERT-UNSETTLED = A, 13 Nov): each change
/// once, in write order, with its journal key. Empty for a run that wrote
/// nothing.
pub(super) fn journal_members_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    run: &str,
) -> MemoryResult<Vec<(JournalKey, StoredChange)>> {
    first_rows_in_txn(&memory.vault().store, txn, run)?
        .into_iter()
        .map(|(key, row)| Ok::<_, MemoryError>((key, journal_member_in_txn(memory, txn, row)?)))
        .collect()
}

/// One journal change as a revert member. A compensated change keeps its
/// receipt; any other change takes the verdict and undo a settle would give
/// it, read as it stands now.
fn journal_member_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    row: RunChangeRow,
) -> MemoryResult<StoredChange> {
    let (verdict, inverse) = match &row.change {
        _ if row.compensation.is_some() => (RunChangeVerdict::Landed, None),
        RunReviewChange::Claim { claim_ref } => claim_member_in_txn(memory, txn, &row, claim_ref)?,
        RunReviewChange::Topology { event_ref } => {
            topology_member_in_txn(memory.vault(), txn, event_ref)?
        }
        // Journaled in the write that committed it, so it landed; the revert
        // reports it backup-only or one-way from the entity's marker now.
        RunReviewChange::Delete { .. } | RunReviewChange::Erase { .. } => {
            (RunChangeVerdict::Landed, None)
        }
        // Its verdict as a settle reads it; it has no undo, so the revert
        // reports one that ran as one-way. A receipt redacted since may have
        // gone out, so it reads as landed.
        RunReviewChange::ExternalEffect { receipt_ref } => (
            super::snapshot::effect_receipt_in_txn(memory.vault(), txn, receipt_ref)?
                .map_or(RunChangeVerdict::Landed, |(_, verdict)| verdict),
            None,
        ),
        RunReviewChange::Note { note_ref, fork_ref } => {
            note_member_in_txn(memory.vault(), txn, &row, note_ref, fork_ref)?
        }
        // Its provenance Claim is read as a claim is; its undo retracts it.
        RunReviewChange::Edge { provenance_ref } => {
            claim_member_in_txn(memory, txn, &row, provenance_ref)?
        }
    };
    Ok(StoredChange {
        member: row.change,
        verdict,
        inverse,
        compensation: row.compensation,
        unrestored: row.unrestored,
    })
}

/// A journal claim's verdict and undo, or a journal edge's, read from its
/// provenance Claim. A claim the gate still holds, or refused, never landed.
/// A landed claim takes the undo a settle would give it: Authored, from the
/// claim's own author, bound to the claim as it stands now; the revert's own
/// checks then keep it when a later change rests on it. A claim deleted
/// since the run wrote it has no undo, so the revert reports it as
/// dependent.
fn claim_member_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    row: &RunChangeRow,
    claim_ref: &str,
) -> MemoryResult<(RunChangeVerdict, Option<RunInverse>)> {
    let vault = memory.vault();
    let id = EntityId::from_hex(claim_ref)?;
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &id)?;
    let body = if state.deleted {
        None
    } else {
        vault.get_claim_in_txn(txn, &id)?
    };
    Ok(match body {
        None => (RunChangeVerdict::Landed, None),
        Some(body) => match body.approval {
            ClaimApprovalStatus::Proposed => (RunChangeVerdict::Waiting, None),
            ClaimApprovalStatus::Rejected => (RunChangeVerdict::Rejected, None),
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved => (
                RunChangeVerdict::Landed,
                Some(RunInverse::Authored {
                    author: snapshot::claim_author(&body)?.to_hex(),
                    fingerprint: fingerprint(&snapshot::binding(memory, txn, &row.change)?.0),
                }),
            ),
        },
    })
}

/// A journal NOTE fork's verdict and undo (ruling RUNCHANGES-NOTE-UNDO =
/// A): a fork that landed, whoever landed it, takes the undo its landing
/// kept on this row, which restores the revision from before it; a pending
/// fork waits, and a rejected fork, or one an erase of its opener took,
/// never landed. A landed fork whose row kept no undo has none, so the
/// revert reports it as dependent.
fn note_member_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    row: &RunChangeRow,
    note_ref: &str,
    fork_ref: &str,
) -> MemoryResult<(RunChangeVerdict, Option<RunInverse>)> {
    use crate::note::{NoteForkState, NoteVerdict};
    if let Some(undo) = &row.note_undo {
        return Ok((
            RunChangeVerdict::Landed,
            Some(RunInverse::Note(undo.clone())),
        ));
    }
    Ok(
        match crate::note::note_fork_state_in_txn(
            vault,
            txn,
            EntityId::from_hex(note_ref)?,
            EntityId::from_hex(fork_ref)?,
        )? {
            NoteForkState::Waiting => (RunChangeVerdict::Waiting, None),
            NoteForkState::Absent | NoteForkState::Decided(Some(NoteVerdict::Reject)) => {
                (RunChangeVerdict::Rejected, None)
            }
            NoteForkState::Decided(_) => (RunChangeVerdict::Landed, None),
        },
    )
}

/// A journal topology event's verdict and undo, from the effective ledger
/// as a settle reads them (FIX 9966): an applied event landed and is its own
/// undo; a proposal waits until a ruling retires it, and once approved its
/// undo is the op that ruling applied. An event the ledger no longer holds
/// has no undo, so the revert reports it as dependent.
fn topology_member_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &str,
) -> MemoryResult<(RunChangeVerdict, Option<RunInverse>)> {
    let id = EntityId::from_hex(event_ref)?;
    let Some(event) = vault.identity_topology_decision_in_txn(txn, &id)? else {
        return Ok((RunChangeVerdict::Landed, None));
    };
    let outcome = super::topology::topology_outcome_in_txn(vault, txn, id, &event)?;
    Ok((
        outcome.verdict,
        outcome.applied.map(|event| RunInverse::Topology {
            event: event.to_hex(),
        }),
    ))
}

/// Takes back the journal change at `key` in the caller's write, and keeps
/// its compensation on that row, so a repeat or a later pick of the same
/// change does nothing twice.
pub(super) fn undo_journal_member_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    actor: WriteActor,
    key: &JournalKey,
) -> MemoryResult<Result<(String, Vec<String>), RunNotUndoneReason>> {
    let store = &memory.vault().store;
    let row = CHANGES
        .get(store, &*txn, key)?
        .ok_or_else(|| MemoryError::bad_request("change left the run"))?;
    let (run, fresh, note_undo) = (
        row.run.clone(),
        row.compensation.is_none(),
        row.note_undo.clone(),
    );
    let mut member = journal_member_in_txn(memory, &*txn, row)?;
    let undone = super::revert::undo_member_in_txn(memory, txn, owner, actor, &mut member)?;
    if fresh && undone.is_ok() {
        CHANGES.put(
            store,
            txn,
            key,
            &RunChangeRow {
                run,
                change: member.member,
                compensation: member.compensation,
                unrestored: member.unrestored,
                note_undo,
            },
        )?;
    }
    Ok(undone)
}

/// Each stored journal row of `run`, in write order: its whole key's and its
/// value's byte lengths, for the journal's write-cost measurement.
#[cfg(oneiron_test_support)]
pub(crate) fn journal_row_sizes(
    vault: &crate::Vault,
    run: &str,
) -> crate::Result<Vec<(usize, usize)>> {
    let txn = vault.store.env.read_txn()?;
    let prefix = CHANGES.decl().prefix.len();
    CHANGES
        .iter_raw_from(&vault.store, &txn, &run_hash(run))?
        .map(|row| row.map(|(key, value)| (prefix + key.len(), value.len())))
        .collect()
}

/// The run's changes in write order, each once, read without an owner.
#[cfg(oneiron_test_support)]
pub(crate) fn journal_changes(vault: &crate::Vault, run: &str) -> crate::Result<serde_json::Value> {
    let txn = vault.store.env.read_txn()?;
    let changes = run_changes_in_txn(&vault.store, &txn, run)
        .map_err(|error| crate::Error::InvalidConfig(format!("run journal: {error:?}")))?;
    serde_json::to_value(changes)
        .map_err(|error| crate::Error::InvalidConfig(format!("run journal: {error}")))
}

impl Memory<'_> {
    /// Every change the run wrote, in write order, as `vault.runs.review`
    /// takes them. An unknown run has none.
    pub fn run_changes_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunChangesRequest,
    ) -> MemoryResult<RunChanges> {
        let run = run_key(&input.run_id)?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_owner(self, &txn, owner)?;
        let changes = run_changes_in_txn(&self.vault().store, &txn, &run)?;
        self.produced_from(
            changes
                .iter()
                .map(RunReviewChange::rows)
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(RunChanges {
            run_id: run,
            changes,
        })
    }
}
