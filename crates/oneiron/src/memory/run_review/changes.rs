//! A run's own change journal (ARCH-0040 #revert-run, REV-2): each change a
//! run writes is recorded under that run in the change's own write
//! transaction, so the engine lists a run's changes by itself and a client no
//! longer assembles them. Membership is what the run wrote, from the run
//! reference its dispatcher bound, never guessed from an actor or a time.
//! `Memory::run_changes_as_owner` is its call surface;
//! `record_run_claim_in_txn` is its claim writer. A run nobody settled is
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
/// standing; rows written before the first revert hold neither.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunChangeRow {
    run: String,
    change: RunReviewChange,
    #[serde(default)]
    compensation: Option<String>,
    #[serde(default)]
    unrestored: Vec<String>,
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

/// Appends `change` after the run's last recorded change.
fn record_change_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    change: RunReviewChange,
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
/// receipt. A claim the gate still holds, or refused, never landed. A landed
/// claim takes the undo a settle would give it: Authored, from the claim's
/// own author, bound to the claim as it stands now; the revert's own checks
/// then keep it when a later change rests on it. A claim deleted since the
/// run wrote it has no undo, so the revert reports it as dependent.
fn journal_member_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    row: RunChangeRow,
) -> MemoryResult<StoredChange> {
    let (verdict, inverse) = if row.compensation.is_some() {
        (RunChangeVerdict::Landed, None)
    } else {
        let RunReviewChange::Claim { claim_ref } = &row.change else {
            return Err(MemoryError::bad_request(
                "the run journal holds a change kind it does not record",
            ));
        };
        let vault = memory.vault();
        let id = EntityId::from_hex(claim_ref)?;
        let body = if vault.store.port_deletion_state(txn, &id)?.deleted {
            None
        } else {
            vault.get_claim_in_txn(txn, &id)?
        };
        match body {
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
    let (run, fresh) = (row.run.clone(), row.compensation.is_none());
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
