//! A run's own change journal (ARCH-0040 #revert-run, REV-2): each change a
//! run writes is recorded under that run in the change's own write
//! transaction, so the engine lists a run's changes by itself and a client no
//! longer assembles them. Membership is what the run wrote, from the run
//! reference its dispatcher bound, never guessed from an actor or a time.
//! `Memory::run_changes_as_owner` is its call surface;
//! `record_run_claim_in_txn` is its claim writer.

use super::*;

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

/// One journal row: the run, spelled whole beside its hashed key, and the change.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunChangeRow {
    run: String,
    change: RunReviewChange,
}

const CHANGES: SideTable<([u8; 16], u64), RunChangeRow, Named> =
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
        },
    )
}

/// The run's changes in write order, each once: a change the run wrote again
/// keeps its first place.
pub(super) fn run_changes_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    run: &str,
) -> MemoryResult<Vec<RunReviewChange>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut changes = Vec::new();
    for row in CHANGES.iter_from(store, txn, &run_hash(run))? {
        let (_, row) = row?;
        if row.run == run && seen.insert(row.change.change().to_owned()) {
            changes.push(row.change);
        }
    }
    Ok(changes)
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
