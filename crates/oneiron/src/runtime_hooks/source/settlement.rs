//! The settlement source (ARCH-0080 §4 Sources and cursors; OF-579): one row
//! per settled proposal, appended in the transaction of the door that
//! settles it. The sequence is drawn there, so feed order is commit order.
//! A settlement no fact binding reads appends nothing (FIX 22154). The
//! runner and each housekeeping pass prune the rows every hook binding has
//! passed (FIX 22180), and an erase leaves a row that names the erased
//! proposal or settler at its sequence with nothing in it (FIX 22141).

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::ports::EntityStoreRead;
use crate::runtime_hooks::store::source_erased_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

use super::{
    FactEntry, FactKind, FactOp, FactPosition, FactSource, SettledFact, SettledOutcome,
    SettlementDetails, SettlementKind, SettlementPosition, SourceBatch,
};

/// The settlement feed: one row per settled proposal, keyed by its sequence.
const SETTLED: SideTable<u64, SettlementFeedRow, Named> =
    SideTable::new(&side_table::HOOKS_SETTLED);
/// The last settlement sequence handed out.
const SETTLED_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::HOOKS_SETTLED_NEXT);

/// One settlement feed row, at the sequence its settlement committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SettlementFeedRow {
    /// A settled proposal.
    Settled(SettledRow),
    /// A settlement whose proposal or settler was erased: it keeps its
    /// position, so a cursor past it neither breaks nor reads it again, and
    /// names no proposal, settler or body. No reader takes it.
    Erased,
}

/// One settled proposal, as the feed keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::runtime_hooks) struct SettledRow {
    #[serde(with = "crate::serialize::entity_ref")]
    proposal: EntityId,
    outcome: SettledOutcome,
    #[serde(with = "crate::serialize::entity_ref")]
    settled_by: EntityId,
    kind: SettlementKind,
    /// BLAKE3 of the proposal's body when it settled, when it had one.
    body_hash: Option<[u8; 32]>,
    recorded_at: u64,
}

impl SettledRow {
    fn input_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-settlement.v1");
        hasher.update(self.proposal.as_bytes());
        hasher.update(&[self.outcome as u8, self.kind as u8]);
        hasher.update(self.settled_by.as_bytes());
        hasher.update(&self.body_hash.unwrap_or_default());
        *hasher.finalize().as_bytes()
    }
}

/// Appends one settlement to the feed, in the settling door's transaction.
/// The sequence is allocated there, so feed order is commit order. A
/// settlement with no reader there ([`super::has_reader_in_txn`]: hooks
/// off, or no enabled fact binding that takes `proposal.settled` follows
/// the feed) is one no hook reads, so it appends nothing (FIX 22154); a
/// binding enabled later starts at the feed head, past it. One whose
/// proposal or settler a permanent erase fenced appends nothing either: the
/// erase's scrub would have emptied it (FIX 22191).
pub(crate) fn record_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fact: SettledFact,
) -> Result<()> {
    if !super::has_reader_in_txn(
        vault,
        txn,
        FactSource::Settlement,
        FactKind::ProposalSettled,
    )? {
        return Ok(());
    }
    if source_erased_in_txn(vault, txn, &fact.proposal)?
        || source_erased_in_txn(vault, txn, &fact.settled_by)?
    {
        return Ok(());
    }
    let (position, row) = prepare_settlement_in_txn(vault, txn, fact)?;
    let sequence = position.0;
    SETTLED.put(
        &vault.store,
        txn,
        &sequence,
        &SettlementFeedRow::Settled(row),
    )?;
    SETTLED_NEXT.put(&vault.store, txn, &(), &sequence)
}

pub(in crate::runtime_hooks) fn prepare_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fact: SettledFact,
) -> Result<(SettlementPosition, SettledRow)> {
    let last = SETTLED_NEXT.get(&vault.store, txn, &())?.unwrap_or(0);
    let sequence = last
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hook settlement sequence"))?;
    let body_hash = vault
        .store
        .port_entity_record(txn, &fact.proposal)?
        .map(|row| *blake3::hash(&row.body).as_bytes());
    let row = SettledRow {
        proposal: fact.proposal,
        outcome: fact.outcome,
        settled_by: fact.settled_by,
        kind: fact.kind,
        body_hash,
        recorded_at: vault.store.clock.now_recorded_at(),
    };
    Ok((SettlementPosition(sequence), row))
}

/// The actor a critical-confirm timeout demotion settles as (FIX 1093): no
/// person answered, so the fact names the engine's own unattributed
/// principal, the same one the demotion's changelog row carries.
fn timeout_settled_by() -> Result<EntityId> {
    crate::ports::storage_service_principal()
}

/// Records a critical-confirm timeout's demotion in the demoting door's
/// transaction: a `Demoted` settlement, settled by the engine, through
/// [`record_settlement_in_txn`].
pub(crate) fn record_timeout_demotion_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: EntityId,
) -> Result<()> {
    record_settlement_in_txn(
        vault,
        txn,
        SettledFact {
            proposal,
            outcome: SettledOutcome::Demoted,
            settled_by: timeout_settled_by()?,
            kind: SettlementKind::CriticalWriteConfirm,
        },
    )
}

/// Settlements after `after`, at most `max_entries` rows scanned. An erased
/// row is scanned past, so the cursor moves over it as over a skipped fact.
pub(super) fn settlements_after(
    vault: &Vault,
    after: Option<SettlementPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    settlements_after_in_txn(vault, &rtxn, after, max_entries)
}

pub(super) fn settlements_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<SettlementPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |position| Bound::Excluded(&position.0));
    let mut batch = SourceBatch::default();
    for (scanned, row) in SETTLED
        .iter_range(&vault.store, txn, start, Bound::Unbounded)?
        .enumerate()
    {
        if scanned >= max_entries {
            batch.more = true;
            break;
        }
        let (sequence, row) = row?;
        let position = FactPosition::Settlement(SettlementPosition(sequence));
        batch.through = Some(position);
        let SettlementFeedRow::Settled(settled) = row else {
            continue;
        };
        batch.entries.push(settlement_fact_in_txn(
            vault,
            txn,
            SettlementPosition(sequence),
            &settled,
        )?);
    }
    Ok(batch)
}

pub(in crate::runtime_hooks) fn settlement_fact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    position: SettlementPosition,
    settled: &SettledRow,
) -> Result<FactEntry> {
    let position = FactPosition::Settlement(position);
    let revision = match settled.body_hash.as_ref() {
        Some(body_hash) => crate::vault::entity_revision::revision_for_body_hash_in_txn(
            vault,
            txn,
            &settled.proposal,
            body_hash,
        )?,
        None => None,
    };
    Ok(FactEntry {
        position,
        kind: FactKind::ProposalSettled,
        entity: settled.proposal,
        op: FactOp::Settle,
        actor: settled.settled_by,
        recorded_at: settled.recorded_at,
        input_hash: settled.input_hash(),
        body_hash: settled.body_hash,
        revision,
        settlement: Some(SettlementDetails {
            kind: settled.kind,
            outcome: settled.outcome,
        }),
        predicate: None,
        tick: None,
        surface: None,
    })
}

/// The newest settlement position, or `None` while the feed is empty, in
/// the caller's snapshot, including a binding lifecycle write's own
/// settlement.
pub(super) fn head_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<FactPosition>> {
    Ok(SETTLED
        .iter_rev_from(&vault.store, txn, &[])?
        .next()
        .transpose()?
        .map(|(sequence, _)| FactPosition::Settlement(SettlementPosition(sequence))))
}

/// The settlement rows at or before `floor`, the lowest cursor of every
/// enabled fact binding, at most `max_rows`, read in `txn` for a later write
/// to delete ([`delete_settlements_in_txn`]). A binding starts at the feed
/// head when it is enabled or met again ([`super::enable_start_in_txn`]),
/// and nothing else reads the feed by sequence, so no passed row is read
/// again.
pub(super) fn passed_settlements_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    floor: SettlementPosition,
    max_rows: usize,
) -> Result<Vec<u64>> {
    let mut passed = Vec::new();
    for row in SETTLED.iter_range(
        &vault.store,
        txn,
        Bound::Unbounded,
        Bound::Included(&floor.0),
    )? {
        if passed.len() >= max_rows {
            break;
        }
        let (sequence, _) = row?;
        passed.push(sequence);
    }
    Ok(passed)
}

/// Deletes the settlement feed rows `sequences` names, in the caller's
/// write.
pub(super) fn delete_settlements_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sequences: &[u64],
) -> Result<()> {
    for sequence in sequences {
        SETTLED.delete(&vault.store, txn, sequence)?;
    }
    Ok(())
}

/// Erases `ids` from the settlement feed in the caller's erase write: each
/// row whose proposal or settler is one of them becomes
/// [`SettlementFeedRow::Erased`] at its own sequence. One complete scan for
/// all of them, as the other hook carriers' scrub; a row erased already
/// stays as it is.
pub(super) fn scrub_settlements_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut named = Vec::new();
    for row in SETTLED.iter_from(&vault.store, txn, &[])? {
        let (sequence, row) = row?;
        if matches!(
            &row,
            SettlementFeedRow::Settled(settled)
                if ids.contains(&settled.proposal) || ids.contains(&settled.settled_by)
        ) {
            named.push(sequence);
        }
    }
    for sequence in &named {
        SETTLED.put(&vault.store, txn, sequence, &SettlementFeedRow::Erased)?;
    }
    Ok(())
}
