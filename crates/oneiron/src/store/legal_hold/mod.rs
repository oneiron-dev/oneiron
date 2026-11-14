//! The one legal-hold store (OF-470, design B; ARCH-0038 #legal-hold).
//!
//! A hold is a typed row naming records or gate-decision partitions. No hold
//! keeps anything in the vault any more (LEGAL-HOLD-USE = B, owner
//! 2026-11-05; ARCH-0038 #legal-hold-clone-ruling): every hold writes a
//! sealed copy of its scope to a hold store outside the vault
//! (`deletion::legal_hold::clone`), and deletes, erases, scrubs, compaction,
//! backup expiry and key retirement run as they would without it. A hold is
//! not an in-place retention pin or an erase-completion gate.
//!
//! Every byte-destroying path still calls [`Store::reject_legal_holds_in_txn`]
//! inside the transaction that destroys; only a cooperative restriction
//! refuses there now. Several holds may name one record; each lifts on its
//! own.
//!
//! Customer holds and their log are canonical rows a restore keeps live. Host-order holds and their log sit
//! under `legal_hold:host:`, a runtime prefix no checkpoint image carries, so
//! an owner backup or export never holds an order or its reference (C2). The
//! owner reads a host order's rows through the one permitted view
//! (`LegalHold::owner_may_see`), never a copy.

pub(crate) mod events;
mod notice;
mod use_limit;

pub(crate) use use_limit::{
    CooperativeRestriction, CooperativeRestrictionKey, any_cooperative_restriction_in_txn,
    cooperative_restriction_active_in_txn, held_in_txn, partition_held_in_txn, rows_keep_record,
    use_limit_in_txn,
};

use std::sync::{Mutex, PoisonError};

use heed::{RoTxn, RwTxn};

pub(crate) use events::{host_events_in_txn, log_in_txn, owner_events_in_txn};

use crate::deletion::{
    LEGAL_HOLD_LOG_RETENTION_MONTHS, LegalHold, LegalHoldActorKind, LegalHoldEventKind,
    LegalHoldKind, LegalHoldReason, LegalHoldTarget,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

/// The 17-byte spelling of a hold target: `1` then the id for a record or
/// a claim's partition (the two hold together), all zero for the
/// claim-free partition.
type HeldKey = [u8; 17];
type Rows = SideTable<EntityId, LegalHold, Named>;

/// Customer holds. Key: id16 (hold).
const ROWS: Rows = SideTable::new(&side_table::LEGAL_HOLD_ROW);
/// Host-order holds. Key: id16 (hold).
const HOST_ROWS: Rows = SideTable::new(&side_table::LEGAL_HOLD_HOST_ROW);

const fn rows_of(kind: LegalHoldKind) -> Rows {
    match kind {
        LegalHoldKind::Customer => ROWS,
        LegalHoldKind::HostOrder => HOST_ROWS,
    }
}

fn id_key(id: &[u8; 16]) -> HeldKey {
    let mut key = [0; 17];
    key[0] = 1;
    key[1..].copy_from_slice(id);
    key
}

fn held_key(target: &LegalHoldTarget) -> HeldKey {
    match target {
        LegalHoldTarget::Record(id) | LegalHoldTarget::GatePartition(Some(id)) => {
            id_key(id.as_bytes())
        }
        LegalHoldTarget::GatePartition(None) => [0; 17],
    }
}

/// Who a hold event names (C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HoldActor {
    pub(crate) kind: LegalHoldActorKind,
    pub(crate) id: Option<String>,
    /// The delete was a privacy erasure request (C5).
    pub(crate) privacy_erase: bool,
}

impl HoldActor {
    pub(crate) const UNATTRIBUTED: Self = Self::new(LegalHoldActorKind::Unattributed, None);
    pub(crate) const TIMER: Self = Self::new(LegalHoldActorKind::Timer, None);

    pub(crate) const fn new(kind: LegalHoldActorKind, id: Option<String>) -> Self {
        Self {
            kind,
            id,
            privacy_erase: false,
        }
    }

    pub(crate) fn owner(actor: EntityId) -> Self {
        Self::new(LegalHoldActorKind::Owner, Some(actor.to_hex()))
    }

    pub(crate) fn host(operator: &str) -> Self {
        Self::new(LegalHoldActorKind::Host, Some(operator.to_owned()))
    }

    #[must_use]
    pub(crate) fn privacy(mut self, privacy_erase: bool) -> Self {
        self.privacy_erase = privacy_erase;
        self
    }
}

/// A per-vault wake for a HOST order's prospective capture worker
/// (LEGAL-HOLD-USE = B as a clone, FIX 13866). A writer that seals a new
/// message into an outbox bumps it inside that writer; the worker records the
/// generation, then takes the LMDB writer as a barrier before it reads, so a
/// bump it saw is never read before its writer ended. Never persisted.
#[derive(Debug, Default)]
pub(crate) struct ProspectiveWake {
    generation: Mutex<u64>,
    changed: std::sync::Condvar,
}

impl ProspectiveWake {
    /// The current generation.
    pub(crate) fn generation(&self) -> u64 {
        *self
            .generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves the generation and wakes every waiter.
    pub(crate) fn bump(&self) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *generation = generation.wrapping_add(1);
        self.changed.notify_all();
    }

    /// Waits until the generation is no longer `seen`, or `timeout` passes.
    pub(crate) fn wait_past(&self, seen: u64, timeout: std::time::Duration) {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .changed
            .wait_timeout_while(generation, timeout, |generation| *generation == seen)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// The hold row `id`, customer or host-order.
pub(crate) fn hold_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<LegalHold>> {
    match ROWS.get(dbs, txn, id)? {
        Some(hold) => Ok(Some(hold)),
        None => HOST_ROWS.get(dbs, txn, id),
    }
}

/// Every hold row, standing or released, customer then host-order.
pub(crate) fn holds_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<Vec<LegalHold>> {
    let mut holds: Vec<LegalHold> = ROWS
        .scan(dbs, txn)?
        .into_iter()
        .map(|(_, hold)| hold)
        .collect();
    holds.extend(HOST_ROWS.scan(dbs, txn)?.into_iter().map(|(_, hold)| hold));
    Ok(holds)
}

/// Writes `hold`. No hold indexes its targets (LEGAL-HOLD-USE = B, ARCH-0038
/// #legal-hold-clone-ruling).
pub(crate) fn put_hold_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &LegalHold,
) -> Result<()> {
    rows_of(hold.kind).put(dbs, txn, &hold.hold_id, hold)
}

impl Store {
    /// THE legal-hold check (C7). Every byte-destroying path calls it inside
    /// the transaction that destroys, for every id it destroys, whoever acts:
    /// agent, timer, member or owner. No legal hold refuses any more
    /// (LEGAL-HOLD-USE = B, ARCH-0038 #legal-hold-clone-ruling): every hold
    /// keeps its sealed copy outside the vault, and erases, deletes and
    /// backup expiry run as they would without it. Only a cooperative
    /// restriction refuses now, with absence (`EntityNotFound`), and no
    /// refusal is logged, so `_actor` names no one in any log.
    pub(crate) fn reject_legal_holds_in_txn(
        &self,
        txn: &RoTxn<'_>,
        ids: &[EntityId],
        _actor: &HoldActor,
    ) -> Result<()> {
        for id in ids {
            self.reject_held_key_in_txn(txn, Some(LegalHoldTarget::Record(*id)))?;
        }
        Ok(())
    }

    /// [`Self::reject_legal_holds_in_txn`] for one id, from a seam that knows
    /// no actor.
    pub(crate) fn reject_legal_hold_in_txn(&self, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<()> {
        let target = EntityId::from_bytes(*id).ok().map(LegalHoldTarget::Record);
        self.reject_held_key_in_txn(txn, target)
    }

    /// Absence while a cooperative restriction stands on the record `target`
    /// names; no hold refuses.
    fn reject_held_key_in_txn(
        &self,
        txn: &RoTxn<'_>,
        target: Option<LegalHoldTarget>,
    ) -> Result<()> {
        if let Some(LegalHoldTarget::Record(record)) = target
            && cooperative_restriction_active_in_txn(self, txn, &record)?
        {
            return Err(Error::EntityNotFound);
        }
        Ok(())
    }
}

/// The gate-decision partition door's own hold on `target`: one row per
/// partition, its id derived from the partition, so placing it twice is one
/// hold and releasing it lifts that hold alone.
pub(crate) fn set_partition_hold_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    target: LegalHoldTarget,
    held: bool,
    now: u64,
) -> Result<()> {
    let mut seed = b"legal_hold:gate_partition:v1".to_vec();
    seed.extend_from_slice(&held_key(&target));
    let digest = blake3::hash(&seed);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    let hold_id = EntityId::from_bytes(id)?;
    let existing = ROWS.get(dbs, txn, &hold_id)?;
    let actor = HoldActor::new(LegalHoldActorKind::Host, None);
    match (existing, held) {
        (Some(hold), true) if hold.stands() => Ok(()),
        (Some(mut hold), true) => {
            hold.lifted_at = None;
            hold.placed_at = now;
            put_hold_in_txn(dbs, txn, &hold)?;
            log_in_txn(
                dbs,
                txn,
                &hold,
                LegalHoldEventKind::Placed,
                LegalHoldReason::HostPlaced,
                hold.targets.clone(),
                &actor,
                now,
                None,
            )
        }
        (None, true) => {
            let hold = LegalHold {
                hold_id,
                kind: LegalHoldKind::Customer,
                targets: vec![target],
                placed_by: None,
                placed_by_kind: LegalHoldActorKind::Host,
                placed_at: now,
                ends_at: None,
                secret_until: None,
                matter_ref: None,
                legal_basis_ref: None,
                jurisdiction: None,
                issuing_authority_ref: None,
                lifted_at: None,
                owner_told: true,
                requires_non_use: false,
                clone_captures: Vec::new(),
            };
            put_hold_in_txn(dbs, txn, &hold)?;
            log_in_txn(
                dbs,
                txn,
                &hold,
                LegalHoldEventKind::Placed,
                LegalHoldReason::HostPlaced,
                vec![target],
                &actor,
                now,
                None,
            )
        }
        (Some(mut hold), false) if hold.stands() => {
            hold.lifted_at = Some(now);
            put_hold_in_txn(dbs, txn, &hold)?;
            log_in_txn(
                dbs,
                txn,
                &hold,
                LegalHoldEventKind::Lifted,
                LegalHoldReason::HostReleased,
                hold.targets.clone(),
                &actor,
                now,
                None,
            )
        }
        (_, false) => Ok(()),
    }
}

/// When a released hold's log rows expire: its release plus 24 calendar
/// months (C3).
fn retention_end(lifted_at: u64) -> u64 {
    let months = chrono::Months::new(LEGAL_HOLD_LOG_RETENTION_MONTHS);
    i64::try_from(lifted_at)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .and_then(|at| at.checked_add_months(months))
        .and_then(|end| u64::try_from(end.timestamp()).ok())
        .unwrap_or(u64::MAX)
}

/// Drops each released hold's log rows and its row once the release is 24
/// calendar months past (C3). A standing hold keeps all of its rows, and one
/// hold's expiry never touches another's. Returns the rows removed.
pub(crate) fn expire_in_txn(dbs: &impl SideTableDbs, txn: &mut RwTxn<'_>, now: u64) -> Result<u64> {
    let mut removed = 0_u64;
    for rows in [ROWS, HOST_ROWS] {
        for (id, hold) in rows.scan(dbs, txn)? {
            let Some(lifted) = hold.lifted_at else {
                continue;
            };
            if now < retention_end(lifted) {
                continue;
            }
            let dropped = events::drop_events_in_txn(dbs, txn, &id)?;
            rows.delete(dbs, txn, &id)?;
            removed = removed.saturating_add(dropped).saturating_add(1);
        }
    }
    Ok(removed)
}
