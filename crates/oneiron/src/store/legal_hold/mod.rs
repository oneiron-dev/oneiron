//! The one legal-hold store (OF-470, design B; ARCH-0038 #legal-hold).
//!
//! A hold is a typed row naming records or gate-decision partitions. The
//! target index beside it is what every byte-destroying path reads, inside
//! the transaction that destroys ([`Store::reject_legal_holds_in_txn`]).
//! Several holds may name one record; each lifts on its own.
//!
//! Customer holds, the owner-visible log, confirmed-erase links and use
//! limits are canonical rows a restore keeps live. Host-order holds and the
//! host-only log sit under `legal_hold:host:`, a runtime prefix no
//! checkpoint image carries, so an owner backup or export never holds an
//! order or its reference (C2).

mod events;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

pub(crate) use events::{host_events_in_txn, log_in_txn, owner_events_in_txn};

use crate::deletion::{
    LEGAL_HOLD_DEFERRAL, LEGAL_HOLD_LOG_RETENTION_MONTHS, LEGAL_HOLD_REFUSAL, LegalHold,
    LegalHoldActorKind, LegalHoldEventKind, LegalHoldKind, LegalHoldReason, LegalHoldTarget,
    LegalHoldUseLimit,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable, SideTableDbs};
use crate::store::Store;

/// The index spelling of what a hold holds: `1` then the id for a record or
/// a claim's partition (the two hold together), all zero for the
/// claim-free partition.
type HeldKey = [u8; 17];
type Rows = SideTable<EntityId, LegalHold, Named>;
type Targets = SideTable<(HeldKey, EntityId), (), Raw>;

/// Customer holds. Key: id16 (hold).
const ROWS: Rows = SideTable::new(&side_table::LEGAL_HOLD_ROW);
/// What each standing customer hold holds. Key: held key (17) + id16 (hold).
const TARGETS: Targets = SideTable::new(&side_table::LEGAL_HOLD_TARGET);
/// Host-order holds. Key: id16 (hold).
const HOST_ROWS: Rows = SideTable::new(&side_table::LEGAL_HOLD_HOST_ROW);
/// What each standing host-order hold holds. Key: held key (17) + id16 (hold).
const HOST_TARGETS: Targets = SideTable::new(&side_table::LEGAL_HOLD_HOST_TARGET);
/// An owner erase a host order keeps waiting. Key: id16 (record).
const PENDING_ERASES: SideTable<EntityId, PendingErase, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_PENDING_ERASE);
/// The customer holds an owner's confirm lifted from a record, until its
/// deletion receipt completes. Key: id16 (record).
const ERASE_LINKS: SideTable<EntityId, EraseLink, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_ERASE_LINK);
/// The host orders an owner's confirmed erase met. Key: id16 (record).
const HOST_ERASE_LINKS: SideTable<EntityId, EraseLink, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_HOST_ERASE_LINK);
/// Records kept after a refused privacy erasure (C6). Key: id16 (record).
const USE_LIMITS: SideTable<EntityId, LegalHoldUseLimit, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_USE_LIMIT);

/// An owner's confirmed erase that waits on a host order. It names no hold,
/// so its row tells the owner nothing an order keeps secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingErase {
    confirmed_by: Option<String>,
    confirmed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseLink {
    holds: Vec<EntityId>,
}

const fn tables(kind: LegalHoldKind) -> (Rows, Targets) {
    match kind {
        LegalHoldKind::Customer => (ROWS, TARGETS),
        LegalHoldKind::HostOrder => (HOST_ROWS, HOST_TARGETS),
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

/// Whether `target` holds the record or claim partition `id`.
pub(crate) fn names_id(target: &LegalHoldTarget, id: &EntityId) -> bool {
    held_key(target) == id_key(id.as_bytes())
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

/// One refused delete, waiting for its hold log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusalNote {
    hold: EntityId,
    target: LegalHoldTarget,
    actor: HoldActor,
    at: u64,
}

impl RefusalNote {
    /// The same refusal, whenever it happened.
    fn same(&self, other: &Self) -> bool {
        self.hold == other.hold && self.target == other.target && self.actor == other.actor
    }
}

/// Refusals not yet in a hold log. The refusing transaction rolls back, so
/// the door that owns it logs them in a short write of its own once that
/// writer has ended, before it returns
/// ([`Store::flush_legal_hold_refusals_settled`]). A note a failed log write
/// put back waits here for the next flush. Never persisted.
#[derive(Debug, Default)]
pub(crate) struct LegalHoldRefusals(Mutex<Vec<RefusalNote>>);

impl LegalHoldRefusals {
    fn note(&self, note: RefusalNote) {
        let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // One delete checks before publication and again in its writer.
        if queue.iter().any(|queued| queued.same(&note)) {
            return;
        }
        queue.push(note);
    }

    fn is_empty(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    fn take(&self) -> Vec<RefusalNote> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Puts back refusals a failed flush did not write.
    fn restore(&self, notes: Vec<RefusalNote>) {
        for note in notes {
            self.note(note);
        }
    }
}

/// The ids of the standing holds on `key`, customer then host-order.
fn standing_on_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    key: &HeldKey,
) -> Result<Vec<EntityId>> {
    let mut holds: Vec<EntityId> = TARGETS
        .scan_keys(dbs, txn, key)?
        .into_iter()
        .map(|(_, hold)| hold)
        .collect();
    holds.extend(
        HOST_TARGETS
            .scan_keys(dbs, txn, key)?
            .into_iter()
            .map(|(_, hold)| hold),
    );
    Ok(holds)
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

/// The standing holds that name `target`.
pub(crate) fn holds_on_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    target: &LegalHoldTarget,
) -> Result<Vec<LegalHold>> {
    standing_on_in_txn(dbs, txn, &held_key(target))?
        .iter()
        .map(|id| standing_row_in_txn(dbs, txn, id))
        .collect()
}

fn standing_row_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<LegalHold> {
    let Some(hold) = hold_in_txn(dbs, txn, id)? else {
        return Err(Error::CorruptedIndex("legal hold target"));
    };
    Ok(hold)
}

/// Whether a standing hold names the record or claim partition `id`, for a
/// door with no store handle. Read inside the destroying transaction.
pub(crate) fn held_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<bool> {
    Ok(!standing_on_in_txn(dbs, txn, &id_key(id))?.is_empty())
}

/// Whether a standing hold names the gate-decision partition `claim`
/// (`None`: the claim-free one).
pub(crate) fn partition_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    claim: Option<&[u8; 16]>,
) -> Result<bool> {
    let key = claim.map_or([0; 17], id_key);
    Ok(!standing_on_in_txn(dbs, txn, &key)?.is_empty())
}

/// [`held_in_txn`] as a refusal, for a door with no store handle.
pub(crate) fn refuse_held_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    id: &[u8; 16],
) -> Result<()> {
    if held_in_txn(dbs, txn, id)? {
        return Err(Error::InvalidConfig(LEGAL_HOLD_REFUSAL.to_owned()));
    }
    Ok(())
}

/// Writes `hold`, keeping its target index exact: a standing hold indexes
/// every target it names, a lifted one none.
pub(crate) fn put_hold_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &LegalHold,
) -> Result<()> {
    let (rows, targets) = tables(hold.kind);
    let keys = |hold: &LegalHold| -> BTreeSet<HeldKey> {
        if hold.stands() {
            hold.targets.iter().map(held_key).collect()
        } else {
            BTreeSet::new()
        }
    };
    let before = rows
        .get(dbs, txn, &hold.hold_id)?
        .map(|old| keys(&old))
        .unwrap_or_default();
    let after = keys(hold);
    for key in before.difference(&after) {
        targets.delete(dbs, txn, &(*key, hold.hold_id))?;
    }
    for key in after.difference(&before) {
        targets.put(dbs, txn, &(*key, hold.hold_id), &())?;
    }
    rows.put(dbs, txn, &hold.hold_id, hold)
}

impl Store {
    /// THE legal-hold check (C7). Every byte-destroying path calls it inside
    /// the transaction that destroys, for every id it destroys, whoever acts:
    /// agent, timer, member or owner. A held id fails with the named refusal
    /// [`LEGAL_HOLD_REFUSAL`], or with [`LEGAL_HOLD_DEFERRAL`] when only a
    /// secret order holds it. The owner lifts a customer hold only through
    /// `Vault::confirm_lift_legal_hold_and_erase`. The refusal is queued for
    /// the hold log, since the refusing transaction rolls back.
    pub(crate) fn reject_legal_holds_in_txn(
        &self,
        txn: &RoTxn<'_>,
        ids: &[EntityId],
        actor: &HoldActor,
    ) -> Result<()> {
        for id in ids {
            self.reject_held_key_in_txn(
                txn,
                &id_key(id.as_bytes()),
                Some(LegalHoldTarget::Record(*id)),
                actor,
            )?;
        }
        Ok(())
    }

    /// [`Self::reject_legal_holds_in_txn`] for one id, from a seam that knows
    /// no actor.
    pub(crate) fn reject_legal_hold_in_txn(&self, txn: &RoTxn<'_>, id: &[u8; 16]) -> Result<()> {
        let target = EntityId::from_bytes(*id).ok().map(LegalHoldTarget::Record);
        self.reject_held_key_in_txn(txn, &id_key(id), target, &HoldActor::UNATTRIBUTED)
    }

    fn reject_held_key_in_txn(
        &self,
        txn: &RoTxn<'_>,
        key: &HeldKey,
        target: Option<LegalHoldTarget>,
        actor: &HoldActor,
    ) -> Result<()> {
        let holds = standing_on_in_txn(self, txn, key)?;
        if holds.is_empty() {
            return Ok(());
        }
        let now = self.clock.now_recorded_at();
        let mut only_secret = true;
        for id in holds {
            only_secret &= standing_row_in_txn(self, txn, &id)?.secret_at(now);
            if let Some(target) = target {
                let note = RefusalNote {
                    hold: id,
                    target,
                    actor: actor.clone(),
                    at: now,
                };
                self.legal_hold_refusals.note(note);
            }
        }
        let refusal = if only_secret {
            LEGAL_HOLD_DEFERRAL
        } else {
            LEGAL_HOLD_REFUSAL
        };
        Err(Error::InvalidConfig(refusal.to_owned()))
    }

    /// Writes the queued refusals to their hold logs in one raw write of its
    /// own, never through the group commit (whose return flushes here). Only
    /// on a thread that holds no writer. A failed write puts them back.
    /// Returns how many were written.
    pub(crate) fn flush_legal_hold_refusals_now(&self) -> Result<u64> {
        let notes = self.legal_hold_refusals.take();
        if notes.is_empty() {
            return Ok(0);
        }
        let hosted = hosts_bytes(self);
        let written = self.env.write_txn().and_then(|mut txn| {
            let written = flush_refusals_in_txn(self, &mut txn, &notes, hosted)?;
            txn.commit()?;
            Ok(written)
        });
        if written.is_err() {
            self.legal_hold_refusals.restore(notes);
        }
        written
    }

    /// The door's flush, once the writer that refused has ended: its refusals
    /// reach their logs before the door returns. A failed write leaves them
    /// queued for the next flush and never replaces the door's own result.
    /// A thread still holding a session segment permit leaves them queued
    /// too: that permit is taken under the base writer, never before it.
    pub(crate) fn flush_legal_hold_refusals_settled(&self) {
        if self.legal_hold_refusals.is_empty() || crate::session_overlay::txn_segment_installed() {
            return;
        }
        if let Err(error) = self.flush_legal_hold_refusals_now() {
            tracing::warn!(
                error = %error,
                "legal hold refusals kept for the next flush"
            );
        }
    }
}

/// Oneiron hosts this vault's bytes: Cloud, or our relay copy of a
/// self-hosted vault.
fn hosts_bytes(store: &Store) -> bool {
    matches!(
        store.privacy_posture,
        crate::HostingPrivacyPosture::Hosted | crate::HostingPrivacyPosture::Relay
    )
}

/// Writes queued refusals to their hold logs. A refused privacy erasure keeps
/// the held record for that legal reason only: where Oneiron hosts the bytes
/// it gets a use limit (C5, C6). Returns how many were written.
pub(crate) fn flush_refusals_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    notes: &[RefusalNote],
    hosted: bool,
) -> Result<u64> {
    let mut written = 0_u64;
    for note in notes {
        // A hold its retention already dropped has no log left.
        let Some(hold) = hold_in_txn(dbs, txn, &note.hold)? else {
            continue;
        };
        let reason = if note.actor.privacy_erase {
            LegalHoldReason::PrivacyEraseKept
        } else {
            LegalHoldReason::HeldRecord
        };
        log_in_txn(
            dbs,
            txn,
            &hold,
            LegalHoldEventKind::DeleteRefused,
            reason,
            vec![note.target],
            &note.actor,
            note.at,
            None,
        )?;
        if let LegalHoldTarget::Record(record) = note.target
            && note.actor.privacy_erase
            && hosted
        {
            keep_use_limited_in_txn(dbs, txn, record, note.at)?;
        }
        written = written.saturating_add(1);
    }
    Ok(written)
}

fn keep_use_limited_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: EntityId,
    at: u64,
) -> Result<()> {
    if USE_LIMITS.contains(dbs, txn, &record)? {
        return Ok(());
    }
    USE_LIMITS.put(
        dbs,
        txn,
        &record,
        &LegalHoldUseLimit {
            record,
            since: at,
            reason: LegalHoldReason::PrivacyEraseKept,
        },
    )
}

/// A privacy erasure request over `records` (C5): returns the records no
/// hold names, for the caller to erase, and the held ones it keeps. Each
/// held record logs a refusal with its reason; where Oneiron hosts the bytes
/// it is kept under a use limit (C6). It never lifts or skips a hold.
pub(crate) fn split_privacy_erase_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    records: &[EntityId],
    actor: &HoldActor,
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let now = store.clock.now_recorded_at();
    let hosted = hosts_bytes(store);
    let actor = actor.clone().privacy(true);
    let (mut erase, mut kept) = (Vec::new(), Vec::new());
    for record in records {
        let target = LegalHoldTarget::Record(*record);
        let holds = holds_on_in_txn(store, txn, &target)?;
        if holds.is_empty() {
            erase.push(*record);
            continue;
        }
        let notes: Vec<RefusalNote> = holds
            .iter()
            .map(|hold| RefusalNote {
                hold: hold.hold_id,
                target,
                actor: actor.clone(),
                at: now,
            })
            .collect();
        flush_refusals_in_txn(store, txn, &notes, hosted)?;
        kept.push(*record);
    }
    Ok((erase, kept))
}

/// The C6 use limit on `record`, if it was kept after a refused privacy
/// erasure.
pub(crate) fn use_limit_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<LegalHoldUseLimit>> {
    USE_LIMITS.get(dbs, txn, record)
}

/// Records that an owner confirmed erasing `record` while a host order keeps
/// it: the erase runs once nothing holds it.
pub(crate) fn put_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    confirmed_by: Option<String>,
    at: u64,
) -> Result<()> {
    PENDING_ERASES.put(
        dbs,
        txn,
        record,
        &PendingErase {
            confirmed_by,
            confirmed_at: at,
        },
    )
}

/// The records whose confirmed erase waits, and that nothing holds now.
pub(crate) fn due_erases_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut due = Vec::new();
    for record in PENDING_ERASES.scan_keys(dbs, txn, &[])? {
        if !held_in_txn(dbs, txn, record.as_bytes())? {
            due.push(record);
        }
    }
    Ok(due)
}

pub(crate) fn drop_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
) -> Result<()> {
    PENDING_ERASES.delete(dbs, txn, record)?;
    Ok(())
}

/// Links `record`'s coming deletion receipt to `hold`, for its "erase
/// completed" event (C4).
pub(crate) fn link_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    hold: &LegalHold,
) -> Result<()> {
    let links = match hold.kind {
        LegalHoldKind::Customer => ERASE_LINKS,
        LegalHoldKind::HostOrder => HOST_ERASE_LINKS,
    };
    let mut link = links.get(dbs, txn, record)?.unwrap_or_default();
    if !link.holds.contains(&hold.hold_id) {
        link.holds.push(hold.hold_id);
        links.put(dbs, txn, record, &link)?;
    }
    Ok(())
}

/// "Erase completed" (C4): the deletion receipt over `records` now has both
/// `hard_purge_complete_at` and `sweep_complete_at`. Logs one event, with
/// the receipt's `request_id`, for each hold an owner's confirm lifted or met
/// on each record, then drops the link, so a retried sweep logs it once.
pub(crate) fn note_erase_completed_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    records: &[String],
    request_id: &str,
    at: u64,
) -> Result<()> {
    for hex in records {
        let Ok(record) = EntityId::from_hex(hex) else {
            continue;
        };
        for links in [ERASE_LINKS, HOST_ERASE_LINKS] {
            let Some(link) = links.get(dbs, txn, &record)? else {
                continue;
            };
            for id in &link.holds {
                if let Some(hold) = hold_in_txn(dbs, txn, id)? {
                    log_in_txn(
                        dbs,
                        txn,
                        &hold,
                        LegalHoldEventKind::EraseCompleted,
                        LegalHoldReason::ReceiptCompleted,
                        vec![LegalHoldTarget::Record(record)],
                        &HoldActor::TIMER,
                        at,
                        Some(request_id.to_owned()),
                    )?;
                }
            }
            links.delete(dbs, txn, &record)?;
        }
    }
    Ok(())
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
                lifted_at: None,
                owner_told: true,
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

/// The age sweep met a held partition with rows past the horizon: one
/// timer refusal per hold, not one per pass while the hold stands.
pub(crate) fn log_timer_refusal_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    target: LegalHoldTarget,
    at: u64,
) -> Result<()> {
    for hold in holds_on_in_txn(dbs, txn, &target)? {
        let last = events::last_event_in_txn(dbs, txn, &hold)?;
        let repeated = last.is_some_and(|last| {
            last.event == LegalHoldEventKind::DeleteRefused
                && last.actor_kind == LegalHoldActorKind::Timer
                && last.targets == [target]
        });
        if !repeated {
            log_in_txn(
                dbs,
                txn,
                &hold,
                LegalHoldEventKind::DeleteRefused,
                LegalHoldReason::HeldRecord,
                vec![target],
                &HoldActor::TIMER,
                at,
                None,
            )?;
        }
    }
    Ok(())
}

/// The `vault_meta` prefixes of the two target indexes, for the checkpoint
/// custody reader.
pub(crate) fn target_prefixes() -> [&'static [u8]; 2] {
    [TARGETS.decl().prefix, HOST_TARGETS.decl().prefix]
}

/// Whether `rows` (a checkpoint's, or a live vault's custody rows) hold a
/// standing hold on the claim partition `claim`.
pub(crate) fn rows_hold_claim(rows: &[(Vec<u8>, Vec<u8>)], claim: &[u8; 16]) -> bool {
    let key = id_key(claim);
    target_prefixes().iter().any(|prefix| {
        let mut wanted = prefix.to_vec();
        wanted.extend_from_slice(&key);
        rows.iter().any(|(stored, _)| stored.starts_with(&wanted))
    })
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
    let mut gone = BTreeSet::new();
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
            gone.insert(id);
        }
    }
    if gone.is_empty() {
        return Ok(removed);
    }
    for links in [ERASE_LINKS, HOST_ERASE_LINKS] {
        let mut changed = BTreeMap::new();
        for (record, mut link) in links.scan(dbs, txn)? {
            let before = link.holds.len();
            link.holds.retain(|hold| !gone.contains(hold));
            if link.holds.len() != before {
                changed.insert(record, link);
            }
        }
        for (record, link) in changed {
            if link.holds.is_empty() {
                links.delete(dbs, txn, &record)?;
            } else {
                links.put(dbs, txn, &record, &link)?;
            }
        }
    }
    Ok(removed)
}

/// Drops what this store keys by an erased record: its use limit and its
/// waiting erase. Its erase links stay for the receipt's completion.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    USE_LIMITS.delete(store, txn, id)?;
    PENDING_ERASES.delete(store, txn, id)?;
    Ok(())
}
