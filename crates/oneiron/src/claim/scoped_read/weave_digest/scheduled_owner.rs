//! FIX 1259: a due Owner schedule renders the Owner report with no present
//! opener. The authority is the owner's own recorded schedule: its writer
//! bound `Owner(id)` to his authenticated live Owner proof
//! (`Vault::set_weave_digest_schedule`), and [`ScheduledOwner`] is made
//! only from that persisted row. Each projection and the publication read
//! the row again, byte for byte, with the live-owner census (a co-Owner as
//! well as the first, each a live PERSON) in their own transaction; the
//! queued lens's model step reads the saved period as the owner's
//! background lens does. A person's standing, a stored credential, an
//! Owner proof made from an id, a timer Admin and `Person(owner)` play no
//! part.
//!
//! The timer tries the scheduled render first and publishes as an open
//! would: the same schedule bytes and report in its writer, the source
//! index, the save and cadence advance, and the generate step queued. The
//! period's due notice and his exposure to it go out exactly once, with the
//! publication; no human open is recorded and nothing reads as one. Any
//! failure of the new path sends today's due notice instead
//! ([`WEAVE_OWNER_SCHEDULE_FAILURE`]), never a refusal, a hold of its own
//! or a new retry interval. Live opens and saved periods are unchanged.

use super::super::ScopedRead;
use super::super::weave_lens::snapshot_still_served;
use super::{SCHEDULE_PREFIX, StoredWeaveDigest};
use super::{
    WeaveDigestReader, WireDigest, WireSchedule, dependencies, digest_key, digest_row_in,
    index_source_in_txn, invalid, put_digest_row_in_txn, sources_live_in_txn,
};
use crate::claim::ScopedReadActorKey;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// What a due Owner schedule does when its scheduled render does not
/// publish (CALLS `FIX 1259 WEAVE_OWNER_SCHEDULE_FAILURE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduleFailure {
    /// Today's due notice: the period waits for the owner to open it.
    DueNoticeFallback,
}

const WEAVE_OWNER_SCHEDULE_FAILURE: ScheduleFailure = ScheduleFailure::DueNoticeFallback;

/// A due Owner schedule's recorded Owner: the owner its row names, the
/// row's key and its bytes as the timer read them. Made only here, from a
/// persisted Owner schedule row; never an Owner proof.
pub(in crate::claim::scoped_read) struct ScheduledOwner {
    owner: EntityId,
    key: Vec<u8>,
    schedule: Vec<u8>,
}

/// The parts of an Owner schedule a scheduled period stands on: its cadence
/// and its recipe, never its due time or hold, so the cadence's own advance
/// keeps it. A digest of their serialized form.
fn schedule_basis(wire: &WireSchedule) -> Result<String> {
    let bytes = serde_json::to_vec(&(wire.cadence, &wire.recipe)).map_err(|_| invalid())?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl ScheduledOwner {
    /// The recorded Owner of the schedule row `schedule` stored at `key`,
    /// when `key` is `owner`'s own Owner schedule key.
    fn recorded(owner: EntityId, key: &[u8], schedule: &[u8]) -> Option<Self> {
        (WeaveDigestReader::from_schedule_key(key) == Some(WeaveDigestReader::Owner(owner))).then(
            || Self {
                owner,
                key: key.to_vec(),
                schedule: schedule.to_vec(),
            },
        )
    }

    /// The Owner the schedule row names: never a proof by itself.
    pub(in crate::claim::scoped_read) fn owner(&self) -> EntityId {
        self.owner
    }

    /// The recorded Owner, while he still holds in `txn`: `read` is his own
    /// lane, his schedule row is still exactly the bytes recorded, and the
    /// live-owner census counts him.
    ///
    /// # Errors
    /// When any part does not hold, or a check does not answer.
    pub(in crate::claim::scoped_read) fn current_in(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> Result<EntityId> {
        if read.actor_key.actor_ref() != self.owner.to_hex()
            || read.vault.store.vault_meta.get(txn, &self.key)?.as_deref()
                != Some(self.schedule.as_slice())
            || !crate::policy_model::is_live_vault_owner_in_txn(read.vault, txn, &self.owner)?
        {
            return Err(Error::InvalidConfig(
                "a due owner schedule's recorded owner is no longer current".into(),
            ));
        }
        Ok(self.owner)
    }
}

impl Vault {
    /// The deadline timer's Owner arm: the scheduled render first, then, if
    /// it published nothing, today's due notice. `true`: the row was served.
    pub(super) fn serve_due_owner_weave_digest(
        &self,
        owner: EntityId,
        key: &[u8],
        saved: &[u8],
        now: u64,
    ) -> Result<bool> {
        match self.publish_scheduled_owner_weave_digest(owner, key, saved, now) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "a due owner schedule did not render; its due notice goes out (FIX 1259)"
            ),
        }
        match WEAVE_OWNER_SCHEDULE_FAILURE {
            ScheduleFailure::DueNoticeFallback => {
                self.notify_owner_weave_digest_due(owner, key, saved, now)
            }
        }
    }

    /// Renders and publishes `owner`'s due period from his recorded
    /// schedule `saved` at `key` (see the module doc). `false`: nothing was
    /// published, the row or the report moved, or he is no longer this
    /// schedule's live Owner.
    fn publish_scheduled_owner_weave_digest(
        &self,
        owner: EntityId,
        key: &[u8],
        saved: &[u8],
        now: u64,
    ) -> Result<bool> {
        let Some(scheduled) = ScheduledOwner::recorded(owner, key, saved) else {
            return Ok(false);
        };
        let reader = WeaveDigestReader::Owner(owner);
        let wire: WireSchedule = serde_json::from_slice(saved).map_err(|_| invalid())?;
        let scheduled_for = wire.next_due_at;
        if now < scheduled_for {
            return Ok(false);
        }
        let cadence = wire.cadence;
        let next_due_at = wire.next_boundary_after(now)?;
        let basis = schedule_basis(&wire)?;
        let row = wire.into_row(reader)?;
        // His own Owner lane, never a human's narrower one, its owner proved
        // in each read by the live-owner census rather than an actor binding:
        // a live co-Owner with none reads as himself.
        let read = self.scoped_read(ScopedReadActorKey::vault_owner_by_census(owner));
        let report = {
            // Its grants judge at the refreshed persisted clock (FIX 8671).
            let txn = read.grant_read_txn()?;
            read.weave_report_for_scheduled_owner_in_txn(&txn, &scheduled, &row.recipe)?
        };
        let sources = dependencies::indexed_sources(&report.value)?;
        // The period keeps the schedule it rendered from, rechecked before
        // the period reaches a model.
        let mut published = WireDigest::from_report(now, &report)?;
        published.scheduled_basis = Some(basis);
        let bytes = serde_json::to_vec(&published).map_err(|_| invalid())?;
        let next = serde_json::to_vec(&WireSchedule {
            next_due_at,
            ..WireSchedule::from_row(&row)
        })
        .map_err(|_| invalid())?;
        let digest_key = digest_key(reader, scheduled_for);
        let notice =
            self.with_write_txn_grouped(|txn| {
                if self.store.vault_meta.get(&*txn, key)?.as_deref() != Some(saved) {
                    return Ok(None);
                }
                if !sources_live_in_txn(&self.store, txn, &report.value)? {
                    return Ok(None);
                }
                // The same projection in this writer's snapshot, his schedule
                // and standing read again: each row it saves must still serve,
                // and a loop decision the ledger gained since joins the next
                // period (FIX 7694).
                let current =
                    read.weave_report_for_scheduled_owner_in_txn(txn, &scheduled, &row.recipe)?;
                if current.receipt != report.receipt
                    || !snapshot_still_served(&report.value, &current.value)
                {
                    return Ok(None);
                }
                if let Some(raw) = digest_row_in(&self.store, txn, &digest_key)? {
                    let previous: WireDigest =
                        serde_json::from_slice(&raw).map_err(|_| invalid())?;
                    for source in dependencies::indexed_sources(&previous.into_report()?.value)? {
                        index_source_in_txn(&self.store, txn, &source, &digest_key, false)?;
                    }
                }
                for source in &sources {
                    index_source_in_txn(&self.store, txn, source, &digest_key, true)?;
                }
                put_digest_row_in_txn(&self.store, txn, &digest_key, &bytes)?;
                self.store.vault_meta.put(txn, key, &next)?;
                // The period's one due notice, in this same write: the owner
                // learns of it as he always has, and his open finds it saved.
                let notice =
                    self.record_notification_in_txn(txn, &reader.notification(scheduled_for, now))?;
                // The lens's generate step renders the period on the Dreamer's
                // lent model, queued in this same write.
                if report
                    .value
                    .sections
                    .iter()
                    .any(|section| !section.items.is_empty())
                {
                    crate::dreamer_runner::DreamerRunnerStore::new(self)
                        .enqueue_weave_lens_in_txn(txn, reader, scheduled_for, now)?;
                }
                Ok(Some(notice))
            })?;
        let Some(notice) = notice else {
            return Ok(false);
        };
        // His own exposure to the period, for the Coach (FIX 5495), in its
        // own write after the notice's; never his open.
        self.note_owner_weave_digest_notice(owner, scheduled_for, cadence, notice, now);
        Ok(true)
    }

    /// A scheduled Owner period as the lens's generate step reads it, before
    /// any model sees it; `None` when the period is no scheduled publication
    /// (or does not read here), so the owner's existing read serves it.
    pub(super) fn scheduled_owner_period_for_lens(
        &self,
        owner: EntityId,
        scheduled_for: u64,
    ) -> Option<Result<Option<StoredWeaveDigest>>> {
        let reader = WeaveDigestReader::Owner(owner);
        let basis = {
            let txn = self.store.env.read_txn().ok()?;
            let raw =
                digest_row_in(&self.store, &txn, &digest_key(reader, scheduled_for)).ok()??;
            serde_json::from_slice::<WireDigest>(&raw)
                .ok()?
                .scheduled_basis?
        };
        Some(self.scheduled_owner_lens_read(owner, scheduled_for, &basis))
    }

    /// [`Self::scheduled_owner_period_for_lens`] for a period published
    /// from the schedule `basis`: in this pre-model snapshot his schedule
    /// must still stand on that basis (its cadence's advance aside) and the
    /// live-owner census still count him; else no model sees the period.
    fn scheduled_owner_lens_read(
        &self,
        owner: EntityId,
        scheduled_for: u64,
        basis: &str,
    ) -> Result<Option<StoredWeaveDigest>> {
        let reader = WeaveDigestReader::Owner(owner);
        let read = self.scoped_read(ScopedReadActorKey::vault_owner_by_census(owner));
        // Its grants judge at the refreshed persisted clock (FIX 8671).
        let txn = read.grant_read_txn()?;
        let current = match self
            .store
            .vault_meta
            .get(&txn, &reader.key(SCHEDULE_PREFIX))?
        {
            Some(bytes) => match serde_json::from_slice::<WireSchedule>(bytes) {
                Ok(wire) => Some(schedule_basis(&wire)?),
                Err(_) => None,
            },
            None => None,
        };
        if current.as_deref() != Some(basis)
            || !crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &owner)?
        {
            return Ok(None);
        }
        read.saved_weave_digest_in_txn(&txn, reader, scheduled_for, None)
    }

    /// Today's Owner arm, and the scheduled render's fallback: a due row
    /// gets a notice naming its period, then waits for the owner to open
    /// it.
    fn notify_owner_weave_digest_due(
        &self,
        owner: EntityId,
        key: &[u8],
        saved: &[u8],
        now: u64,
    ) -> Result<bool> {
        let wire: WireSchedule = serde_json::from_slice(saved).map_err(|_| invalid())?;
        let scheduled_for = wire.next_due_at;
        let cadence = wire.cadence;
        let held = serde_json::to_vec(&WireSchedule {
            held_until: Some(wire.next_boundary_after(now)?),
            held_because: None,
            ..wire
        })
        .map_err(|_| invalid())?;
        let notice = self.with_write_txn_grouped(|txn| {
            if self.store.vault_meta.get(&*txn, key)?.as_deref() != Some(saved) {
                return Ok(None);
            }
            let notice = self.record_notification_in_txn(
                txn,
                &WeaveDigestReader::Owner(owner).notification(scheduled_for, now),
            )?;
            self.store.vault_meta.put(txn, key, &held)?;
            Ok(Some(notice))
        })?;
        // The owner's own exposure to the period, for the Coach (FIX 5495),
        // in its own write after the notice's.
        if let Some(notice) = notice {
            self.note_owner_weave_digest_notice(owner, scheduled_for, cadence, notice, now);
        }
        Ok(notice.is_some())
    }
}
