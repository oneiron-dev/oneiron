//! The model seats a spent login or subscription parks Dreamer tries on, and the durable
//! available write that wakes them.
//!
//! A seat is one login or subscription, named by [`ModelSeatId`]. A refusal moves the seat's row
//! to [`ModelSeatAvailability::Unavailable`] at a new generation and parks the try typed on that
//! generation; the seat's available write answers one generation and wakes every park of the seat
//! it covers, in its own write. The reset a refusal reported is carried on the row and indexed
//! by time, so the sweep releases what is due; the reset alone wakes nothing.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::{
    DreamerParkWait, DreamerParkedAttemptRecord, DreamerRunnerStore, DreamerTryLease, ModelSeatId,
    PARKED, ParkDreamerAttempt, ParkResumer,
};

/// One seat's durable state, keyed by the seat id.
const SEAT_STATE: SideTable<ModelSeatId, ModelSeatState, Named> =
    SideTable::new(&side_table::MODEL_SEAT_STATE);
/// Seats with a reported reset, keyed by (reset, seat), so the sweep reads what is due.
const SEAT_RESET_DUE: SideTable<(u64, ModelSeatId), (), Named> =
    SideTable::new(&side_table::MODEL_SEAT_RESET_DUE);
/// Seat parks by (seat, attempt), so one available write wakes every park of its seat.
const SEAT_WAITS: SideTable<(ModelSeatId, AttemptId), (), Named> =
    SideTable::new(&side_table::MODEL_SEAT_WAITS);

/// Whether a model seat may take work now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelSeatAvailability {
    /// A refusal parked tries on the seat; its available write has not landed.
    Unavailable,
    /// The seat's available write answered its current generation.
    Available,
}

/// What moved a model seat's row last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelSeatSource {
    /// A refusal parked a try on the seat.
    Refused,
    /// The reported reset passed.
    ResetPassed,
    /// A completed run proved the seat's login works again.
    LoginRestored,
}

/// What a seat-available write answers with: a passed reset or a restored login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelSeatAvailableSource {
    /// The reported reset passed.
    ResetPassed,
    /// A completed run proved the seat's login works again.
    LoginRestored,
}

impl From<ModelSeatAvailableSource> for ModelSeatSource {
    fn from(source: ModelSeatAvailableSource) -> Self {
        match source {
            ModelSeatAvailableSource::ResetPassed => Self::ResetPassed,
            ModelSeatAvailableSource::LoginRestored => Self::LoginRestored,
        }
    }
}

/// One model seat's durable state: whether it may take work, the refusal generation its parks
/// name, the latest refusal's reset, when it last moved, and what moved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSeatState {
    /// Whether the seat may take work now.
    pub availability: ModelSeatAvailability,
    /// The latest refusal's generation; every park of the seat names one at most this.
    pub generation: u64,
    /// The latest refusal's vendor-reported reset, when it named one.
    pub reset_at_s: Option<u64>,
    /// When the row last moved, in store-clock seconds.
    pub changed_at_s: u64,
    /// What moved the row last.
    pub source: ModelSeatSource,
}

/// The seat `record` waits on, when it carries a seat wait.
fn seat_of(record: &DreamerParkedAttemptRecord) -> Option<ModelSeatId> {
    match record.wait.as_ref().map(|wait| &wait.wait) {
        Some(DreamerParkWait::Seat { seat, .. }) => Some(*seat),
        _ => None,
    }
}

/// Indexes `record`'s seat wait, in the writer that parks it.
pub(crate) fn index_seat_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(seat) = seat_of(record) else {
        return Ok(());
    };
    SEAT_WAITS.put(&vault.store, wtxn, &(seat, record.attempt_id), &())
}

/// Drops `record`'s seat-wait row, in the writer that clears or replaces it.
pub(crate) fn unindex_seat_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(seat) = seat_of(record) else {
        return Ok(());
    };
    SEAT_WAITS.delete(&vault.store, wtxn, &(seat, record.attempt_id))?;
    Ok(())
}

/// The typed refusal of a seat-available write nothing was written for.
fn seat_refused(seat: ModelSeatId, answers_generation: u64, reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::ModelSeatAvailableRefused {
        seat,
        answers_generation,
        reason,
    })
}

/// Whether `error` refuses a seat-available write, rather than failing the store.
fn is_seat_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Artifact(ArtifactError::ModelSeatAvailableRefused { .. })
    )
}

impl Vault {
    /// Records a refusal on `seat`: the row moves to Unavailable at generation + 1 (1 for a new
    /// row), its reset becomes this refusal's, and the due entry moves with it. Returns the new
    /// generation, which the refusal's park names.
    pub(crate) fn refuse_model_seat_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        seat: ModelSeatId,
        reset_at_s: Option<u64>,
        now: u64,
    ) -> Result<u64> {
        let previous = SEAT_STATE.get(&self.store, &*wtxn, &seat)?;
        let generation = match &previous {
            Some(row) => row
                .generation
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("model seat generation"))?,
            None => 1,
        };
        if let Some(previous) = &previous
            && previous.reset_at_s != reset_at_s
            && let Some(due) = previous.reset_at_s
        {
            SEAT_RESET_DUE.delete(&self.store, wtxn, &(due, seat))?;
        }
        if let Some(due) = reset_at_s {
            SEAT_RESET_DUE.put(&self.store, wtxn, &(due, seat), &())?;
        }
        SEAT_STATE.put(
            &self.store,
            wtxn,
            &seat,
            &ModelSeatState {
                availability: ModelSeatAvailability::Unavailable,
                generation,
                reset_at_s,
                changed_at_s: now,
                source: ModelSeatSource::Refused,
            },
        )?;
        Ok(generation)
    }

    /// One seat's durable row, if it has one.
    pub fn model_seat_state(&self, seat: ModelSeatId) -> Result<Option<ModelSeatState>> {
        let rtxn = self.store.env.read_txn()?;
        self.model_seat_state_in_txn(&rtxn, seat)
    }

    /// [`Self::model_seat_state`] at `txn`'s revision.
    pub(crate) fn model_seat_state_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        seat: ModelSeatId,
    ) -> Result<Option<ModelSeatState>> {
        SEAT_STATE.get(&self.store, txn, &seat)
    }

    /// Records that `seat` is back, answering `answers_generation` with `source`, and wakes every
    /// park of the seat that generation covers, in one write. Returns the tries it woke.
    ///
    /// Refuses, writing nothing, unless the row exists and is Unavailable at exactly
    /// `answers_generation`, and for [`ModelSeatAvailableSource::ResetPassed`] unless the row's
    /// reset is reported and reached by the recorded now.
    pub fn record_model_seat_available(
        &self,
        seat: ModelSeatId,
        answers_generation: u64,
        source: ModelSeatAvailableSource,
    ) -> Result<Vec<AttemptId>> {
        let resumed = self.with_write_txn_grouped(|wtxn| {
            self.record_model_seat_available_in_txn(wtxn, seat, answers_generation, source)
        })?;
        self.store.notify_attempt_observers();
        if !resumed.is_empty() {
            // The deadline lane arms the woken tries at once.
            self.store.notify_proactivity_changes();
        }
        Ok(resumed)
    }

    /// [`Self::record_model_seat_available`] in the caller's write: the row goes Available at the
    /// answered generation, its due entry goes, and every park of the seat that generation covers
    /// resumes under its own park owner with its notices resolved. A missing row, an Available
    /// row, another generation, or an unreached reset refuses with nothing written.
    pub(crate) fn record_model_seat_available_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        seat: ModelSeatId,
        answers_generation: u64,
        source: ModelSeatAvailableSource,
    ) -> Result<Vec<AttemptId>> {
        let now = self.store.clock.now_recorded_at();
        let row = SEAT_STATE.get(&self.store, &*wtxn, &seat)?;
        let Some(row) = row else {
            return Err(seat_refused(
                seat,
                answers_generation,
                "the seat has no row",
            ));
        };
        if !matches!(row.availability, ModelSeatAvailability::Unavailable) {
            return Err(seat_refused(
                seat,
                answers_generation,
                "the seat is already available",
            ));
        }
        if row.generation != answers_generation {
            return Err(seat_refused(
                seat,
                answers_generation,
                "another generation is current",
            ));
        }
        if matches!(source, ModelSeatAvailableSource::ResetPassed)
            && row.reset_at_s.is_none_or(|reset| reset > now)
        {
            return Err(seat_refused(
                seat,
                answers_generation,
                "the reset has not passed",
            ));
        }
        SEAT_STATE.put(
            &self.store,
            wtxn,
            &seat,
            &ModelSeatState {
                availability: ModelSeatAvailability::Available,
                generation: answers_generation,
                reset_at_s: row.reset_at_s,
                changed_at_s: now,
                source: ModelSeatSource::from(source),
            },
        )?;
        if let Some(due) = row.reset_at_s {
            SEAT_RESET_DUE.delete(&self.store, wtxn, &(due, seat))?;
        }
        self.wake_seat_parks_in_txn(wtxn, seat, answers_generation, now)
    }

    /// Wakes every park of `seat` whose generation `answers` covers, in the caller's write, and
    /// returns the tries it woke. A wait entry with no park, or a park that waits on another seat
    /// now, is stale and goes with the read; a newer generation, a park its resumer does not admit,
    /// and a lease that moved on are left for their own write.
    fn wake_seat_parks_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        seat: ModelSeatId,
        answers: u64,
        now: u64,
    ) -> Result<Vec<AttemptId>> {
        let store = DreamerRunnerStore::new(self);
        let queue = AttemptQueue::new(self);
        let mut resumed = Vec::new();
        // Materialize the scan before waking: resuming a park deletes its wait entry.
        for (_, attempt) in SEAT_WAITS.scan_keys(&self.store, wtxn, seat.as_bytes())? {
            let key = (seat, attempt);
            let Some(park) = PARKED.get(&self.store, &*wtxn, &attempt)? else {
                SEAT_WAITS.delete(&self.store, wtxn, &key)?;
                continue;
            };
            let waits_here = match park.wait.as_ref() {
                Some(wait) => match &wait.wait {
                    DreamerParkWait::Seat {
                        seat: waited,
                        generation,
                        ..
                    } if *waited == seat => Some((*generation, wait.lease_generation)),
                    _ => None,
                },
                None => None,
            };
            let Some((generation, lease_generation)) = waits_here else {
                SEAT_WAITS.delete(&self.store, wtxn, &key)?;
                continue;
            };
            if generation > answers {
                tracing::info!(
                    attempt = ?attempt,
                    generation,
                    answers,
                    "a seat-available write left a newer generation parked"
                );
                continue;
            }
            if !park.resumable_by(ParkResumer::SeatAvailable) {
                tracing::info!(
                    attempt = ?attempt,
                    "a seat-available write skipped a park that does not admit it"
                );
                continue;
            }
            let live = queue.get_in_txn(wtxn, attempt)?;
            let fresh = live
                .as_ref()
                .is_some_and(|row| row.state.is_running() && row.attempt_count == lease_generation);
            if !fresh {
                tracing::info!(
                    attempt = ?attempt,
                    "a seat-available write skipped a stale park lease"
                );
                continue;
            }
            if store
                .resume_parked_in_txn(wtxn, attempt, &park.park_owner, now)?
                .is_none()
            {
                tracing::warn!(
                    attempt = ?attempt,
                    "a seat-available write met a park that went missing in its own write"
                );
                continue;
            }
            super::park_release::resolve_notices_in_txn(self, wtxn, &park, lease_generation)?;
            resumed.push(attempt);
        }
        Ok(resumed)
    }

    /// Releases every seat whose reported reset the recorded now has reached: one seat-available
    /// write per due seat, in one write. Returns the seats it released. With nothing due it opens
    /// no write: the watcher sweeps on every attempt commit.
    pub fn release_due_model_seats(&self) -> Result<Vec<ModelSeatId>> {
        let now = self.store.clock.now_recorded_at();
        if self
            .next_model_seat_reset_due()?
            .is_none_or(|due_at| due_at > now)
        {
            return Ok(Vec::new());
        }
        let (released, resumed) =
            self.with_write_txn_grouped(|wtxn| self.release_due_model_seats_in_txn(wtxn))?;
        if !released.is_empty() {
            self.store.notify_attempt_observers();
        }
        if resumed {
            // The deadline lane arms the woken tries at once.
            self.store.notify_proactivity_changes();
        }
        Ok(released)
    }

    /// [`Self::release_due_model_seats`] in the caller's write. Returns the seats it released and
    /// whether any try woke. A due entry with no row, an Available row, or a reset the last refusal
    /// moved is stale and goes; a seat its own write refuses is left for its own write.
    fn release_due_model_seats_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<(Vec<ModelSeatId>, bool)> {
        let now = self.store.clock.now_recorded_at();
        // Materialize the scan before writing: each release deletes its due entry.
        let due: Vec<(u64, ModelSeatId)> = SEAT_RESET_DUE
            .scan_keys(&self.store, wtxn, &[])?
            .into_iter()
            .filter(|(due_at, _)| *due_at <= now)
            .collect();
        let mut released = Vec::new();
        let mut resumed_any = false;
        for (due_at, seat) in due {
            let row = self.model_seat_state_in_txn(wtxn, seat)?;
            let Some(row) = row.filter(|row| {
                matches!(row.availability, ModelSeatAvailability::Unavailable)
                    && row.reset_at_s == Some(due_at)
            }) else {
                SEAT_RESET_DUE.delete(&self.store, wtxn, &(due_at, seat))?;
                continue;
            };
            match self.record_model_seat_available_in_txn(
                wtxn,
                seat,
                row.generation,
                ModelSeatAvailableSource::ResetPassed,
            ) {
                Ok(woken) => {
                    resumed_any |= !woken.is_empty();
                    released.push(seat);
                }
                Err(error) if is_seat_refusal(&error) => {
                    tracing::warn!(
                        seat = %seat.to_hex(),
                        generation = row.generation,
                        "a due seat's own write refused it; left for its own write"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok((released, resumed_any))
    }

    /// The next reported seat reset, if any seat waits on one.
    pub fn next_model_seat_reset_due(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        let mut due = SEAT_RESET_DUE.iter_from(&self.store, &rtxn, &[])?;
        Ok(due.next().transpose()?.map(|((due_at, _), _)| due_at))
    }
}

impl DreamerRunnerStore<'_> {
    /// Refuses `seat` and parks `input` on it, fenced on `lease` in one writer: `Ok(None)`,
    /// nothing written, when the try was resumed or claimed again since that lease ran it. The seat
    /// row moves to Unavailable at a new generation, and the park names that generation with this
    /// refusal's reset. A read before this writer would still race.
    pub(crate) fn park_on_seat_if_current_lease_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ParkDreamerAttempt,
        lease: DreamerTryLease<'_>,
        seat: ModelSeatId,
        reset_at_s: Option<u64>,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        if let Some(record) = self.attempts.get_in_txn(wtxn, input.attempt_id)?
            && !lease.still_holds(&record)
        {
            tracing::info!(
                attempt_id = %bytes_to_hex_lower(input.attempt_id.as_bytes()),
                state = record.state.as_str(),
                "a stale pass's seat park was skipped; the try was resumed or claimed again"
            );
            return Ok(None);
        }
        let generation = self
            .vault
            .refuse_model_seat_in_txn(wtxn, seat, reset_at_s, input.now)?;
        self.park_attempt_with_wait_in_txn(
            wtxn,
            input,
            Some(DreamerParkWait::Seat {
                seat,
                generation,
                reset_at_s,
            }),
        )
        .map(Some)
    }

    /// [`Self::park_on_seat_if_current_lease_in_txn`] in its own writer.
    pub(crate) fn park_on_seat_if_current_lease(
        &self,
        input: ParkDreamerAttempt,
        lease: DreamerTryLease<'_>,
        seat: ModelSeatId,
        reset_at_s: Option<u64>,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        let record = self.vault.with_write_txn_grouped(|wtxn| {
            self.park_on_seat_if_current_lease_in_txn(wtxn, input, lease, seat, reset_at_s)
        })?;
        if record.is_some() {
            self.vault.store.notify_attempt_observers();
        }
        Ok(record)
    }
}
