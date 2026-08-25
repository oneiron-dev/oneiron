//! The live Dreamer progress lane on the ephemeral sync keyspace.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::attempt_queue::{AttemptId, AttemptState};
use crate::error::{Error, Result, SyncEngineContext};
use crate::sync::{EphemeralStore, LoroValue, TransportError, encode_ephemeral};

use super::codec::invalid_dreamer_runner;
use super::constants::{KEY_ATTEMPT_ID, KEY_SCHEMA_VERSION, KEY_TOTAL_UNITS};
use super::store::DreamerRunnerStore;
use super::types::{
    AdmitDreamerAttempt, CompleteDreamerAttempt, CompleteDreamerAttemptOutcome,
    DreamerAdmissionOutcome, DreamerAttemptProgressState, DreamerAttemptStatus,
    DreamerDurableMilestone, DreamerParkedAttemptRecord, FailDreamerAttempt,
    FailDreamerAttemptOutcome, ParkDreamerAttempt,
};

/// Flat ephemeral key prefix for live Dreamer attempt progress.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX: &str = "job:";
/// Current schema version for live Dreamer attempt progress ephemeral values.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION: i64 = 1;
/// Default per-attempt live progress throttle: at most one update per second.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS: u64 = 1_000;
/// Default in-process terminal-stop retention, matching the sync lane TTL.
#[cfg(feature = "sync")]
pub const DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS: u64 = 30_000;

#[cfg(feature = "sync")]
pub(super) const KEY_STATE: &str = "state";
#[cfg(feature = "sync")]
pub(super) const KEY_MESSAGE: &str = "message";
#[cfg(feature = "sync")]
pub(super) const KEY_COMPLETED_UNITS: &str = "completed_units";
#[cfg(feature = "sync")]
const KEY_UPDATED_AT_MS: &str = "updated_at_ms";
#[cfg(feature = "sync")]
const DREAMER_ATTEMPT_PROGRESS_VALUE_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_STATE,
    KEY_MESSAGE,
    KEY_COMPLETED_UNITS,
    KEY_TOTAL_UNITS,
    KEY_UPDATED_AT_MS,
];

#[cfg(feature = "sync")]
pub(super) const MAX_DREAMER_PROGRESS_MESSAGE_LEN: usize = 512;

/// Live Dreamer progress update to publish into the ephemeral keyspace.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerAttemptProgressUpdate {
    pub attempt_id: AttemptId,
    pub state: DreamerAttemptProgressState,
    pub message: Option<String>,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub updated_at_ms: u64,
}

/// Source used for a progress snapshot returned to a consumer.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerAttemptProgressSource {
    Ephemeral,
    DurableMilestone,
}

/// Consumer-facing progress snapshot: live row if present, durable milestone
/// fallback otherwise.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerAttemptProgressSnapshot {
    pub attempt_id: AttemptId,
    pub state: DreamerAttemptProgressState,
    pub source: DreamerAttemptProgressSource,
    pub message: Option<String>,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub updated_at_ms: u64,
}

/// In-process producer for Dreamer live progress on the Loro ephemeral lane.
///
/// The producer keeps only bounded throttle/terminal-stop bookkeeping. The
/// sync-visible state remains exactly one mutable `job:{job_id}` row in the
/// provided [`EphemeralStore`].
#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
pub struct DreamerAttemptProgressProducer {
    throttle_ms: u64,
    terminal_retention_ms: u64,
    last_emitted_at_ms: HashMap<AttemptId, u64>,
    terminal_at_ms: HashMap<AttemptId, u64>,
}

/// Runner transition outcome plus an optional encoded ephemeral frame.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerProgressed<T> {
    pub outcome: T,
    pub frame: Option<Vec<u8>>,
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressUpdate {
    fn validate(&self) -> std::result::Result<(), TransportError> {
        if let Some(total) = self.total_units
            && self.completed_units > total
        {
            return Err(TransportError::InvalidPayload(
                "dreamer progress completed_units exceeds total_units",
            ));
        }
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_DREAMER_PROGRESS_MESSAGE_LEN)
        {
            return Err(TransportError::InvalidPayload(
                "dreamer progress message exceeds 512 bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressSnapshot {
    fn from_live_update(update: &DreamerAttemptProgressUpdate) -> Self {
        Self {
            attempt_id: update.attempt_id,
            state: update.state,
            source: DreamerAttemptProgressSource::Ephemeral,
            message: update.message.clone(),
            completed_units: update.completed_units,
            total_units: update.total_units,
            updated_at_ms: update.updated_at_ms,
        }
    }

    fn from_milestone(milestone: DreamerDurableMilestone) -> Self {
        Self {
            attempt_id: milestone.attempt_id,
            state: milestone.kind.into(),
            source: DreamerAttemptProgressSource::DurableMilestone,
            message: None,
            completed_units: 0,
            total_units: None,
            updated_at_ms: milestone.at.saturating_mul(1_000),
        }
    }
}

#[cfg(feature = "sync")]
impl Default for DreamerAttemptProgressProducer {
    fn default() -> Self {
        Self::with_limits(
            DREAMER_ATTEMPT_PROGRESS_THROTTLE_MS,
            DREAMER_ATTEMPT_PROGRESS_TERMINAL_RETENTION_MS,
        )
        .expect("default dreamer progress limits are valid")
    }
}

#[cfg(feature = "sync")]
impl DreamerAttemptProgressProducer {
    /// Creates a producer with the contract-pinned 1Hz throttle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a producer with explicit limits. `terminal_retention_ms` should
    /// match the [`EphemeralStore`] timeout so stopped attempts cannot resume
    /// ticking before their last live row ages out.
    pub fn with_limits(throttle_ms: u64, terminal_retention_ms: u64) -> Result<Self> {
        if throttle_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress throttle_ms must be > 0",
            ));
        }
        if terminal_retention_ms == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer progress terminal_retention_ms must be > 0",
            ));
        }
        Ok(Self {
            throttle_ms,
            terminal_retention_ms,
            last_emitted_at_ms: HashMap::new(),
            terminal_at_ms: HashMap::new(),
        })
    }

    /// Publishes one live progress update if it passes the per-attempt throttle.
    ///
    /// Terminal `Done`/`Failed` updates overwrite the mutable live row with a
    /// terminal state, then stop any further live production until TTL ageout.
    pub fn publish(
        &mut self,
        store: &EphemeralStore,
        update: DreamerAttemptProgressUpdate,
    ) -> std::result::Result<Option<Vec<u8>>, TransportError> {
        update.validate()?;
        self.retain_terminal_stops(update.updated_at_ms);

        if update.state.is_terminal() {
            let key = dreamer_attempt_progress_key(update.attempt_id);
            let value = encode_attempt_progress_value(&update)?;
            store.set(&key, value);
            self.mark_terminal(update.attempt_id, update.updated_at_ms);
            return encode_ephemeral(&store.encode(&key))
                .into_result()
                .map(Some);
        }
        if self.terminal_at_ms.contains_key(&update.attempt_id) {
            return Ok(None);
        }
        if let Some(last) = self.last_emitted_at_ms.get(&update.attempt_id)
            && update.updated_at_ms.saturating_sub(*last) < self.throttle_ms
        {
            return Ok(None);
        }

        let key = dreamer_attempt_progress_key(update.attempt_id);
        let value = encode_attempt_progress_value(&update)?;
        store.set(&key, value);
        self.last_emitted_at_ms
            .insert(update.attempt_id, update.updated_at_ms);
        encode_ephemeral(&store.encode(&key))
            .into_result()
            .map(Some)
    }

    /// Marks an attempt terminal without producing a live progress frame.
    pub fn mark_terminal(&mut self, attempt_id: AttemptId, now_ms: u64) {
        self.last_emitted_at_ms.remove(&attempt_id);
        self.terminal_at_ms.insert(attempt_id, now_ms);
    }

    /// Runs the Rust-side `EphemeralStore` TTL pass and prunes old terminal
    /// stop markers from this producer.
    pub fn remove_outdated(&mut self, store: &EphemeralStore, now_ms: u64) {
        store.remove_outdated();
        self.retain_terminal_stops(now_ms);
    }

    fn retain_terminal_stops(&mut self, now_ms: u64) {
        let retention = self.terminal_retention_ms;
        self.terminal_at_ms
            .retain(|_, terminal_at| now_ms.saturating_sub(*terminal_at) < retention);
    }
}

impl DreamerRunnerStore<'_> {
    /// Publishes a live progress update for an existing Dreamer attempt.
    ///
    /// This is the runner seam used by execution loops for in-flight ticks;
    /// the producer enforces per-attempt throttling and terminal-stop behavior.
    #[cfg(feature = "sync")]
    pub fn publish_progress(
        &self,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
        update: DreamerAttemptProgressUpdate,
    ) -> Result<Option<Vec<u8>>> {
        let status = self
            .status(update.attempt_id)?
            .ok_or(invalid_dreamer_runner(
                "dreamer progress attempt must exist before publish",
            ))?;
        match (status.attempt.state, update.state) {
            (AttemptState::Completed, DreamerAttemptProgressState::Done)
            | (AttemptState::Failed, DreamerAttemptProgressState::Failed)
            // A scheduled try is pre-lease, exactly like a queued one: live
            // progress keeps flowing on the existing queued/deferred path.
            | (AttemptState::Queued | AttemptState::Leased | AttemptState::Scheduled, _) => {}
            (
                AttemptState::Paused
                | AttemptState::Completed
                | AttemptState::Failed
                | AttemptState::Cancelled,
                _,
            ) => {
                return Ok(None);
            }
        }
        producer
            .publish(ephemeral, update)
            .map_err(dreamer_progress_error)
    }

    /// Admits the next Dreamer attempt and emits its initial live progress row.
    #[cfg(feature = "sync")]
    pub fn admit_next_with_progress(
        &self,
        input: AdmitDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerAdmissionOutcome>> {
        let now_ms = input.now.saturating_mul(1_000);
        let outcome = self.admit_next(input)?;
        let frame = if let DreamerAdmissionOutcome::Admitted(admitted) = &outcome {
            let reservation = &admitted.reservation;
            self.publish_progress(
                producer,
                ephemeral,
                DreamerAttemptProgressUpdate {
                    attempt_id: admitted.status.attempt.id,
                    state: DreamerAttemptProgressState::Started,
                    message: None,
                    completed_units: 0,
                    total_units: Some(reservation.reserved_units),
                    updated_at_ms: now_ms,
                },
            )?
        } else {
            None
        };
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Marks a leased Dreamer attempt complete and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn complete_with_progress(
        &self,
        input: CompleteDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<CompleteDreamerAttemptOutcome>> {
        let outcome = self.complete(input)?;
        let status = complete_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: status.attempt.id,
                state: DreamerAttemptProgressState::Done,
                message: None,
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.attempt.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Marks a leased Dreamer attempt failed and stops live progress production.
    #[cfg(feature = "sync")]
    pub fn fail_with_progress(
        &self,
        input: FailDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<FailDreamerAttemptOutcome>> {
        let outcome = self.fail(input)?;
        let status = fail_outcome_status(&outcome);
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: status.attempt.id,
                state: DreamerAttemptProgressState::Failed,
                message: bounded_progress_message(status.attempt.last_error.as_deref()),
                completed_units: 0,
                total_units: None,
                updated_at_ms: status.attempt.updated_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed { outcome, frame })
    }

    /// Parks a Dreamer attempt and emits a live parked progress row.
    #[cfg(feature = "sync")]
    pub fn park_attempt_with_progress(
        &self,
        input: ParkDreamerAttempt,
        producer: &mut DreamerAttemptProgressProducer,
        ephemeral: &EphemeralStore,
    ) -> Result<DreamerProgressed<DreamerParkedAttemptRecord>> {
        let record = self.park_attempt(input)?;
        let frame = self.publish_progress(
            producer,
            ephemeral,
            DreamerAttemptProgressUpdate {
                attempt_id: record.attempt_id,
                state: DreamerAttemptProgressState::Parked,
                message: Some(record.reason.clone()),
                completed_units: 0,
                total_units: None,
                updated_at_ms: record.parked_at.saturating_mul(1_000),
            },
        )?;
        Ok(DreamerProgressed {
            outcome: record,
            frame,
        })
    }

    /// Returns the live ephemeral progress row when present, otherwise falls
    /// back to the latest durable milestone claim.
    #[cfg(feature = "sync")]
    pub fn progress_snapshot(
        &self,
        ephemeral: &EphemeralStore,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerAttemptProgressSnapshot>> {
        if let Some(value) = ephemeral.get(&dreamer_attempt_progress_key(attempt_id))
            && let Ok(update) = decode_attempt_progress_value(&value, attempt_id)
        {
            return Ok(Some(DreamerAttemptProgressSnapshot::from_live_update(
                &update,
            )));
        }

        self.latest_durable_milestone(attempt_id)
            .map(|milestone| milestone.map(DreamerAttemptProgressSnapshot::from_milestone))
    }
}

#[cfg(feature = "sync")]
fn dreamer_progress_error(error: TransportError) -> Error {
    Error::sync_engine(SyncEngineContext::DreamerProgressTransport, error)
}

#[cfg(feature = "sync")]
fn complete_outcome_status(outcome: &CompleteDreamerAttemptOutcome) -> &DreamerAttemptStatus {
    match outcome {
        CompleteDreamerAttemptOutcome::Completed(status)
        | CompleteDreamerAttemptOutcome::AlreadyCompleted(status) => status,
    }
}

#[cfg(feature = "sync")]
fn fail_outcome_status(outcome: &FailDreamerAttemptOutcome) -> &DreamerAttemptStatus {
    match outcome {
        FailDreamerAttemptOutcome::Failed(status)
        | FailDreamerAttemptOutcome::AlreadyFailed(status) => status,
    }
}

#[cfg(feature = "sync")]
fn bounded_progress_message(message: Option<&str>) -> Option<String> {
    let message = message?;
    if message.len() <= MAX_DREAMER_PROGRESS_MESSAGE_LEN {
        return Some(message.to_owned());
    }

    let mut end = 0;
    for (index, ch) in message.char_indices() {
        let next = index + ch.len_utf8();
        if next > MAX_DREAMER_PROGRESS_MESSAGE_LEN {
            break;
        }
        end = next;
    }
    Some(message[..end].to_owned())
}

#[cfg(feature = "sync")]
#[must_use]
pub fn dreamer_attempt_progress_key(attempt_id: AttemptId) -> String {
    let mut key = String::with_capacity(DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX.len() + 32);
    key.push_str(DREAMER_ATTEMPT_PROGRESS_KEY_PREFIX);
    for byte in attempt_id.as_bytes() {
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    key
}

#[cfg(feature = "sync")]
fn encode_attempt_progress_value(
    update: &DreamerAttemptProgressUpdate,
) -> std::result::Result<LoroValue, TransportError> {
    update.validate()?;
    Ok(LoroValue::Map(
        vec![
            (
                KEY_SCHEMA_VERSION.to_owned(),
                LoroValue::I64(DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION),
            ),
            (
                KEY_ATTEMPT_ID.to_owned(),
                LoroValue::String(dreamer_attempt_id_hex(update.attempt_id).into()),
            ),
            (
                KEY_STATE.to_owned(),
                LoroValue::String(update.state.as_str().into()),
            ),
            (
                KEY_MESSAGE.to_owned(),
                update
                    .message
                    .as_deref()
                    .map_or(LoroValue::Null, |message| LoroValue::String(message.into())),
            ),
            (
                KEY_COMPLETED_UNITS.to_owned(),
                LoroValue::I64(u64_to_i64_progress(update.completed_units)?),
            ),
            (
                KEY_TOTAL_UNITS.to_owned(),
                update
                    .total_units
                    .map(u64_to_i64_progress)
                    .transpose()?
                    .map_or(LoroValue::Null, LoroValue::I64),
            ),
            (
                KEY_UPDATED_AT_MS.to_owned(),
                LoroValue::I64(u64_to_i64_progress(update.updated_at_ms)?),
            ),
        ]
        .into(),
    ))
}

#[cfg(feature = "sync")]
fn decode_attempt_progress_value(
    value: &LoroValue,
    expected_attempt_id: AttemptId,
) -> std::result::Result<DreamerAttemptProgressUpdate, TransportError> {
    let LoroValue::Map(entries) = value else {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value must be a map",
        ));
    };
    if entries
        .keys()
        .any(|key| !DREAMER_ATTEMPT_PROGRESS_VALUE_KEYS.contains(&key.as_str()))
    {
        return Err(TransportError::InvalidPayload(
            "dreamer progress value key is not pinned",
        ));
    }

    let schema_version = expect_loro_i64(entries.get(KEY_SCHEMA_VERSION), KEY_SCHEMA_VERSION)?;
    if schema_version != DREAMER_ATTEMPT_PROGRESS_VALUE_SCHEMA_VERSION {
        return Err(TransportError::InvalidPayload(
            "unsupported dreamer progress schema_version",
        ));
    }

    let attempt_id = expect_loro_string(entries.get(KEY_ATTEMPT_ID), KEY_ATTEMPT_ID)?;
    if attempt_id != dreamer_attempt_id_hex(expected_attempt_id) {
        return Err(TransportError::InvalidPayload(
            "dreamer progress job_id mismatch",
        ));
    }

    let state =
        DreamerAttemptProgressState::parse(expect_loro_string(entries.get(KEY_STATE), KEY_STATE)?)
            .ok_or(TransportError::InvalidPayload(
                "unknown dreamer progress state",
            ))?;
    let message = match entries.get(KEY_MESSAGE) {
        Some(LoroValue::Null) | None => None,
        Some(value) => Some(expect_loro_string(Some(value), KEY_MESSAGE)?.to_owned()),
    };
    let completed_units = i64_to_u64_progress(expect_loro_i64(
        entries.get(KEY_COMPLETED_UNITS),
        KEY_COMPLETED_UNITS,
    )?)?;
    let total_units = match entries.get(KEY_TOTAL_UNITS) {
        Some(LoroValue::Null) | None => None,
        Some(value) => Some(i64_to_u64_progress(expect_loro_i64(
            Some(value),
            KEY_TOTAL_UNITS,
        )?)?),
    };
    let updated_at_ms = i64_to_u64_progress(expect_loro_i64(
        entries.get(KEY_UPDATED_AT_MS),
        KEY_UPDATED_AT_MS,
    )?)?;

    let update = DreamerAttemptProgressUpdate {
        attempt_id: expected_attempt_id,
        state,
        message,
        completed_units,
        total_units,
        updated_at_ms,
    };
    update.validate()?;
    Ok(update)
}

#[cfg(feature = "sync")]
fn dreamer_attempt_id_hex(attempt_id: AttemptId) -> String {
    let mut out = String::with_capacity(32);
    for byte in attempt_id.as_bytes() {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[cfg(feature = "sync")]
fn u64_to_i64_progress(value: u64) -> std::result::Result<i64, TransportError> {
    i64::try_from(value)
        .map_err(|_| TransportError::InvalidPayload("dreamer progress integer exceeds i64"))
}

#[cfg(feature = "sync")]
fn i64_to_u64_progress(value: i64) -> std::result::Result<u64, TransportError> {
    u64::try_from(value)
        .map_err(|_| TransportError::InvalidPayload("dreamer progress integer is negative"))
}

#[cfg(feature = "sync")]
fn expect_loro_i64(
    value: Option<&LoroValue>,
    field: &'static str,
) -> std::result::Result<i64, TransportError> {
    let Some(LoroValue::I64(value)) = value else {
        return Err(TransportError::InvalidPayload(field));
    };
    Ok(*value)
}

#[cfg(feature = "sync")]
fn expect_loro_string<'a>(
    value: Option<&'a LoroValue>,
    field: &'static str,
) -> std::result::Result<&'a str, TransportError> {
    let Some(LoroValue::String(value)) = value else {
        return Err(TransportError::InvalidPayload(field));
    };
    Ok(value.as_str())
}
