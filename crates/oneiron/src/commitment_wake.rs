//! Commitment timer-wake bridge (CMT-3, ONE-1540): due phase → Dreamer
//! attempt → inbox proposal → OF-327 delivery.
//!
//! This module owns NOTHING that already exists. It is the producer-side
//! wiring between four landed surfaces:
//!
//! * CMT-2 ([`crate::commitment_schedule`]) owns the due index, its keys, and
//!   the two crate-private transaction twins this module consumes. Nothing
//!   here reads or writes a due-index key.
//! * CMT-1 ([`crate::commitment`]) owns the obligation record. Only
//!   [`CommitmentStrength::Commitment`] reaches the wake path: a `Decision` is
//!   query/check-in material and a `StatedIntention` is retrieval-only.
//! * The Dreamer ([`crate::dreamer_wake`]) owns wake enqueue and attempt
//!   execution. The wake is an ordinary `WakeTrigger::Event` MICRO attempt and
//!   [`CommitmentWakeExecutor`] is a WRAPPER — an ordinary partition attempt is
//!   delegated byte-for-byte.
//! * The inbox ([`crate::inbox`]) and OF-327 ([`crate::outbound`]) own consent
//!   and delivery. The proposal lands through the same
//!   `claim_candidate(..).apply_recording_gate_decisions(..)` door
//!   `dreamer_promotion` uses, so the pending consent row — and therefore the
//!   approval door — exists without a new grouping mechanism.
//!
//! The one invented thing is the deterministic PHASE KEY `cmt:<32-hex>:<phase>`
//! ([`CommitmentWakeDue::idempotency_key`]). It is the Dreamer enqueue's
//! advisory dedupe key, its run id (and therefore its inbox group key through
//! the existing literal-run fallback), and the outbound draft's idempotency
//! key. It is deliberately NOT a `job_ref`: `cmt:...` is not a 32-hex attempt
//! id and must never alias the attempt run index.
//!
//! Nothing here delivers. [`fire_due_commitment_wake`] enqueues; the executor
//! proposes; only [`schedule_approved_commitment_wake`], behind an inbox
//! approval and an actor binding, reaches
//! [`crate::memory::Memory::schedule_outbound`].

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    session_claim_producer,
};
use crate::commitment::{
    CommitmentRecord, CommitmentStatus, CommitmentStrength, decode_commitment_claim,
};
use crate::commitment_schedule::{CommitmentDueEntry, CommitmentDuePhase};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerConsolidationScope, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakeTrigger,
    request_wake_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult, OutboundDraftInput, OutboundIntentReceipt};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// 1. Vocabulary
// ---------------------------------------------------------------------------

/// Schema version of the tagged Dreamer attempt payload this module encodes.
pub const COMMITMENT_WAKE_SCHEMA_VERSION: u64 = 1;

/// Prefix of the deterministic phase key used as dedupe key, run id, inbox
/// group key, and outbound idempotency key.
pub const COMMITMENT_WAKE_RUN_PREFIX: &str = "cmt:";

/// The gated action-proposal predicate the wake executor writes.
///
/// Deliberately NOT a member of CMT-1's `COMMITMENT_CLAIM_PREDICATES`: this is
/// a proposal about a commitment, never a spelling of one, and joining that
/// family would put it through the `commitment.record` structural validator.
pub const PREDICATE_COMMITMENT_WAKE_PROPOSAL: &str = "commitment.wake_proposal";

/// Schema version of the proposal claim value.
pub const COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION: u64 = 1;

/// The trigger token OF-327 already maps to
/// [`crate::outbound::OutboundIntentSource::Commitment`]. Also the tagged
/// payload's `event` discriminator, so one string names the whole path.
pub const COMMITMENT_WAKE_TRIGGER: &str = "commitment_timer_wake";

/// Prefix of the canonical commitment receipt reference.
pub const COMMITMENT_WAKE_TRIGGER_REF_PREFIX: &str = "commitment:";

/// Byte bound on every caller-supplied delivery string on this surface.
pub const MAX_COMMITMENT_WAKE_STRING_BYTES: usize = 1_024;

/// BLAKE3 domain separator for the deterministic proposal claim id.
const COMMITMENT_WAKE_PROPOSAL_CLAIM_ID_DOMAIN: &[u8] = b"oneiron.commitment.wake_proposal.v1\0";

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_EVENT: &str = "event";
const KEY_COMMITMENT_REF: &str = "commitment_ref";
const KEY_PHASE: &str = "phase";
const KEY_FIRE_AT: &str = "fire_at";
const KEY_DUE_AT: &str = "due_at";
const KEY_INSTANCE_REF: &str = "instance_ref";
const KEY_OCCURRED_AT: &str = "occurred_at";
const KEY_IDEMPOTENCY_KEY: &str = "idempotency_key";
const KEY_TRIGGER_REF: &str = "trigger_ref";
const KEY_VERB: &str = "verb";
const KEY_CHANNEL: &str = "channel";
const KEY_TARGET: &str = "target";
const KEY_ON_BEHALF_OF: &str = "on_behalf_of";
const KEY_CONTENT_REF: &str = "content_ref";
const KEY_DEDUPE_KEY: &str = "dedupe_key";

const PROVENANCE_KEY_SURFACE: &str = "surface";
const PROVENANCE_KEY_RUN: &str = "run";
const PROVENANCE_KEY_JOB_ID: &str = "job_id";

/// Which of an instance's two actionable phases a wake names.
///
/// `Project` is engine-internal and `LifecycleDue` is ONE-1541's lapse feed;
/// neither can be spelled here, which is what keeps them out of the timer
/// path structurally rather than by a filter someone can forget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentWakePhase {
    /// The occurrence became visible (`due_at - lead`).
    Lead,
    /// The occurrence is owed now.
    Due,
}

impl CommitmentWakePhase {
    /// The stable phase token used inside every key this module derives.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lead => "lead",
            Self::Due => "due",
        }
    }

    /// Parses a pinned phase token. Anything else is never a wake phase.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "lead" => Some(Self::Lead),
            "due" => Some(Self::Due),
            _ => None,
        }
    }

    /// The due-index phase this wake phase consumes.
    #[must_use]
    pub const fn due_phase(self) -> CommitmentDuePhase {
        match self {
            Self::Lead => CommitmentDuePhase::Lead,
            Self::Due => CommitmentDuePhase::Due,
        }
    }

    /// The wake phase for an acknowledgeable due-index phase, if there is one.
    #[must_use]
    pub const fn from_due_phase(phase: CommitmentDuePhase) -> Option<Self> {
        match phase {
            CommitmentDuePhase::Lead => Some(Self::Lead),
            CommitmentDuePhase::Due => Some(Self::Due),
            _ => None,
        }
    }
}

/// Adapter view over ONE-1539's [`CommitmentDueEntry`]; never persisted
/// separately and never derived from a due-index KEY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentWakeDue {
    /// The materialized commitment instance this phase belongs to.
    pub instance_id: EntityId,
    /// Which of the two actionable phases came due.
    pub phase: CommitmentWakePhase,
    /// Unix seconds at which this phase becomes actionable.
    pub fire_at: u64,
    /// The instance's actual due time, in Unix seconds.
    pub due_at: u64,
}

impl CommitmentWakeDue {
    /// The deterministic phase key: dedupe key, run id, inbox group key, and
    /// outbound idempotency key, all one string.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        format!(
            "{COMMITMENT_WAKE_RUN_PREFIX}{}:{}",
            self.instance_id.to_hex(),
            self.phase.as_str()
        )
    }

    /// The canonical commitment receipt reference (ONE-1542's door shape).
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        commitment_trigger_ref(&self.instance_id)
    }

    /// Typed conversion from the owner's due row.
    ///
    /// `Ok(None)` is "not an actionable wake phase" — a `Project` or
    /// `LifecycleDue` row, which this module must never consume. A `Lead`/`Due`
    /// row with no instance ref is a corrupt row, not a phase to skip.
    pub fn from_due_entry(entry: &CommitmentDueEntry) -> Result<Option<Self>> {
        let Some(phase) = CommitmentWakePhase::from_due_phase(entry.phase) else {
            return Ok(None);
        };
        let instance_id = entry.instance_ref.ok_or(Error::CorruptedIndex(
            "commitment due row phase and instance ref disagree",
        ))?;
        Ok(Some(Self {
            instance_id,
            phase,
            fire_at: entry.at,
            due_at: entry.occurrence.due_at,
        }))
    }

    fn event(&self) -> CommitmentWakeEvent {
        CommitmentWakeEvent {
            schema_version: COMMITMENT_WAKE_SCHEMA_VERSION,
            instance_id: self.instance_id,
            phase: self.phase,
            fire_at: self.fire_at,
            due_at: self.due_at,
        }
    }
}

/// The tagged Dreamer attempt payload. It carries no prompt text and no
/// proposed channel, target, verb, or content: WHAT to say is the planner's
/// job at execution time, not a fact frozen into the queue row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentWakeEvent {
    pub schema_version: u64,
    pub instance_id: EntityId,
    pub phase: CommitmentWakePhase,
    pub fire_at: u64,
    pub due_at: u64,
}

impl CommitmentWakeEvent {
    /// The phase key this event's wake was enqueued under.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        self.due().idempotency_key()
    }

    /// The canonical commitment receipt reference.
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        commitment_trigger_ref(&self.instance_id)
    }

    const fn due(&self) -> CommitmentWakeDue {
        CommitmentWakeDue {
            instance_id: self.instance_id,
            phase: self.phase,
            fire_at: self.fire_at,
            due_at: self.due_at,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != COMMITMENT_WAKE_SCHEMA_VERSION {
            return Err(Error::InvalidClaimBody(
                "unsupported commitment wake event schema version",
            ));
        }
        // A Lead fires at `due_at - lead`; a Due fires exactly at `due_at`.
        // Anything else names an instant the projector could not have written.
        let consistent = match self.phase {
            CommitmentWakePhase::Lead => self.fire_at <= self.due_at,
            CommitmentWakePhase::Due => self.fire_at == self.due_at,
        };
        if !consistent {
            return Err(Error::InvalidClaimBody(
                "commitment wake event timestamps are inconsistent",
            ));
        }
        Ok(())
    }
}

fn commitment_trigger_ref(instance_id: &EntityId) -> String {
    format!(
        "{COMMITMENT_WAKE_TRIGGER_REF_PREFIX}{}",
        instance_id.to_hex()
    )
}

/// Encodes the exact six-key MessagePack map.
pub fn encode_commitment_wake_event(event: &CommitmentWakeEvent) -> Result<Value> {
    event.validate()?;
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(event.schema_version),
        ),
        (Value::from(KEY_EVENT), Value::from(COMMITMENT_WAKE_TRIGGER)),
        (
            Value::from(KEY_COMMITMENT_REF),
            Value::from(event.trigger_ref()),
        ),
        (Value::from(KEY_PHASE), Value::from(event.phase.as_str())),
        (Value::from(KEY_FIRE_AT), Value::from(event.fire_at)),
        (Value::from(KEY_DUE_AT), Value::from(event.due_at)),
    ]))
}

/// Decodes a Dreamer attempt payload as a commitment wake event.
///
/// `Ok(None)` means an ordinary non-commitment payload and is the wrapper's
/// byte-for-byte delegation path. A payload carrying the commitment event tag
/// but malformed fields is a TYPED ERROR, never `None`: a corrupt tagged event
/// silently delegating into the partition decoder is exactly the confusion
/// this split exists to prevent.
pub fn decode_commitment_wake_event(value: &Value) -> Result<Option<CommitmentWakeEvent>> {
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    if !carries_commitment_wake_tag(entries) {
        return Ok(None);
    }
    decode_tagged_commitment_wake_event(entries).map(Some)
}

/// The tag probe is deliberately tolerant: it only asks "does exactly one
/// `event` key say `commitment_timer_wake`". Everything stricter belongs to
/// the decoder, so an ordinary payload that happens to carry an `event` key is
/// delegated rather than refused.
fn carries_commitment_wake_tag(entries: &[(Value, Value)]) -> bool {
    entries.iter().any(|(key, value)| {
        key.as_str() == Some(KEY_EVENT) && value.as_str() == Some(COMMITMENT_WAKE_TRIGGER)
    })
}

fn decode_tagged_commitment_wake_event(entries: &[(Value, Value)]) -> Result<CommitmentWakeEvent> {
    let mut schema_version: Option<u64> = None;
    let mut commitment_ref: Option<String> = None;
    let mut phase: Option<String> = None;
    let mut fire_at: Option<u64> = None;
    let mut due_at: Option<u64> = None;
    let mut tag_seen = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(malformed_event("commitment wake event key is not a string"));
        };
        let duplicate = match key {
            KEY_SCHEMA_VERSION => set_once(&mut schema_version, required_u64(value)?),
            KEY_EVENT => std::mem::replace(&mut tag_seen, true),
            KEY_COMMITMENT_REF => set_once(&mut commitment_ref, required_string(value)?),
            KEY_PHASE => set_once(&mut phase, required_string(value)?),
            KEY_FIRE_AT => set_once(&mut fire_at, required_u64(value)?),
            KEY_DUE_AT => set_once(&mut due_at, required_u64(value)?),
            _ => return Err(malformed_event("commitment wake event has an unknown key")),
        };
        if duplicate {
            return Err(malformed_event("commitment wake event has a duplicate key"));
        }
    }

    let missing = || malformed_event("commitment wake event is missing a required key");
    let commitment_ref = commitment_ref.ok_or_else(missing)?;
    let phase = phase.ok_or_else(missing)?;
    let event = CommitmentWakeEvent {
        schema_version: schema_version.ok_or_else(missing)?,
        instance_id: parse_commitment_trigger_ref(&commitment_ref)?,
        phase: CommitmentWakePhase::parse(&phase)
            .ok_or_else(|| malformed_event("commitment wake event phase is not lead|due"))?,
        fire_at: fire_at.ok_or_else(missing)?,
        due_at: due_at.ok_or_else(missing)?,
    };
    event.validate()?;
    Ok(event)
}

/// Returns whether the slot was already filled — the duplicate-key signal.
fn set_once<T>(slot: &mut Option<T>, value: T) -> bool {
    slot.replace(value).is_some()
}

const fn malformed_event(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn required_u64(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| malformed_event("commitment wake value is not an unsigned integer"))
}

fn required_string(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| malformed_event("commitment wake value is not a string"))
}

fn parse_commitment_trigger_ref(reference: &str) -> Result<EntityId> {
    reference
        .strip_prefix(COMMITMENT_WAKE_TRIGGER_REF_PREFIX)
        .ok_or_else(|| malformed_event("commitment reference is malformed"))
        .and_then(|hex| {
            EntityId::from_hex(hex)
                .map_err(|_| malformed_event("commitment reference is malformed"))
        })
}

fn validate_wake_string(value: &str, reason: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_COMMITMENT_WAKE_STRING_BYTES {
        return Err(Error::InvalidClaimBody(reason));
    }
    Ok(())
}

fn validate_optional_wake_string(value: Option<&str>, reason: &'static str) -> Result<()> {
    match value {
        Some(value) => validate_wake_string(value, reason),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// 2. Atomic fire-once door
// ---------------------------------------------------------------------------

/// The only shape of due-index access this module has.
///
/// ONE-1539 owns the rows and their keys; this trait is the narrow adapter
/// over its two crate-private transaction twins. Nothing here imports a key
/// prefix or writes a row directly.
pub(crate) trait CommitmentWakeIndexTxn {
    /// The earliest actionable `Lead`/`Due` phase, as a typed wake due.
    fn next_wake_due_in_txn(&self, txn: &RoTxn<'_>) -> Result<Option<CommitmentWakeDue>>;

    /// Acknowledges EXACTLY `due` — never "whatever is currently first".
    fn settle_wake_phase_in_txn(&self, txn: &mut RwTxn<'_>, due: &CommitmentWakeDue) -> Result<()>;
}

impl CommitmentWakeIndexTxn for Vault {
    fn next_wake_due_in_txn(&self, txn: &RoTxn<'_>) -> Result<Option<CommitmentWakeDue>> {
        let Some(entry) = self.next_actionable_wake_phase_in_txn(txn)? else {
            return Ok(None);
        };
        CommitmentWakeDue::from_due_entry(&entry)
    }

    fn settle_wake_phase_in_txn(&self, txn: &mut RwTxn<'_>, due: &CommitmentWakeDue) -> Result<()> {
        // Re-read rather than reconstruct: the owner's row carries a
        // `series_ref` and an occurrence this adapter's view deliberately does
        // not, so the only honest way to name the exact row is to read it and
        // check that it is still the one the caller was handed.
        let entry =
            self.next_actionable_wake_phase_in_txn(&*txn)?
                .ok_or(Error::InvariantViolation(
                    "commitment wake phase vanished inside its own transaction",
                ))?;
        if CommitmentWakeDue::from_due_entry(&entry)?.as_ref() != Some(due) {
            return Err(Error::InvariantViolation(
                "commitment wake phase changed inside its own transaction",
            ));
        }
        self.acknowledge_commitment_due_in_txn(txn, &entry)?;
        Ok(())
    }
}

/// What one [`fire_due_commitment_wake`] transaction did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeFireOutcome {
    /// A new durable Dreamer attempt exists and the phase is settled.
    Enqueued { attempt_id: AttemptId },
    /// The advisory dedupe key already named an attempt; the phase is settled
    /// in the same transaction, so this is progress, not a retry.
    Existing { attempt_id: AttemptId },
    /// Nothing was enqueued. Every variant but `Raced` settled the phase.
    Skipped(CommitmentWakeSkip),
}

/// Why a due phase produced no Dreamer attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeSkip {
    /// The exact due entry no longer matches the transaction's current
    /// minimum. Settles nothing and enqueues nothing; the competing writer
    /// owns progress and the caller simply re-reads.
    Raced,
    /// A missing instance acknowledges the exact stale phase before commit.
    MissingInstance,
    /// A non-open instance acknowledges the exact stale phase before commit.
    ClosedInstance,
    /// Retrieval-only strength acknowledges the exact phase without enqueueing.
    StatedIntention,
    /// Query-only strength acknowledges the exact phase without enqueueing.
    Decision,
}

/// Eligibility verdict for one instance, before any write happens.
enum WakeEligibility {
    Eligible,
    Skip(CommitmentWakeSkip),
}

/// Fires ONE due commitment phase in ONE write transaction.
///
/// Order is load-bearing (blueprint §2):
///
/// 1. Re-read the current `Lead`/`Due` minimum. A miss is
///    [`CommitmentWakeSkip::Raced`]: it settles nothing and enqueues nothing,
///    because a stale caller must never settle a phase it did not see.
/// 2. Read the raw claim through the crate-private
///    [`Vault::get_claim_in_txn`] and type it with CMT-1's public
///    `decode_commitment_claim`. The PUBLIC `get_commitment_claim` opens a
///    nested read transaction, which is illegal under LMDB, and is therefore
///    never reachable from here.
/// 3. Ineligible instances acknowledge the exact phase and commit, so the
///    deadline-source read converges instead of busy-looping.
/// 4. An eligible instance enqueues one `Event`/MICRO attempt.
/// 5. The phase is acknowledged in the SAME transaction: any error before
///    commit persists neither the enqueue nor the phase advance.
///
/// This function never calls `schedule_outbound`. Its only eligible side
/// effect is the durable Dreamer enqueue.
pub fn fire_due_commitment_wake(
    vault: &Vault,
    due: CommitmentWakeDue,
    now: u64,
) -> Result<CommitmentWakeFireOutcome> {
    vault.with_write_txn(|wtxn| {
        if vault.next_wake_due_in_txn(&*wtxn)? != Some(due) {
            return Ok(CommitmentWakeFireOutcome::Skipped(
                CommitmentWakeSkip::Raced,
            ));
        }
        if let WakeEligibility::Skip(skip) = wake_eligibility_in_txn(vault, wtxn, &due)? {
            vault.settle_wake_phase_in_txn(wtxn, &due)?;
            return Ok(CommitmentWakeFireOutcome::Skipped(skip));
        }
        let outcome = enqueue_commitment_wake_in_txn(vault, wtxn, &due, now)?;
        vault.settle_wake_phase_in_txn(wtxn, &due)?;
        Ok(outcome)
    })
}

fn wake_eligibility_in_txn(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    due: &CommitmentWakeDue,
) -> Result<WakeEligibility> {
    let Some(body) = vault.get_claim_in_txn(wtxn, &due.instance_id)? else {
        return Ok(WakeEligibility::Skip(CommitmentWakeSkip::MissingInstance));
    };
    // A non-commitment claim at an instance ref is an index that outlived its
    // subject: the same fact a missing entity states, so it settles the same way.
    let Some(record) = decode_commitment_claim(&body)? else {
        return Ok(WakeEligibility::Skip(CommitmentWakeSkip::MissingInstance));
    };
    Ok(wake_eligibility(&record))
}

fn wake_eligibility(record: &CommitmentRecord) -> WakeEligibility {
    if record.status != CommitmentStatus::Open {
        return WakeEligibility::Skip(CommitmentWakeSkip::ClosedInstance);
    }
    match record.strength {
        CommitmentStrength::Commitment => WakeEligibility::Eligible,
        CommitmentStrength::StatedIntention => {
            WakeEligibility::Skip(CommitmentWakeSkip::StatedIntention)
        }
        CommitmentStrength::Decision => WakeEligibility::Skip(CommitmentWakeSkip::Decision),
    }
}

fn enqueue_commitment_wake_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    due: &CommitmentWakeDue,
    now: u64,
) -> Result<CommitmentWakeFireOutcome> {
    let key = due.idempotency_key();
    let payload = DreamerAttemptPayload {
        attempt_type: DreamerConsolidationScope::Micro.as_str().to_owned(),
        input: encode_commitment_wake_event(&due.event())?,
        parent_attempt: None,
    };
    // `WakeTrigger::Event` derives `DreamerConsolidationScope::Micro`: one due
    // phase is one small consolidation, never a Meso/Macro pass.
    let outcome = request_wake_in_txn(
        &DreamerRunnerStore::new(vault),
        wtxn,
        WakeTrigger::Event,
        payload,
        Some(key.clone()),
        Some(key),
        now,
    )?;
    Ok(match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status) => CommitmentWakeFireOutcome::Enqueued {
            attempt_id: status.attempt.id,
        },
        EnqueueDreamerAttemptOutcome::Existing(status) => CommitmentWakeFireOutcome::Existing {
            attempt_id: status.attempt.id,
        },
    })
}

// ---------------------------------------------------------------------------
// 4. Proposal planner, deterministic claim id, and the wrapper executor
// ---------------------------------------------------------------------------

/// The ONLY fields a planner controls.
///
/// Instance, phase, timestamps, trigger reference, approval status, proposal
/// id, and idempotency key are all derived from the event: a planner proposes
/// a delivery, it does not restate the obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentWakeProposalDraft {
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub on_behalf_of: Option<String>,
    pub content_ref: Option<String>,
    pub dedupe_key: Option<String>,
}

impl CommitmentWakeProposalDraft {
    fn validate(&self) -> Result<()> {
        validate_wake_string(&self.verb, "commitment wake proposal verb is invalid")?;
        validate_wake_string(&self.channel, "commitment wake proposal channel is invalid")?;
        validate_wake_string(&self.target, "commitment wake proposal target is invalid")?;
        validate_optional_wake_string(
            self.on_behalf_of.as_deref(),
            "commitment wake proposal on_behalf_of is invalid",
        )?;
        validate_optional_wake_string(
            self.content_ref.as_deref(),
            "commitment wake proposal content_ref is invalid",
        )?;
        validate_optional_wake_string(
            self.dedupe_key.as_deref(),
            "commitment wake proposal dedupe_key is invalid",
        )
    }
}

/// Host-injected proposal planner.
///
/// Deliberately SYNCHRONOUS and deterministic in v1: the tagged path satisfies
/// the at-least-once executor contract through deterministic-claim-id
/// idempotency instead of `call_as_step`, which is only sound while replay
/// re-derives an identical proposal at zero chargeable spend. A planner that
/// wants to call a model must pre-materialize its content behind `content_ref`;
/// an async or budgeted planner MUST adopt `call_as_step` first.
pub trait CommitmentWakeProposalPlanner {
    /// Proposes the delivery fields for one wake.
    ///
    /// # Errors
    ///
    /// Any typed reason the host cannot propose a delivery.
    fn plan(
        &mut self,
        event: &CommitmentWakeEvent,
        commitment: &CommitmentRecord,
    ) -> Result<CommitmentWakeProposalDraft>;
}

/// Why a tagged attempt completed without writing a proposal. Every arm is a
/// COMPLETION with zero units, never a park and never a decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeProposalSkip {
    /// The host installed no planner. The wrapper is still installed by
    /// default, so the tagged event is logged and retired rather than falling
    /// through to the partition decoder.
    NoPlannerConfigured,
    /// The instance is gone.
    MissingInstance,
    /// The instance is closed or no longer `Commitment` strength.
    IneligibleInstance,
}

impl CommitmentWakeProposalSkip {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoPlannerConfigured => "no_planner_configured",
            Self::MissingInstance => "missing_instance",
            Self::IneligibleInstance => "ineligible_instance",
        }
    }
}

/// The deterministic proposal claim id for one attempt.
///
/// Hashes exactly the domain separator plus the 16 attempt bytes, then takes
/// the first 16 BLAKE3 bytes RAW. A prefix colliding with a reserved sentinel
/// is perturbed deterministically (`raw[0] ^= 1`, `raw[15] ^= 1`), exactly as
/// `dreamer_consolidation` does — no RFC-4122 version or variant bits are
/// rewritten, so the id stays a pure function of the attempt.
#[must_use]
pub fn commitment_wake_proposal_claim_id(attempt_id: AttemptId) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_WAKE_PROPOSAL_CLAIM_ID_DOMAIN);
    hasher.update(attempt_id.as_bytes());
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    entity_id_from_digest_prefix(raw)
}

/// The sentinel-safe raw-prefix rule, factored out so the perturb branch is
/// reachable by a fixture: a BLAKE3 prefix landing on a reserved id is roughly
/// a 2^-120 event and would otherwise be untestable.
fn entity_id_from_digest_prefix(mut raw: [u8; 16]) -> EntityId {
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).unwrap_or_else(|_| {
            unreachable!("perturbed commitment wake proposal id is non-reserved")
        })
    })
}

/// Wraps the ordinary consolidation executor with the commitment-wake arm.
///
/// The wrapper is installed by the production factory ALWAYS, planner or not:
/// a tagged event reaching the partition decoder is a decode error and a
/// parked driver, and "install the handler only when configured" is exactly
/// the wiring mistake that produces it.
pub struct CommitmentWakeExecutor<'p, E> {
    inner: E,
    planner: Option<&'p mut dyn CommitmentWakeProposalPlanner>,
    agent_actor: WriteActor,
}

impl<'p, E> CommitmentWakeExecutor<'p, E> {
    /// Composes the wrapper.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] when a planner is installed behind a
    /// non-Agent actor. A planner-LESS wrapper never uses the actor and
    /// constructs for every legal existing host, including a System-class one —
    /// which is what keeps the default composition site infallible in practice.
    pub fn new(
        inner: E,
        planner: Option<&'p mut dyn CommitmentWakeProposalPlanner>,
        agent_actor: WriteActor,
    ) -> Result<Self> {
        if planner.is_some() && agent_actor.actor_class() != EdgeActorClass::Agent {
            return Err(Error::InvalidClaimBody(
                "commitment wake planner requires agent actor",
            ));
        }
        Ok(Self {
            inner,
            planner,
            agent_actor,
        })
    }
}

impl<E: DreamerAttemptExecutor> DreamerAttemptExecutor for CommitmentWakeExecutor<'_, E> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        // Step 1-2: an ordinary partition attempt is delegated with its
        // payload, context, result, and error untouched.
        let Some(event) = decode_commitment_wake_event(&attempt.status.payload.input)? else {
            return self.inner.execute(attempt, ctx).await;
        };
        self.execute_commitment_wake(&event, attempt, ctx)
    }
}

impl<E> CommitmentWakeExecutor<'_, E> {
    /// Steps 3-9. Synchronous on purpose: no model call, no `call_as_step`,
    /// and exactly `completed_units: 0` on every terminal path.
    fn execute_commitment_wake(
        &mut self,
        event: &CommitmentWakeEvent,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        // Step 3: re-read the instance through the ORDINARY public read; this
        // executor owns no transaction, so the nested-read hazard of the fire
        // door does not apply here.
        let Some(record) = ctx.vault.get_commitment_claim(&event.instance_id)? else {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::MissingInstance,
                event,
                attempt_id,
            ));
        };
        if !matches!(wake_eligibility(&record), WakeEligibility::Eligible) {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::IneligibleInstance,
                event,
                attempt_id,
            ));
        }
        // Step 4: no planner is a typed COMPLETION, never a partition decode.
        let agent_actor = self.agent_actor;
        let Some(planner) = self.planner.as_deref_mut() else {
            return Ok(skip_completion(
                CommitmentWakeProposalSkip::NoPlannerConfigured,
                event,
                attempt_id,
            ));
        };
        // Step 5: the planner supplies the delivery fields and nothing else.
        let draft = planner.plan(event, &record)?;
        draft.validate()?;
        write_commitment_wake_proposal(
            ctx.vault,
            &ProposalWrite {
                event,
                draft: &draft,
                attempt_id,
                run_id: attempt.status.attempt.run_id.as_deref(),
                agent_actor,
            },
        )?;
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

/// Every tagged-event terminal path that writes nothing. `completed_units: 0`
/// is EXACT, not an estimate: this arm performs no chargeable work at all.
fn skip_completion(
    skip: CommitmentWakeProposalSkip,
    event: &CommitmentWakeEvent,
    attempt_id: AttemptId,
) -> DreamerAttemptExecution {
    tracing::info!(
        skip = skip.as_str(),
        attempt = %bytes_to_hex_lower(attempt_id.as_bytes()),
        run = %event.idempotency_key(),
        "commitment wake attempt completed without a proposal"
    );
    DreamerAttemptExecution::Completed { completed_units: 0 }
}

/// Everything the proposal write needs, gathered so the writer stays one
/// readable transaction rather than a seven-argument function.
struct ProposalWrite<'a> {
    event: &'a CommitmentWakeEvent,
    draft: &'a CommitmentWakeProposalDraft,
    attempt_id: AttemptId,
    run_id: Option<&'a str>,
    agent_actor: WriteActor,
}

/// Steps 6-9: derive the id, require the run to be the phase key, assemble one
/// candidate, then READ BEFORE WRITE.
///
/// The read-first rule is what makes replay idempotent without `call_as_step`:
/// identical immutables are success with NO write — even after the inbox has
/// advanced the row to `Approved` — and differing immutables at the same
/// deterministic id are typed corruption.
fn write_commitment_wake_proposal(vault: &Vault, write: &ProposalWrite<'_>) -> Result<()> {
    let claim_id = commitment_wake_proposal_claim_id(write.attempt_id);
    let expected_run = write.event.idempotency_key();
    if write.run_id != Some(expected_run.as_str()) {
        return Err(Error::InvalidClaimBody(
            "commitment wake attempt run id is not its phase key",
        ));
    }
    let value = encode_commitment_wake_proposal(write.event, write.draft);
    let provenance = proposal_provenance(&expected_run, write.attempt_id);
    let envelope = WriteEnvelope::new(
        write.agent_actor,
        ClaimSource::Generated,
        WriteProvenance::new(provenance.clone())?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        PREDICATE_COMMITMENT_WAKE_PROPOSAL,
        ClaimSubject::Entity(write.event.instance_id),
        value.clone(),
        1.0,
    )
    // GATE-12's evidence floor: a Dreamer-authored claim must cite at least one
    // ref that still resolves. The honest citation is the OBLIGATION itself —
    // the commitment instance claim this proposal exists to serve — so the
    // floor is met by the fact that motivated the wake, not by a token entity
    // minted to satisfy it.
    .with_evidence(commitment_wake_evidence(write.event.instance_id));
    let occurred = TimeRange {
        start: write.event.fire_at,
        end: write.event.fire_at,
    };

    vault.with_write_txn(|wtxn| {
        if let Some(landed) = vault.get_claim_in_txn(&*wtxn, &claim_id)? {
            return match_landed_proposal(&landed, write.event, &value, &provenance);
        }
        // The ONE write door: a raw claim write that omits recording gate
        // decisions would omit the pending consent row and remove the inbox
        // approval door entirely.
        vault
            .batch_in()
            .claim_candidate(
                &claim_id,
                candidate,
                &envelope,
                occurred,
                write.event.fire_at,
            )
            .apply_recording_gate_decisions(wtxn)?;
        vault
            .get_claim_in_txn(&*wtxn, &claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "commitment wake proposal is missing inside its own write transaction",
            ))?;
        Ok(())
    })
}

/// Replay comparison. Approval and lifecycle are deliberately NOT compared:
/// an accepted proposal is a proposal that advanced, not a proposal that was
/// corrupted, and rewriting it back to `Proposed` would undo a consent answer.
fn match_landed_proposal(
    landed: &ClaimBody,
    event: &CommitmentWakeEvent,
    value: &Value,
    provenance: &Value,
) -> Result<()> {
    let corrupt = || {
        Err(Error::InvalidClaimBody(
            "commitment wake proposal id holds a different proposal",
        ))
    };
    if landed.predicate != PREDICATE_COMMITMENT_WAKE_PROPOSAL
        || landed.subject != ClaimSubject::Entity(event.instance_id)
        || landed.source != Some(ClaimSource::Generated)
        || &landed.value != value
    {
        return corrupt();
    }
    if claim_provenance(landed).as_ref() != Some(provenance) {
        return corrupt();
    }
    Ok(())
}

/// The proposal's candidate-evidence envelope, in the exact shape GATE-12's
/// floor decodes. `Generated` is the honest meet: a proposal is engine output
/// about an obligation, never a restatement of what the user said.
fn commitment_wake_evidence(instance_id: EntityId) -> Value {
    crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![instance_id],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    )
}

fn proposal_provenance(run_id: &str, attempt_id: AttemptId) -> Value {
    Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from(PROVENANCE_KEY_RUN), Value::from(run_id)),
        (
            Value::from(PROVENANCE_KEY_JOB_ID),
            Value::from(bytes_to_hex_lower(attempt_id.as_bytes())),
        ),
    ])
}

fn encode_commitment_wake_proposal(
    event: &CommitmentWakeEvent,
    draft: &CommitmentWakeProposalDraft,
) -> Value {
    let optional =
        |value: Option<&String>| value.map_or(Value::Nil, |value| Value::from(value.as_str()));
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_INSTANCE_REF),
            Value::Binary(event.instance_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_PHASE), Value::from(event.phase.as_str())),
        (Value::from(KEY_FIRE_AT), Value::from(event.fire_at)),
        (Value::from(KEY_DUE_AT), Value::from(event.due_at)),
        // Replay-deterministic: the event's fire instant, never `now`.
        (Value::from(KEY_OCCURRED_AT), Value::from(event.fire_at)),
        (
            Value::from(KEY_IDEMPOTENCY_KEY),
            Value::from(event.idempotency_key()),
        ),
        (
            Value::from(KEY_TRIGGER_REF),
            Value::from(event.trigger_ref()),
        ),
        (Value::from(KEY_VERB), Value::from(draft.verb.as_str())),
        (
            Value::from(KEY_CHANNEL),
            Value::from(draft.channel.as_str()),
        ),
        (Value::from(KEY_TARGET), Value::from(draft.target.as_str())),
        (
            Value::from(KEY_ON_BEHALF_OF),
            optional(draft.on_behalf_of.as_ref()),
        ),
        (
            Value::from(KEY_CONTENT_REF),
            optional(draft.content_ref.as_ref()),
        ),
        (
            Value::from(KEY_DEDUPE_KEY),
            optional(draft.dedupe_key.as_ref()),
        ),
    ])
}

// ---------------------------------------------------------------------------
// 5. Approved token, actor binding, and the outbound adapter
// ---------------------------------------------------------------------------

/// An APPROVED commitment wake proposal, bound to the Dreamer agent that
/// authored it.
///
/// Opaque by construction: there is no public constructor and no field setter,
/// so the only way to hold one is to have re-read an approved row through
/// [`approved_commitment_wake`]. Landed inbox acceptance flips approval and
/// records no separate approver identity, so approval CAUSATION is enforced by
/// requiring [`ClaimApprovalStatus::Approved`] — which only the inbox door can
/// set — and author binding is what prevents cross-actor replay double-send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCommitmentWake {
    proposal_claim_id: EntityId,
    instance_id: EntityId,
    phase: CommitmentWakePhase,
    run_id: String,
    idempotency_key: String,
    verb: String,
    channel: String,
    target: String,
    on_behalf_of: Option<String>,
    content_ref: Option<String>,
    dedupe_key: Option<String>,
    occurred_at: u64,
    bound_actor: EntityId,
}

impl ApprovedCommitmentWake {
    /// The proposal claim this token was minted from.
    #[must_use]
    pub const fn proposal_claim_id(&self) -> EntityId {
        self.proposal_claim_id
    }

    /// The commitment instance the approved wake is about.
    #[must_use]
    pub const fn instance_id(&self) -> EntityId {
        self.instance_id
    }

    /// Which phase fired.
    #[must_use]
    pub const fn phase(&self) -> CommitmentWakePhase {
        self.phase
    }

    /// The deterministic phase key: run id, inbox group key, and outbound
    /// idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// The proposal-authoring Dreamer agent this token is bound to.
    #[must_use]
    pub const fn bound_actor(&self) -> EntityId {
        self.bound_actor
    }

    /// The canonical commitment receipt reference.
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        commitment_trigger_ref(&self.instance_id)
    }
}

/// Decoded proposal value, before it is checked against its own provenance.
struct ProposalFields {
    instance_id: EntityId,
    phase: CommitmentWakePhase,
    fire_at: u64,
    due_at: u64,
    occurred_at: u64,
    idempotency_key: String,
    trigger_ref: String,
    verb: String,
    channel: String,
    target: String,
    on_behalf_of: Option<String>,
    content_ref: Option<String>,
    dedupe_key: Option<String>,
}

/// Mints the opaque approved token from ONE approved proposal row.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for a missing claim and
/// [`Error::InvalidClaimBody`] for every other refusal: `Proposed`,
/// `Rejected`, a non-active lifecycle, a wrong predicate or source, malformed
/// or disagreeing fields, unrelated provenance, and a commitment that no
/// longer resolves, is no longer `Open`, or is no longer `Commitment` strength.
pub fn approved_commitment_wake(
    vault: &Vault,
    proposal_claim_id: &EntityId,
) -> Result<ApprovedCommitmentWake> {
    let body = vault
        .get_claim(proposal_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    require_approved_proposal_shape(&body)?;
    let fields = decode_commitment_wake_proposal(&body.value)?;
    let run_id = require_proposal_provenance(&body, &fields)?;
    let bound_actor = session_claim_producer(&body).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal carries no envelope actor",
    ))?;
    require_live_commitment(vault, &fields.instance_id)?;
    Ok(ApprovedCommitmentWake {
        proposal_claim_id: *proposal_claim_id,
        instance_id: fields.instance_id,
        phase: fields.phase,
        run_id,
        idempotency_key: fields.idempotency_key,
        verb: fields.verb,
        channel: fields.channel,
        target: fields.target,
        on_behalf_of: fields.on_behalf_of,
        content_ref: fields.content_ref,
        dedupe_key: fields.dedupe_key,
        occurred_at: fields.occurred_at,
        bound_actor,
    })
}

fn require_approved_proposal_shape(body: &ClaimBody) -> Result<()> {
    if body.predicate != PREDICATE_COMMITMENT_WAKE_PROPOSAL {
        return Err(Error::InvalidClaimBody(
            "claim predicate is not commitment.wake_proposal",
        ));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not active",
        ));
    }
    if body.approval != ClaimApprovalStatus::Approved {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not approved",
        ));
    }
    if body.source != Some(ClaimSource::Generated) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal is not generated",
        ));
    }
    Ok(())
}

/// Requires the Dreamer provenance to name this exact wake: surface, an exact
/// `cmt:<32-hex>:lead|due` run agreeing with the value's own key, and a 32-hex
/// originating attempt.
fn require_proposal_provenance(body: &ClaimBody, fields: &ProposalFields) -> Result<String> {
    let provenance = claim_provenance(body).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal carries no provenance",
    ))?;
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal provenance is malformed",
        ));
    };
    let entry = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then(|| value.as_str())?)
    };
    if entry(PROVENANCE_KEY_SURFACE) != Some(DREAMER_RUNNER_ATTEMPT_KIND) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal provenance is not a dreamer run",
        ));
    }
    let run = entry(PROVENANCE_KEY_RUN).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal provenance names no run",
    ))?;
    if run != fields.idempotency_key {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal run does not match its phase key",
        ));
    }
    let job_id = entry(PROVENANCE_KEY_JOB_ID).ok_or(Error::InvalidClaimBody(
        "commitment wake proposal provenance names no job",
    ))?;
    if job_id.len() != 32 || !job_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal job id is not an attempt id",
        ));
    }
    Ok(run.to_owned())
}

fn require_live_commitment(vault: &Vault, instance_id: &EntityId) -> Result<()> {
    let record = vault
        .get_commitment_claim(instance_id)?
        .ok_or(Error::InvalidClaimBody(
            "commitment wake proposal names a missing commitment",
        ))?;
    if !matches!(wake_eligibility(&record), WakeEligibility::Eligible) {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal names a closed or ineligible commitment",
        ));
    }
    Ok(())
}

fn claim_provenance(body: &ClaimBody) -> Option<Value> {
    let Value::Map(entries) = body.evidence.as_ref()? else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some("provenance")).then(|| value.clone()))
}

fn decode_commitment_wake_proposal(value: &Value) -> Result<ProposalFields> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal value is malformed",
        ));
    };
    let get = |wanted: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then_some(value))
    };
    let missing = || Error::InvalidClaimBody("commitment wake proposal value is incomplete");
    let required = |key: &str| get(key).ok_or_else(missing);
    let optional_string = |key: &str| -> Result<Option<String>> {
        match get(key) {
            None | Some(Value::Nil) => Ok(None),
            Some(value) => required_string(value).map(Some),
        }
    };
    if required(KEY_SCHEMA_VERSION)?.as_u64() != Some(COMMITMENT_WAKE_PROPOSAL_SCHEMA_VERSION) {
        return Err(Error::InvalidClaimBody(
            "unsupported commitment wake proposal schema version",
        ));
    }
    let Value::Binary(instance_bytes) = required(KEY_INSTANCE_REF)? else {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal instance ref is malformed",
        ));
    };
    let instance_bytes: [u8; 16] = instance_bytes.as_slice().try_into().map_err(|_| {
        Error::InvalidClaimBody("commitment wake proposal instance ref is malformed")
    })?;
    let fields = ProposalFields {
        instance_id: EntityId::from_bytes(instance_bytes).map_err(|_| {
            Error::InvalidClaimBody("commitment wake proposal instance ref is malformed")
        })?,
        phase: CommitmentWakePhase::parse(&required_string(required(KEY_PHASE)?)?).ok_or(
            Error::InvalidClaimBody("commitment wake proposal phase is not lead|due"),
        )?,
        fire_at: required_u64(required(KEY_FIRE_AT)?)?,
        due_at: required_u64(required(KEY_DUE_AT)?)?,
        occurred_at: required_u64(required(KEY_OCCURRED_AT)?)?,
        idempotency_key: required_string(required(KEY_IDEMPOTENCY_KEY)?)?,
        trigger_ref: required_string(required(KEY_TRIGGER_REF)?)?,
        verb: required_string(required(KEY_VERB)?)?,
        channel: required_string(required(KEY_CHANNEL)?)?,
        target: required_string(required(KEY_TARGET)?)?,
        on_behalf_of: optional_string(KEY_ON_BEHALF_OF)?,
        content_ref: optional_string(KEY_CONTENT_REF)?,
        dedupe_key: optional_string(KEY_DEDUPE_KEY)?,
    };
    require_proposal_agreement(&fields)?;
    Ok(fields)
}

/// Every derived field must still agree with the instance and phase it claims
/// to be about, and every delivery string must obey the normal bounds.
fn require_proposal_agreement(fields: &ProposalFields) -> Result<()> {
    let due = CommitmentWakeDue {
        instance_id: fields.instance_id,
        phase: fields.phase,
        fire_at: fields.fire_at,
        due_at: fields.due_at,
    };
    due.event().validate()?;
    if fields.idempotency_key != due.idempotency_key()
        || fields.trigger_ref != due.trigger_ref()
        || fields.occurred_at != fields.fire_at
    {
        return Err(Error::InvalidClaimBody(
            "commitment wake proposal fields disagree",
        ));
    }
    CommitmentWakeProposalDraft {
        verb: fields.verb.clone(),
        channel: fields.channel.clone(),
        target: fields.target.clone(),
        on_behalf_of: fields.on_behalf_of.clone(),
        content_ref: fields.content_ref.clone(),
        dedupe_key: fields.dedupe_key.clone(),
    }
    .validate()
}

/// Converts ONE approved token into the existing outbound draft and delegates
/// EXACTLY ONCE to [`crate::memory::Memory::schedule_outbound`].
///
/// Two ordered guards run before any draft is constructed or any outbound
/// method is called:
///
/// 0. The token is reconstructed from CURRENT vault state and must compare
///    equal. A revoked proposal, a closed or stale commitment, or a mutated
///    field is refused here — BEFORE actor checking — so a stale token can
///    never reach a connector, gate, task, receipt, or idempotency lookup. The
///    residual read-then-schedule TOCTOU window is accepted, matching every
///    other non-transactional facade verb.
/// 1. The facade must be bound to the proposal's authoring agent. Same-actor
///    replay proceeds into the existing idempotency path and coalesces.
///
/// # Errors
///
/// A typed facade error for either guard, plus every existing
/// `schedule_outbound` refusal — including a planner-supplied channel/verb the
/// outbound door rejects, which leaves the approved proposal inert.
pub fn schedule_approved_commitment_wake(
    facade: &Memory<'_>,
    approved: ApprovedCommitmentWake,
) -> MemoryResult<OutboundIntentReceipt> {
    let current = approved_commitment_wake(facade.vault(), &approved.proposal_claim_id)
        .map_err(|_| stale_commitment_wake_token())?;
    if current != approved {
        return Err(stale_commitment_wake_token());
    }
    if facade.actor() != approved.bound_actor {
        return Err(MemoryError::from(Error::ActorLacksClaimAuthority {
            reason: "commitment wake is bound to its authoring agent actor",
        }));
    }
    facade.schedule_outbound(&OutboundDraftInput {
        verb: approved.verb,
        channel: approved.channel,
        target: approved.target,
        on_behalf_of: approved.on_behalf_of,
        content_ref: approved.content_ref,
        idempotency_key: Some(approved.idempotency_key),
        dedupe_key: approved.dedupe_key,
        trigger: COMMITMENT_WAKE_TRIGGER.to_owned(),
        trigger_ref: commitment_trigger_ref(&approved.instance_id),
        // NOT the phase key: `cmt:...` is not a 32-hex attempt id and must
        // never alias the attempt run index.
        job_ref: None,
        occurred_at: Some(approved.occurred_at),
    })
}

fn stale_commitment_wake_token() -> MemoryError {
    MemoryError::from(Error::InvalidClaimBody(
        "approved commitment wake token is stale",
    ))
}
