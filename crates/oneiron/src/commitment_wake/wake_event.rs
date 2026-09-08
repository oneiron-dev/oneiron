//! Commitment wake event vocabulary and tagged-payload codec.

use rmpv::Value;

use crate::commitment_schedule::{CommitmentDueEntry, CommitmentDuePhase};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

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
pub(super) const COMMITMENT_WAKE_PROPOSAL_CLAIM_ID_DOMAIN: &[u8] =
    b"oneiron.commitment.wake_proposal.v1\0";

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

const KEY_EVENT: &str = "event";

const KEY_COMMITMENT_REF: &str = "commitment_ref";

pub(super) const KEY_PHASE: &str = "phase";

pub(super) const KEY_FIRE_AT: &str = "fire_at";

pub(super) const KEY_DUE_AT: &str = "due_at";

pub(super) const KEY_INSTANCE_REF: &str = "instance_ref";

pub(super) const KEY_OCCURRED_AT: &str = "occurred_at";

pub(super) const KEY_IDEMPOTENCY_KEY: &str = "idempotency_key";

pub(super) const KEY_TRIGGER_REF: &str = "trigger_ref";

pub(super) const KEY_VERB: &str = "verb";

pub(super) const KEY_CHANNEL: &str = "channel";

pub(super) const KEY_TARGET: &str = "target";

pub(super) const KEY_ON_BEHALF_OF: &str = "on_behalf_of";

pub(super) const KEY_CONTENT_REF: &str = "content_ref";

pub(super) const KEY_DEDUPE_KEY: &str = "dedupe_key";

pub(super) const PROVENANCE_KEY_SURFACE: &str = "surface";

pub(super) const PROVENANCE_KEY_RUN: &str = "run";

pub(super) const PROVENANCE_KEY_JOB_ID: &str = "job_id";

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

    pub(super) fn event(&self) -> CommitmentWakeEvent {
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

    pub(super) fn validate(&self) -> Result<()> {
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

pub(super) fn commitment_trigger_ref(instance_id: &EntityId) -> String {
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

pub(super) fn required_u64(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| malformed_event("commitment wake value is not an unsigned integer"))
}

pub(super) fn required_string(value: &Value) -> Result<String> {
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

pub(super) fn validate_wake_string(value: &str, reason: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_COMMITMENT_WAKE_STRING_BYTES {
        return Err(Error::InvalidClaimBody(reason));
    }
    Ok(())
}

pub(super) fn validate_optional_wake_string(
    value: Option<&str>,
    reason: &'static str,
) -> Result<()> {
    match value {
        Some(value) => validate_wake_string(value, reason),
        None => Ok(()),
    }
}
