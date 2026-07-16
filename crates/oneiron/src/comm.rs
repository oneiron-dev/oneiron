//! Communication standing-state claims and the ARCH-0035 projector.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, entity_id_from_type_index_key};
use crate::write_envelope::WriteActor;

/// Current schema version for `comm.*` claim values and comm-owned records.
pub const COMM_SCHEMA_VERSION: u64 = 1;

/// Standing opt-out state for one `(party, channel_class)` key.
pub const PREDICATE_COMM_OPT_OUT: &str = "comm.opt_out";
/// Most recent successful send for one `(party, channel_class)` key.
pub const PREDICATE_COMM_LAST_TOUCH: &str = "comm.last_touch";
/// Membership state for one `(thread_ref, party)` key.
pub const PREDICATE_COMM_THREAD_MEMBER: &str = "comm.thread_member";
/// Reachability state for one `(party, channel_class)` key.
pub const PREDICATE_COMM_REACHABLE_VIA: &str = "comm.reachable_via";

/// Complete `comm.*` standing-state claim family.
pub const COMM_CLAIM_PREDICATES: [&str; 4] = [
    PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_LAST_TOUCH,
    PREDICATE_COMM_THREAD_MEMBER,
    PREDICATE_COMM_REACHABLE_VIA,
];

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_PARTY_REF: &str = "party_ref";
const KEY_CHANNEL_CLASS: &str = "channel_class";
const KEY_THREAD_REF: &str = "thread_ref";
const KEY_OCCURRED_AT: &str = "occurred_at";
const KEY_OPTED_OUT: &str = "opted_out";
const KEY_JOINED: &str = "joined";
const KEY_REACHABLE: &str = "reachable";
const KEY_REASON: &str = "reason";

const COMM_RECORD_KEYS: [&str; 15] = [
    "schema_version",
    "record_kind",
    "sequence",
    "event_kind",
    "party_ref",
    "channel_class",
    "thread_ref",
    "occurred_at",
    "projected",
    "claim_ref",
    "gate_status",
    "outcome",
    "view_bytes",
    "entry_count",
    "actor_ref",
];
const RECORD_KIND_EVENT: &str = "event";
const RECORD_KIND_GATE: &str = "gate";
const RECORD_KIND_RECEIPT: &str = "receipt";
const GATE_STATUS_PENDING: &str = "pending";
const GATE_STATUS_CONSUMED: &str = "consumed";
const OPT_OUT_REASON_STOP: &str = "counterparty_opt_out_stop";
const OPT_OUT_REASONS: [&str; 1] = [OPT_OUT_REASON_STOP];
const OPT_OUT_CLEAR_REASON: &str = "comm_opt_out_clear";
const OPT_OUT_CLEAR_APPROVED: &str = "comm_opt_out_clear_approved";
const PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";
const EVENT_SEQUENCE_KEY: &[u8] = b"comm.event_sequence.v1";
const MAX_KEY_BYTES: usize = 512;

/// Typed error for communication projector and consent operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommError {
    /// Underlying vault operation failed.
    #[error(transparent)]
    Engine(#[from] Error),
    /// A comm key or stored comm record failed validation.
    #[error("invalid comm record")]
    InvalidRecord,
    /// Clearing opt-out was requested without an active restrictive claim.
    #[error("active comm opt-out not found")]
    ActiveOptOutNotFound,
    /// No pending widening transition matches this party and channel.
    #[error("pending comm consent gate not found")]
    PendingGateNotFound,
    /// The ruling timestamp precedes the pending gate.
    #[error("comm consent ruling predates pending gate")]
    RulingPredatesGate,
    /// The ruling principal is not human.
    #[error("comm consent widening requires a human principal")]
    HumanApprovalRequired,
}

impl From<heed::Error> for CommError {
    fn from(error: heed::Error) -> Self {
        Self::Engine(Error::from(error))
    }
}

/// Result type for communication projector and consent operations.
pub type CommResult<T> = std::result::Result<T, CommError>;

/// Outcome of requesting a restrictive-to-widening opt-out transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommClearOptOutOutcome {
    /// The active opt-out remains in force while a human ruling is pending.
    PendingHumanRuling,
}

/// Typed value carried by one claim in the `comm.*` family.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommClaimValue {
    /// Restrictive opt-out state.
    OptOut {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Normalized communication channel class.
        channel_class: String,
        /// Stable machine reason for the restrictive state.
        reason: String,
        /// Event time at which the state became valid.
        occurred_at: u64,
    },
    /// Most recent successful send state.
    LastTouch {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Normalized communication channel class.
        channel_class: String,
        /// Successful-send event time.
        occurred_at: u64,
    },
    /// Thread membership state.
    ThreadMember {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Stable thread reference.
        thread_ref: String,
        /// Join event time.
        occurred_at: u64,
    },
    /// Reachability state. This ticket defines validation but no projector rule.
    ReachableVia {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Normalized communication channel class.
        channel_class: String,
        /// Whether the channel is currently reachable.
        reachable: bool,
    },
}

impl CommClaimValue {
    /// Builds a fully governed claim body for this value.
    #[must_use]
    pub fn claim_body(&self) -> ClaimBody {
        let (predicate, subject, value, valid_from) = match self {
            Self::OptOut {
                party_ref,
                channel_class,
                reason,
                occurred_at,
            } => (
                PREDICATE_COMM_OPT_OUT,
                *party_ref,
                Value::Map(vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                    (
                        Value::from(KEY_CHANNEL_CLASS),
                        Value::from(channel_class.as_str()),
                    ),
                    (Value::from(KEY_OPTED_OUT), Value::Boolean(true)),
                    (Value::from(KEY_REASON), Value::from(reason.as_str())),
                    (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                ]),
                Some(*occurred_at),
            ),
            Self::LastTouch {
                party_ref,
                channel_class,
                occurred_at,
            } => (
                PREDICATE_COMM_LAST_TOUCH,
                *party_ref,
                Value::Map(vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                    (
                        Value::from(KEY_CHANNEL_CLASS),
                        Value::from(channel_class.as_str()),
                    ),
                    (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                ]),
                Some(*occurred_at),
            ),
            Self::ThreadMember {
                party_ref,
                thread_ref,
                occurred_at,
            } => (
                PREDICATE_COMM_THREAD_MEMBER,
                *party_ref,
                Value::Map(vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                    (
                        Value::from(KEY_THREAD_REF),
                        Value::from(thread_ref.as_str()),
                    ),
                    (Value::from(KEY_JOINED), Value::Boolean(true)),
                    (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                ]),
                Some(*occurred_at),
            ),
            Self::ReachableVia {
                party_ref,
                channel_class,
                reachable,
            } => (
                PREDICATE_COMM_REACHABLE_VIA,
                *party_ref,
                Value::Map(vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                    (
                        Value::from(KEY_CHANNEL_CLASS),
                        Value::from(channel_class.as_str()),
                    ),
                    (Value::from(KEY_REACHABLE), Value::Boolean(*reachable)),
                ]),
                None,
            ),
        };
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = valid_from;
        body.source = Some(ClaimSource::Observed);
        let mut scope = vec![(Value::from("sensitivity"), Value::from(2_u64))];
        if matches!(self, Self::OptOut { .. }) {
            scope.push((Value::from("criticality"), Value::from("critical")));
        }
        body.scope = Some(Value::Map(scope));
        body
    }

    fn party_ref(&self) -> EntityId {
        match self {
            Self::OptOut { party_ref, .. }
            | Self::LastTouch { party_ref, .. }
            | Self::ThreadMember { party_ref, .. }
            | Self::ReachableVia { party_ref, .. } => *party_ref,
        }
    }
}

/// Typed read view over a `comm.*` claim and its governance fields.
#[derive(Debug, Clone, PartialEq)]
pub struct CommClaim {
    /// Decoded family value.
    pub value: CommClaimValue,
    /// Approval state copied from the claim governance row.
    pub approval: ClaimApprovalStatus,
    /// Lifecycle state copied from the claim governance row.
    pub lifecycle: ClaimLifecycleStatus,
    /// Validity start copied from the claim governance row.
    pub valid_from: Option<u64>,
    /// Validity end copied from the claim governance row.
    pub valid_to: Option<u64>,
    /// Derived-data staleness marker.
    pub stale: bool,
}

impl CommClaim {
    /// Decodes and structurally validates a claim in the communication family.
    pub fn from_claim_body(body: &ClaimBody) -> Result<Self> {
        validate_comm_claim_structure(body)?;
        let entries = value_map(&body.value)?;
        let party_ref = required_entity_ref(entries, KEY_PARTY_REF)?;
        let value = match body.predicate.as_str() {
            PREDICATE_COMM_OPT_OUT => CommClaimValue::OptOut {
                party_ref,
                channel_class: required_string(entries, KEY_CHANNEL_CLASS)?.to_owned(),
                reason: required_string(entries, KEY_REASON)?.to_owned(),
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
            },
            PREDICATE_COMM_LAST_TOUCH => CommClaimValue::LastTouch {
                party_ref,
                channel_class: required_string(entries, KEY_CHANNEL_CLASS)?.to_owned(),
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
            },
            PREDICATE_COMM_THREAD_MEMBER => CommClaimValue::ThreadMember {
                party_ref,
                thread_ref: required_string(entries, KEY_THREAD_REF)?.to_owned(),
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
            },
            PREDICATE_COMM_REACHABLE_VIA => CommClaimValue::ReachableVia {
                party_ref,
                channel_class: required_string(entries, KEY_CHANNEL_CLASS)?.to_owned(),
                reachable: required_bool(entries, KEY_REACHABLE)?,
            },
            _ => unreachable!("predicate membership checked by validator"),
        };
        Ok(Self {
            value,
            approval: body.approval,
            lifecycle: body.lifecycle,
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            stale: body.stale,
        })
    }

    /// Returns whether this claim contributes to standing state at `at`.
    #[must_use]
    pub fn is_effective_at(&self, at: u64) -> bool {
        matches!(
            self.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) && self.lifecycle == ClaimLifecycleStatus::Active
            && !self.stale
            && self.valid_from.is_none_or(|from| from <= at)
            && self.valid_to.is_none_or(|to| at <= to)
    }

    /// Returns whether this claim is the current standing-state head.
    #[must_use]
    pub fn is_standing(&self) -> bool {
        matches!(
            self.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) && self.lifecycle == ClaimLifecycleStatus::Active
            && !self.stale
    }
}

/// Returns whether `predicate` belongs to the communication claim family.
#[must_use]
pub fn is_comm_claim_predicate(predicate: &str) -> bool {
    COMM_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `comm.*` claim value, subject, and conflict-key shape.
pub(crate) fn validate_comm_claim_structure(body: &ClaimBody) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_claim("comm claim subject must be an entity"));
    };
    if !is_comm_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown comm claim predicate"));
    }
    let entries = value_map(&body.value)?;
    if required_u64(entries, KEY_SCHEMA_VERSION)? != COMM_SCHEMA_VERSION {
        return Err(invalid_claim("comm schema_version is invalid"));
    }
    if required_entity_ref(entries, KEY_PARTY_REF)? != subject {
        return Err(invalid_claim("comm party_ref must match subject"));
    }
    match body.predicate.as_str() {
        PREDICATE_COMM_OPT_OUT => {
            validate_keys(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_PARTY_REF,
                    KEY_CHANNEL_CLASS,
                    KEY_OPTED_OUT,
                    KEY_REASON,
                    KEY_OCCURRED_AT,
                ],
            )?;
            validate_channel_class(required_string(entries, KEY_CHANNEL_CLASS)?)?;
            if !required_bool(entries, KEY_OPTED_OUT)? {
                return Err(invalid_claim("comm.opt_out must be restrictive"));
            }
            let reason = required_string(entries, KEY_REASON)?;
            if !OPT_OUT_REASONS.contains(&reason) {
                return Err(invalid_claim("comm.opt_out reason is invalid"));
            }
            required_u64(entries, KEY_OCCURRED_AT).map(|_| ())
        }
        PREDICATE_COMM_LAST_TOUCH => {
            validate_keys(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_PARTY_REF,
                    KEY_CHANNEL_CLASS,
                    KEY_OCCURRED_AT,
                ],
            )?;
            validate_channel_class(required_string(entries, KEY_CHANNEL_CLASS)?)?;
            required_u64(entries, KEY_OCCURRED_AT).map(|_| ())
        }
        PREDICATE_COMM_THREAD_MEMBER => {
            validate_keys(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_PARTY_REF,
                    KEY_THREAD_REF,
                    KEY_JOINED,
                    KEY_OCCURRED_AT,
                ],
            )?;
            validate_key_string(required_string(entries, KEY_THREAD_REF)?)?;
            if !required_bool(entries, KEY_JOINED)? {
                return Err(invalid_claim(
                    "comm.thread_member must represent membership",
                ));
            }
            required_u64(entries, KEY_OCCURRED_AT).map(|_| ())
        }
        PREDICATE_COMM_REACHABLE_VIA => {
            validate_keys(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_PARTY_REF,
                    KEY_CHANNEL_CLASS,
                    KEY_REACHABLE,
                ],
            )?;
            validate_channel_class(required_string(entries, KEY_CHANNEL_CLASS)?)?;
            required_bool(entries, KEY_REACHABLE).map(|_| ())
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommEventKind {
    SendSucceeded,
    InboundStop,
    ThreadJoined,
    ThreadLeft,
}

impl CommEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SendSucceeded => "send_succeeded",
            Self::InboundStop => "inbound_stop",
            Self::ThreadJoined => "thread_joined",
            Self::ThreadLeft => "thread_left",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "send_succeeded" => Some(Self::SendSucceeded),
            "inbound_stop" => Some(Self::InboundStop),
            "thread_joined" => Some(Self::ThreadJoined),
            "thread_left" => Some(Self::ThreadLeft),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum CommRecord {
    Event {
        sequence: u64,
        kind: CommEventKind,
        party_ref: EntityId,
        channel_class: Option<String>,
        thread_ref: Option<String>,
        occurred_at: u64,
        projected: bool,
    },
    Gate {
        party_ref: EntityId,
        channel_class: String,
        claim_ref: EntityId,
        created_at: u64,
        pending: bool,
    },
    Receipt {
        party_ref: EntityId,
        channel_class: String,
        occurred_at: u64,
        outcome: String,
        actor_ref: EntityId,
    },
}

impl CommRecord {
    fn occurred_at(&self) -> u64 {
        match self {
            Self::Event { occurred_at, .. } | Self::Receipt { occurred_at, .. } => *occurred_at,
            Self::Gate { created_at, .. } => *created_at,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ProjectorAction {
    UpsertLastTouch,
    SetOptOut,
    JoinThread,
    LeaveThread,
}

#[derive(Debug, Clone, Copy)]
struct ProjectorRule {
    event_kind: CommEventKind,
    predicate: &'static str,
    action: ProjectorAction,
}

const PROJECTOR_RULES: [ProjectorRule; 4] = [
    ProjectorRule {
        event_kind: CommEventKind::SendSucceeded,
        predicate: PREDICATE_COMM_LAST_TOUCH,
        action: ProjectorAction::UpsertLastTouch,
    },
    ProjectorRule {
        event_kind: CommEventKind::InboundStop,
        predicate: PREDICATE_COMM_OPT_OUT,
        action: ProjectorAction::SetOptOut,
    },
    ProjectorRule {
        event_kind: CommEventKind::ThreadJoined,
        predicate: PREDICATE_COMM_THREAD_MEMBER,
        action: ProjectorAction::JoinThread,
    },
    ProjectorRule {
        event_kind: CommEventKind::ThreadLeft,
        predicate: PREDICATE_COMM_THREAD_MEMBER,
        action: ProjectorAction::LeaveThread,
    },
];

/// Records a successful send receipt without directly writing standing-state claims.
pub fn record_comm_send_receipt(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        Some(channel_class),
        None,
        CommEventKind::SendSucceeded,
        occurred_at,
    )
}

/// Records an inbound restrictive STOP event without directly writing claims.
pub fn record_comm_inbound_stop(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        Some(channel_class),
        None,
        CommEventKind::InboundStop,
        occurred_at,
    )
}

/// Records a thread join or leave event without directly writing claims.
pub fn record_comm_thread_event(
    vault: &Vault,
    thread_ref: &str,
    party: &str,
    joined: bool,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        None,
        Some(thread_ref),
        if joined {
            CommEventKind::ThreadJoined
        } else {
            CommEventKind::ThreadLeft
        },
        occurred_at,
    )
}

/// Runs one ordered, idempotent communication projector pass.
pub fn run_comm_projector(vault: &Vault) -> CommResult<()> {
    let mut pending = {
        let rtxn = vault.store.env.read_txn()?;
        comm_records_in_txn(vault, &rtxn)?
            .into_iter()
            .filter_map(|(id, record)| match record {
                CommRecord::Event {
                    sequence,
                    projected: false,
                    ..
                } => Some((sequence, id)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    pending.sort_by_key(|(sequence, _)| *sequence);
    for (_, event_id) in pending {
        project_event(vault, event_id)?;
    }
    Ok(())
}

/// Counts active claims by the full `(predicate, party, channel_class)` key.
pub fn count_active_comm_claims(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    count_comm_claims(vault, predicate, party, Some(channel_class), None, true)
}

/// Counts all claim history rows by the full `(predicate, party, channel_class)` key.
pub fn count_total_comm_claim_rows(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    count_comm_claims(vault, predicate, party, Some(channel_class), None, false)
}

/// Counts active `comm.thread_member` claims by `(thread_ref, party)`.
pub fn count_active_thread_member_claims(
    vault: &Vault,
    thread_ref: &str,
    party: &str,
) -> CommResult<usize> {
    count_comm_claims(
        vault,
        PREDICATE_COMM_THREAD_MEMBER,
        party,
        None,
        Some(thread_ref),
        true,
    )
}

/// Counts all pending human-gate rows for communication widening transitions.
pub fn count_pending_comm_consent_gates(vault: &Vault) -> CommResult<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(comm_records_in_txn(vault, &rtxn)?
        .into_iter()
        .filter(|(_, record)| matches!(record, CommRecord::Gate { pending: true, .. }))
        .count())
}

/// Requests human review to clear one active `comm.opt_out` claim.
pub fn request_opt_out_clear(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    created_at: u64,
) -> CommResult<CommClearOptOutOutcome> {
    validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::ActiveOptOutNotFound);
    };
    vault.try_with_write_txn(|wtxn| {
        let records = comm_records_in_txn(vault, &*wtxn)?;
        let active = matching_claims_in_txn(
            vault,
            &*wtxn,
            party_ref,
            PREDICATE_COMM_OPT_OUT,
            Some(channel_class),
            None,
            true,
        )?;
        require_at_most_one(&active)?;
        let Some((claim_ref, _)) = active.into_iter().next() else {
            return Err(CommError::ActiveOptOutNotFound);
        };
        let pending_count = records
            .iter()
            .filter(|(_, record)| {
                matches!(record, CommRecord::Gate {
                    party_ref: candidate_party,
                    channel_class: candidate_channel,
                    pending: true,
                    ..
                } if *candidate_party == party_ref && candidate_channel == channel_class)
            })
            .count();
        match pending_count {
            0 => {}
            1 => return Ok(CommClearOptOutOutcome::PendingHumanRuling),
            _ => return Err(CommError::InvalidRecord),
        }
        let gate = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: true,
        };
        put_comm_record_in_txn(vault, wtxn, EntityId::now(), &gate)?;
        Ok(CommClearOptOutOutcome::PendingHumanRuling)
    })
}

/// Applies a one-shot opt-out-clear ruling, accepting only a bound human actor.
pub fn approve_pending_opt_out_clear(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    actor: WriteActor,
    ruled_at: u64,
) -> CommResult<()> {
    let Some(actor_entity_type) = vault.get_entity_type(&actor.entity_ref())? else {
        return Err(CommError::Engine(Error::EntityNotFound));
    };
    validate_actor_class(actor_entity_type, actor.actor_class())?;
    if actor.actor_class() != EdgeActorClass::Human {
        return Err(CommError::HumanApprovalRequired);
    }
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::PendingGateNotFound);
    };
    let cleared = vault.try_with_write_txn(|wtxn| {
        let records = comm_records_in_txn(vault, &*wtxn)?;
        let mut gates = records.into_iter().filter(|(_, record)| {
            matches!(record, CommRecord::Gate {
                party_ref: candidate_party,
                channel_class: candidate_channel,
                pending: true,
                ..
            } if *candidate_party == party_ref && candidate_channel == channel_class)
        });
        let gate = gates.next();
        if gates.next().is_some() {
            return Err(CommError::InvalidRecord);
        }
        let Some((gate_id, gate)) = gate else {
            return Err(CommError::PendingGateNotFound);
        };
        let CommRecord::Gate {
            claim_ref,
            created_at,
            ..
        } = gate
        else {
            unreachable!("filtered to gate")
        };
        if ruled_at < created_at {
            return Err(CommError::RulingPredatesGate);
        }
        let active = matching_claims_in_txn(
            vault,
            &*wtxn,
            party_ref,
            PREDICATE_COMM_OPT_OUT,
            Some(channel_class),
            None,
            true,
        )?;
        require_at_most_one(&active)?;
        let live_claim_ref = active.into_iter().next().map(|(claim_id, _)| claim_id);
        if let Some(live_claim_ref) = live_claim_ref {
            vault.retract_claim_in_txn(wtxn, &live_claim_ref, ruled_at)?;
        }
        let consumed = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: false,
        };
        put_comm_record_in_txn(vault, wtxn, gate_id, &consumed)?;
        if live_claim_ref.is_some() {
            let receipt = CommRecord::Receipt {
                party_ref,
                channel_class: channel_class.to_owned(),
                occurred_at: ruled_at,
                outcome: OPT_OUT_CLEAR_APPROVED.to_owned(),
                actor_ref: actor.entity_ref(),
            };
            put_comm_record_in_txn(vault, wtxn, EntityId::now(), &receipt)?;
        }
        Ok(live_claim_ref.is_some())
    })?;
    if cleared {
        Ok(())
    } else {
        Err(CommError::ActiveOptOutNotFound)
    }
}

/// Counts durable opt-out-clear approval receipts for one party.
pub fn count_opt_out_clear_receipts(vault: &Vault, party: &str) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(comm_records_in_txn(vault, &rtxn)?
        .into_iter()
        .filter(|(_, record)| {
            matches!(record, CommRecord::Receipt {
                party_ref: candidate_party,
                outcome,
                ..
            } if *candidate_party == party_ref && outcome == OPT_OUT_CLEAR_APPROVED)
        })
        .count())
}

/// Returns canonical contact-view bytes derived from live standing claims.
pub fn materialize_contact_record(vault: &Vault, party: &str) -> CommResult<Vec<u8>> {
    let party_ref = resolve_or_create_party(vault, party)?;
    let rtxn = vault.store.env.read_txn()?;
    build_contact_view_in_txn(vault, &rtxn, party_ref).map(|(bytes, _)| bytes)
}

/// No-op because the contact record is always derived from live claims.
pub fn drop_contact_record(_vault: &Vault, _party: &str) -> CommResult<()> {
    Ok(())
}

/// Counts contact-view entries derived from live standing claims.
pub fn count_contact_record_claim_entries(vault: &Vault, party: &str) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    let (_, entry_count) = build_contact_view_in_txn(vault, &rtxn, party_ref)?;
    usize::try_from(entry_count).map_err(|_| CommError::InvalidRecord)
}

/// Resolves or creates the PERSON entity used as a comm claim subject.
pub fn resolve_or_create_comm_party(vault: &Vault, party: &str) -> CommResult<EntityId> {
    resolve_or_create_party(vault, party)
}

fn record_event(
    vault: &Vault,
    party: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    kind: CommEventKind,
    occurred_at: u64,
) -> CommResult<()> {
    if let Some(channel_class) = channel_class {
        validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    }
    if let Some(thread_ref) = thread_ref {
        validate_key_string(thread_ref).map_err(|_| CommError::InvalidRecord)?;
    }
    let party_ref = resolve_or_create_party(vault, party)?;
    vault.try_with_write_txn(|wtxn| {
        let sequence = next_event_sequence_in_txn(vault, wtxn)?;
        let record = CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class: channel_class.map(str::to_owned),
            thread_ref: thread_ref.map(str::to_owned),
            occurred_at,
            projected: false,
        };
        put_comm_record_in_txn(vault, wtxn, EntityId::now(), &record)
    })
}

fn project_event(vault: &Vault, event_id: EntityId) -> CommResult<()> {
    vault.try_with_write_txn(|wtxn| {
        let Some(raw) = vault.store.entities.get(&*wtxn, event_id.as_bytes())? else {
            return Ok(());
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or(CommError::InvalidRecord)?;
        if header.entity_type != ENTITY_TYPE_COMM_RECORD {
            return Err(CommError::InvalidRecord);
        }
        let record = decode_comm_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class,
            thread_ref,
            occurred_at,
            projected,
        } = record
        else {
            return Err(CommError::InvalidRecord);
        };
        if projected {
            return Ok(());
        }
        let rule = PROJECTOR_RULES
            .iter()
            .find(|rule| rule.event_kind == kind)
            .ok_or(CommError::InvalidRecord)?;
        apply_projector_rule_in_txn(
            vault,
            wtxn,
            *rule,
            party_ref,
            channel_class.as_deref(),
            thread_ref.as_deref(),
            occurred_at,
        )?;
        let consumed = CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class,
            thread_ref,
            occurred_at,
            projected: true,
        };
        put_comm_record_in_txn(vault, wtxn, event_id, &consumed)?;
        Ok(())
    })
}

fn apply_projector_rule_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    rule: ProjectorRule,
    party_ref: EntityId,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    occurred_at: u64,
) -> CommResult<()> {
    match rule.action {
        ProjectorAction::UpsertLastTouch => {
            let channel = channel_class.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                Some(channel),
                None,
                true,
            )?;
            require_at_most_one(&active)?;
            let value = CommClaimValue::LastTouch {
                party_ref,
                channel_class: channel.to_owned(),
                occurred_at,
            };
            let new_id = put_comm_claim_in_txn(vault, wtxn, &value, occurred_at)?;
            if let Some((old_id, _)) = active.into_iter().next() {
                let raw = vault
                    .store
                    .entities
                    .get(&*wtxn, old_id.as_bytes())?
                    .ok_or(CommError::InvalidRecord)?;
                let header = EntityMetadataHeader::parse(&raw).ok_or(CommError::InvalidRecord)?;
                if header.entity_type != ENTITY_TYPE_CLAIM {
                    return Err(CommError::InvalidRecord);
                }
                let close_at = occurred_at.max(header.occurred_start);
                vault.supersede_claim_in_txn(wtxn, &new_id, &old_id, close_at)?;
            }
            Ok(())
        }
        ProjectorAction::SetOptOut => {
            let channel = channel_class.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                Some(channel),
                None,
                true,
            )?;
            require_at_most_one(&active)?;
            if active.is_empty() {
                let value = CommClaimValue::OptOut {
                    party_ref,
                    channel_class: channel.to_owned(),
                    reason: OPT_OUT_REASON_STOP.to_owned(),
                    occurred_at,
                };
                put_comm_claim_in_txn(vault, wtxn, &value, occurred_at)?;
            }
            Ok(())
        }
        ProjectorAction::JoinThread => {
            let thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                None,
                Some(thread),
                true,
            )?;
            require_at_most_one(&active)?;
            if active.is_empty() {
                let value = CommClaimValue::ThreadMember {
                    party_ref,
                    thread_ref: thread.to_owned(),
                    occurred_at,
                };
                put_comm_claim_in_txn(vault, wtxn, &value, occurred_at)?;
            }
            Ok(())
        }
        ProjectorAction::LeaveThread => {
            let thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                None,
                Some(thread),
                true,
            )?;
            require_at_most_one(&active)?;
            if let Some((claim_id, _)) = active.into_iter().next() {
                vault.retract_claim_in_txn(wtxn, &claim_id, occurred_at)?;
            }
            Ok(())
        }
    }
}

fn put_comm_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<EntityId> {
    let body = value.claim_body();
    let data = encode_claim_body(&body)?;
    let id = EntityId::now();
    let subject = value.party_ref();
    if vault
        .store
        .entities
        .get(&*wtxn, subject.as_bytes())?
        .is_none()
    {
        return Err(CommError::Engine(Error::EntityNotFound));
    }
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: occurred_at,
                    end: occurred_at,
                },
                learned_at: occurred_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            },
            BatchOp::Edge {
                src: id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}

fn count_comm_claims(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    active_only: bool,
) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(matching_claims_in_txn(
        vault,
        &rtxn,
        party_ref,
        predicate,
        channel_class,
        thread_ref,
        active_only,
    )?
    .len())
}

fn matching_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
    predicate: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    active_only: bool,
) -> CommResult<Vec<(EntityId, CommClaim)>> {
    let mut matches = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != predicate || !is_comm_claim_predicate(&body.predicate) {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if active_only && !claim.is_standing() {
            continue;
        }
        let key_matches = match &claim.value {
            CommClaimValue::OptOut {
                channel_class: candidate,
                ..
            }
            | CommClaimValue::LastTouch {
                channel_class: candidate,
                ..
            }
            | CommClaimValue::ReachableVia {
                channel_class: candidate,
                ..
            } => channel_class == Some(candidate.as_str()),
            CommClaimValue::ThreadMember {
                thread_ref: candidate,
                ..
            } => thread_ref == Some(candidate.as_str()),
        };
        if key_matches {
            matches.push((claim_id, claim));
        }
    }
    Ok(matches)
}

fn require_at_most_one(matches: &[(EntityId, CommClaim)]) -> CommResult<()> {
    if matches.len() > 1 {
        Err(CommError::InvalidRecord)
    } else {
        Ok(())
    }
}

fn build_contact_view_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<(Vec<u8>, u64)> {
    let mut last_touch = Vec::new();
    let mut opt_out = Vec::new();
    let mut threads = BTreeSet::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if !is_comm_claim_predicate(&body.predicate) {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        match claim.value {
            CommClaimValue::LastTouch {
                channel_class,
                occurred_at,
                ..
            } => last_touch.push((channel_class, occurred_at)),
            CommClaimValue::OptOut {
                channel_class,
                occurred_at,
                ..
            } => opt_out.push((channel_class, occurred_at)),
            CommClaimValue::ThreadMember { thread_ref, .. } => {
                threads.insert(thread_ref);
            }
            CommClaimValue::ReachableVia { .. } => {}
        }
    }
    last_touch.sort();
    opt_out.sort();
    let entry_count = u64::try_from(last_touch.len() + opt_out.len() + threads.len())
        .map_err(|_| CommError::InvalidRecord)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMM_SCHEMA_VERSION),
        ),
        (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
        (Value::from("first_touch"), Value::Nil),
        (
            Value::from("last_touch"),
            Value::Array(
                last_touch
                    .iter()
                    .map(|(channel, occurred_at)| {
                        Value::Map(vec![
                            (
                                Value::from(KEY_CHANNEL_CLASS),
                                Value::from(channel.as_str()),
                            ),
                            (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::from("opt_out"),
            Value::Array(
                opt_out
                    .iter()
                    .map(|(channel, occurred_at)| {
                        Value::Map(vec![
                            (
                                Value::from(KEY_CHANNEL_CLASS),
                                Value::from(channel.as_str()),
                            ),
                            (Value::from(KEY_OPTED_OUT), Value::Boolean(true)),
                            (Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::from("threads"),
            Value::Array(
                threads
                    .iter()
                    .map(|thread| Value::from(thread.as_str()))
                    .collect(),
            ),
        ),
    ]);
    Ok((encode_value(&value)?, entry_count))
}

fn resolve_or_create_party(vault: &Vault, party: &str) -> CommResult<EntityId> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    let index_key = party_index_key(party);
    vault.try_with_write_txn(|wtxn| {
        if let Some(raw) = vault.store.vault_meta.get(&*wtxn, &index_key)? {
            return decode_entity_id(&raw).map_err(CommError::from);
        }
        let id = EntityId::now();
        let body = encode_value(&Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(COMM_SCHEMA_VERSION),
            ),
            (Value::from("party_key"), Value::from(party)),
        ]))?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_PERSON,
                occurred: TimeRange { start: 0, end: 0 },
                learned_at: 0,
                data: body,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        vault
            .store
            .vault_meta
            .put(wtxn, &index_key, id.as_bytes())?;
        Ok(id)
    })
}

fn resolve_party(vault: &Vault, party: &str) -> CommResult<Option<EntityId>> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &party_index_key(party))?
        .as_deref()
        .map(decode_entity_id)
        .transpose()
        .map_err(CommError::from)
}

fn party_index_key(party: &str) -> Vec<u8> {
    let digest = Sha256::digest(party.as_bytes());
    let mut key = Vec::with_capacity(PARTY_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(PARTY_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

fn next_event_sequence_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> CommResult<u64> {
    let current = vault
        .store
        .vault_meta
        .get(&*wtxn, EVENT_SEQUENCE_KEY)?
        .map(|raw| {
            let bytes: [u8; 8] = raw
                .as_ref()
                .try_into()
                .map_err(|_| CommError::InvalidRecord)?;
            Ok::<u64, CommError>(u64::from_le_bytes(bytes))
        })
        .transpose()?
        .unwrap_or(0);
    let next = current.checked_add(1).ok_or(CommError::InvalidRecord)?;
    vault
        .store
        .vault_meta
        .put(wtxn, EVENT_SEQUENCE_KEY, &next.to_le_bytes())?;
    Ok(next)
}

fn comm_records_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<Vec<(EntityId, CommRecord)>> {
    let mut records = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_COMM_RECORD])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_COMM_RECORD {
            continue;
        }
        let Ok(record) = decode_comm_record(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            continue;
        };
        records.push((id, record));
    }
    Ok(records)
}

fn put_comm_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    record: &CommRecord,
) -> CommResult<()> {
    let occurred_at = record.occurred_at();
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_COMM_RECORD,
            occurred: TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            learned_at: occurred_at,
            data: encode_comm_record(record)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(())
}

fn encode_comm_record(record: &CommRecord) -> CommResult<Vec<u8>> {
    let mut values = vec![Value::Nil; COMM_RECORD_KEYS.len()];
    values[0] = Value::from(COMM_SCHEMA_VERSION);
    match record {
        CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class,
            thread_ref,
            occurred_at,
            projected,
        } => {
            values[1] = Value::from(RECORD_KIND_EVENT);
            values[2] = Value::from(*sequence);
            values[3] = Value::from(kind.as_str());
            values[4] = Value::from(party_ref.to_hex());
            values[5] = channel_class.as_deref().map_or(Value::Nil, Value::from);
            values[6] = thread_ref.as_deref().map_or(Value::Nil, Value::from);
            values[7] = Value::from(*occurred_at);
            values[8] = Value::Boolean(*projected);
        }
        CommRecord::Gate {
            party_ref,
            channel_class,
            claim_ref,
            created_at,
            pending,
        } => {
            values[1] = Value::from(RECORD_KIND_GATE);
            values[4] = Value::from(party_ref.to_hex());
            values[5] = Value::from(channel_class.as_str());
            values[7] = Value::from(*created_at);
            values[9] = Value::from(claim_ref.to_hex());
            values[10] = Value::from(if *pending {
                GATE_STATUS_PENDING
            } else {
                GATE_STATUS_CONSUMED
            });
            values[11] = Value::from(OPT_OUT_CLEAR_REASON);
        }
        CommRecord::Receipt {
            party_ref,
            channel_class,
            occurred_at,
            outcome,
            actor_ref,
        } => {
            values[1] = Value::from(RECORD_KIND_RECEIPT);
            values[4] = Value::from(party_ref.to_hex());
            values[5] = Value::from(channel_class.as_str());
            values[7] = Value::from(*occurred_at);
            values[11] = Value::from(outcome.as_str());
            values[14] = Value::from(actor_ref.to_hex());
        }
    }
    let map = Value::Map(
        COMM_RECORD_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| (Value::from(*key), value))
            .collect(),
    );
    encode_value(&map).map_err(CommError::from)
}

fn decode_comm_record(bytes: &[u8]) -> CommResult<CommRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| CommError::InvalidRecord)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CommError::InvalidRecord);
    }
    let entries = value_map(&value).map_err(|_| CommError::InvalidRecord)?;
    validate_keys(entries, &COMM_RECORD_KEYS).map_err(|_| CommError::InvalidRecord)?;
    if required_u64(entries, KEY_SCHEMA_VERSION).map_err(|_| CommError::InvalidRecord)?
        != COMM_SCHEMA_VERSION
    {
        return Err(CommError::InvalidRecord);
    }
    let kind = required_string(entries, "record_kind").map_err(|_| CommError::InvalidRecord)?;
    let party_ref =
        required_entity_ref(entries, KEY_PARTY_REF).map_err(|_| CommError::InvalidRecord)?;
    match kind {
        RECORD_KIND_EVENT => Ok(CommRecord::Event {
            sequence: required_u64(entries, "sequence").map_err(|_| CommError::InvalidRecord)?,
            kind: required_string(entries, "event_kind")
                .ok()
                .and_then(CommEventKind::parse)
                .ok_or(CommError::InvalidRecord)?,
            party_ref,
            channel_class: optional_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?,
            thread_ref: optional_string(entries, KEY_THREAD_REF)
                .map_err(|_| CommError::InvalidRecord)?,
            occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                .map_err(|_| CommError::InvalidRecord)?,
            projected: required_bool(entries, "projected").map_err(|_| CommError::InvalidRecord)?,
        }),
        RECORD_KIND_GATE => Ok(CommRecord::Gate {
            party_ref,
            channel_class: required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned(),
            claim_ref: required_entity_ref(entries, "claim_ref")
                .map_err(|_| CommError::InvalidRecord)?,
            created_at: required_u64(entries, KEY_OCCURRED_AT)
                .map_err(|_| CommError::InvalidRecord)?,
            pending: match required_string(entries, "gate_status")
                .map_err(|_| CommError::InvalidRecord)?
            {
                GATE_STATUS_PENDING => true,
                GATE_STATUS_CONSUMED => false,
                _ => return Err(CommError::InvalidRecord),
            },
        }),
        RECORD_KIND_RECEIPT => Ok(CommRecord::Receipt {
            party_ref,
            channel_class: required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned(),
            occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                .map_err(|_| CommError::InvalidRecord)?,
            outcome: required_string(entries, "outcome")
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned(),
            actor_ref: required_entity_ref(entries, "actor_ref")
                .map_err(|_| CommError::InvalidRecord)?,
        }),
        _ => Err(CommError::InvalidRecord),
    }
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("comm claim value must be a map")),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("comm value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("comm value contains duplicate key"));
    }
    Ok(value)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| invalid_claim("comm value string invalid"))
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    let value = required_value(entries, key)?;
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| invalid_claim("comm optional string invalid"))
    }
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("comm value integer invalid"))
}

fn required_bool(entries: &[(Value, Value)], key: &str) -> Result<bool> {
    match required_value(entries, key)? {
        Value::Boolean(value) => Ok(*value),
        _ => Err(invalid_claim("comm value boolean invalid")),
    }
}

fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    EntityId::from_hex(required_string(entries, key)?)
        .map_err(|_| invalid_claim("comm entity reference invalid"))
}

fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    if entries.len() != expected.len() {
        return Err(invalid_claim("comm value key set invalid"));
    }
    for expected_key in expected {
        required_value(entries, expected_key)?;
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !expected.contains(&key)))
    {
        return Err(invalid_claim("comm value key set invalid"));
    }
    Ok(())
}

fn validate_key_string(value: &str) -> Result<()> {
    if value.trim() != value || value.is_empty() || value.len() > MAX_KEY_BYTES {
        return Err(invalid_claim("comm key string invalid"));
    }
    Ok(())
}

fn validate_channel_class(value: &str) -> Result<()> {
    validate_key_string(value)?;
    if value != value.to_ascii_lowercase() {
        return Err(invalid_claim("comm channel_class must be normalized"));
    }
    Ok(())
}

fn decode_entity_id(raw: &[u8]) -> Result<EntityId> {
    let bytes: [u8; ENTITY_ID_LEN] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("comm entity reference"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("comm entity reference"))
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("comm MessagePack encode failed"))?;
    Ok(bytes)
}

fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests;
