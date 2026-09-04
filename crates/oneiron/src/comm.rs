//! Communication standing-state claims and the ARCH-0035 projector.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
use crate::counterparty_contact::{
    CounterpartyOptOutReason, normalize_channel_class, rematerialize_contact_cache_in_txn,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use crate::provenance::validate_actor_class;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, entity_id_from_type_index_key};
use crate::write_envelope::WriteActor;

/// Current schema version for `comm.*` claim values and comm-owned records.
pub const COMM_SCHEMA_VERSION: u64 = 1;

/// Standing opt-out state for one `(party, channel_class)` key.
///
/// An ABSENT `channel_class` is the party-wide key: it means every channel
/// class, and it is what a contact-level opt-out projects (ONE-1752). Landed
/// channel-scoped heads keep validating and keep matching only their own
/// normalized class.
pub const PREDICATE_COMM_OPT_OUT: &str = "comm.opt_out";
/// Most recent successful send for one `(party, channel_class)` key.
pub const PREDICATE_COMM_LAST_TOUCH: &str = "comm.last_touch";
/// Membership state for one `(thread_ref, party)` key.
pub const PREDICATE_COMM_THREAD_MEMBER: &str = "comm.thread_member";
/// Reachability state for one `(party, channel_class)` key.
pub const PREDICATE_COMM_REACHABLE_VIA: &str = "comm.reachable_via";
/// Owner decision authorizing sends to an opted-out party (ARCH-0057 §3.1).
///
/// It never clears an opt-out: `comm.opt_out`, `comm.do_not_contact` and the
/// contact-level opt-out all stand untouched, and CLEAR remains a distinct op.
/// The override only changes what the external-effect gate does with the
/// suppression it still sees.
pub const PREDICATE_COMM_SEND_OVERRIDE: &str = "comm.send_override";

/// Complete `comm.*` standing-state claim family.
pub const COMM_CLAIM_PREDICATES: [&str; 5] = [
    PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_LAST_TOUCH,
    PREDICATE_COMM_THREAD_MEMBER,
    PREDICATE_COMM_REACHABLE_VIA,
    PREDICATE_COMM_SEND_OVERRIDE,
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
const KEY_SCOPE: &str = "scope";
const KEY_SEND_REF: &str = "send_ref";
const KEY_ISSUED_AT: &str = "issued_at";
const KEY_VALID_TO: &str = "valid_to";
/// Synced-truth field on a comm-owned PERSON body. `PARTY_INDEX_PREFIX` caches
/// the lookup; THIS is what the cache is a cache of.
const KEY_PARTY_KEY: &str = "party_key";

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
/// The `comm.opt_out` reason vocabulary is the RECEIPT vocabulary
/// (`CounterpartyOptOutReason::receipt_reason`), never the `as_str()` one: the
/// landed heads carry these tokens, and swapping vocabularies would invalidate
/// them. Pinned to the enum's own const fn so the two can never drift.
const OPT_OUT_REASON_STOP: &str = CounterpartyOptOutReason::Stop.receipt_reason();
const OPT_OUT_REASON_UNSUBSCRIBE: &str = CounterpartyOptOutReason::Unsubscribe.receipt_reason();
const OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL: &str =
    CounterpartyOptOutReason::BlockOrFriendRemoval.receipt_reason();
const OPT_OUT_REASONS: [&str; 3] = [
    OPT_OUT_REASON_STOP,
    OPT_OUT_REASON_UNSUBSCRIBE,
    OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL,
];
/// Longest `send_ref` a one-shot override may bind.
const MAX_SEND_REF_BYTES: usize = 256;
const OPT_OUT_CLEAR_REASON: &str = "comm_opt_out_clear";
const OPT_OUT_CLEAR_APPROVED: &str = "comm_opt_out_clear_approved";
const PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";
const EVENT_SEQUENCE_KEY: &[u8] = b"comm.event_sequence.v1";
const MAX_KEY_BYTES: usize = 512;

/// Stable machine rationale recorded on the MS-01 ledger event when the
/// projector reconciles offline-minted twins of one `party_key`.
const PARTY_KEY_TWIN_RATIONALE: &str = "comm.party_key_offline_twin";

/// Domain separator for projector-derived `comm.*` CLAIM ids. A deterministic
/// projector derives its row ids from its inputs, so replaying one source event
/// — or projecting it independently on two devices — converges on ONE physical
/// row instead of racing two random ids into the same conflict key.
const PROJECTED_COMM_CLAIM_ID_DOMAIN: &[u8] = b"oneiron.comm.projected_claim.v1\0";

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
    /// A restrictive event re-asserted the opt-out at or after the pending
    /// clear gate was created, so the clear must fail closed.
    #[error("comm opt-out clear superseded by a later restrictive event")]
    PendingClearSupersededByStop,
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

/// How widely one `comm.send_override` authorizes sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOverrideScope {
    /// Every send to the party (and channel class, when one is named) until the
    /// head is retracted or expires.
    Standing,
    /// Exactly one send, bound at mint time to that send's `send_ref` and
    /// expiry-bound by a mandatory `valid_to`.
    OneShot,
}

impl SendOverrideScope {
    /// Stable machine token stored in the claim value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standing => "standing",
            Self::OneShot => "one_shot",
        }
    }

    /// Exact inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "standing" => Some(Self::Standing),
            "one_shot" => Some(Self::OneShot),
            _ => None,
        }
    }
}

/// Which override authorized a send, for the gate receipt.
///
/// A send matches at most ONE of these: on overlap, standing wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOverrideMatch {
    /// A standing head covered the send.
    Standing,
    /// A one-shot head bound to exactly this send ref covered it.
    OneShot,
}

/// One row of the ARCH-0057 §4 claim-class table for the `comm.*` family.
///
/// PURE DATA. There is no descriptor runtime in the engine and this ticket
/// mints none: the rows DESCRIBE the write classes the family's own verbs
/// enforce, so a future descriptor registry has something exact to register and
/// a reader has something exact to check the verbs against. Nothing here is
/// persisted, and nothing here gates a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimClassDescriptorRow {
    /// The predicate this row describes.
    pub predicate: &'static str,
    /// `recorded` | `human_ruled` | `ordinary`.
    pub write_class: &'static str,
    /// Whether a door enforces the write class today.
    pub enforcement: bool,
    /// Whether the predicate is restrictive (a head can only add suppression).
    pub restrictive: bool,
    /// Whether only a projector authors the predicate.
    pub projector_only: bool,
}

/// The six `comm.*` claim-class rows, in family order.
///
/// `comm.do_not_contact` is CA-owned; this row DESCRIBES the door CA landed and
/// never redefines it.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    vec![
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_OPT_OUT,
            write_class: "recorded",
            enforcement: true,
            restrictive: true,
            projector_only: true,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_LAST_TOUCH,
            write_class: "recorded",
            enforcement: false,
            restrictive: false,
            projector_only: true,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_THREAD_MEMBER,
            write_class: "recorded",
            enforcement: false,
            restrictive: false,
            projector_only: true,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_REACHABLE_VIA,
            write_class: "ordinary",
            enforcement: false,
            restrictive: false,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_SEND_OVERRIDE,
            write_class: "human_ruled",
            enforcement: true,
            restrictive: false,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT,
            write_class: "human_ruled",
            enforcement: true,
            restrictive: true,
            projector_only: false,
        },
    ]
}

/// Typed value carried by one claim in the `comm.*` family.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommClaimValue {
    /// Restrictive opt-out state.
    OptOut {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Normalized communication channel class, or `None` for every channel.
        channel_class: Option<String>,
        /// Stable machine reason for the restrictive state.
        reason: String,
        /// Event time at which the state became valid.
        occurred_at: u64,
    },
    /// Owner decision authorizing sends to an opted-out party.
    SendOverride {
        /// Party duplicated in the value key for deterministic folding.
        party_ref: EntityId,
        /// Normalized channel class, or `None` for every channel.
        channel_class: Option<String>,
        /// How widely this override authorizes.
        scope: SendOverrideScope,
        /// One-shot binding to exactly one send ref. Forbidden for standing.
        send_ref: Option<String>,
        /// When the owner ruled.
        issued_at: u64,
        /// Expiry. REQUIRED for one-shot, optional for standing.
        valid_to: Option<u64>,
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
            } => {
                // The channel key is ELIDED, never nulled, when the head covers
                // every channel: a landed channel-scoped head keeps its exact
                // bytes, and absence is the only shape that means "all".
                let mut entries = vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                ];
                if let Some(channel_class) = channel_class {
                    entries.push((
                        Value::from(KEY_CHANNEL_CLASS),
                        Value::from(channel_class.as_str()),
                    ));
                }
                entries.push((Value::from(KEY_OPTED_OUT), Value::Boolean(true)));
                entries.push((Value::from(KEY_REASON), Value::from(reason.as_str())));
                entries.push((Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)));
                (
                    PREDICATE_COMM_OPT_OUT,
                    *party_ref,
                    Value::Map(entries),
                    Some(*occurred_at),
                )
            }
            Self::SendOverride {
                party_ref,
                channel_class,
                scope,
                send_ref,
                issued_at,
                valid_to,
            } => {
                let mut entries = vec![
                    (
                        Value::from(KEY_SCHEMA_VERSION),
                        Value::from(COMM_SCHEMA_VERSION),
                    ),
                    (Value::from(KEY_PARTY_REF), Value::from(party_ref.to_hex())),
                ];
                if let Some(channel_class) = channel_class {
                    entries.push((
                        Value::from(KEY_CHANNEL_CLASS),
                        Value::from(channel_class.as_str()),
                    ));
                }
                entries.push((Value::from(KEY_SCOPE), Value::from(scope.as_str())));
                if let Some(send_ref) = send_ref {
                    entries.push((Value::from(KEY_SEND_REF), Value::from(send_ref.as_str())));
                }
                entries.push((Value::from(KEY_ISSUED_AT), Value::from(*issued_at)));
                if let Some(valid_to) = valid_to {
                    entries.push((Value::from(KEY_VALID_TO), Value::from(*valid_to)));
                }
                (
                    PREDICATE_COMM_SEND_OVERRIDE,
                    *party_ref,
                    Value::Map(entries),
                    Some(*issued_at),
                )
            }
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
            | Self::SendOverride { party_ref, .. }
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
                channel_class: elided_string(entries, KEY_CHANNEL_CLASS)?.map(str::to_owned),
                reason: required_string(entries, KEY_REASON)?.to_owned(),
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
            },
            PREDICATE_COMM_SEND_OVERRIDE => CommClaimValue::SendOverride {
                party_ref,
                channel_class: elided_string(entries, KEY_CHANNEL_CLASS)?.map(str::to_owned),
                scope: SendOverrideScope::parse(required_string(entries, KEY_SCOPE)?)
                    .ok_or_else(|| invalid_claim("comm.send_override scope is invalid"))?,
                send_ref: elided_string(entries, KEY_SEND_REF)?.map(str::to_owned),
                issued_at: required_u64(entries, KEY_ISSUED_AT)?,
                valid_to: elided_u64(entries, KEY_VALID_TO)?,
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
            // ADDITIVE: `channel_class` may be elided, and then the head covers
            // every channel class. Every landed head names one and validates
            // exactly as before.
            validate_keys_with_optional(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_PARTY_REF,
                    KEY_OPTED_OUT,
                    KEY_REASON,
                    KEY_OCCURRED_AT,
                ],
                &[KEY_CHANNEL_CLASS],
            )?;
            if let Some(channel_class) = elided_string(entries, KEY_CHANNEL_CLASS)? {
                validate_channel_class(channel_class)?;
            }
            if !required_bool(entries, KEY_OPTED_OUT)? {
                return Err(invalid_claim("comm.opt_out must be restrictive"));
            }
            let reason = required_string(entries, KEY_REASON)?;
            if !OPT_OUT_REASONS.contains(&reason) {
                return Err(invalid_claim("comm.opt_out reason is invalid"));
            }
            required_u64(entries, KEY_OCCURRED_AT).map(|_| ())
        }
        PREDICATE_COMM_SEND_OVERRIDE => {
            validate_keys_with_optional(
                entries,
                &[KEY_SCHEMA_VERSION, KEY_PARTY_REF, KEY_SCOPE, KEY_ISSUED_AT],
                &[KEY_CHANNEL_CLASS, KEY_SEND_REF, KEY_VALID_TO],
            )?;
            if let Some(channel_class) = elided_string(entries, KEY_CHANNEL_CLASS)? {
                validate_channel_class(channel_class)?;
            }
            let scope = SendOverrideScope::parse(required_string(entries, KEY_SCOPE)?)
                .ok_or_else(|| invalid_claim("comm.send_override scope is invalid"))?;
            let send_ref = elided_string(entries, KEY_SEND_REF)?;
            let issued_at = required_u64(entries, KEY_ISSUED_AT)?;
            let valid_to = elided_u64(entries, KEY_VALID_TO)?;
            match scope {
                // A one-shot override that outlived its send would be a
                // standing override nobody named: the send ref BINDS it and the
                // expiry BOUNDS it, so both are required at mint (Q-025.3).
                SendOverrideScope::OneShot => {
                    let send_ref = send_ref.ok_or_else(|| {
                        invalid_claim("comm.send_override one_shot requires send_ref")
                    })?;
                    validate_send_ref(send_ref)?;
                    if valid_to.is_none() {
                        return Err(invalid_claim(
                            "comm.send_override one_shot requires valid_to",
                        ));
                    }
                }
                // A standing override is not bound to any one send, so carrying
                // a send ref would state a binding it does not have.
                SendOverrideScope::Standing => {
                    if send_ref.is_some() {
                        return Err(invalid_claim(
                            "comm.send_override standing forbids send_ref",
                        ));
                    }
                }
            }
            if valid_to.is_some_and(|valid_to| valid_to < issued_at) {
                return Err(invalid_claim(
                    "comm.send_override valid_to precedes issued_at",
                ));
            }
            Ok(())
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

/// One `(party, channel_class)` standing-state slot — the key an opt-out clear
/// gate is filed under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartyChannelKey {
    party_ref: EntityId,
    channel_class: String,
}

/// One `(party, thread_ref)` membership slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartyThreadKey {
    party_ref: EntityId,
    thread_ref: String,
}

/// A pending clear gate as the pass snapshot saw it. Every field is snapshot
/// data: nothing here is written back without re-reading the resident row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedGate {
    id: EntityId,
    claim_ref: EntityId,
    created_at: u64,
}

/// Pass-local index over one decoded COMM_RECORD snapshot.
///
/// The projector used to re-walk the whole type-136 family for every pending
/// event — candidate clear gates for a `STOP`, the latest projected thread
/// boundary for a join/leave — which made one pass O(P·R) in P pending events
/// and R records. One snapshot answers all of those lookups instead, at
/// O(R + P log P) plus the rows actually mutated.
///
/// This is a snapshot, never a source of truth and never persisted: every id it
/// hands out is re-read and revalidated inside the event's own write
/// transaction before anything is mutated, and the index advances only from
/// deltas returned by transactions that already committed. Records written
/// after the snapshot are simply picked up by the next pass.
#[derive(Debug, Default)]
struct CommProjectorIndex {
    /// Unprojected source events as `(sequence, id)`, sequence ascending.
    pending_events: Vec<(u64, EntityId)>,
    pending_gates: HashMap<PartyChannelKey, Vec<IndexedGate>>,
    latest_projected_thread_transition: HashMap<PartyThreadKey, u64>,
    /// Snapshotted pending join/leave event ids by membership slot. A
    /// join/leave deciding before this pass's cursor reaches a same-key entry
    /// re-reads only these rows, so a peer pass's already-committed transition
    /// still bounds the decision instead of being folded too late, after an
    /// earlier retried join already minted standing membership.
    pending_thread_events: HashMap<PartyThreadKey, Vec<EntityId>>,
}

impl CommProjectorIndex {
    fn from_records(records: &[(EntityId, CommRecord)]) -> Self {
        let mut index = Self::default();
        for (id, record) in records {
            match record {
                CommRecord::Event {
                    sequence,
                    kind,
                    party_ref,
                    thread_ref,
                    projected: false,
                    ..
                } => {
                    index.pending_events.push((*sequence, *id));
                    if matches!(
                        kind,
                        CommEventKind::ThreadJoined | CommEventKind::ThreadLeft
                    ) && let Some(thread_ref) = thread_ref
                    {
                        index
                            .pending_thread_events
                            .entry(PartyThreadKey {
                                party_ref: *party_ref,
                                thread_ref: thread_ref.clone(),
                            })
                            .or_default()
                            .push(*id);
                    }
                }
                CommRecord::Event {
                    kind: CommEventKind::ThreadJoined | CommEventKind::ThreadLeft,
                    party_ref,
                    thread_ref: Some(thread_ref),
                    occurred_at,
                    projected: true,
                    ..
                } => index.note_thread_transition(
                    PartyThreadKey {
                        party_ref: *party_ref,
                        thread_ref: thread_ref.clone(),
                    },
                    *occurred_at,
                ),
                CommRecord::Gate {
                    party_ref,
                    channel_class,
                    claim_ref,
                    created_at,
                    pending: true,
                } => index
                    .pending_gates
                    .entry(PartyChannelKey {
                        party_ref: *party_ref,
                        channel_class: channel_class.clone(),
                    })
                    .or_default()
                    .push(IndexedGate {
                        id: *id,
                        claim_ref: *claim_ref,
                        created_at: *created_at,
                    }),
                _ => {}
            }
        }
        // Stable, so records that somehow share a sequence keep the family
        // scan's id order rather than an arbitrary one.
        index.pending_events.sort_by_key(|(sequence, _)| *sequence);
        index
    }

    /// Pending source events in this pass's projection order.
    fn pending_event_ids(&self) -> Vec<EntityId> {
        self.pending_events.iter().map(|(_, id)| *id).collect()
    }

    /// Clear gates that a `STOP` at `stop_at` may consume, as candidates only.
    fn eligible_gates(&self, key: &PartyChannelKey, stop_at: u64) -> Vec<IndexedGate> {
        let Some(gates) = self.pending_gates.get(key) else {
            return Vec::new();
        };
        gates
            .iter()
            .copied()
            .filter(|gate| gate.created_at <= stop_at)
            .collect()
    }

    /// Newest already-projected join/leave boundary for one membership slot.
    fn latest_thread_transition(&self, key: &PartyThreadKey) -> Option<u64> {
        self.latest_projected_thread_transition.get(key).copied()
    }

    fn note_thread_transition(&mut self, key: PartyThreadKey, occurred_at: u64) {
        self.latest_projected_thread_transition
            .entry(key)
            .and_modify(|latest| *latest = (*latest).max(occurred_at))
            .or_insert(occurred_at);
    }

    /// Latest membership boundary from snapshotted same-key join/leave events
    /// that a peer pass has already committed — including entries still AHEAD
    /// of this pass's cursor, which neither the snapshot nor `apply_committed`
    /// can have folded yet. This restores exactly what the pre-index
    /// in-transaction family rescan observed for the slot at decision time,
    /// by re-reading only the snapshotted candidate rows: O(pending same-key),
    /// never a COMM_RECORD family scan. Rows still pending (or failed soft)
    /// are not boundaries and skip themselves; the deciding event's own row is
    /// excluded, since it cannot be projected before its rule runs inside this
    /// event's write transaction.
    fn peer_projected_thread_transition_in_txn(
        &self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        key: &PartyThreadKey,
        source_event_id: EntityId,
    ) -> CommResult<Option<u64>> {
        let mut latest = None;
        let Some(candidates) = self.pending_thread_events.get(key) else {
            return Ok(None);
        };
        for candidate_id in candidates {
            if *candidate_id == source_event_id {
                continue;
            }
            let Some(CommRecord::Event {
                kind: CommEventKind::ThreadJoined | CommEventKind::ThreadLeft,
                party_ref,
                thread_ref: Some(thread_ref),
                occurred_at,
                projected: true,
                ..
            }) = read_comm_record_in_txn(vault, rtxn, *candidate_id)?
            else {
                continue;
            };
            if party_ref == key.party_ref && thread_ref == key.thread_ref {
                latest = latest.max(Some(occurred_at));
            }
        }
        Ok(latest)
    }

    /// Folds in the effects of one event whose transaction HAS COMMITTED.
    /// Applying a delta before the commit would let a rolled-back event poison
    /// every later lookup in the pass.
    fn apply_committed(&mut self, delta: ProjectorIndexDelta) {
        let mut consumed_by_key: HashMap<PartyChannelKey, HashSet<EntityId>> = HashMap::new();
        for (key, gate_id) in delta.consumed_gate_ids {
            consumed_by_key.entry(key).or_default().insert(gate_id);
        }
        for (key, consumed_ids) in consumed_by_key {
            let Some(gates) = self.pending_gates.get_mut(&key) else {
                continue;
            };
            note_pending_gate_retain();
            gates.retain(|gate| !consumed_ids.contains(&gate.id));
            if gates.is_empty() {
                self.pending_gates.remove(&key);
            }
        }
        if let Some((key, occurred_at)) = delta.projected_thread_transition {
            self.note_thread_transition(key, occurred_at);
        }
    }
}

/// Index changes one committed event authorizes. Empty for events that mutate
/// no indexed row.
#[derive(Debug, Default)]
struct ProjectorIndexDelta {
    consumed_gate_ids: Vec<(PartyChannelKey, EntityId)>,
    projected_thread_transition: Option<(PartyThreadKey, u64)>,
}

/// Runs one ordered, idempotent communication projector pass.
///
/// Concurrent passes are supported callers: LMDB serializes each event's write
/// transaction, and when a peer pass commits one of this pass's snapshotted
/// events first, the re-read observes that committed boundary and folds it
/// into this pass's index before any later event decides from it
/// (`project_event`). A join/leave deciding while a same-key snapshotted event
/// is still AHEAD of this pass's cursor additionally re-reads just those
/// candidate rows, so a boundary a peer committed after this pass's snapshot
/// but before this event's write transaction still bounds the decision now
/// (`CommProjectorIndex::peer_projected_thread_transition_in_txn`). Events
/// RECORDED after this pass's snapshot are not observed at all; they are the
/// next pass's business.
pub fn run_comm_projector(vault: &Vault) -> CommResult<()> {
    let records = {
        let rtxn = vault.store.env.read_txn()?;
        comm_records_in_txn(vault, &rtxn)?
    };
    let mut index = CommProjectorIndex::from_records(&records);
    drop(records);
    for event_id in index.pending_event_ids() {
        // Each event keeps its own write transaction, so a later bad event
        // cannot roll back what earlier events already projected.
        match project_event(vault, event_id, &index) {
            Ok(delta) => index.apply_committed(delta),
            Err(CommError::Engine(Error::EntityNotFound)) => {
                // A replicated event can arrive before its party row. Leave it
                // unprojected — and the index untouched — so a later pass
                // retries after the party syncs.
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    reconcile_comm_party_twins(vault, crate::unix_seconds_now())?;
    Ok(())
}

/// Converges offline-minted twins of one `party_key` onto a single canonical
/// party, returning how many twins were merged away.
///
/// Identity created while synced truth was unreachable reconciles by MERGE, not
/// by prevention: two devices that each minted a party row for one key are both
/// right about the party and simply disagree about its id. Each group's lowest
/// id survives (a total order every node computes identically) and the rest go
/// through the ARCH-0055 MS-01 door as read-through merges — that door owns the
/// shell edges, the maintenance-band ledger, and undo. No claim subject is
/// rewritten and no `merged_into` edge is authored here.
///
/// Different `party_key` values are never merged. Deciding that two keys name
/// one human is cross-channel identity judgment and belongs to the Dreamer tier.
fn reconcile_comm_party_twins(vault: &Vault, now: u64) -> CommResult<usize> {
    let twin_groups: Vec<(String, Vec<EntityId>)> = {
        let rtxn = vault.store.env.read_txn()?;
        active_comm_persons_by_party_key_in_txn(vault, &rtxn)?
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .collect()
    };
    let mut merged = 0;
    for (party_key, twins) in twin_groups {
        // The door takes its own write transaction, so it runs outside the
        // PERSON scan's read transaction.
        let (survivor, sources) = twins.split_first().ok_or(CommError::InvalidRecord)?;
        let outcome = vault.apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: sources.to_vec(),
                survivor: *survivor,
                evidence: IdentityOpEvidence {
                    refs: twins.clone(),
                    rationale: PARTY_KEY_TWIN_RATIONALE.to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            now,
        )?;
        if matches!(outcome, IdentityOpOutcome::Applied { .. }) {
            merged += sources.len();
        }
        vault.try_with_write_txn(|wtxn| {
            put_party_index_in_txn(vault, wtxn, &party_key, *survivor)
        })?;
    }
    Ok(merged)
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
    enum ClearRuling {
        Cleared,
        NoActiveOptOut,
        Superseded,
    }

    let actor_ref = actor.entity_ref();
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::PendingGateNotFound);
    };
    let ruling = vault.try_with_write_txn(|wtxn| {
        // Authorize the approving actor from the write transaction's view so a
        // concurrent delete/recreate cannot leave the gate consumed under a
        // stale authorization decision (TOCTOU).
        let actor_entity_type = vault
            .store
            .entities
            .get(&*wtxn, actor_ref.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(CommError::Engine(Error::EntityNotFound))?;
        validate_actor_class(actor_entity_type, actor.actor_class())?;
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(CommError::HumanApprovalRequired);
        }
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
        let live_claim = active.into_iter().next();
        // Fail-closed on a stale gate. The gate records a clear REQUEST;
        // approval authorizes that request, not the current state — a request
        // that predates the party's restrictive assertion is stale, and the
        // restriction forces a fresh request. Refuse (consume the stale gate,
        // no receipt) if the opt-out was (re-)asserted at or after the request:
        //   (a) the STOP that established the live head postdates the request
        //       (gate.created_at < head_valid_from), or
        //   (b) a later projected InboundStop re-asserted this (party, channel)
        //       past the head, at or after the request.
        // This is the approve-time half of the restrictive-wins rule the
        // projector enforces at :1013.
        if let Some((_, matched)) = &live_claim {
            let head_valid_from = matched.valid_from.unwrap_or(0);
            let superseded = created_at < head_valid_from
                || comm_records_in_txn(vault, &*wtxn)?
                    .iter()
                    .any(|(_, record)| {
                        matches!(record, CommRecord::Event {
                        kind: CommEventKind::InboundStop,
                        party_ref: event_party,
                        channel_class: Some(event_channel),
                        occurred_at,
                        projected: true,
                        ..
                    } if *event_party == party_ref
                        && event_channel == channel_class
                        && *occurred_at >= created_at
                        && *occurred_at > head_valid_from)
                    });
            if superseded {
                let consumed = CommRecord::Gate {
                    party_ref,
                    channel_class: channel_class.to_owned(),
                    claim_ref,
                    created_at,
                    pending: false,
                };
                put_comm_record_in_txn(vault, wtxn, gate_id, &consumed)?;
                // Commit the consumed gate, then refuse after the txn — returning
                // Err here would roll the consume back.
                return Ok(ClearRuling::Superseded);
            }
        }
        if let Some((live_claim_ref, matched)) = &live_claim {
            let close_at = ruled_at.max(matched.valid_from.unwrap_or(ruled_at));
            vault.retract_claim_in_txn(wtxn, live_claim_ref, close_at)?;
            // Claims moved; the cache follows in the SAME transaction
            // (ONE-1752), exactly as the STOP projector does on the way in. A
            // cleared head that left type-132 saying opted-out would make the
            // gate keep escalating on cache state the claims no longer carry —
            // cache as authority, the inversion the claims-first rule forbids.
            // The sweep is class-scoped like the head it just retracted, so it
            // re-derives every row that head could have suppressed and no
            // other; whether a REMAINING head still suppresses each of those
            // rows stays the fold's decision.
            if let Some(party_key) = active_comm_party_key_in_txn(vault, &*wtxn, party_ref)? {
                crate::counterparty_contact::rematerialize_party_contact_cache_in_txn(
                    vault,
                    wtxn,
                    &party_key,
                    Some(channel_class),
                    ruled_at,
                )?;
            }
        }
        let consumed = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: false,
        };
        put_comm_record_in_txn(vault, wtxn, gate_id, &consumed)?;
        if live_claim.is_some() {
            let receipt = CommRecord::Receipt {
                party_ref,
                channel_class: channel_class.to_owned(),
                occurred_at: ruled_at,
                outcome: OPT_OUT_CLEAR_APPROVED.to_owned(),
                actor_ref: actor.entity_ref(),
            };
            put_comm_record_in_txn(vault, wtxn, EntityId::now(), &receipt)?;
        }
        Ok(if live_claim.is_some() {
            ClearRuling::Cleared
        } else {
            ClearRuling::NoActiveOptOut
        })
    })?;
    match ruling {
        ClearRuling::Cleared => Ok(()),
        ClearRuling::NoActiveOptOut => Err(CommError::ActiveOptOutNotFound),
        ClearRuling::Superseded => Err(CommError::PendingClearSupersededByStop),
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
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(Vec::new());
    };
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
    vault.try_with_write_txn(|wtxn| {
        // Resolve/create the party in the SAME transaction as the event so a
        // concurrent party deletion cannot leave the event bound to a missing
        // PERSON (which the projector would then skip forever as EntityNotFound).
        let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
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

/// Projects one source event in its own write transaction, returning the index
/// changes the commit made true. `try_with_write_txn` yields `Ok` only after the
/// commit, so the caller can never fold in a delta that was rolled back.
fn project_event(
    vault: &Vault,
    event_id: EntityId,
    index: &CommProjectorIndex,
) -> CommResult<ProjectorIndexDelta> {
    vault.try_with_write_txn(|wtxn| {
        let Some(raw) = vault.store.entities.get(&*wtxn, event_id.as_bytes())? else {
            return Ok(ProjectorIndexDelta::default());
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
            // A peer pass already committed this snapshotted event. A join or
            // leave is a durable membership boundary even when its commit
            // mutated no claim (a join while a member claim already stands, a
            // leave with nothing active), and this pass's index saw it only as
            // pending — never as a transition. Folding the live row in here
            // keeps a later same-pass join/leave deciding against exactly the
            // boundary set the pre-index in-transaction family rescan used.
            return Ok(match (kind, thread_ref) {
                (CommEventKind::ThreadJoined | CommEventKind::ThreadLeft, Some(thread_ref)) => {
                    ProjectorIndexDelta {
                        consumed_gate_ids: Vec::new(),
                        projected_thread_transition: Some((
                            PartyThreadKey {
                                party_ref,
                                thread_ref,
                            },
                            occurred_at,
                        )),
                    }
                }
                _ => ProjectorIndexDelta::default(),
            });
        }
        let rule = PROJECTOR_RULES
            .iter()
            .find(|rule| rule.event_kind == kind)
            .ok_or(CommError::InvalidRecord)?;
        let delta = apply_projector_rule_in_txn(
            vault,
            wtxn,
            index,
            &ProjectedCommEvent {
                rule: *rule,
                source_event_id: event_id,
                party_ref,
                channel_class: channel_class.as_deref(),
                thread_ref: thread_ref.as_deref(),
                occurred_at,
            },
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
        Ok(delta)
    })
}

/// One source COMM_RECORD event, resolved to the projector rule it fires.
/// Bundled so the deterministic id's source event travels with the inputs it is
/// derived from rather than as one more positional argument.
#[derive(Debug, Clone, Copy)]
struct ProjectedCommEvent<'a> {
    rule: ProjectorRule,
    source_event_id: EntityId,
    party_ref: EntityId,
    channel_class: Option<&'a str>,
    thread_ref: Option<&'a str>,
    occurred_at: u64,
}

fn apply_projector_rule_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    index: &CommProjectorIndex,
    event: &ProjectedCommEvent<'_>,
) -> CommResult<ProjectorIndexDelta> {
    let &ProjectedCommEvent {
        rule,
        source_event_id,
        party_ref,
        channel_class,
        thread_ref,
        occurred_at,
    } = event;
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
            let (new_id, minted) =
                put_projected_comm_claim_in_txn(vault, wtxn, source_event_id, &value, occurred_at)?;
            if !minted {
                return Ok(ProjectorIndexDelta::default());
            }
            if let Some((old_head_id, old_head)) = active.into_iter().find(|(id, _)| *id != new_id)
            {
                let head_at = old_head.valid_from.unwrap_or(occurred_at);
                let close_at = occurred_at.max(head_at);
                if occurred_at >= head_at {
                    vault.supersede_claim_in_txn(wtxn, &new_id, &old_head_id, close_at)?;
                } else {
                    vault.supersede_claim_in_txn(wtxn, &old_head_id, &new_id, close_at)?;
                }
            }
            Ok(ProjectorIndexDelta::default())
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
                let history = matching_claims_in_txn(
                    vault,
                    &*wtxn,
                    party_ref,
                    rule.predicate,
                    Some(channel),
                    None,
                    false,
                )?;
                let latest_transition = latest_claim_transition_boundary(&history);
                let value = CommClaimValue::OptOut {
                    party_ref,
                    channel_class: Some(channel.to_owned()),
                    reason: OPT_OUT_REASON_STOP.to_owned(),
                    occurred_at,
                };
                let (claim_id, minted) = put_projected_comm_claim_in_txn(
                    vault,
                    wtxn,
                    source_event_id,
                    &value,
                    occurred_at,
                )?;
                if minted
                    && let Some(boundary) =
                        latest_transition.filter(|boundary| occurred_at < *boundary)
                {
                    vault.retract_claim_in_txn(wtxn, &claim_id, boundary)?;
                }
                rematerialize_party_channel_contact_cache_in_txn(
                    vault,
                    wtxn,
                    party_ref,
                    channel,
                    occurred_at,
                )?;
                Ok(ProjectorIndexDelta::default())
            } else {
                // The pass index only NARROWS the candidates for this slot; the
                // decision to consume is made from the resident row read back
                // here, inside this event's own write transaction. A snapshot
                // gate that has since been deleted, consumed, re-keyed, or
                // re-pointed at a different claim is left alone for the next
                // pass — and a clear gate that outlives this STOP still fails
                // closed at approval time, which rechecks projected STOP
                // history against the live head.
                let key = PartyChannelKey {
                    party_ref,
                    channel_class: channel.to_owned(),
                };
                let mut consumed_gate_ids = Vec::new();
                for candidate in index.eligible_gates(&key, occurred_at) {
                    let Some(CommRecord::Gate {
                        party_ref: gate_party_ref,
                        channel_class: gate_channel,
                        claim_ref,
                        created_at,
                        pending,
                    }) = read_comm_record_in_txn(vault, &*wtxn, candidate.id)?
                    else {
                        continue;
                    };
                    if !pending
                        || gate_party_ref != party_ref
                        || gate_channel != channel
                        || claim_ref != candidate.claim_ref
                        || created_at > occurred_at
                    {
                        continue;
                    }
                    let consumed = CommRecord::Gate {
                        party_ref,
                        channel_class: channel.to_owned(),
                        claim_ref,
                        created_at,
                        pending: false,
                    };
                    put_comm_record_in_txn(vault, wtxn, candidate.id, &consumed)?;
                    consumed_gate_ids.push((key.clone(), candidate.id));
                }
                Ok(ProjectorIndexDelta {
                    consumed_gate_ids,
                    projected_thread_transition: None,
                })
            }
        }
        ProjectorAction::JoinThread => {
            let thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let key = PartyThreadKey {
                party_ref,
                thread_ref: thread.to_owned(),
            };
            // A peer pass may already have committed a same-key snapshotted
            // join/leave still AHEAD of this pass's cursor. That boundary must
            // bound THIS decision — folding it index-only when the pass later
            // reaches that event's own id cannot retract a claim minted now.
            let peer_transition = index.peer_projected_thread_transition_in_txn(
                vault,
                &*wtxn,
                &key,
                source_event_id,
            )?;
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
                let history = matching_claims_in_txn(
                    vault,
                    &*wtxn,
                    party_ref,
                    rule.predicate,
                    None,
                    Some(thread),
                    false,
                )?;
                let latest_transition = latest_claim_transition_boundary(&history)
                    .max(index.latest_thread_transition(&key))
                    .max(peer_transition);
                let value = CommClaimValue::ThreadMember {
                    party_ref,
                    thread_ref: thread.to_owned(),
                    occurred_at,
                };
                let (claim_id, minted) = put_projected_comm_claim_in_txn(
                    vault,
                    wtxn,
                    source_event_id,
                    &value,
                    occurred_at,
                )?;
                // Deterministic tie-breaker: at equal occurred_at a join loses to
                // the boundary (a same-time leave/transition), so equal-time
                // opposing thread events converge to non-membership regardless of
                // projection order (restrictive-wins-tie, symmetric with LeaveThread).
                if minted
                    && let Some(boundary) =
                        latest_transition.filter(|boundary| occurred_at <= *boundary)
                {
                    vault.retract_claim_in_txn(wtxn, &claim_id, boundary)?;
                }
            }
            // The source event row is stamped `projected` by the same commit,
            // so this join becomes part of the boundary history either way —
            // exactly what a full rescan of projected thread events would see.
            // The peer-committed boundary observed above folds in too, but only
            // via this post-commit delta: the EntityNotFound path returns no
            // delta, so a still-absent party can never poison the index.
            Ok(ProjectorIndexDelta {
                consumed_gate_ids: Vec::new(),
                projected_thread_transition: Some((
                    key,
                    peer_transition.map_or(occurred_at, |peer| occurred_at.max(peer)),
                )),
            })
        }
        ProjectorAction::LeaveThread => {
            let thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let key = PartyThreadKey {
                party_ref,
                thread_ref: thread.to_owned(),
            };
            // Same ahead-of-cursor observation as JoinThread: a peer can
            // commit a later same-key transition while this pass is still
            // retrying this earlier leave, and this leave's staleness check
            // must see it now rather than at that event's own id.
            let peer_transition = index.peer_projected_thread_transition_in_txn(
                vault,
                &*wtxn,
                &key,
                source_event_id,
            )?;
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
            if let Some((claim_id, matched)) = active.into_iter().next() {
                // Latest-event-wins: a leave older than the newest projected
                // transition for this membership is stale and must not end
                // it; the COMM_RECORD event row remains its durable trace.
                let latest_transition = matched
                    .valid_from
                    .max(index.latest_thread_transition(&key))
                    .max(peer_transition);
                if latest_transition.is_none_or(|boundary| occurred_at >= boundary) {
                    vault.retract_claim_in_txn(wtxn, &claim_id, occurred_at)?;
                }
            }
            Ok(ProjectorIndexDelta {
                consumed_gate_ids: Vec::new(),
                projected_thread_transition: Some((
                    key,
                    peer_transition.map_or(occurred_at, |peer| occurred_at.max(peer)),
                )),
            })
        }
    }
}

/// Canonical conflict key for one projected `comm.*` value: the tuple that
/// makes two claims the SAME standing-state slot. Length-prefixed so
/// `("ab", "c")` and `("a", "bc")` can never hash alike.
fn projected_comm_conflict_key(value: &CommClaimValue) -> Vec<u8> {
    let mut key = Vec::new();
    let mut push = |bytes: &[u8]| {
        key.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        key.extend_from_slice(bytes);
    };
    match value {
        // An elided channel is its OWN slot, not a wildcard over the others:
        // the party-wide head and a channel-scoped head are different standing
        // facts and must never collide. No channel class can be empty
        // (`validate_channel_class` refuses blanks), so the empty component is
        // unambiguously "every channel".
        CommClaimValue::OptOut {
            party_ref,
            channel_class,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_deref().unwrap_or_default().as_bytes());
        }
        CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            ..
        }
        | CommClaimValue::ReachableVia {
            party_ref,
            channel_class,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_bytes());
        }
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            ..
        } => {
            push(party_ref.as_bytes());
            push(thread_ref.as_bytes());
        }
        // No projector rule mints an override — it is a human-ruled verb — so
        // this arm exists for totality. The key still names the whole binding,
        // so it could never merge two distinct owner decisions.
        CommClaimValue::SendOverride {
            party_ref,
            channel_class,
            scope,
            send_ref,
            ..
        } => {
            push(party_ref.as_bytes());
            push(channel_class.as_deref().unwrap_or_default().as_bytes());
            push(scope.as_str().as_bytes());
            push(send_ref.as_deref().unwrap_or_default().as_bytes());
        }
    }
    key
}

/// Derives the deterministic CLAIM id for one projector-created `comm.*` claim
/// from `(source event, predicate, conflict key)`. Version/variant nibbles are
/// stamped exactly as [`crate::outbound::connector_actor_id`] so the result is
/// a well-formed v7-shaped id.
fn projected_comm_claim_id(
    source_event_id: EntityId,
    value: &CommClaimValue,
) -> CommResult<EntityId> {
    let predicate = value.claim_body().predicate;
    let conflict_key = projected_comm_conflict_key(value);
    let mut hash = blake3::Hasher::new();
    hash.update(PROJECTED_COMM_CLAIM_ID_DOMAIN);
    hash.update(source_event_id.as_bytes());
    hash.update(&(predicate.len() as u64).to_le_bytes());
    hash.update(predicate.as_bytes());
    hash.update(&(conflict_key.len() as u64).to_le_bytes());
    hash.update(&conflict_key);
    let mut bytes = [0_u8; ENTITY_ID_LEN];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..ENTITY_ID_LEN]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes).map_err(CommError::from)
}

/// Writes one projector-created `comm.*` claim at its derived id.
///
/// Returns `(id, minted)`. A resident row at the derived id is recognized as a
/// replay — skip the write, `minted = false` — only when it is BYTE-IDENTICAL
/// to the body this projection authors AND is still reachable from the party
/// through a live `claim_of` edge. Anything else is a deterministic-id
/// collision and fails closed rather than overwriting the resident row.
///
/// Both halves are load-bearing, because `minted = false` is exactly what tells
/// [`project_event`] to stamp the source COMM_RECORD `projected`:
///
/// * Byte identity, not typed `CommClaimValue` equality. The encoded body
///   carries the whole governance envelope — `appr`, `life`, and the
///   elided-when-false `stale` marker all live in those bytes, and
///   [`CommClaimValue::claim_body`] pins them to `auto` / `active` / absent. A
///   rejected, supplanted, retracted, or staleness-marked row therefore cannot
///   pass as "already projected" the way decoded-value equality let it, which
///   would have retired the source event against a row that no longer says what
///   the projector meant — silently dropping standing state a `STOP` depends on.
/// * The live edge. The body names its subject, but only the `claim_of` edge
///   makes the claim reachable from the party, and every comm reader walks that
///   edge. A row carrying the right bytes with no live edge is standing state
///   nothing can see.
fn put_projected_comm_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    source_event_id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<(EntityId, bool)> {
    let id = projected_comm_claim_id(source_event_id, value)?;
    if let Some(raw) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw).ok_or(CommError::InvalidRecord)?;
        let projected_body = encode_claim_body(&value.claim_body())?;
        if header.entity_type != ENTITY_TYPE_CLAIM
            || raw[ENTITY_METADATA_HEADER_LEN..] != projected_body[..]
            || !vault
                .claims_for_subject_in_txn(&*wtxn, &value.party_ref())?
                .contains(&id)
        {
            return Err(CommError::InvalidRecord);
        }
        return Ok((id, false));
    }
    put_comm_claim_with_id_in_txn(vault, wtxn, id, value, occurred_at)?;
    Ok((id, true))
}

fn put_comm_claim_with_id_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<EntityId> {
    put_comm_claim_with_id_in_txn_inner(vault, wtxn, id, value, occurred_at, false)
}

/// [`put_comm_claim_with_id_in_txn`] on the ENGINE-OWNED setting, for the
/// projection a contact writer authors on the party's behalf (ONE-1752).
///
/// The contact door already validated and authorized that write; re-asking the
/// public criticality ladder here would turn one recorded counterparty fact
/// into an owner review inside somebody else's transaction, and a refusal would
/// roll back the contact write that the ladder never meant to question. Body
/// validation and the source-trust check are unchanged.
fn put_engine_owned_comm_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
) -> CommResult<EntityId> {
    put_comm_claim_with_id_in_txn_inner(vault, wtxn, id, value, occurred_at, true)
}

fn put_comm_claim_with_id_in_txn_inner(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &CommClaimValue,
    occurred_at: u64,
    engine_owned: bool,
) -> CommResult<EntityId> {
    let body = value.claim_body();
    let data = encode_claim_body(&body)?;
    let subject = value.party_ref();
    // A comm.* claim's subject must be a PERSON party. A replicated event can
    // name any existing entity as party_ref; a subject that is absent or not a
    // PERSON is rejected so the projector fail-soft skips it (see
    // run_comm_projector) rather than attaching communication state to an
    // arbitrary TASK/CLAIM/etc. entity outside the party-indexed contact APIs.
    let subject_is_person = vault
        .store
        .entities
        .get(&*wtxn, subject.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
        == Some(ENTITY_TYPE_PERSON);
    if !subject_is_person {
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
                learned_at: crate::unix_seconds_now(),
                data,
                allow_maintenance: false,
                allow_reserved_predicate: engine_owned,
                hub_sync_imported: false,
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
            // SLOT lookup, not fold matching: a party-wide head answers a
            // `None` query and never a channel-scoped one, so the two heads
            // stay separately addressable for supersession. Whether a
            // party-wide head APPLIES to a channel is the fold's question, and
            // `StandingOptOutHead::matches_channel` answers it.
            CommClaimValue::OptOut {
                channel_class: candidate,
                ..
            }
            | CommClaimValue::SendOverride {
                channel_class: candidate,
                ..
            } => channel_class == candidate.as_deref(),
            CommClaimValue::LastTouch {
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

fn latest_claim_transition_boundary(matches: &[(EntityId, CommClaim)]) -> Option<u64> {
    matches
        .iter()
        .filter_map(|(_, claim)| {
            if claim.is_standing() {
                claim.valid_from
            } else {
                claim.valid_to
            }
        })
        .max()
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
            // Reachability carries no view entry, and an override is an owner
            // DECISION about sending rather than contact state — the lens
            // reports what the counterparty said, not what the owner ruled.
            CommClaimValue::ReachableVia { .. } | CommClaimValue::SendOverride { .. } => {}
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
                        // The lens mirrors the head: a party-wide head has no
                        // channel, so the entry carries none either rather than
                        // inventing a class the head never named.
                        let mut entry = Vec::new();
                        if let Some(channel) = channel {
                            entry.push((
                                Value::from(KEY_CHANNEL_CLASS),
                                Value::from(channel.as_str()),
                            ));
                        }
                        entry.push((Value::from(KEY_OPTED_OUT), Value::Boolean(true)));
                        entry.push((Value::from(KEY_OCCURRED_AT), Value::from(*occurred_at)));
                        Value::Map(entry)
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
    vault.try_with_write_txn(|wtxn| resolve_or_create_party_in_txn(vault, wtxn, party))
}

/// Reads the `party_key` of `id` if — and only if — it is an ACTIVE comm-owned
/// PERSON row. `None` covers every way an id can fail to be synced truth for a
/// party: absent, non-PERSON, undecodable or unrelated body, or a merge shell
/// (whose type stays PERSON while its identity has moved to the survivor).
///
/// Single validator for both the cache check and the synced scan, so the
/// shortcut can never disagree with the truth it is a shortcut for.
fn active_comm_party_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> CommResult<Option<String>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    if vault.entity_lifecycle_state_in_txn(rtxn, &id)? != EntityLifecycleState::Active {
        return Ok(None);
    }
    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Ok(entries) = value_map(&value) else {
        return Ok(None);
    };
    Ok(required_string(entries, KEY_PARTY_KEY)
        .ok()
        .map(str::to_owned))
}

/// Every active comm-owned PERSON row, grouped by its exact `party_key`, ids
/// ascending. This is the synced truth the node-local index caches.
fn active_comm_persons_by_party_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<BTreeMap<String, Vec<EntityId>>> {
    let mut groups: BTreeMap<String, Vec<EntityId>> = BTreeMap::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_PERSON])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        if let Some(party_key) = active_comm_party_key_in_txn(vault, rtxn, id)? {
            groups.entry(party_key).or_default().push(id);
        }
    }
    for ids in groups.values_mut() {
        ids.sort_unstable();
    }
    Ok(groups)
}

/// What synced truth says about one party, and whether the node-local shortcut
/// agrees with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartyLookup {
    /// The shortcut names the canonical row; nothing to repair.
    Fresh(EntityId),
    /// Synced truth names this row, but the shortcut disagrees.
    Repairable(EntityId),
    /// No active comm-owned PERSON carries this `party_key`.
    Absent,
}

/// Resolves one party against synced truth, read-only.
///
/// `PARTY_INDEX_PREFIX` is node-local cache state; the synced truth is the
/// PERSON body's `party_key`. A cache miss therefore means "look again", not
/// "absent" — treating it as absence is what mints a twin for a party that
/// already synced in. On a stale or missing hit this scans the type-4 rows and,
/// when several active rows share the key, picks the lexicographically smallest
/// id so every node converges on the same one.
fn lookup_party_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_key: &str,
) -> CommResult<PartyLookup> {
    if let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, &party_index_key(party_key))?
    {
        let id = decode_entity_id(&raw)?;
        if active_comm_party_key_in_txn(vault, rtxn, id)?.as_deref() == Some(party_key) {
            return Ok(PartyLookup::Fresh(id));
        }
    }
    Ok(active_comm_persons_by_party_key_in_txn(vault, rtxn)?
        .remove(party_key)
        .and_then(|ids| ids.into_iter().next())
        .map_or(PartyLookup::Absent, PartyLookup::Repairable))
}

/// Points the node-local shortcut at `id`.
fn put_party_index_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_key: &str,
    id: EntityId,
) -> CommResult<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, &party_index_key(party_key), id.as_bytes())?;
    Ok(())
}

/// Transaction-composable party resolution: repairs the shortcut from synced
/// truth on a miss and never mints.
fn resolve_party_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_key: &str,
) -> CommResult<Option<EntityId>> {
    match lookup_party_in_txn(vault, &*wtxn, party_key)? {
        PartyLookup::Fresh(id) => Ok(Some(id)),
        PartyLookup::Repairable(id) => {
            put_party_index_in_txn(vault, wtxn, party_key, id)?;
            Ok(Some(id))
        }
        PartyLookup::Absent => Ok(None),
    }
}

/// Resolves (or mints) the PERSON party for `party` inside an existing write
/// transaction, so a caller can make party creation atomic with the write that
/// references it (e.g. recording an event). Doing the resolve in a separate
/// prior transaction lets a concurrent party deletion land in between, leaving
/// the event bound to a missing PERSON.
fn resolve_or_create_party_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
) -> CommResult<EntityId> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    if let Some(id) = resolve_party_in_txn(vault, wtxn, party)? {
        return Ok(id);
    }
    let id = mint_comm_person_in_txn(vault, wtxn, party)?;
    put_party_index_in_txn(vault, wtxn, party, id)?;
    Ok(id)
}

/// Mints one comm-owned PERSON row carrying `party_key`. The caller decides
/// whether the node-local shortcut should name it.
fn mint_comm_person_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
) -> CommResult<EntityId> {
    let id = EntityId::now();
    let body = encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMM_SCHEMA_VERSION),
        ),
        (Value::from(KEY_PARTY_KEY), Value::from(party)),
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
            learned_at: crate::unix_seconds_now(),
            data: body,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}

/// Read-side party lookup. Answers from synced truth, and repairs the node-local
/// shortcut when it disagrees — a read-side miss must not report a party that
/// exists as absent (which would let the next write mint a twin for it). Only a
/// repair takes a write transaction; the fresh and absent cases stay read-only.
fn resolve_party(vault: &Vault, party: &str) -> CommResult<Option<EntityId>> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    let lookup = {
        let rtxn = vault.store.env.read_txn()?;
        lookup_party_in_txn(vault, &rtxn, party)?
    };
    match lookup {
        PartyLookup::Fresh(id) => Ok(Some(id)),
        PartyLookup::Repairable(id) => {
            vault.try_with_write_txn(|wtxn| put_party_index_in_txn(vault, wtxn, party, id))?;
            Ok(Some(id))
        }
        PartyLookup::Absent => Ok(None),
    }
}

/// Transaction-composable READ-ONLY party resolution: the same synced-truth
/// answer [`resolve_party`] gives, without the shortcut repair (a repair needs
/// a write, and this composes into transactions that must not take one, or
/// already hold one).
pub(crate) fn resolve_party_ref_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party: &str,
) -> CommResult<Option<EntityId>> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    Ok(match lookup_party_in_txn(vault, rtxn, party)? {
        PartyLookup::Fresh(id) | PartyLookup::Repairable(id) => Some(id),
        PartyLookup::Absent => None,
    })
}

/// Party resolution for a reader that holds a `Store` and no `Vault` — the
/// external-effect gate door.
///
/// It answers from the node-local shortcut and then RE-VALIDATES the hit
/// against synced truth (the row must still be a PERSON carrying exactly this
/// `party_key`), so a stale shortcut resolves to NOTHING rather than to the
/// wrong person. Deliberately the same interim shape CA's `comm.do_not_contact`
/// leg uses at the same hydration point, and deliberately fail-closed for this
/// caller: an unresolvable party means no override was found, which HOLDS the
/// send rather than releasing it.
pub(crate) fn resolve_party_ref_from_store_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party: &str,
) -> CommResult<Option<EntityId>> {
    let party_key = party.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let Some(raw_id) = store.vault_meta.get(txn, &party_index_key(party_key))? else {
        return Ok(None);
    };
    let id = decode_entity_id(&raw_id)?;
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Ok(entries) = value_map(&value) else {
        return Ok(None);
    };
    Ok((required_string(entries, KEY_PARTY_KEY).ok() == Some(party_key)).then_some(id))
}

/// One standing `comm.opt_out` head, as the restrictive folds read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StandingOptOutHead {
    /// `None` covers every channel class.
    pub(crate) channel_class: Option<String>,
    /// Receipt-vocabulary reason token.
    pub(crate) reason: String,
    /// Event time the opt-out became valid.
    pub(crate) occurred_at: u64,
}

impl StandingOptOutHead {
    /// Whether this head suppresses `channel_class`. An elided channel matches
    /// EVERY class; a named one matches only itself.
    ///
    /// Stated once, here, as the definition of what an absent class MEANS, and
    /// asked by the one reader that needs it: the type-132 rebuild folds a head
    /// into a contact only when this says the head covers that contact's class
    /// (`counterparty_contact::rematerialize_contact_cache_in_txn`). Any future
    /// channel-scoped reader must use this rather than re-derive the rule.
    #[must_use]
    pub(crate) fn matches_channel(&self, channel_class: &str) -> bool {
        self.channel_class
            .as_deref()
            .is_none_or(|stored| stored == normalize_channel_class(channel_class))
    }
}

/// Every standing `comm.opt_out` head for one party, on the caller's
/// transaction. Channel-less and channel-scoped alike: the caller decides which
/// apply, and no caller may be handed a filtered set that already dropped one.
pub(crate) fn standing_opt_out_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<Vec<StandingOptOutHead>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_OPT_OUT {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        if let CommClaimValue::OptOut {
            channel_class,
            reason,
            occurred_at,
            ..
        } = claim.value
        {
            heads.push(StandingOptOutHead {
                channel_class,
                reason,
                occurred_at,
            });
        }
    }
    Ok(heads)
}

/// Records the owner's decision to send to an opted-out party.
///
/// HUMAN-RULED: the actor is authorized inside the write transaction and must
/// be [`EdgeActorClass::Human`], exactly like `approve_pending_opt_out_clear`.
/// This is the verb the descriptor row describes; the generic claim doors
/// validate the body's shape but do not yet enforce the write class, which is
/// the named descriptor-registry follow-on.
///
/// It writes ONE claim and nothing else. No opt-out head is retracted, no
/// contact record is touched: an override authorizes a send THROUGH standing
/// suppression, it does not clear it.
#[expect(
    clippy::too_many_arguments,
    reason = "mint args mirror the send-override claim-body keys one-to-one (party, channel_class, scope, send_ref, issued_at, valid_to) plus vault and the human actor; the named descriptor-registry follow-on owns any reshaping"
)]
pub fn mint_send_override(
    vault: &Vault,
    party: &str,
    channel_class: Option<&str>,
    scope: SendOverrideScope,
    send_ref: Option<&str>,
    actor: WriteActor,
    issued_at: u64,
    valid_to: Option<u64>,
) -> CommResult<EntityId> {
    let actor_ref = actor.entity_ref();
    let channel_class = channel_class.map(normalize_channel_class);
    vault.try_with_write_txn(|wtxn| {
        // Authorize from the write transaction's own view, so a concurrent
        // delete/recreate cannot leave an override minted under a stale
        // authorization decision.
        let actor_entity_type = vault
            .store
            .entities
            .get(&*wtxn, actor_ref.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(CommError::Engine(Error::EntityNotFound))?;
        validate_actor_class(actor_entity_type, actor.actor_class())?;
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(CommError::HumanApprovalRequired);
        }
        let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
        let value = CommClaimValue::SendOverride {
            party_ref,
            channel_class: channel_class.clone(),
            scope,
            send_ref: send_ref.map(str::to_owned),
            issued_at,
            valid_to,
        };
        // Validate BEFORE the write so a malformed ruling is refused as a
        // typed comm failure rather than as an opaque body rejection deep in
        // the claim door.
        validate_comm_claim_structure(&value.claim_body()).map_err(|_| CommError::InvalidRecord)?;
        put_comm_claim_with_id_in_txn(vault, wtxn, EntityId::now(), &value, issued_at)
    })
}

/// The override covering one send, if any. Thin transaction-opening wrapper
/// over [`send_override_for_send_in_txn`].
pub fn send_override_for_send(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    send_ref: Option<&str>,
    now: u64,
) -> CommResult<Option<SendOverrideMatch>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(party_ref) = resolve_party_ref_in_txn(vault, &rtxn, party)? else {
        return Ok(None);
    };
    send_override_for_send_in_txn(
        &vault.store,
        &rtxn,
        &party_ref,
        &normalize_channel_class(channel_class),
        send_ref,
        now,
    )
}

/// The override covering one send, on the caller's transaction.
///
/// `channel_class` must already be normalized — every caller shares
/// [`normalize_channel_class`], so a stored class and a queried class can never
/// disagree over case or padding.
///
/// Three rules, and nothing else:
///
/// * an expired head (`valid_to < now`) never matches, whatever its scope;
/// * a one-shot matches only when its minted `send_ref` BYTE-equals this
///   send's, so an absent or different ref is simply no match;
/// * standing wins on overlap, because it is the wider decision the owner made.
///
/// There is NO consumption write, structurally: this reads on a read
/// transaction. Replay of the same send ref inside a one-shot's validity window
/// matches by design (Q-025.3) — mint-time binding plus mandatory expiry is the
/// lifetime bound at this interim door.
pub(crate) fn send_override_for_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &EntityId,
    channel_class: &str,
    send_ref: Option<&str>,
    now: u64,
) -> CommResult<Option<SendOverrideMatch>> {
    let mut matched = None;
    for claim_id in subject_claim_ids_in_txn(store, txn, party_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_SEND_OVERRIDE {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        let CommClaimValue::SendOverride {
            channel_class: head_channel,
            scope,
            send_ref: head_send_ref,
            valid_to,
            ..
        } = claim.value
        else {
            continue;
        };
        if head_channel
            .as_deref()
            .is_some_and(|stored| stored != channel_class)
        {
            continue;
        }
        if valid_to.is_some_and(|valid_to| valid_to < now) {
            continue;
        }
        match scope {
            SendOverrideScope::Standing => return Ok(Some(SendOverrideMatch::Standing)),
            SendOverrideScope::OneShot => {
                if head_send_ref.is_some() && head_send_ref.as_deref() == send_ref {
                    matched = Some(SendOverrideMatch::OneShot);
                }
            }
        }
    }
    Ok(matched)
}

/// CLAIM ids attached to `subject` through inbound `claim_of` edges, read with
/// a `Store` alone.
fn subject_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> CommResult<Vec<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(subject, EdgeKind::ClaimOf);
    let mut ids = Vec::new();
    for entry in store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        ids.push(crate::vault::parse_edge_record(&key, &value)?.target);
    }
    Ok(ids)
}

/// The CLAIM body stored at `id`, or `None` when the row is absent or is not a
/// type-0 CLAIM.
fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> CommResult<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(CommError::InvalidRecord);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(Some(crate::claim::decode_claim_body(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        true,
    )?))
}

/// Moves the party-wide `comm.opt_out` head for `party` to `reason`, inside the
/// caller's write transaction (ONE-1752).
///
/// The head carries NO channel class, so it covers every channel: a contact who
/// opted out said it to the owner, not to one mailbox. It is party-wide state
/// derived from a contact event, which is why the contact writer authors it —
/// and why it goes through the engine-owned door rather than the public ladder.
///
/// Restrictive and monotonic: an existing head is superseded only by a NEWER
/// opt-out, and nothing here ever retracts one. Clearing stays the separate,
/// human-ruled `request_opt_out_clear` / `approve_pending_opt_out_clear` path.
pub(crate) fn supersede_party_opt_out_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    reason: CounterpartyOptOutReason,
    occurred_at: u64,
) -> CommResult<()> {
    let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
    let active = matching_claims_in_txn(
        vault,
        &*wtxn,
        party_ref,
        PREDICATE_COMM_OPT_OUT,
        None,
        None,
        true,
    )?;
    require_at_most_one(&active)?;
    let head = active.into_iter().next();
    if let Some((_, claim)) = &head
        && let CommClaimValue::OptOut {
            reason: head_reason,
            occurred_at: head_at,
            ..
        } = &claim.value
        && (*head_at > occurred_at
            || (*head_at == occurred_at && head_reason == reason.receipt_reason()))
    {
        return Ok(());
    }
    let value = CommClaimValue::OptOut {
        party_ref,
        channel_class: None,
        reason: reason.receipt_reason().to_owned(),
        occurred_at,
    };
    let new_id =
        put_engine_owned_comm_claim_in_txn(vault, wtxn, EntityId::now(), &value, occurred_at)?;
    if let Some((old_id, _)) = head {
        crate::counterparty_contact::supersede_family_owned_claim_in_txn(
            vault,
            wtxn,
            &new_id,
            &old_id,
            occurred_at,
        )?;
    }
    Ok(())
}

/// Re-derives the type-132 cache for every contact this party reaches on
/// `channel_class`, inside the projector's own write transaction.
///
/// Claims moved; the cache follows in the SAME transaction, so the gate's
/// type-132-fed fold can never observe the old suppression state. The
/// party-channel index (ONE-1868) names the contacts, which keeps an
/// email-scoped STOP from re-deriving a telegram contact: channel scope is
/// decided by which contacts are enumerated here.
fn rematerialize_party_channel_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: EntityId,
    channel_class: &str,
    now: u64,
) -> CommResult<()> {
    let Some(party_key) = active_comm_party_key_in_txn(vault, &*wtxn, party_ref)? else {
        return Ok(());
    };
    let contacts = crate::counterparty_contact::counterparty_contacts_by_party_channel(
        &vault.store,
        &*wtxn,
        &party_key,
        &normalize_channel_class(channel_class),
    )?;
    for (contact_id, _) in contacts {
        rematerialize_contact_cache_in_txn(vault, wtxn, &contact_id, now)?;
    }
    Ok(())
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

// Test-only tally of full COMM_RECORD family scans, per thread so parallel
// tests cannot see each other's scans. The projector's pass index exists to
// keep this count at one per pass however many events the pass projects.
#[cfg(test)]
thread_local! {
    static COMM_RECORD_FAMILY_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_comm_record_family_scan() {
    COMM_RECORD_FAMILY_SCANS.with(|scans| scans.set(scans.get().saturating_add(1)));
}

#[cfg(test)]
thread_local! {
    static PENDING_GATE_RETAINS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_pending_gate_retain() {
    PENDING_GATE_RETAINS.with(|retains| retains.set(retains.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn note_pending_gate_retain() {}

#[cfg(not(test))]
const fn note_comm_record_family_scan() {}

/// Re-reads one COMM_RECORD by id. `None` covers every way a snapshot id can
/// stop naming a record of this family: deleted, retyped, or undecodable.
fn read_comm_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> CommResult<Option<CommRecord>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_COMM_RECORD {
        return Ok(None);
    }
    Ok(decode_comm_record(&raw[ENTITY_METADATA_HEADER_LEN..]).ok())
}

fn comm_records_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<Vec<(EntityId, CommRecord)>> {
    note_comm_record_family_scan();
    let mut records = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_COMM_RECORD])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(record) = read_comm_record_in_txn(vault, rtxn, id)? else {
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
            learned_at: crate::unix_seconds_now(),
            data: encode_comm_record(record)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
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

/// Validates one COMM_RECORD body at the replicated write door (FED-001).
pub(crate) fn validate_comm_record_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_comm_record(bytes)
        .map(|_| ())
        .map_err(|_| Error::InvalidCommRecordBody("body failed validation"))
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
        RECORD_KIND_EVENT => {
            let event_kind = required_string(entries, "event_kind")
                .ok()
                .and_then(CommEventKind::parse)
                .ok_or(CommError::InvalidRecord)?;
            let channel_class = optional_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?;
            if let Some(channel_class) = &channel_class {
                validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
            }
            let thread_ref =
                optional_string(entries, KEY_THREAD_REF).map_err(|_| CommError::InvalidRecord)?;
            if let Some(thread_ref) = &thread_ref {
                validate_key_string(thread_ref).map_err(|_| CommError::InvalidRecord)?;
            }
            // Enforce the exact per-variant field shape: a send/STOP carries a
            // channel_class and no thread_ref; a thread event carries a
            // thread_ref and no channel_class. Cross-populated bodies are
            // rejected at the door (fail-closed) rather than silently accepted.
            match event_kind {
                CommEventKind::SendSucceeded | CommEventKind::InboundStop
                    if channel_class.is_some() && thread_ref.is_none() => {}
                CommEventKind::ThreadJoined | CommEventKind::ThreadLeft
                    if thread_ref.is_some() && channel_class.is_none() => {}
                _ => return Err(CommError::InvalidRecord),
            }
            Ok(CommRecord::Event {
                sequence: required_u64(entries, "sequence")
                    .map_err(|_| CommError::InvalidRecord)?,
                kind: event_kind,
                party_ref,
                channel_class,
                thread_ref,
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                    .map_err(|_| CommError::InvalidRecord)?,
                projected: required_bool(entries, "projected")
                    .map_err(|_| CommError::InvalidRecord)?,
            })
        }
        RECORD_KIND_GATE => {
            let channel_class = required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned();
            validate_channel_class(&channel_class).map_err(|_| CommError::InvalidRecord)?;
            Ok(CommRecord::Gate {
                party_ref,
                channel_class,
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
            })
        }
        RECORD_KIND_RECEIPT => {
            let channel_class = required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned();
            validate_channel_class(&channel_class).map_err(|_| CommError::InvalidRecord)?;
            Ok(CommRecord::Receipt {
                party_ref,
                channel_class,
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                    .map_err(|_| CommError::InvalidRecord)?,
                outcome: required_string(entries, "outcome")
                    .map_err(|_| CommError::InvalidRecord)?
                    .to_owned(),
                actor_ref: required_entity_ref(entries, "actor_ref")
                    .map_err(|_| CommError::InvalidRecord)?,
            })
        }
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

/// A key that may be ELIDED entirely — absence IS the value, and `nil` is not
/// an accepted spelling of it. Duplicates are refused exactly like
/// [`required_value`], so an absent-or-once contract cannot be forged by
/// writing the key twice.
fn elided_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let Some(value) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(invalid_claim("comm value has duplicate key"));
    }
    Ok(Some(value))
}

fn elided_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    elided_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("comm value string invalid"))
        })
        .transpose()
}

fn elided_u64(entries: &[(Value, Value)], key: &str) -> Result<Option<u64>> {
    elided_value(entries, key)?
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_claim("comm value integer invalid"))
        })
        .transpose()
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

/// [`validate_keys`] with a set of keys that may be elided. Every required key
/// must appear exactly once, every optional key at most once, and nothing else
/// may appear at all — unknown keys are never ignored.
fn validate_keys_with_optional(
    entries: &[(Value, Value)],
    required: &[&str],
    optional: &[&str],
) -> Result<()> {
    for required_key in required {
        required_value(entries, required_key)?;
    }
    for optional_key in optional {
        elided_value(entries, optional_key)?;
    }
    if entries.iter().any(|(key, _)| {
        key.as_str()
            .is_none_or(|key| !required.contains(&key) && !optional.contains(&key))
    }) {
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

/// One-shot binding token: nonblank, at most 256 bytes, no NUL. It is compared
/// to `ExternalEffectGateInput.send_ref` by BYTE equality, so it is stored
/// exactly as minted — no trimming, no case folding.
fn validate_send_ref(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_SEND_REF_BYTES || value.as_bytes().contains(&0)
    {
        return Err(invalid_claim("comm.send_override send_ref is invalid"));
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
