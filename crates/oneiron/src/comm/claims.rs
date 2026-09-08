//! Claim family predicates, key vocabulary, typed values, body build/parse/validate.

use rmpv::Value;

use super::consent::OPT_OUT_REASONS;
use super::records::{
    elided_string, elided_u64, invalid_claim, required_bool, required_entity_ref, required_string,
    required_u64, validate_channel_class, validate_key_string, validate_keys,
    validate_keys_with_optional, validate_send_ref, value_map,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

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

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_PARTY_REF: &str = "party_ref";

pub(super) const KEY_CHANNEL_CLASS: &str = "channel_class";

pub(super) const KEY_THREAD_REF: &str = "thread_ref";

pub(super) const KEY_OCCURRED_AT: &str = "occurred_at";

pub(super) const KEY_OPTED_OUT: &str = "opted_out";

const KEY_JOINED: &str = "joined";

const KEY_REACHABLE: &str = "reachable";

const KEY_REASON: &str = "reason";

const KEY_SCOPE: &str = "scope";

const KEY_SEND_REF: &str = "send_ref";

const KEY_ISSUED_AT: &str = "issued_at";

const KEY_VALID_TO: &str = "valid_to";

/// Synced-truth field on a comm-owned PERSON body. `PARTY_INDEX_PREFIX` caches
/// the lookup; THIS is what the cache is a cache of.
pub(super) const KEY_PARTY_KEY: &str = "party_key";

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
