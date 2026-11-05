//! Claim family predicates, key vocabulary, typed values, body build/parse/validate.

use rmpv::Value;

use super::records::{
    elided_string, elided_u64, invalid_claim, required_bool, required_entity_ref, required_string,
    required_u64, validate_channel_class, validate_key_string, validate_keys,
    validate_keys_with_optional, validate_send_ref, value_map,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::communication::COMM_OPT_OUT_REASONS as OPT_OUT_REASONS;
use crate::write_envelope::communication::{
    KEY_ISSUED_AT, KEY_JOINED, KEY_REACHABLE, KEY_REASON, KEY_SCOPE, KEY_SEND_REF, KEY_VALID_TO,
};

pub use crate::write_envelope::communication::COMM_CLAIM_PREDICATES;
pub use crate::write_envelope::communication::COMM_SCHEMA_VERSION;
pub use crate::write_envelope::communication::ClaimClassDescriptorRow;
pub use crate::write_envelope::communication::CommClearOptOutOutcome;
pub use crate::write_envelope::communication::CommError;
pub use crate::write_envelope::communication::CommResult;
pub(super) use crate::write_envelope::communication::KEY_CHANNEL_CLASS;
pub(super) use crate::write_envelope::communication::KEY_OCCURRED_AT;
pub(super) use crate::write_envelope::communication::KEY_OPTED_OUT;
pub(super) use crate::write_envelope::communication::KEY_PARTY_KEY;
pub(super) use crate::write_envelope::communication::KEY_PARTY_REF;
pub(super) use crate::write_envelope::communication::KEY_SCHEMA_VERSION;
pub(super) use crate::write_envelope::communication::KEY_THREAD_REF;
pub use crate::write_envelope::communication::PREDICATE_COMM_LAST_TOUCH;
pub use crate::write_envelope::communication::PREDICATE_COMM_OPT_OUT;
pub use crate::write_envelope::communication::PREDICATE_COMM_REACHABLE_VIA;
pub use crate::write_envelope::communication::PREDICATE_COMM_SEND_OVERRIDE;
pub use crate::write_envelope::communication::PREDICATE_COMM_THREAD_MEMBER;
pub use crate::write_envelope::communication::SendOverrideMatch;
pub use crate::write_envelope::communication::SendOverrideScope;
pub use crate::write_envelope::communication::claim_class_descriptors;

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
    pub fn claim_body(&self) -> Result<ClaimBody> {
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
        )?;
        body.valid_from = valid_from;
        body.source = Some(ClaimSource::Observed);
        let mut scope = vec![(Value::from("sensitivity"), Value::from(2_u64))];
        if matches!(self, Self::OptOut { .. }) {
            scope.push((Value::from("criticality"), Value::from("critical")));
        }
        body.scope = Some(Value::Map(scope));
        Ok(body)
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

pub use crate::write_envelope::communication::is_comm_claim_predicate;

pub(crate) use crate::write_envelope::communication::guard_send_override_put;

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
