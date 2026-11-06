//! Communication predicate, error, send-override and descriptor-row vocabulary.

use crate::write_envelope::claim_body::ClaimBody;
use oneiron_contracts::claim::{ClaimLifecycleStatus, ClaimSource};
use oneiron_contracts::error::{Error, Result};

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

pub const KEY_SCHEMA_VERSION: &str = "schema_version";

pub const KEY_PARTY_REF: &str = "party_ref";

pub const KEY_CHANNEL_CLASS: &str = "channel_class";

pub const KEY_THREAD_REF: &str = "thread_ref";

pub const KEY_OCCURRED_AT: &str = "occurred_at";

pub const KEY_OPTED_OUT: &str = "opted_out";

pub const KEY_JOINED: &str = "joined";

pub const KEY_REACHABLE: &str = "reachable";

pub const KEY_REASON: &str = "reason";

pub const KEY_SCOPE: &str = "scope";

pub const KEY_SEND_REF: &str = "send_ref";

pub const KEY_ISSUED_AT: &str = "issued_at";

pub const KEY_VALID_TO: &str = "valid_to";

/// Synced-truth field on a comm-owned PERSON body. `PARTY_INDEX_PREFIX` caches
/// the lookup; THIS is what the cache is a cache of.
pub const KEY_PARTY_KEY: &str = "party_key";

/// Receipt token for a counterparty STOP opt-out.
pub const COMM_OPT_OUT_REASON_STOP: &str = "counterparty_opt_out_stop";

/// Receipt token for a counterparty unsubscribe opt-out.
pub const COMM_OPT_OUT_REASON_UNSUBSCRIBE: &str = "counterparty_opt_out_unsubscribe";

/// Receipt token for a counterparty block or friend-removal opt-out.
pub const COMM_OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL: &str =
    "counterparty_opt_out_block_or_friend_removal";

/// The receipt vocabulary accepted by `comm.opt_out` claims, in reason order.
pub const COMM_OPT_OUT_REASONS: [&str; 3] = [
    COMM_OPT_OUT_REASON_STOP,
    COMM_OPT_OUT_REASON_UNSUBSCRIBE,
    COMM_OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL,
];

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

/// One row of the ARCH-0057 §4 claim-class table for the `comm.*` family, as
/// this build compiles it.
///
/// The rows DESCRIBE the write classes the family's own verbs enforce. They
/// are the seed and the fallback of the synced descriptor entities
/// (`comm::descriptor`): the open-time seed writes each row as a
/// CLAIM_CLASS_DESCRIPTOR, and a reader with no readable synced row gets the
/// row here. Nothing here gates a write.
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
/// `comm.do_not_contact` is CA-owned: its row is the CRM pack's own row
/// (`campaign::claims::claim_class_descriptors`), copied field for field, so
/// descriptor lookup and the open-time seed read the ordinary, restrictive
/// class the CRM table declares. Clearing one stays on the human-gated doors
/// CA landed; no row here gates a write.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    let mut rows = vec![
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
    ];
    rows.extend(
        crate::write_envelope::cohort_claims::claim_class_descriptors()
            .into_iter()
            .filter(|row| {
                row.predicate == crate::write_envelope::cohort_claims::PREDICATE_COMM_DO_NOT_CONTACT
            })
            .map(|row| ClaimClassDescriptorRow {
                predicate: row.predicate,
                write_class: row.write_class,
                enforcement: row.enforcement,
                restrictive: row.restrictive,
                projector_only: row.projector_only,
            }),
    );
    rows
}

/// Returns whether `predicate` belongs to the communication claim family.
#[must_use]
pub fn is_comm_claim_predicate(predicate: &str) -> bool {
    COMM_CLAIM_PREDICATES.contains(&predicate)
}

/// A live `comm.send_override` is an owner ruling, so only the typed mint
/// (`mint_send_override`, which checks a stored human actor) may write one. Any other door that would land an ACTIVE override (the public
/// claim door, a raw batch put, a generic lifecycle transition) is refused;
/// retracting or superseding one is a restriction and always lands.
/// Replication carries rulings the owner's own devices already admitted; a
/// federated import (restamped `Imported`) is another vault's word and is
/// refused even there.
pub fn guard_send_override_put(body: &ClaimBody, typed_door: bool, replicated: bool) -> Result<()> {
    let imported = body.source == Some(ClaimSource::Imported);
    if body.predicate == PREDICATE_COMM_SEND_OVERRIDE
        && body.lifecycle == ClaimLifecycleStatus::Active
        && (imported || (!typed_door && !replicated))
    {
        return Err(Error::InvalidClaimBody(
            "comm.send_override is ruled only through mint_send_override",
        ));
    }
    Ok(())
}
