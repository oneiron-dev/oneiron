//! Moved from `crates/oneiron/src/secret_custody/reveal/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::gate_decision::types::GateDecisionId;
pub use oneiron_verb_wire::secret_custody::reveal::types::RevealGrantScope;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use zeroize::Zeroizing;

/// Where a reveal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRevealState {
    /// A standing grant covered the reveal when it was asked.
    Covered,
    /// It waits on the owner's answer.
    Asked,
    /// The owner approved this one reveal.
    ApprovedOnce,
    /// The owner approved and stopped asking: a standing grant covers it.
    ApprovedStanding,
    /// The owner denied it.
    Denied,
    /// Its window closed before it was answered or collected.
    Expired,
    /// Its value went to its reader.
    Delivered,
    /// Its secret was erased before its value went out; the row's cause
    /// names why (FIX 8350).
    Unavailable,
}

impl SecretRevealState {
    /// The pinned state word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Asked => "asked",
            Self::ApprovedOnce => "approved_once",
            Self::ApprovedStanding => "approved_standing",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Delivered => "delivered",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Why a reveal closed with no value (FIX 8350).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRevealCause {
    /// The run seat that found the secret ended, and its run-bound record
    /// was erased with it (FIX 8028).
    RunSeatEnded,
}

impl SecretRevealCause {
    /// The pinned cause word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunSeatEnded => "run_seat_ended",
        }
    }
}

/// One reveal's receipt: what was revealed, to whom, why and on whose answer.
/// It names the handle, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealReceipt {
    /// The reveal's id.
    pub reveal: EntityId,
    /// The handle the reveal named, such as `sc12`.
    pub handle: String,
    /// The secret's custody class.
    pub class: String,
    /// The agent's why, or the owner's reason.
    pub why: String,
    /// `agent:<hex>` or `owner:<hex>`.
    pub reader: String,
    /// The model connection the value goes to; `None` for the owner's read.
    pub connection: Option<String>,
    /// The model provider behind the connection, when a host named one.
    pub provider: Option<String>,
    /// The project the reveal was asked in.
    pub project: Option<EntityId>,
    /// The run it was asked from, when a host bound one.
    pub run: Option<String>,
    /// Who answered: `standing:<grant ref>` or `owner:<hex>`; `None` while
    /// it waits.
    pub answered_by: Option<String>,
    /// The Gate decision of its last consent act: the use of a grant, the
    /// owner's approval or denial, or the owner's read.
    pub decision: Option<GateDecisionId>,
    /// The lease that delivered an agent's reveal: its T1 lease, or the one
    /// a PERSON reveal keeps on its row (FIX 11683).
    pub lease: Option<EntityId>,
    /// When it was asked.
    pub asked_at: u64,
    /// When its value went out.
    pub delivered_at: Option<u64>,
    /// The file an agent's read of a marked file named, or the artifact of
    /// a typed body an agent's read showed: its keys are the handles above,
    /// and each went out under its own T1 lease.
    pub file: Option<EntityId>,
    /// Why the reveal closed with no value, `None` otherwise (FIX 8350).
    pub cause: Option<SecretRevealCause>,
    /// The reach of the standing grant that answered it (FIX 2354); `None`
    /// for an answer once, a denial, a repo file read's grant and the
    /// owner's read.
    pub scope: Option<RevealGrantScope>,
}
