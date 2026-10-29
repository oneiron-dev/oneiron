//! The reveal's public value types: its states, decisions, receipts, asks
//! and answers, and what a handle reveals (moved whole out of reveal.rs).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::super::types::{CustodyClass, SecretCustodyStatus};
use crate::consent::EffectDigest;
use crate::entity_id::EntityId;
use crate::genui::ConsentAskCard;
use crate::store::GateDecisionId;

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

/// What `wait` answers about one reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRevealDecision {
    /// The owner has not answered, or a grant was revoked and the reveal is
    /// asked again.
    Pending,
    /// Granted: the value comes with this answer, the first time only.
    Granted,
    /// The owner denied it.
    Denied,
    /// Its window closed.
    Expired,
    /// The secret is gone; the receipt's `cause` names why (FIX 8350).
    Unavailable,
}

impl SecretRevealDecision {
    /// The pinned decision word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Expired => "expired",
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
    /// The T1 lease that delivered an agent's reveal.
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

/// One reveal as the owner reads it, with the in-moment card while it waits
/// on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealAsk {
    /// The reveal's receipt so far.
    pub receipt: SecretRevealReceipt,
    /// Where it stands; an ask past its window reads `expired`.
    pub state: SecretRevealState,
    /// When its window closes.
    pub expires_at: u64,
    /// The engine's line on where the value goes; `None` for an owner read.
    pub disclosure: Option<String>,
    /// The digest an answer sends back as `expected_digest`.
    pub once_digest: Option<EffectDigest>,
    /// The registry row a `standing` answer writes at its default reach:
    /// this connection × this class × this project.
    pub grant_ref: Option<String>,
    /// The reaches a `standing` answer may pick here, the narrowest first
    /// (FIX 2354): a task or a run only when the reveal names one; none for
    /// a repo file read, which picks its own `RepoFileRevealScope`, and for
    /// the owner's read.
    pub scopes: Vec<RevealGrantScope>,
    /// The DEC-0006 ask card, while the reveal waits on the owner.
    pub card: Option<ConsentAskCard>,
}

/// The owner's answer to one asked reveal: the DEC-0006 trio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRevealAnswer {
    /// Approve this one reveal.
    Once,
    /// Approve and stop asking: a standing grant on this connection × this
    /// class × this project.
    Standing,
    /// Deny it.
    Deny,
}

impl SecretRevealAnswer {
    /// The pinned answer word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Standing => "standing",
            Self::Deny => "deny",
        }
    }
}

/// The reach of the owner's standing answer to one reveal (FIX 2354): the
/// grant "approve and stop asking" writes covers this connection × this
/// class × this reach. Each reach is its own grant; none is a wildcard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealGrantScope {
    /// The project the reveal was asked in, until revoked: the default.
    #[default]
    Project,
    /// Every project, until revoked.
    EveryProject,
    /// The task the asking run works, until revoked.
    Task,
    /// The one run (the leased try) that asked; another run asks again.
    Run,
}

impl RevealGrantScope {
    /// The pinned scope word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::EveryProject => "every_project",
            Self::Task => "task",
            Self::Run => "run",
        }
    }
}

/// What an owner's answer wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealAnswered {
    /// The reveal answered.
    pub reveal: EntityId,
    /// The answer given.
    pub answer: SecretRevealAnswer,
    /// The answer's Gate decision.
    pub decision: GateDecisionId,
    /// The standing grant a `standing` answer wrote.
    pub grant_ref: Option<String>,
    /// That grant's reach (FIX 2354); `None` for a repo file read's grant.
    pub scope: Option<RevealGrantScope>,
}

/// The secret an owner's read names: its handle, or its custody name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealTarget {
    /// A handle, `sc12` or `sc12:ab`.
    Handle(String),
    /// A custody name.
    Name(String),
}

/// What the owner reads: the value, and the receipt that names their reason.
pub struct OwnerSecretReveal {
    /// The value. It is wiped when dropped.
    pub value: Zeroizing<Vec<u8>>,
    /// The read's receipt.
    pub receipt: SecretRevealReceipt,
}

impl fmt::Debug for OwnerSecretReveal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerSecretReveal")
            .field("value", &"<redacted>")
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// A secret as a model reads it through `describe(h)`: what it is, and what a
/// reveal of it would do for this asker now. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHandleCard {
    /// The handle.
    pub handle: String,
    /// The custody name.
    pub label: String,
    /// The custody class.
    pub class: CustodyClass,
    /// The record's status.
    pub status: SecretCustodyStatus,
    /// Where a mask on write found it, when one did.
    pub provenance: Option<SecretProvenance>,
    /// What a reveal would do now.
    pub reveal: HandleReveal,
}

/// Where a mask on write found a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretProvenance {
    /// The record whose text or field held it.
    pub record: EntityId,
    /// Where in that record: `body`, `claim`, `text:<field>` or `file`.
    pub place: String,
    /// The scan's word for the key's kind, such as `openai_key`.
    pub kind: String,
    /// When it was lifted.
    pub masked_at: u64,
}

/// What a reveal of a handle would do for its asker now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleReveal {
    /// A standing grant covers it: the value would come at once.
    Hydrates {
        /// The covering grant's registry ref.
        grant_ref: String,
    },
    /// It would ask the owner.
    Asks,
    /// It would be refused.
    Refused {
        /// Why, with no value in it.
        reason: String,
    },
}
