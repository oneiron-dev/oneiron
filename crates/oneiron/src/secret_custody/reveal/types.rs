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

#[doc(hidden)]
pub use oneiron_records::secret_custody::reveal::types::{
    SecretRevealCause, SecretRevealReceipt, SecretRevealState,
};

/// What `wait` answers about one reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRevealDecision {
    /// The owner has not answered, or a grant was revoked and the reveal is
    /// asked again.
    Pending,
    /// Granted: the value comes with this answer, the first time, and again
    /// only to the step that collected it while its lease holds (FIX 2360,
    /// FIX 11683).
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

#[doc(hidden)]
pub use oneiron_verb_wire::secret_custody::reveal::types::RevealGrantScope;

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
    /// The owner's display-label override, or the custody name when none is set.
    pub label: String,
    /// The value-free suggestion derived from the scan kind.
    pub suggested_label: Option<String>,
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
