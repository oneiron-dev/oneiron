//! Moved from `crates/oneiron/src/batch/secret_scan/lift_history/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What queued a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftTrigger {
    /// The owner switched the scan from off to on.
    Switch,
    /// The owner asked for a run.
    Owner,
    /// Custody came to know a value (FIX 2781): a pass marks it in the files
    /// stored before, and reads nothing else.
    KnownValue,
}

/// Why the sweep filed a proposal instead of placing a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCause {
    /// No rule the door has places it: a recovery phrase, a key split over
    /// fields, a masked copy the row's own reading refuses.
    Unplaceable,
    /// The row's own writer refuses a rewrite: an immutable record.
    Immutable,
    /// A legal hold keeps the record as it stands.
    Held,
    /// A file, whose bytes stay as they are; its keys are marked.
    File,
    /// A carrier no door rewrites.
    NoDoor,
    /// The record's retained history still holds the value.
    History,
}

impl LiftCause {
    /// The cause's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unplaceable => "unplaceable",
            Self::Immutable => "immutable",
            Self::Held => "held",
            Self::File => "file",
            Self::NoDoor => "no_door",
            Self::History => "history",
        }
    }
}

/// Why a proposal closed. The owner closes one as `not_a_secret`, `rotated`
/// or `accepted`; the others close it on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCloseReason {
    /// The owner: what the sweep found is no secret.
    NotASecret,
    /// The owner rotated or revoked the value where it is issued.
    Rotated,
    /// The owner keeps the row as it stands.
    Accepted,
    /// A later run read the row again and found no hit there.
    ReadClean,
    /// The owner answered each key the sweep lifted out of the record
    /// through a found-key door: rotate, delete or not a secret.
    Answered,
    /// The row was deleted.
    Deleted,
}

impl LiftCloseReason {
    /// The reason's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotASecret => "not_a_secret",
            Self::Rotated => "rotated",
            Self::Accepted => "accepted",
            Self::ReadClean => "read_clean",
            Self::Answered => "answered",
            Self::Deleted => "deleted",
        }
    }
}

/// How many open proposals one cause holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftCauseCount {
    pub cause: LiftCause,
    pub open: u64,
}

/// `vault.secrets.lift_history`'s input: the status, after closing one
/// proposal or queueing a run when asked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftRequest {
    /// Queue a run now. A run already queued walks again from the start.
    #[serde(default)]
    pub start: bool,
    /// Close one open proposal first, with the owner's reason.
    #[serde(default)]
    pub close: Option<SecretLiftClose>,
}

/// The owner's close of one lift proposal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftClose {
    /// The proposal's `id`.
    pub proposal: String,
    /// `not_a_secret`, `rotated` or `accepted`.
    pub reason: LiftCloseReason,
}
