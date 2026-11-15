//! Moved from `crates/oneiron/src/world_keys/owner_work/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::world_keys::owner_work::diagnostics::BundleHomeWarning;
use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_authority::authority::OwnerWorkRefusal;
use serde::Deserialize;
use serde::Serialize;

/// Why an act's work names no executor (CALLS OWNER_WORK_NO_EXECUTOR,
/// ROOT_WORK_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkUnassigned {
    /// No install but this one may read the world: nobody can do its key
    /// work until the owner links one or widens the read.
    NoEligibleReader,
    /// A root change's target is the install the owner asked on: its own
    /// root door makes the change here.
    TargetIsRecorder,
    /// A root change's target, or a publication's home, is not a linked
    /// install of the vault whose proof key stands here.
    TargetNotLinked,
    /// No linked install but the home holds a counted wrap of the current
    /// key of every world the home's bundle seals (CALLS
    /// BUNDLE_PUBLISH_EXECUTOR).
    NoBundleHolder,
    /// An active custody change names no linked install to hold the
    /// secret's value (CALLS CUSTODY_EXECUTOR).
    NoCustodyHolder,
}

impl OwnerWorkUnassigned {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::NoEligibleReader => "no other install may read the world",
            Self::TargetIsRecorder => "this install is the target; make the change here",
            Self::TargetNotLinked => "the target is not a linked install",
            Self::NoBundleHolder => "no install holds every world's key",
            Self::NoCustodyHolder => "no linked install was named to hold the secret",
        }
    }
}

/// Where one request stands, derived from the fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum OwnerWorkStatus {
    /// Recorded, awaiting a holder: no result yet.
    RecordedAwaitingHolder,
    /// The executor did the work and committed it; for the owner's kit push
    /// (FIX 6053), which no machine executes, the push itself did, in the
    /// commit that recorded it. It never claims that every replica holds it
    /// yet.
    Enacted,
    /// The executor refused it, for the reason given.
    Refused { reason: OwnerWorkRefusal },
    /// The owner cancelled it before its executor answered it (CALLS
    /// ROOT_WORK_CANCEL): a root request only. Its executor never runs it
    /// once it holds the cancel, and no result is signed for it.
    Cancelled,
    /// A newer request on its target superseded it before its executor
    /// answered it (CALLS ROOT_WORK_SUPERSESSION): a root request only. Its
    /// executor never runs it, and no result is signed for it.
    Superseded,
}

impl OwnerWorkStatus {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::RecordedAwaitingHolder => "recorded, awaiting a holder",
            Self::Enacted => "enacted by its holder",
            Self::Refused { .. } => "refused by its holder",
            Self::Cancelled => "cancelled by the owner",
            Self::Superseded => "superseded by a newer request on its target",
        }
    }

    /// What the owner may do next, for a refusal that names a next step: a
    /// root request whose target's roots or standing moved from the ones he
    /// saw (FIX 4738, 5551); and what a cancelled or superseded root request
    /// means for its target (FIX 4739). `None` for every other status.
    #[must_use]
    pub fn advice(self) -> Option<&'static str> {
        match self {
            Self::Refused {
                reason: OwnerWorkRefusal::RootRevisionMismatch,
            } => Some(
                "the target holds owner roots or a standing of its own other than the ones you \
                 saw (a target still syncing what you saw waits instead). Review where it stands \
                 and ask again",
            ),
            Self::Cancelled => Some(
                "the target never runs it once it has synced the cancel; a result it signed \
                 before then stands, and nothing is undone",
            ),
            Self::Superseded => Some(
                "a newer request on the same target replaced it, and the target never runs this \
                 one",
            ),
            Self::RecordedAwaitingHolder | Self::Enacted | Self::Refused { .. } => None,
        }
    }
}

/// Where the owner's cancel of a root request stands, derived from the fold
/// (CALLS ROOT_WORK_CANCEL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkCancelState {
    /// No result came first: the request is cancelled.
    Cancelled,
    /// Its executor enacted the request before it had the cancel: the
    /// result stands, and nothing is undone.
    AlreadyEnacted,
    /// Its executor refused the request before it had the cancel: that
    /// answer stands.
    AlreadyRefused,
}

impl OwnerWorkCancelState {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::AlreadyEnacted => "already enacted: the result stands",
            Self::AlreadyRefused => "already refused: that answer stands",
        }
    }
}

/// The owner's cancels of one root request, as its receipt shows them. Ids
/// only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerWorkCancelNote {
    /// Each cancel's signed authority-log entry, as hex, ascending.
    pub entries: Vec<String>,
    pub state: OwnerWorkCancelState,
}

pub fn entry_hex(hash: &AuthorityEntryHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_entry_hex(hex: &str) -> Option<AuthorityEntryHash> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}
pub mod diagnostics;
