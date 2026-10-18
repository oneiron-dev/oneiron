//! The owner's work an install records for another to do, and what the named
//! install did with it (owner work, on L02's owner-act record).
//!
//! An owner act can need work only some installs can do. A world settings
//! edit needs the world's key minted, or wrapped to every reader the new
//! settings allow, and only an eligible reader that holds the key can do that:
//! key possession and the owner's recipient choice (mesh contract §5). An
//! install that carries the act but cannot do the work records an owner work
//! request in the same commit as the act ([`record`]), naming one executor
//! ([`record::owner_work_executor`], CALLS OWNER_WORK_EXECUTOR). The executor
//! picks it up after its next authority catch-up and on its served lifecycle
//! tick ([`Vault::run_pending_owner_work`], CALLS OWNER_WORK_PICKUP), rechecks
//! it in its own writer transaction, does the work, and records its result
//! beside it in the same commit ([`result`]).
//!
//! A receipt is derived from the fold whenever it is read: a request with no
//! result is "recorded, awaiting a holder". There is no counter, no second
//! queue, no timer and no takeover: a missing key, pad or secret on the
//! executor leaves the work pending, and only a new owner act names another
//! executor.
//!
//! The first kind is a world's key work, in Ensure mode after a settings
//! edit and in Reassert mode after the owner's re-assertion of a world
//! (`super::reassert`): the executor wraps its own keys of the world again
//! before it ensures. Each record it writes names the request it does, so a
//! replica that does not count the executor as mine still takes its wraps
//! within the owner's read choice (CALLS WORLD_KEY_WRAP_AUTH). Bundle
//! publication, custody control and a root request each add an
//! `OwnerWorkBody` variant (with its act kind and wire map) and one arm in
//! [`pickup`]'s dispatch; the request, result, executor pin, receipts and the
//! drain stay shared. A root request names its target install as executor,
//! exactly ([`super::root_work`]).
//!
//! No location, origin or hosted-mode rule reads anything here: the carrier
//! is any live linked machine the carrier rule admits, and `surface` is audit
//! only. What stays is real: only an eligible reader executes, and only one
//! that holds the key opens or wraps it.

mod pickup;
mod record;
mod result;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, OwnerWorkKind, OwnerWorkOutcome, OwnerWorkRefusal,
};

pub use self::pickup::OwnerWorkDrain;

/// Why an act's work names no executor (CALLS OWNER_WORK_NO_EXECUTOR,
/// ROOT_WORK_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkUnassigned {
    /// No install but this one may read the world: nobody can do its key
    /// work until the owner links one or widens the read.
    NoEligibleReader,
    /// A root change's target is the install the owner asked on: its own
    /// root door makes the change here.
    TargetIsRecorder,
    /// A root change's target is not a linked install of the vault whose
    /// proof key stands here.
    TargetNotLinked,
}

impl OwnerWorkUnassigned {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::NoEligibleReader => "no other install may read the world",
            Self::TargetIsRecorder => "this install is the target; make the change here",
            Self::TargetNotLinked => "the target is not a linked install",
        }
    }
}

/// The reason a receipt gives when no install can be named: no request is
/// recorded, the act stands, and the receipt still says "recorded, awaiting
/// a holder". An executor is never invented (CALLS OWNER_WORK_NO_EXECUTOR).
pub(crate) const OWNER_WORK_NO_EXECUTOR: OwnerWorkUnassigned =
    OwnerWorkUnassigned::NoEligibleReader;

/// Where one request stands, derived from the fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum OwnerWorkStatus {
    /// Recorded, awaiting a holder: no result yet.
    RecordedAwaitingHolder,
    /// The executor did the work and committed it. It never claims that
    /// every replica holds it yet.
    Enacted,
    /// The executor refused it, for the reason given.
    Refused { reason: OwnerWorkRefusal },
}

impl OwnerWorkStatus {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::RecordedAwaitingHolder => "recorded, awaiting a holder",
            Self::Enacted => "enacted by its holder",
            Self::Refused { .. } => "refused by its holder",
        }
    }
}

/// What an owner act recorded for a holder, and where it stands. Ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerWorkReceipt {
    /// The request's signed authority-log entry, as hex; `None` when no
    /// install could be named and no request was recorded.
    pub request: Option<String>,
    pub kind: OwnerWorkKind,
    /// What the work is for: the world, or the install a root change is
    /// for.
    pub target: EntityId,
    /// The one install that is to do it; `None` with no request.
    pub executor: Option<EntityId>,
    pub status: OwnerWorkStatus,
    /// Why no install was named; `None` once a request is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unassigned: Option<OwnerWorkUnassigned>,
}

impl OwnerWorkReceipt {
    /// No install could be named, for the reason given: nothing was
    /// recorded.
    fn unassigned(kind: OwnerWorkKind, target: EntityId, why: OwnerWorkUnassigned) -> Self {
        Self {
            request: None,
            kind,
            target,
            executor: None,
            status: OwnerWorkStatus::RecordedAwaitingHolder,
            unassigned: Some(why),
        }
    }

    /// The receipt of the request signed as entry `request`, as `fold`
    /// stands; `None` unless the fold admitted that request.
    pub(crate) fn of(fold: &AuthorityFold, request: AuthorityEntryHash) -> Option<Self> {
        let recorded = fold.owner_work_request(&request)?;
        let status = match fold
            .owner_work_result(&request)
            .map(|answer| answer.outcome)
        {
            None => OwnerWorkStatus::RecordedAwaitingHolder,
            Some(OwnerWorkOutcome::Enacted) => OwnerWorkStatus::Enacted,
            Some(OwnerWorkOutcome::Refused { reason }) => OwnerWorkStatus::Refused { reason },
        };
        Some(Self {
            request: Some(entry_hex(&request)),
            kind: recorded.kind(),
            target: recorded.act.target,
            executor: Some(recorded.executor),
            status,
            unassigned: None,
        })
    }

    /// This receipt again from `fold`, when it names a request the fold
    /// holds: what a stored receipt reads as now.
    pub(crate) fn refreshed(self, fold: &AuthorityFold) -> Self {
        self.request
            .as_deref()
            .and_then(parse_entry_hex)
            .and_then(|request| Self::of(fold, request))
            .unwrap_or(self)
    }
}

fn entry_hex(hash: &AuthorityEntryHash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_entry_hex(hex: &str) -> Option<AuthorityEntryHash> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}
