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
//! executor. A root request the owner cancelled, or a newer request on its
//! target superseded, before its executor answered it reads as cancelled or
//! superseded instead, and no result is signed for it (FIX 4739, CALLS
//! ROOT_WORK_CANCEL, ROOT_WORK_SUPERSESSION); a cancel its result came first
//! says it came too late, and the result stands.
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
//! exactly ([`super::root_work`]). A bundle publication names the lowest
//! install that holds every key the bundle seals; its pickup only rechecks,
//! and the sealed bundle relay publishes (`super::bundle`'s publication). A
//! custody change names its holder, and a revoke the install that records
//! it, which enacts it in the same commit (`crate::secret_custody`'s
//! control); a pickup loads this install's hybrid secret only for the kinds
//! that read it, so a revoke needs no byte.
//!
//! What blocks a pending request is the executor's to observe
//! ([`diagnostics`]): an owner's read that decides nothing, and that any
//! other install answers as unavailable.
//!
//! No location, origin or hosted-mode rule reads anything here: the carrier
//! is any live linked machine the carrier rule admits, and `surface` is audit
//! only. What stays is real: only an eligible reader executes, and only one
//! that holds the key opens or wraps it.

mod diagnostics;
mod pickup;
mod record;
mod relay_start;
mod result;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, OwnerWorkBody, OwnerWorkKind, OwnerWorkOutcome,
    OwnerWorkRefusal,
};
use oneiron_authority::authority::CustodyRegisterCheck;

pub use self::diagnostics::{
    BundleHomeWarning, CapsuleRead, EnsureDiagnostics, EnsureView, ExecutorObservation, LatestRead,
    OwnerWorkDiagnostics, PublicationDiagnostics, PublishAttemptView, PublishObserved,
    PublishReach, ReassertDiagnostics, ReassertKey, ReassertKeyState, ReassertUnread,
    RelayObservation, UnmergedUploadView,
};
pub use self::pickup::OwnerWorkDrain;
pub use self::relay_start::DeviceSyncStart;

#[doc(hidden)]
pub use oneiron_verb_wire::world_keys::owner_work::{
    OwnerWorkCancelNote, OwnerWorkCancelState, OwnerWorkStatus, OwnerWorkUnassigned,
};
#[doc(hidden)]
use oneiron_verb_wire::world_keys::owner_work::{entry_hex, parse_entry_hex};

/// The reason a receipt gives when no install can be named: no request is
/// recorded, the act stands, and the receipt still says "recorded, awaiting
/// a holder". An executor is never invented (CALLS OWNER_WORK_NO_EXECUTOR).
pub(crate) const OWNER_WORK_NO_EXECUTOR: OwnerWorkUnassigned =
    OwnerWorkUnassigned::NoEligibleReader;

/// What an owner act recorded for a holder, and where it stands. Ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerWorkReceipt {
    /// The request's signed authority-log entry, as hex; `None` when no
    /// install could be named and no request was recorded.
    pub request: Option<String>,
    pub kind: OwnerWorkKind,
    /// What the work is for: the world, the install a root change is for,
    /// the home a bundle publication is for, or the secret's custody record
    /// a custody change is for.
    pub target: EntityId,
    /// The one install that is to do it; `None` with no request.
    pub executor: Option<EntityId>,
    pub status: OwnerWorkStatus,
    /// Why no install was named; `None` once a request is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unassigned: Option<OwnerWorkUnassigned>,
    /// For a custody register whose owner's surface stated no
    /// `manifest_ref`, what its holder checked the record against, as its
    /// signed result says (FIX 5334): the manifest it checked, or why it
    /// registered without a manifest check, by manifest refs alone. `None`
    /// before the result, and for any other work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_check: Option<CustodyRegisterCheck>,
    /// For a bundle publication, why the home it names may keep no sealed
    /// copy, as its profile stands here (FIX 4786): a phone's, or none known.
    /// It says why the request may stay pending and decides nothing. `None`
    /// for a home whose profile keeps sealed copies, and for any other work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_warning: Option<BundleHomeWarning>,
    /// For a root request the owner cancelled, his cancels and where they
    /// stand (FIX 4739): the request cancelled, or answered before its
    /// executor had a cancel, which says so. `None` for a request no cancel
    /// names, and for any other work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel: Option<OwnerWorkCancelNote>,
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
            manifest_check: None,
            home_warning: None,
            cancel: None,
        }
    }

    /// The receipt of the request signed as entry `request`, as `fold`
    /// stands, with the manifest judgment its holder's result carries and
    /// the owner's cancels of it; `None` unless the fold admitted that
    /// request. A result is the request's one terminal state: a cancel or a
    /// newer request closes only a request with none.
    pub(crate) fn of(fold: &AuthorityFold, request: AuthorityEntryHash) -> Option<Self> {
        let recorded = fold.owner_work_request(&request)?;
        let outcome = fold
            .owner_work_result(&request)
            .map(|answer| &answer.outcome);
        let status = match outcome {
            // The owner's kit push (FIX 6053) is enacted by the push that
            // recorded it: it never waits for a holder, none picks it up.
            None if recorded.kit_root().is_some() => OwnerWorkStatus::Enacted,
            None if fold.root_request_cancelled(&request) => OwnerWorkStatus::Cancelled,
            None if fold.root_request_superseded(&request) => OwnerWorkStatus::Superseded,
            None => OwnerWorkStatus::RecordedAwaitingHolder,
            Some(OwnerWorkOutcome::Enacted { .. } | OwnerWorkOutcome::Sealed { .. }) => {
                OwnerWorkStatus::Enacted
            }
            Some(OwnerWorkOutcome::Refused { reason }) => {
                OwnerWorkStatus::Refused { reason: *reason }
            }
        };
        let cancels: Vec<String> = fold
            .owner_work_cancels(&request)
            .map(|cancel| entry_hex(&cancel))
            .collect();
        let cancel_state = match outcome {
            None => OwnerWorkCancelState::Cancelled,
            Some(OwnerWorkOutcome::Enacted { .. } | OwnerWorkOutcome::Sealed { .. }) => {
                OwnerWorkCancelState::AlreadyEnacted
            }
            Some(OwnerWorkOutcome::Refused { .. }) => OwnerWorkCancelState::AlreadyRefused,
        };
        let cancel = if cancels.is_empty() {
            None
        } else {
            Some(OwnerWorkCancelNote {
                entries: cancels,
                state: cancel_state,
            })
        };
        // The receipt reads the fold alone, so it names no world awaiting a
        // reader: the executor's diagnostics read the home's newest
        // generation (FIX 4496).
        let home_warning = match recorded.work {
            OwnerWorkBody::PublishBundle { home } => {
                diagnostics::bundle_home_warning(fold, home, &[])
            }
            OwnerWorkBody::WorldKey { .. }
            | OwnerWorkBody::Root { .. }
            | OwnerWorkBody::Custody { .. }
            | OwnerWorkBody::ExportSecret(_) => None,
        };
        Some(Self {
            request: Some(entry_hex(&request)),
            kind: recorded.kind(),
            target: recorded.act.target,
            // No machine executes a kit request: none is named.
            executor: recorded.executor_machine(),
            status,
            unassigned: None,
            manifest_check: outcome.and_then(OwnerWorkOutcome::register_check).cloned(),
            home_warning,
            cancel,
        })
    }

    /// This receipt again from `fold`, when it names a request the fold
    /// holds: what a stored receipt reads as now.
    pub(crate) fn refreshed(self, fold: &AuthorityFold) -> Self {
        self.request_entry()
            .and_then(|request| Self::of(fold, request))
            .unwrap_or(self)
    }

    /// The request's signed entry; `None` when nothing was recorded.
    pub(crate) fn request_entry(&self) -> Option<AuthorityEntryHash> {
        self.request.as_deref().and_then(parse_entry_hex)
    }
}
