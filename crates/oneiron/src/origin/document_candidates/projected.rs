//! Core half of `origin::document_candidates::projected`: its store-layer items live in `oneiron_store::origin::document_candidates::projected` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the candidate intake calls it in 2b-ii-B"
)]

pub(crate) use oneiron_store::origin::document_candidates::projected::*;

use crate::EntityId;
use crate::git_wire::{GitOid, GitRefName};
use crate::origin::document_candidate_types::{CodePushCandidateHold, CodePushCandidateState};
use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use crate::origin::secret_projection::git::RepoGitProjection;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::origin::document_candidates::projected::{
    RepoProjectedCandidateFilePin, RepoProjectedCandidatePins,
};

/// The ORIGINAL `submitted_old`, a projected push's old COPY tip, stands
/// for in `projection`, by root occurrence only.
pub(crate) fn resolve_projected_push_base(
    projection: &RepoGitProjection,
    submitted_old: Option<&GitOid>,
) -> ProjectedPushBase {
    let Some(old) = submitted_old else {
        return ProjectedPushBase::NewBranch;
    };
    let mut found: Option<(Option<GitRefName>, GitOid)> = None;
    let roots = projection
        .refs()
        .iter()
        .map(|(name, original, copy)| (Some(name.clone()), original, copy))
        .chain(
            projection
                .private_root()
                .map(|(original, copy)| (None, original, copy)),
        );
    for (root, original, copy) in roots {
        if copy != old {
            continue;
        }
        if let Some((_, seen)) = &found {
            if seen != original {
                return ProjectedPushBase::Unresolved;
            }
            continue;
        }
        found = Some((root, original.clone()));
    }
    found.map_or(ProjectedPushBase::Unresolved, |(root, original)| {
        ProjectedPushBase::Original { root, original }
    })
}

/// The hold `pins` keep while `cause` is uncleared: the existing state
/// (`Proposed` when a canonical target resolved and its proposal waits,
/// `HeldShape` when there is no executable translation) and the cause's
/// reason code; `None` once cleared. Only this cause is refreshed.
pub(crate) fn refresh_projected_candidate_hold(
    pins: &RepoProjectedCandidatePins,
    cause: Option<RepoProjectionHoldCause>,
) -> Option<CodePushCandidateHold> {
    let cause = cause?;
    let state = if pins.canonical_target_tree.is_some() {
        CodePushCandidateState::Proposed
    } else {
        CodePushCandidateState::HeldShape
    };
    Some(CodePushCandidateHold {
        state,
        reason: cause.as_str().to_owned(),
    })
}
