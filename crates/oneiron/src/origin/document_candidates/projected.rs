//! A candidate received from a masked copy (FIX 7608 slice 2b-ii-A, G4 PR2
//! translation, ASK S): its immutable projection pins and its base.
//!
//! A push from a masked copy is received as it was pushed, into its own
//! ingress; its candidate translates the agent's content diff onto the
//! ORIGINAL as one native proposal, never a rewrite of incoming history.
//! The pins name the copy graph and ingress proof it was received under,
//! the submitted COPY tips, the ORIGINAL base the copy's base stood for,
//! the canonical target tree the translation resolved (none while it has
//! no unique one) and each file's original, copy, submitted and canonical
//! blobs with its typed cause. They are frozen with the candidate and
//! enter its digest; a clearance is recorded beside them, never in them.
//!
//! A copy's base maps back to its ORIGINAL only by occurrence: the frozen
//! root (or the lease's private root) whose copy the push names as its old
//! tip. Two roots whose copies agree but whose originals differ name no
//! unique original, and a tip no root names is not resolved here: never a
//! newest or equal-content guess.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the candidate intake calls it in 2b-ii-B"
)]

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::git_wire::{GitOid, GitRefName};
use crate::origin::document_candidate_types::{CodePushCandidateHold, CodePushCandidateState};
use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use crate::origin::secret_projection::git::RepoGitProjection;

/// One file of a projected candidate, by its path: the ORIGINAL blob its
/// copy stood for, the copy blob the agent was given, the blob it
/// submitted, the canonical blob its translation resolved and the typed
/// cause that holds it, if any. Git ids, lower hex; no content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RepoProjectedCandidateFilePin {
    pub path: String,
    pub original_blob: Option<String>,
    pub copy_blob: Option<String>,
    pub submitted_blob: Option<String>,
    pub canonical_blob: Option<String>,
    pub cause: Option<RepoProjectionHoldCause>,
}

/// The immutable projection pins of a candidate received from a masked
/// copy: kept apart from the submitted COPY tips, so the canonical target
/// is never the submitted tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RepoProjectedCandidatePins {
    /// The masked copy's graph claim.
    pub graph: EntityId,
    /// The ingress proof's record id.
    pub ingress: EntityId,
    /// The submitted COPY old tip; none for a new branch.
    pub submitted_old: Option<String>,
    /// The submitted COPY new tip.
    pub submitted_new: String,
    /// The ORIGINAL commit the copy's old tip stood for.
    pub canonical_base: Option<String>,
    /// The canonical tree the translation resolved; none while a file has
    /// no unique translation.
    pub canonical_target_tree: Option<String>,
    /// Each changed file, in path order.
    pub files: Vec<RepoProjectedCandidateFilePin>,
}

impl RepoProjectedCandidatePins {
    /// The digest these pins enter a candidate's digest as: every pin,
    /// length-prefixed, under its own domain.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.repo_projection.candidate_pins.v1");
        let mut part = |field: &[u8]| {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        };
        let text = |field: Option<&String>| field.map_or("", String::as_str).to_owned();
        part(self.graph.as_bytes());
        part(self.ingress.as_bytes());
        part(text(self.submitted_old.as_ref()).as_bytes());
        part(self.submitted_new.as_bytes());
        part(text(self.canonical_base.as_ref()).as_bytes());
        part(text(self.canonical_target_tree.as_ref()).as_bytes());
        for file in &self.files {
            part(file.path.as_bytes());
            part(text(file.original_blob.as_ref()).as_bytes());
            part(text(file.copy_blob.as_ref()).as_bytes());
            part(text(file.submitted_blob.as_ref()).as_bytes());
            part(text(file.canonical_blob.as_ref()).as_bytes());
            part(
                file.cause
                    .map_or("", RepoProjectionHoldCause::as_str)
                    .as_bytes(),
            );
        }
        *hasher.finalize().as_bytes()
    }

    /// The cause the candidate holds on before any clearance: a file's
    /// (sealed-file edits first), or a conflict when no canonical target
    /// resolved.
    pub(crate) fn hold_cause(&self) -> Option<RepoProjectionHoldCause> {
        self.files
            .iter()
            .filter_map(|file| file.cause)
            .min()
            .or_else(|| {
                self.canonical_target_tree
                    .is_none()
                    .then_some(RepoProjectionHoldCause::ProjectionEditConflict)
            })
    }
}

/// What a projected push's old tip maps back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectedPushBase {
    /// The frozen root (or the lease's private root, `None`) whose copy the
    /// push names, and the ORIGINAL it was frozen at.
    Original {
        root: Option<GitRefName>,
        original: GitOid,
    },
    /// A new branch: the existing G4 rule for a null old tip decides.
    NewBranch,
    /// No unique ORIGINAL: no root names the tip, or roots whose copies
    /// agree name different originals.
    Unresolved,
}

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
