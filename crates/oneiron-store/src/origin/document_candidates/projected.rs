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

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use oneiron_contracts::entity_id::EntityId;

/// What a projected push's old tip maps back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectedPushBase {
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
