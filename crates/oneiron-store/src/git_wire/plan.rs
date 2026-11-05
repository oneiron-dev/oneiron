//! Two-phase plan assembly: object writes plus the ref publications they authorize.

use crate::git_wire::config::GIT_WIRE_DOMAIN;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefExpectation;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::objects::GitCommitRequest;
use crate::git_wire::objects::GitTreeEntry;
use crate::git_wire::record::hash_field;
use oneiron_base::error::Result;

/// A reference to an object a plan will publish: either one already in the
/// store, or the output of an earlier step of the same plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWirePlannedOid {
    Existing(usize),
    Written(usize),
}

/// A publication whose target may still be unwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPublication {
    pub name: GitRefName,
    pub expected: GitRefExpectation,
    pub next: Option<GitWirePlannedOid>,
}

pub fn hash_publication_target(hasher: &mut blake3::Hasher, publication: &PlannedPublication) {
    match &publication.expected {
        GitRefExpectation::Absent => hash_field(hasher, b"absent"),
        GitRefExpectation::Value(oid) => hash_field(hasher, oid.as_str().as_bytes()),
        GitRefExpectation::Any => hash_field(hasher, b"any"),
    }
    match publication.next {
        Some(GitWirePlannedOid::Written(index)) => {
            hash_field(hasher, format!("written:{index}").as_bytes());
        }
        Some(GitWirePlannedOid::Existing(index)) => {
            hash_field(hasher, format!("existing:{index}").as_bytes());
        }
        None => hash_field(hasher, b"delete"),
    }
}
