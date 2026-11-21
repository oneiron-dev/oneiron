//! Two-phase plan assembly: object writes plus the ref publications they authorize.

use crate::git_wire::config::GIT_WIRE_DOMAIN;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefExpectation;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::objects::GitCommitRequest;
use crate::git_wire::objects::GitTreeEntry;
use oneiron_base::error::Result;
use oneiron_contracts::fingerprint::LegacyDigest;

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

/// A publication's expectation and target, into a plan hash: each framed by
/// its length as a u32 big-endian (`purposes::git_wire::PLAN_HASH`).
pub fn hash_publication_target(digest: &mut LegacyDigest, publication: &PlannedPublication) {
    let expected = match &publication.expected {
        GitRefExpectation::Absent => b"absent".as_slice(),
        GitRefExpectation::Value(oid) => oid.as_str().as_bytes(),
        GitRefExpectation::Any => b"any".as_slice(),
    };
    let target = match publication.next {
        Some(GitWirePlannedOid::Written(index)) => format!("written:{index}"),
        Some(GitWirePlannedOid::Existing(index)) => format!("existing:{index}"),
        None => "delete".to_owned(),
    };
    for field in [expected, target.as_bytes()] {
        digest.len_u32_be_saturating(field.len()).raw(field);
    }
}
