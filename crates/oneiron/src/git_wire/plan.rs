//! Two-phase plan assembly: object writes plus the ref publications they authorize.

use super::argv::FrozenGitArgv;
use super::config::{GIT_WIRE_MAX_PLAN_OBJECTS, GIT_WIRE_MAX_PUBLICATIONS};
use super::failure::invalid;
use super::record::hash_field;
use super::{
    GIT_WIRE_DOMAIN, GitCommitRequest, GitOid, GitRefExpectation, GitRefName, GitTreeEntry,
    GitWireResult,
};
use crate::error::Result;

/// One object-producing step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWireObjectWrite {
    Blob(Vec<u8>),
    Tree(Vec<GitTreeEntry>),
    Commit(GitCommitRequest),
}

impl GitWireObjectWrite {
    pub(super) fn argv(&self) -> GitWireResult<FrozenGitArgv> {
        match self {
            Self::Blob(bytes) => Ok(FrozenGitArgv::write_blob(bytes)),
            Self::Tree(entries) => FrozenGitArgv::write_tree(entries),
            Self::Commit(request) => FrozenGitArgv::write_commit(request),
        }
    }
}

/// A reference to an object a plan will publish: either one already in the
/// store, or the output of an earlier step of the same plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWirePlannedOid {
    Existing(usize),
    Written(usize),
}

/// A publication whose target may still be unwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedPublication {
    pub(super) name: GitRefName,
    pub(super) expected: GitRefExpectation,
    pub(super) next: Option<GitWirePlannedOid>,
}

/// A phase-one plan: object writes plus the ref publications they authorize.
///
/// This is the whole public two-phase entry. A caller assembles a plan with
/// typed builders, hands it to [`GitWire::stage`](crate::git_wire::GitWire::stage), and commits the returned
/// capability — no private field is ever needed, and a ref-moving operation
/// such as `notes add` cannot enter phase one because no plan step can express
/// one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitWirePlan {
    pub(super) objects: Vec<GitWireObjectWrite>,
    pub(super) existing: Vec<GitOid>,
    pub(super) publications: Vec<PlannedPublication>,
}

impl GitWirePlan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a blob write and returns a handle to its object id.
    pub fn write_blob(&mut self, bytes: impl Into<Vec<u8>>) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Blob(bytes.into()))
    }

    /// Adds a tree write and returns a handle to its object id.
    pub fn write_tree(&mut self, entries: Vec<GitTreeEntry>) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Tree(entries))
    }

    /// Adds a commit write and returns a handle to its object id.
    pub fn write_commit(&mut self, request: GitCommitRequest) -> GitWireResult<GitWirePlannedOid> {
        self.push_object(GitWireObjectWrite::Commit(request))
    }

    /// Names an object that already exists in the store.
    pub fn existing_object(&mut self, oid: GitOid) -> GitWireResult<GitWirePlannedOid> {
        if self.existing.len() >= GIT_WIRE_MAX_PLAN_OBJECTS {
            return Err(invalid("git wire plan exceeds its object bound"));
        }
        self.existing.push(oid);
        Ok(GitWirePlannedOid::Existing(self.existing.len() - 1))
    }

    /// Publishes `name` at `target`, requiring the value the caller decided
    /// against.
    pub fn publish(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
        target: GitWirePlannedOid,
    ) -> GitWireResult<()> {
        self.push_publication(name, expected, Some(target))
    }

    /// Deletes `name`, requiring the value the caller decided against.
    pub fn unpublish(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
    ) -> GitWireResult<()> {
        self.push_publication(name, expected, None)
    }

    fn push_object(&mut self, write: GitWireObjectWrite) -> GitWireResult<GitWirePlannedOid> {
        if self.objects.len() >= GIT_WIRE_MAX_PLAN_OBJECTS {
            return Err(invalid("git wire plan exceeds its object bound"));
        }
        self.objects.push(write);
        Ok(GitWirePlannedOid::Written(self.objects.len() - 1))
    }

    fn push_publication(
        &mut self,
        name: GitRefName,
        expected: GitRefExpectation,
        next: Option<GitWirePlannedOid>,
    ) -> GitWireResult<()> {
        if self.publications.len() >= GIT_WIRE_MAX_PUBLICATIONS {
            return Err(invalid("git wire plan exceeds its publication bound"));
        }
        if name.is_keep_ref() {
            return Err(invalid(
                "git wire plan must not publish an engine keep-ref directly",
            ));
        }
        if matches!(expected, GitRefExpectation::Any) {
            return Err(invalid(
                "git wire publication must state the value it was decided against",
            ));
        }
        if self.publications.iter().any(|entry| entry.name == name) {
            return Err(invalid("git wire plan names one ref twice"));
        }
        self.publications.push(PlannedPublication {
            name,
            expected,
            next,
        });
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.publications.is_empty() {
            return Err(invalid("git wire plan must publish at least one ref"));
        }
        for publication in &self.publications {
            let Some(target) = publication.next else {
                continue;
            };
            let known = match target {
                GitWirePlannedOid::Written(index) => index < self.objects.len(),
                GitWirePlannedOid::Existing(index) => index < self.existing.len(),
            };
            if !known {
                return Err(invalid("git wire plan publishes an unknown object handle"));
            }
        }
        Ok(())
    }

    /// The stable content hash of the plan: object payload hashes plus the
    /// publications, so two textually identical plans claim one stage key and
    /// two different plans never collide.
    pub(super) fn plan_hash(&self) -> GitWireResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"plan");
        for write in &self.objects {
            let argv = write.argv()?;
            hash_field(&mut hasher, argv.operation().as_str().as_bytes());
            hash_field(&mut hasher, argv.stdin().unwrap_or(&[]));
        }
        for oid in &self.existing {
            hash_field(&mut hasher, oid.as_str().as_bytes());
        }
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_str().as_bytes());
            hash_publication_target(&mut hasher, publication);
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

fn hash_publication_target(hasher: &mut blake3::Hasher, publication: &PlannedPublication) {
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
