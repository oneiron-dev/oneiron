//! What one repository's secret marks and remediation links say (FIX 7608
//! slice 8): the read behind the repo secret notice. Value-free: a mark
//! names its blob, path, detector kind, source and custody handle, never a
//! value, span or excerpt; a link names its proposal, commit and paths.

use rmpv::Value;

use super::link::REPO_SECRET_REMEDIATION_PREDICATE;
use super::{canonical_repo_ref_for_root, resolve_mutable_repo_root};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSubject};
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitWire;
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_marks::{
    RepoSecretMark, RepoSecretMarkLookup, RepoSecretPlacement, RepoSecretSource,
    for_each_repo_secret_mark_in_txn,
};

/// Where a mark's blob was seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoSecretMarkSeen {
    /// A pushed ref's move: the ref and the commit it moved to.
    RefMove { name: String, new_commit: String },
    /// The push's quarantine, with no proved ref.
    Quarantine,
    /// A translated sync copy edit landed the bytes on a marked source.
    SyncLanding,
}

/// One mark, value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecretMarkEntry {
    pub mark: EntityId,
    /// The receive operation that wrote it.
    pub operation: EntityId,
    /// The blob's Git OID.
    pub blob: String,
    /// The exact path, when the door knew it.
    pub path: Option<String>,
    /// A reason code, never an excerpt.
    pub detector_kind: String,
    pub seen: RepoSecretMarkSeen,
    /// The custody record holding the placed key's value; `None` for a
    /// blob's opaque residue, which no span isolates.
    pub custody: Option<EntityId>,
    /// The custody handle the key stands as in a masked copy.
    pub handle: Option<String>,
    pub marked_at: u64,
}

/// One remediation link (`offered` or `proposed`), value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecretRemediationLinkEntry {
    pub state: String,
    pub proposal: EntityId,
    pub commit: Option<String>,
    pub paths: Vec<String>,
    pub linked_at: u64,
}

/// What a repository's object store holds marked, and the remediations
/// linked to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecretMarks {
    /// The canonical object store's identity (hex).
    pub store_identity: String,
    pub marks: Vec<RepoSecretMarkEntry>,
    pub links: Vec<RepoSecretRemediationLinkEntry>,
}

impl Vault {
    /// Every readable mark of `repo_ref`'s canonical object store, and every
    /// remediation link to it, oldest first.
    ///
    /// # Errors
    /// A repository that does not open, a store failure, or a mark or link
    /// that does not decode.
    pub fn repo_secret_marks(&self, repo_ref: &RepoRef) -> Result<RepoSecretMarks> {
        let root = resolve_mutable_repo_root(repo_ref)?;
        let canonical = canonical_repo_ref_for_root(repo_ref, &root)?;
        let store_identity = {
            let wire = GitWire::new(self)?;
            let repo = wire.open_repo(canonical, &root)?;
            repo.identity().as_hex()
        };
        let store_id = lfs_repo_id(&store_identity)?;
        let txn = self.store.env.read_txn()?;
        let mut marks = Vec::new();
        for_each_repo_secret_mark_in_txn(
            self,
            &txn,
            RepoSecretMarkLookup::ReadableClaims,
            &mut |mark: RepoSecretMark| {
                if mark.store_identity == store_identity {
                    marks.push(mark_entry(&mark)?);
                }
                Ok(())
            },
        )?;
        marks.sort_by(|a, b| (a.marked_at, a.mark).cmp(&(b.marked_at, b.mark)));
        let mut links = Vec::new();
        crate::store::claim_projection::for_each_claim_id_for_predicate_in_txn(
            &self.store,
            &txn,
            REPO_SECRET_REMEDIATION_PREDICATE,
            |id| {
                if let Some(body) = self.get_claim_in_txn(&txn, &id)?
                    && let Some(link) = link_entry(&body, &store_id)?
                {
                    links.push(link);
                }
                Ok(())
            },
        )?;
        links.sort_by(|a, b| (a.linked_at, a.proposal).cmp(&(b.linked_at, b.proposal)));
        Ok(RepoSecretMarks {
            store_identity,
            marks,
            links,
        })
    }
}

fn mark_entry(mark: &RepoSecretMark) -> Result<RepoSecretMarkEntry> {
    let seen = match &mark.source {
        RepoSecretSource::RefMove { name, new_oid, .. } => RepoSecretMarkSeen::RefMove {
            name: name.clone(),
            new_commit: new_oid.as_str().to_owned(),
        },
        RepoSecretSource::Quarantine => RepoSecretMarkSeen::Quarantine,
        RepoSecretSource::SyncLanding { .. } => RepoSecretMarkSeen::SyncLanding,
    };
    let (custody, handle) = match &mark.placement {
        RepoSecretPlacement::Span {
            custody, handle, ..
        } => (Some(*custody), Some(handle.clone())),
        RepoSecretPlacement::Opaque => (None, None),
    };
    Ok(RepoSecretMarkEntry {
        mark: mark.mark_id()?,
        operation: mark.operation_id,
        blob: mark.blob_oid.as_str().to_owned(),
        path: mark.path.clone(),
        detector_kind: mark.detector_kind.clone(),
        seen,
        custody,
        handle,
        marked_at: mark.marked_at,
    })
}

/// The link `body` holds when it links a proposal to the store `store_id`;
/// `None` for another store's link or one no longer approved.
fn link_entry(
    body: &ClaimBody,
    store_id: &EntityId,
) -> Result<Option<RepoSecretRemediationLinkEntry>> {
    let corrupt = || Error::CorruptedIndex("a repo secret remediation link does not decode");
    if body.predicate != REPO_SECRET_REMEDIATION_PREDICATE {
        return Err(corrupt());
    }
    if body.approval != ClaimApprovalStatus::Approved {
        return Ok(None);
    }
    let ClaimSubject::Edge { target, .. } = &body.subject else {
        return Err(corrupt());
    };
    if target != store_id {
        return Ok(None);
    }
    let map = body.value.as_map().ok_or_else(corrupt)?;
    let text = |value: &Value| value.as_str().map(str::to_owned).ok_or_else(corrupt);
    let state = text(link_field(map, "state")?)?;
    let proposal =
        EntityId::from_hex(&text(link_field(map, "proposal")?)?).map_err(|_| corrupt())?;
    let commit = match link_field(map, "commit")? {
        Value::Nil => None,
        value => Some(text(value)?),
    };
    let paths = link_field(map, "paths")?
        .as_array()
        .ok_or_else(corrupt)?
        .iter()
        .map(text)
        .collect::<Result<Vec<_>>>()?;
    let linked_at = link_field(map, "linked_at")?.as_u64().ok_or_else(corrupt)?;
    Ok(Some(RepoSecretRemediationLinkEntry {
        state,
        proposal,
        commit,
        paths,
        linked_at,
    }))
}

/// The value a link's field `key` holds.
fn link_field<'v>(map: &'v [(Value, Value)], key: &str) -> Result<&'v Value> {
    map.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or(Error::CorruptedIndex(
            "a repo secret remediation link does not decode",
        ))
}
