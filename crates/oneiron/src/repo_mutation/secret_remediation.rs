//! Current-code remediation of marked secrets (FIX 7608 slice 6, owner
//! ruling SECRETS-IN-REPOS = A: "Proposal on current code: key -> vault
//! secret store, reference in place, .env line in .gitignore, add
//! .env.example"; ".env: values -> secret store, names ->
//! .oneiron/secret-manifest.toml"; "committed .env = any key + a proposal
//! to delete it").
//!
//! [`Vault::propose_repo_secret_remediation`] reads the repository's
//! current HEAD from its canonical object store, every file whole, and
//! matches each file's bytes to the marks receive wrote (`repo.secret_mark`,
//! by the BLAKE3 of the whole blob). It never reads the custody-filtered
//! fork, which reads a withheld file as absent. It stages ONE native file
//! bundle (slice 5) pinned at that HEAD:
//! - each marked literal in code becomes a reference to its environment
//!   variable ([`RepoSecretReferenceRenderer`]);
//! - each committed live dotenv file is removed, and its names go, blank,
//!   into the `.env.example` beside it; an example file's marked values are
//!   blanked and its names kept;
//! - `.gitignore` gains `.env` and each removed dotenv file's exact path;
//! - the secret manifest gains one entry per secret, mapping its env name
//!   onto the custody record's name, never a value.
//!
//! The custody record keeps each value. The bundle only proposes: nothing
//! here approves, enqueues or lands it, and it stores no old byte of a file
//! its base withholds. A key only history holds is in no current file: it
//! gets no edit, and its original commit is never rewritten.
//!
//! CALL REMEDIATION-STALE ([`moved_base`]): a base that moves while the
//! bundle is staged leaves nothing written and reports stale; a retry reads
//! the current HEAD again. A staged bundle whose base moved later stays
//! proposed: the queue takes it only at its own commit, and nothing
//! rebases it or overwrites current work.
//!
//! CALL RENDERER-UNRESOLVED ([`RepoSecretReferenceRenderer::reference`]):
//! a key no reference replaces stays an explicit unresolved action naming
//! its path and reason, never a corrupt patch and never a refusal.

mod env;
mod link;
mod plan;
mod render;
mod text;

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use self::env::{
    REPO_ENV_VALUE_REASON, dotenv_value_lifts, is_unindexed_dotenv_name, masked_record_name,
    repo_env_entries, repo_env_file,
};
pub(crate) use self::link::offer_secret_remediation_in_txn;
use self::plan::Plan;
pub use self::render::RepoSecretReferenceRenderer;
use super::git::{canonical_repo_ref_for_root, git_common_dir, resolve_mutable_repo_root};
use super::proposal::{ProposalBase, RepoProposalReview, invalid};
use super::snapshot::SnapshotCustody;
use super::types::{RepoBundleFile, RepoMutationOperation, RepoMutationRequest};
use crate::Vault;
use crate::code_document::CodeOpProvenance;
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo, lock_repository};
use crate::origin::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};

/// The message a remediation bundle lands under.
const REMEDIATION_MESSAGE: &str =
    "Move committed secrets out of the current code into the vault's secret store";

/// A tree entry's mode for a subtree.
const MODE_TREE: u32 = 0o040_000;

/// What a caller asks a remediation of.
#[derive(Debug, Clone)]
pub struct RepoSecretRemediationRequest {
    /// The local repository. Its commit is not taken as the base: the
    /// builder reads the current HEAD.
    pub repo_ref: RepoRef,
    pub actor_id: EntityId,
    pub session_id: EntityId,
    /// The CLAIM the proposal's provenance names.
    pub provenance_claim_id: EntityId,
    pub op_provenance: CodeOpProvenance,
    pub actor_class: Option<EdgeActorClass>,
    /// The review the one proposal is held to.
    pub review: RepoProposalReview,
}

/// Where a remediation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoSecretRemediationStatus {
    /// ONE bundle is staged and waits for its review.
    Proposed,
    /// Nothing could be staged; each marked key is an unresolved action.
    Unresolved,
    /// The base moved while the bundle was staged: nothing was written.
    /// Asking again reads the current HEAD.
    Stale,
    /// No current file holds a marked key or a dotenv value.
    Clean,
}

/// One change the staged bundle makes. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoSecretRemediationAction {
    /// The marked literals of `path` now read these environment variables.
    ReplaceLiterals {
        path: String,
        env_names: Vec<String>,
    },
    /// A committed live dotenv file is removed.
    RemoveDotenv { path: String },
    /// An example file's marked values are blanked and these names added.
    WriteExample { path: String, names: Vec<String> },
    /// The ignore file gains these entries.
    IgnoreDotenv { entries: Vec<String> },
    /// The secret manifest maps these env names onto custody names.
    DeclareEnvNames { env_names: Vec<String> },
}

/// Why a marked key stays where it is (CALL RENDERER-UNRESOLVED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoSecretUnresolvedReason {
    /// The file's form has no reference the renderer writes.
    NoReference,
    /// The key is not exactly one quoted literal.
    NotOneLiteral,
    /// The key sits in a container member.
    ContainerMember,
    /// A mark holds residue no span isolates.
    Opaque,
    /// The edited file would still read as secret.
    StillSecret,
    /// A dotenv value no mark names: no custody record holds it.
    NotInCustody,
    /// A mark's custody record does not read.
    NoCustodyRecord,
    /// The current secret manifest does not parse.
    ManifestUnreadable,
    /// The manifest declares this secret with no env name.
    DeclaredWithoutEnvName,
}

impl RepoSecretUnresolvedReason {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoReference => "no_reference",
            Self::NotOneLiteral => "not_one_literal",
            Self::ContainerMember => "container_member",
            Self::Opaque => "opaque",
            Self::StillSecret => "still_secret",
            Self::NotInCustody => "not_in_custody",
            Self::NoCustodyRecord => "no_custody_record",
            Self::ManifestUnreadable => "manifest_unreadable",
            Self::DeclaredWithoutEnvName => "declared_without_env_name",
        }
    }
}

/// One key, or one file, a remediation leaves as it is, and why. A record
/// id, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecretUnresolved {
    pub path: String,
    pub reason: RepoSecretUnresolvedReason,
    pub custody: Option<EntityId>,
}

/// What one remediation did. No value, span or excerpt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSecretRemediation {
    pub status: RepoSecretRemediationStatus,
    /// The HEAD it read.
    pub base_commit: String,
    /// The staged bundle, when one is.
    pub proposal: Option<EntityId>,
    pub actions: Vec<RepoSecretRemediationAction>,
    pub unresolved: Vec<RepoSecretUnresolved>,
}

/// CALL REMEDIATION-STALE: a base that moved before the bundle was staged
/// leaves nothing written; a retry reads the current HEAD. One hook.
fn moved_base() -> RepoSecretRemediationStatus {
    RepoSecretRemediationStatus::Stale
}

impl Vault {
    /// Stages ONE native bundle moving the marked keys out of the current
    /// code of `request`'s repository (see the module). It only proposes.
    ///
    /// # Errors
    /// A repository, object store or mark walk that cannot be read, or the
    /// bundle proposer's own refusal. A base that moved is no error: it is
    /// [`RepoSecretRemediationStatus::Stale`].
    pub fn propose_repo_secret_remediation(
        &self,
        request: RepoSecretRemediationRequest,
    ) -> Result<RepoSecretRemediation> {
        let root = resolve_mutable_repo_root(&request.repo_ref)?;
        let canonical = canonical_repo_ref_for_root(&request.repo_ref, &root)?;
        let RepoRef::LocalFolder { path: folder, .. } = &canonical else {
            return Err(invalid("a secret remediation names a local repository"));
        };
        let folder = folder.clone();
        let (head, files, base, store) = {
            let _guard = lock_repository(&git_common_dir(&root)?)?;
            let wire = GitWire::new(self)?;
            let repo = wire.open_repo(canonical, &root)?;
            let head = wire.resolve_commit(&repo, "HEAD")?;
            let files = commit_files(&wire, &repo, &head, None)?;
            let base = self.capture_repo_snapshot_at_commit(&repo, &head)?;
            (head, files, base, repo.identity().as_hex())
        };
        let custody = SnapshotCustody::of(self, &root)?;
        let mut plan = Plan::default();
        {
            let txn = self.store.env.read_txn()?;
            let facts =
                RepoMarkFacts::read_in_txn(self, &txn, RepoSecretMarkLookup::ReadableClaims)?;
            plan.build(self, &txn, &facts, &custody, &files)?;
        }
        let base_commit = head.as_str().to_owned();
        let report = |plan: Plan,
                      status: RepoSecretRemediationStatus,
                      proposal: Option<EntityId>| RepoSecretRemediation {
            status,
            base_commit: base_commit.clone(),
            proposal,
            actions: plan
                .files
                .into_values()
                .map(|staged| staged.action)
                .collect(),
            unresolved: plan.unresolved,
        };
        if plan.files.is_empty() {
            let status = if plan.unresolved.is_empty() {
                RepoSecretRemediationStatus::Clean
            } else {
                RepoSecretRemediationStatus::Unresolved
            };
            return Ok(report(plan, status, None));
        }
        // Each staged path with the BLAKE3 of the bytes HEAD holds there:
        // the queue checks a withheld base by it (FIX 10974).
        let proven: super::bundle::ProvenFiles = plan
            .files
            .keys()
            .map(|path| {
                let base = files
                    .get(path)
                    .map(|file| *blake3::hash(&file.content).as_bytes());
                (path.clone(), base)
            })
            .collect();
        let bundle = plan
            .files
            .iter()
            .map(|(path, staged)| RepoBundleFile::new(path.clone(), staged.content.clone(), None))
            .collect();
        let mutation = RepoMutationRequest {
            repo_ref: RepoRef::LocalFolder {
                path: folder,
                commit: base_commit.clone(),
            },
            actor_id: Some(request.actor_id),
            actor_class: request.actor_class,
            session_id: Some(request.session_id),
            provenance_claim_id: Some(request.provenance_claim_id),
            op_provenance: request.op_provenance,
            operation: RepoMutationOperation::CommitFiles {
                files: bundle,
                message: REMEDIATION_MESSAGE.to_owned(),
            },
        };
        let staged = self.propose_repo_bundle_checked::<std::convert::Infallible>(
            mutation,
            request.review,
            ProposalBase::Pinned(base),
            None,
            &proven,
            |_| Ok(Ok(())),
        );
        let row = match staged {
            Ok(Ok(row)) => row,
            Ok(Err(never)) => match never {},
            Err(Error::ConcurrentWrite(_)) => return Ok(report(plan, moved_base(), None)),
            Err(error) => return Err(error),
        };
        link::record_remediation_proposed(self, &store, &row, &plan.marked)?;
        Ok(report(
            plan,
            RepoSecretRemediationStatus::Proposed,
            Some(row.id),
        ))
    }
}

/// One file of a commit, as its tree holds it.
struct CommitFile {
    content: Vec<u8>,
}

/// Every regular file of `commit`'s tree, read whole from the object
/// store, or only those `wanted` names. A symlink or submodule link holds
/// no key a remediation edits, and is passed over. The files' bytes come
/// from batched reads of their distinct blobs (FIX 10976), not two Git
/// calls a file.
fn commit_files(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
    wanted: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, CommitFile>> {
    let mut files: Vec<(String, GitOid)> = Vec::new();
    let mut pending = vec![(String::new(), commit.clone())];
    while let Some((prefix, tree)) = pending.pop() {
        for entry in wire.read_tree(repo, &tree)? {
            let name = String::from_utf8(entry.name)
                .map_err(|_| invalid("a repository path is not UTF-8"))?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match entry.mode {
                MODE_TREE => {
                    let below = format!("{path}/");
                    if wanted
                        .is_none_or(|wanted| wanted.iter().any(|want| want.starts_with(&below)))
                    {
                        pending.push((path, entry.oid));
                    }
                }
                0o100_644 | 0o100_755 => {
                    if wanted.is_none_or(|wanted| wanted.contains(&path)) {
                        files.push((path, entry.oid));
                    }
                }
                _ => {}
            }
        }
    }
    let blobs: Vec<GitOid> = files
        .iter()
        .map(|(_, oid)| oid.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut contents: BTreeMap<GitOid, Vec<u8>> = BTreeMap::new();
    let whole = wire.for_each_blob(repo, &blobs, |oid, bytes| {
        contents.insert(oid.clone(), bytes.to_vec());
    })?;
    if !whole {
        return Err(invalid(
            "a repository file's blob is not in its object store",
        ));
    }
    files
        .into_iter()
        .map(|(path, oid)| {
            let content = contents.get(&oid).cloned().ok_or(invalid(
                "a repository file's blob is not in its object store",
            ))?;
            Ok((path, CommitFile { content }))
        })
        .collect()
}
