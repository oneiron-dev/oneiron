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
mod render;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use heed::RoTxn;

pub(crate) use self::env::{
    REPO_ENV_VALUE_REASON, dotenv_value_lifts, repo_env_entries, repo_env_file,
};
use self::env::{RepoEnvEntry, RepoEnvFileKind};
pub(crate) use self::link::offer_secret_remediation_in_txn;
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
use crate::origin::secret_manifest::SECRET_MANIFEST_PATH;
use crate::origin::secret_marks::{
    RepoBlobMarks, RepoMarkFacts, RepoSecretMarkLookup, RepoSecretPlacement,
};
use crate::secret_manifest::{
    SECRET_MANIFEST_SCHEMA_VERSION, is_secret_env_name, parse_secret_manifest,
};

/// The message a remediation bundle lands under.
const REMEDIATION_MESSAGE: &str =
    "Move committed secrets out of the current code into the vault's secret store";

/// The example file the names of moved literals go into.
const ROOT_EXAMPLE_PATH: &str = ".env.example";

/// The ignore file a remediation extends.
const IGNORE_PATH: &str = ".gitignore";

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
        let proven: BTreeSet<String> = plan.files.keys().cloned().collect();
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
/// no key a remediation edits, and is passed over.
fn commit_files(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
    wanted: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, CommitFile>> {
    let mut files = BTreeMap::new();
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
                        let content = wire.read_object(repo, &entry.oid)?;
                        files.insert(path, CommitFile { content });
                    }
                }
                _ => {}
            }
        }
    }
    Ok(files)
}

/// The exact bytes of each of `paths` in the commit `repo` is pinned at,
/// read from its canonical object store: a remediated file its bundle's
/// base withholds, which the queue checks against the tested tree by these
/// bytes (FIX 7608 slice 6).
///
/// # Errors
/// A repository or commit that cannot be read, or a path the commit does
/// not hold as a regular file.
pub(in crate::repo_mutation) fn pinned_commit_files(
    vault: &Vault,
    repo: &RepoRef,
    paths: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let commit = GitOid::parse_hex(
        repo.commit_hash()
            .ok_or(invalid("a pinned repository names its commit"))?,
    )?;
    let root = resolve_mutable_repo_root(repo)?;
    let canonical = canonical_repo_ref_for_root(repo, &root)?;
    let _guard = lock_repository(&git_common_dir(&root)?)?;
    let wire = GitWire::new(vault)?;
    let git = wire.open_repo(canonical, &root)?;
    let files = commit_files(&wire, &git, &commit, Some(paths))?;
    if paths.iter().any(|path| !files.contains_key(path)) {
        return Err(invalid("a remediated file is not in its pinned commit"));
    }
    Ok(files
        .into_iter()
        .map(|(path, file)| (path, file.content))
        .collect())
}

/// One file the bundle writes (`Some`) or removes (`None`), the action it
/// is, and the custody records whose keys it moves.
struct Staged {
    content: Option<Vec<u8>>,
    action: RepoSecretRemediationAction,
    custody: Vec<EntityId>,
}

/// One secret's manifest entry: its custody record's name and class, and
/// its env name.
struct Declaration {
    record: String,
    class: &'static str,
    env_name: String,
}

/// The current secret manifest, as the remediation found it.
enum Manifest {
    Absent,
    Text(String),
    Unreadable,
}

/// The env names a remediation gives: one per custody record, each taken
/// once in the manifest.
#[derive(Default)]
struct Names {
    by_custody: BTreeMap<EntityId, String>,
    taken: BTreeSet<String>,
    /// Each manifest entry's custody name and env name, as declared.
    declared: BTreeMap<String, Option<String>>,
}

impl Names {
    /// The env name of `custody`, whose record is named `record`: the one it
    /// already has, the manifest's, or `wanted` with the first free suffix.
    fn name(&mut self, custody: EntityId, record: &str, wanted: &str) -> String {
        if let Some(name) = self.by_custody.get(&custody) {
            return name.clone();
        }
        let name = match self.declared.get(record) {
            Some(Some(declared)) => declared.clone(),
            _ => {
                let mut name = wanted.to_owned();
                let mut suffix = 2_u32;
                while self.taken.contains(&name) {
                    name = format!("{wanted}_{suffix}");
                    suffix += 1;
                }
                name
            }
        };
        self.taken.insert(name.clone());
        self.by_custody.insert(custody, name.clone());
        name
    }
}

/// One remediation's plan, built in one read of the marks.
#[derive(Default)]
struct Plan {
    files: BTreeMap<String, Staged>,
    unresolved: Vec<RepoSecretUnresolved>,
    /// The current files holding marked keys, which the link names.
    marked: Vec<String>,
    names: Names,
    declared: BTreeMap<EntityId, Declaration>,
    /// The names each example file gains, by its path.
    examples: BTreeMap<String, BTreeSet<String>>,
    /// The removed dotenv files' paths, which the ignore file gains.
    ignored: BTreeSet<String>,
}

impl Plan {
    fn build(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        facts: &RepoMarkFacts,
        custody: &SnapshotCustody,
        files: &BTreeMap<String, CommitFile>,
    ) -> Result<()> {
        let manifest = self.read_manifest(files);
        // Dotenv files first: their names are the ones programs read.
        for (path, file) in files {
            if let Some(kind) = repo_env_file(path) {
                let marks = facts.for_hash(blake3::hash(&file.content).as_bytes());
                self.dotenv(vault, txn, custody, path, &file.content, kind, &marks)?;
            }
        }
        for (path, file) in files {
            if repo_env_file(path).is_none() {
                let marks = facts.for_hash(blake3::hash(&file.content).as_bytes());
                if !marks.is_empty() {
                    self.code(vault, txn, custody, path, &file.content, &marks)?;
                }
            }
        }
        if self.files.is_empty() {
            return Ok(());
        }
        self.write_examples(files);
        self.write_ignore(files);
        self.write_manifest(manifest);
        Ok(())
    }

    fn unresolved(
        &mut self,
        path: &str,
        reason: RepoSecretUnresolvedReason,
        custody: Option<EntityId>,
    ) {
        self.unresolved.push(RepoSecretUnresolved {
            path: path.to_owned(),
            reason,
            custody,
        });
    }

    fn read_manifest(&mut self, files: &BTreeMap<String, CommitFile>) -> Manifest {
        let Some(file) = files.get(SECRET_MANIFEST_PATH) else {
            return Manifest::Absent;
        };
        let parsed = std::str::from_utf8(&file.content)
            .ok()
            .and_then(|text| Some((text, parse_secret_manifest(text).ok()?)));
        let Some((text, manifest)) = parsed else {
            self.unresolved(
                SECRET_MANIFEST_PATH,
                RepoSecretUnresolvedReason::ManifestUnreadable,
                None,
            );
            return Manifest::Unreadable;
        };
        for entry in manifest.secrets {
            if let Some(env_name) = &entry.env_name {
                self.names.taken.insert(env_name.clone());
            }
            self.names.declared.insert(entry.name, entry.env_name);
        }
        Manifest::Text(text.to_owned())
    }

    /// The custody record `custody` names and its class, or an unresolved
    /// action at `path` when it does not read.
    fn record(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        path: &str,
        custody: EntityId,
    ) -> Result<Option<(String, &'static str)>> {
        let record =
            crate::secret_custody::read_secret_custody_meta_in_txn(&vault.store, txn, &custody)?
                .map(|record| (record.name.clone(), record.class.as_str()));
        if record.is_none() {
            self.unresolved(
                path,
                RepoSecretUnresolvedReason::NoCustodyRecord,
                Some(custody),
            );
        }
        Ok(record)
    }

    fn declare(&mut self, custody: EntityId, record: String, class: &'static str, env_name: &str) {
        self.declared.entry(custody).or_insert(Declaration {
            record,
            class,
            env_name: env_name.to_owned(),
        });
    }

    /// A dotenv file: a live one is removed and each value it lifts is
    /// declared; an example's marked values are blanked.
    #[allow(clippy::too_many_arguments)]
    fn dotenv(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        custody: &SnapshotCustody,
        path: &str,
        content: &[u8],
        kind: RepoEnvFileKind,
        marks: &RepoBlobMarks,
    ) -> Result<()> {
        let entries = repo_env_entries(content);
        let spans = top_level_spans(marks)?;
        let held = |entry: &RepoEnvEntry| {
            spans
                .iter()
                .find(|(span, _)| span.start < entry.value.end && entry.value.start < span.end)
                .map(|(_, id)| *id)
        };
        if !marks.is_empty() {
            self.marked.push(path.to_owned());
        }
        match kind {
            RepoEnvFileKind::Live => {
                let lifted: Vec<&RepoEnvEntry> = entries
                    .iter()
                    .filter(|entry| {
                        content
                            .get(entry.value.clone())
                            .is_some_and(dotenv_value_lifts)
                    })
                    .collect();
                if lifted.is_empty() && marks.is_empty() {
                    return Ok(());
                }
                let mut moved = Vec::new();
                for entry in lifted {
                    let Some(id) = held(entry) else {
                        self.unresolved(path, RepoSecretUnresolvedReason::NotInCustody, None);
                        continue;
                    };
                    if let Some((record, class)) = self.record(vault, txn, path, id)? {
                        let env_name = self.names.name(id, &record, &entry.name);
                        self.declare(id, record, class, &env_name);
                        moved.push(id);
                    }
                }
                let example = example_beside(path);
                let names = self.examples.entry(example).or_default();
                names.extend(entries.iter().map(|entry| entry.name.clone()));
                self.ignored.insert(path.to_owned());
                self.files.insert(
                    path.to_owned(),
                    Staged {
                        content: None,
                        action: RepoSecretRemediationAction::RemoveDotenv {
                            path: path.to_owned(),
                        },
                        custody: moved,
                    },
                );
            }
            RepoEnvFileKind::Example => {
                if marks.is_empty() {
                    return Ok(());
                }
                if marks.opaque() {
                    self.unresolved(path, RepoSecretUnresolvedReason::Opaque, None);
                    return Ok(());
                }
                let mut blanked = content.to_vec();
                let mut moved = Vec::new();
                for entry in entries.iter().rev() {
                    if let Some(id) = held(entry) {
                        blanked.drain(entry.value.clone());
                        moved.push(id);
                    }
                }
                if moved.is_empty() {
                    return Ok(());
                }
                if custody.withholds(path, &blanked).is_some() {
                    for id in moved {
                        self.unresolved(path, RepoSecretUnresolvedReason::StillSecret, Some(id));
                    }
                    return Ok(());
                }
                self.files.insert(
                    path.to_owned(),
                    Staged {
                        content: Some(blanked),
                        action: RepoSecretRemediationAction::WriteExample {
                            path: path.to_owned(),
                            names: Vec::new(),
                        },
                        custody: moved,
                    },
                );
            }
        }
        Ok(())
    }

    /// A code file whose bytes a mark names: each marked literal becomes a
    /// reference, from the end so earlier offsets hold.
    fn code(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        custody: &SnapshotCustody,
        path: &str,
        content: &[u8],
        marks: &RepoBlobMarks,
    ) -> Result<()> {
        self.marked.push(path.to_owned());
        if marks.opaque() {
            self.unresolved(path, RepoSecretUnresolvedReason::Opaque, None);
            return Ok(());
        }
        for mark in marks.marks() {
            if let RepoSecretPlacement::Span {
                member,
                custody: id,
                ..
            } = &mark.placement
                && !member.is_empty()
            {
                self.unresolved(path, RepoSecretUnresolvedReason::ContainerMember, Some(*id));
            }
        }
        let handles = handles_of(marks);
        let mut edited = content.to_vec();
        let mut env_names = BTreeSet::new();
        let mut moved = Vec::new();
        let mut floor = content.len();
        for (span, id) in top_level_spans(marks)?.into_iter().rev() {
            let Some(literal) = literal_bounds(content, &span).filter(|lit| lit.end <= floor)
            else {
                self.unresolved(path, RepoSecretUnresolvedReason::NotOneLiteral, Some(id));
                continue;
            };
            let Some((record, class)) = self.record(vault, txn, path, id)? else {
                continue;
            };
            let before = line_before(content, literal.start);
            let wanted = assigned_name(before)
                .unwrap_or_else(|| fallback_name(handles.get(&id).map(String::as_str)));
            let env_name = self.names.name(id, &record, &wanted);
            let Some(reference) =
                RepoSecretReferenceRenderer::reference(path, content, before, &env_name)
            else {
                self.unresolved(path, RepoSecretUnresolvedReason::NoReference, Some(id));
                continue;
            };
            self.declare(id, record, class, &env_name);
            edited.splice(literal.clone(), reference.into_bytes());
            floor = literal.start;
            env_names.insert(env_name);
            moved.push(id);
        }
        if moved.is_empty() {
            return Ok(());
        }
        if custody.withholds(path, &edited).is_some() {
            for id in moved {
                self.unresolved(path, RepoSecretUnresolvedReason::StillSecret, Some(id));
            }
            return Ok(());
        }
        self.examples
            .entry(ROOT_EXAMPLE_PATH.to_owned())
            .or_default()
            .extend(env_names.iter().cloned());
        self.files.insert(
            path.to_owned(),
            Staged {
                content: Some(edited),
                action: RepoSecretRemediationAction::ReplaceLiterals {
                    path: path.to_owned(),
                    env_names: env_names.into_iter().collect(),
                },
                custody: moved,
            },
        );
        Ok(())
    }

    /// Each example file gains the names it lacks, blank.
    fn write_examples(&mut self, files: &BTreeMap<String, CommitFile>) {
        let examples = std::mem::take(&mut self.examples);
        for (path, names) in examples {
            let staged = self.files.remove(&path);
            let mut text = match &staged {
                Some(staged) => staged.content.clone().unwrap_or_default(),
                None => files
                    .get(&path)
                    .map(|file| file.content.clone())
                    .unwrap_or_default(),
            };
            let present: BTreeSet<String> = repo_env_entries(&text)
                .into_iter()
                .map(|entry| entry.name)
                .collect();
            let missing: Vec<String> = names
                .into_iter()
                .filter(|name| !present.contains(name))
                .collect();
            if !text.is_empty() && !text.ends_with(b"\n") && !missing.is_empty() {
                text.push(b'\n');
            }
            for name in &missing {
                text.extend_from_slice(name.as_bytes());
                text.extend_from_slice(b"=\n");
            }
            let custody = staged.map(|staged| staged.custody).unwrap_or_default();
            if missing.is_empty() && custody.is_empty() {
                continue;
            }
            self.files.insert(
                path.clone(),
                Staged {
                    content: Some(text),
                    action: RepoSecretRemediationAction::WriteExample {
                        path,
                        names: missing,
                    },
                    custody,
                },
            );
        }
    }

    /// The ignore file gains `.env` and each removed dotenv file's exact
    /// path, unless a line already names it.
    fn write_ignore(&mut self, files: &BTreeMap<String, CommitFile>) {
        let mut text = files
            .get(IGNORE_PATH)
            .map(|file| file.content.clone())
            .unwrap_or_default();
        let present: BTreeSet<String> = text
            .split(|byte| *byte == b'\n')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .map(|line| line.trim().trim_start_matches('/').to_owned())
            .collect();
        let mut wanted = std::mem::take(&mut self.ignored);
        wanted.insert(".env".to_owned());
        let missing: Vec<String> = wanted
            .into_iter()
            .filter(|entry| !present.contains(entry))
            .collect();
        if missing.is_empty() {
            return;
        }
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.push(b'\n');
        }
        for entry in &missing {
            text.extend_from_slice(entry.as_bytes());
            text.push(b'\n');
        }
        self.files.insert(
            IGNORE_PATH.to_owned(),
            Staged {
                content: Some(text),
                action: RepoSecretRemediationAction::IgnoreDotenv { entries: missing },
                custody: Vec::new(),
            },
        );
    }

    /// The manifest gains one entry per secret it does not declare yet,
    /// mapping its env name onto its custody record's name.
    fn write_manifest(&mut self, manifest: Manifest) {
        let mut text = match manifest {
            Manifest::Unreadable => return,
            Manifest::Absent => format!("schema_version = {SECRET_MANIFEST_SCHEMA_VERSION}\n"),
            Manifest::Text(text) => text,
        };
        let mut added = Vec::new();
        let mut kept = Vec::new();
        for (custody, declaration) in &self.declared {
            match self.names.declared.get(&declaration.record) {
                Some(Some(_)) => continue,
                Some(None) => {
                    kept.push(*custody);
                    continue;
                }
                None => {}
            }
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "\n[[secrets]]\nname = {}\nclass = {}\nenv_name = {}\ndeclared_paths = []\n",
                toml_string(&declaration.record),
                toml_string(declaration.class),
                toml_string(&declaration.env_name),
            ));
            added.push(declaration.env_name.clone());
        }
        for custody in kept {
            self.unresolved(
                SECRET_MANIFEST_PATH,
                RepoSecretUnresolvedReason::DeclaredWithoutEnvName,
                Some(custody),
            );
        }
        if added.is_empty() {
            return;
        }
        self.files.insert(
            SECRET_MANIFEST_PATH.to_owned(),
            Staged {
                content: Some(text.into_bytes()),
                action: RepoSecretRemediationAction::DeclareEnvNames { env_names: added },
                custody: Vec::new(),
            },
        );
    }
}

/// Each span mark in a blob's own bytes, by its byte span, once each, in
/// byte order, with its custody record.
fn top_level_spans(marks: &RepoBlobMarks) -> Result<Vec<(Range<usize>, EntityId)>> {
    let mut spans = BTreeMap::new();
    for mark in marks.marks() {
        if let RepoSecretPlacement::Span {
            member,
            start,
            end,
            custody,
            ..
        } = &mark.placement
            && member.is_empty()
        {
            let at = |offset: u64| {
                usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow("a mark span"))
            };
            spans.entry((at(*start)?, at(*end)?)).or_insert(*custody);
        }
    }
    Ok(spans
        .into_iter()
        .map(|((start, end), custody)| (start..end, custody))
        .collect())
}

/// Each custody record's handle, as its marks name it.
fn handles_of(marks: &RepoBlobMarks) -> BTreeMap<EntityId, String> {
    marks
        .marks()
        .iter()
        .filter_map(|mark| match &mark.placement {
            RepoSecretPlacement::Span {
                custody, handle, ..
            } => Some((*custody, handle.clone())),
            RepoSecretPlacement::Opaque => None,
        })
        .collect()
}

/// The example file beside the dotenv file at `path`.
fn example_beside(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{ROOT_EXAMPLE_PATH}"),
        None => ROOT_EXAMPLE_PATH.to_owned(),
    }
}

/// The quoted literal that is exactly the key at `span`, quotes included:
/// one quote byte closes it on both sides, and no prefix, escape, doubled
/// quote or line break changes how a language reads it.
fn literal_bounds(content: &[u8], span: &Range<usize>) -> Option<Range<usize>> {
    let open = span.start.checked_sub(1)?;
    let quote = *content.get(open)?;
    if !matches!(quote, b'"' | b'\'' | b'`') || content.get(span.end) != Some(&quote) {
        return None;
    }
    if content
        .get(span.clone())?
        .iter()
        .any(|byte| *byte == quote || *byte == b'\\' || *byte == b'\n')
    {
        return None;
    }
    let before = open.checked_sub(1).and_then(|at| content.get(at)).copied();
    if before.is_some_and(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'\\' | b'#' | b'@' | b'$')
            || byte == quote
    }) {
        return None;
    }
    let after = content.get(span.end + 1).copied();
    if after.is_some_and(|byte| byte == quote || byte == b'#') {
        return None;
    }
    Some(open..span.end + 1)
}

/// The line `content` holds before offset `at`.
fn line_before(content: &[u8], at: usize) -> &[u8] {
    let head = content.get(..at).unwrap_or_default();
    let start = head
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    head.get(start..).unwrap_or_default()
}

/// The env name of the name a literal is assigned to on its line
/// (`API_KEY = `, `apiKey: `, `"api-key": `, `key := `), if one is.
fn assigned_name(before: &[u8]) -> Option<String> {
    let text = before.trim_ascii_end();
    let operators: [&[u8]; 4] = [b"=>", b":=", b"=", b":"];
    let text = operators
        .iter()
        .find_map(|operator| text.strip_suffix(*operator))?
        .trim_ascii_end();
    let identifier = match text.split_last()? {
        (&quote @ (b'"' | b'\''), inner) => {
            let start = inner.iter().rposition(|byte| *byte == quote)? + 1;
            inner.get(start..)?
        }
        _ => {
            let start = text
                .iter()
                .rposition(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
                .map_or(0, |at| at + 1);
            text.get(start..)?
        }
    };
    env_name_from(std::str::from_utf8(identifier).ok()?)
}

/// `identifier` as an upper snake env name (`apiKey`, `api-key` ->
/// `API_KEY`), when it makes one.
fn env_name_from(identifier: &str) -> Option<String> {
    let mut name = String::new();
    let mut lower_before = false;
    for c in identifier.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && lower_before {
                name.push('_');
            }
            lower_before = c.is_ascii_lowercase() || c.is_ascii_digit();
            name.push(c.to_ascii_uppercase());
        } else if !name.is_empty() && !name.ends_with('_') {
            name.push('_');
            lower_before = false;
        }
    }
    let name = name.trim_end_matches('_');
    is_secret_env_name(name).then(|| name.to_owned())
}

/// The env name of a key no assignment names: its custody handle's.
fn fallback_name(handle: Option<&str>) -> String {
    handle
        .and_then(env_name_from)
        .map_or_else(|| "SECRET".to_owned(), |handle| format!("SECRET_{handle}"))
}

/// `text` as a TOML basic string.
fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
