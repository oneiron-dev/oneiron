//! Export finalized engine commits through GitWire objects and the origin CAS protocol.
use super::publication::{
    OriginPublicationReceipt, OriginPublicationRequest, origin_publication_intent_claim,
};
use super::residence::OriginAuthorityLease;
use super::tree::OriginTreeFile;
use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitCommitRequest, GitOid, GitRefName, GitTreeEntry, GitWire, GitWirePlan, GitWireRepo,
    lock_repository,
};
use crate::repo_mutation::REPO_PROVENANCE_TRAILER_KEY;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::temporal::TimeRange;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct EngineCommitExport {
    pub revision_id: EntityId,
    pub ref_name: GitRefName,
    pub expected_old_oid: Option<GitOid>,
}

/// Stable Git commit projection (oid hex text) of one finalized engine CodeRevision. Key:
/// string(repo identity hex) ":" id16(revision) — the ':' is a literal byte, not a NUL.
const ENGINE_EXPORTS: SideTable<RepoRevisionKey, String, Raw> =
    SideTable::new(&side_table::ORIGIN_ENGINE_EXPORT);

struct RepoRevisionKey {
    repo_hex: String,
    revision: EntityId,
}

impl SideKey for RepoRevisionKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.repo_hex.as_bytes());
        out.push(b':');
        self.revision.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let id_start = bytes.len().checked_sub(16)?;
        let (rest, id) = bytes.split_at(id_start);
        let (&separator, repo_hex) = rest.split_last()?;
        if separator != b':' {
            return None;
        }
        Some(Self {
            repo_hex: String::from_utf8(repo_hex.to_vec()).ok()?,
            revision: EntityId::from_bytes(id.try_into().ok()?).ok()?,
        })
    }
}

fn export_key(repo: &GitWireRepo, revision: EntityId) -> RepoRevisionKey {
    RepoRevisionKey {
        repo_hex: repo.identity().as_hex(),
        revision,
    }
}

impl Vault {
    /// Reads the stable Git projection of a finalized engine revision.
    pub fn exported_engine_commit(
        &self,
        repo: &GitWireRepo,
        revision: EntityId,
    ) -> Result<Option<GitOid>> {
        let txn = self.store.env.read_txn()?;
        ENGINE_EXPORTS
            .get(&self.store, &txn, &export_key(repo, revision))?
            .map(|oid| GitOid::parse_hex(&oid))
            .transpose()
    }
    /// No caller-supplied tree is accepted: bytes regenerate from authenticated
    /// file frontiers on the persisted CodeRevision. Git remains a projection.
    pub fn export_engine_commit(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        request: &EngineCommitExport,
        authority: Option<&OriginAuthorityLease>,
    ) -> Result<OriginPublicationReceipt> {
        let _guard = lock_repository(repo.common_dir())?;
        let revision = self
            .get_code_revision(&request.revision_id)?
            .ok_or(Error::EntityNotFound)?;
        // Recheck the complete fold trace, including the stored session frontier.
        if !self
            .code_revisions_for_session(&revision.session_id)?
            .contains(&revision)
        {
            return Err(Error::InvariantViolation(
                "engine export revision is not finalized",
            ));
        }
        // Session membership authenticates history, not independent approval.
        // Recheck the immutable promotion receipt before creating any Git object.
        self.require_code_revision_promotion(request.revision_id)?;
        let metadata = revision
            .commit_metadata
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "engine commit has no canonical authorship/message",
            ))?;
        let provenance = revision
            .provenance_claim_id
            .ok_or(Error::InvariantViolation(
                "engine commit export requires provenance",
            ))?;
        if self
            .get_claim(&provenance)?
            .is_none_or(|body| body.lifecycle != ClaimLifecycleStatus::Active)
        {
            return Err(Error::InvariantViolation(
                "engine commit export provenance is not active",
            ));
        }
        if self.get_entity_type(&metadata.author)?.is_none() {
            return Err(Error::EntityNotFound);
        }
        if revision.file_frontiers.is_empty() {
            return Err(Error::InvariantViolation(
                "engine commit has no tested file frontier map",
            ));
        }
        let mut files = BTreeMap::new();
        let target_scope = crate::repo_mutation::canonical_mutation_scope(repo.repo_root())?;
        for frontier in revision.file_frontiers.values() {
            if frontier.repo != target_scope {
                return Err(Error::InvariantViolation(
                    "engine commit belongs to another repository",
                ));
            }
            let content = self.code_document_at(frontier)?.into_bytes();
            if files
                .insert(
                    frontier.path.clone(),
                    OriginTreeFile {
                        mode: metadata
                            .file_modes
                            .get(&frontier.document_id)
                            .copied()
                            .unwrap_or(0o100644),
                        content,
                    },
                )
                .is_some()
            {
                return Err(Error::InvariantViolation(
                    "engine commit duplicates a file path",
                ));
            }
        }
        let parents = revision
            .parent_revision_id
            .map(|id| {
                self.exported_engine_commit(repo, id)?
                    .ok_or(Error::InvariantViolation(
                        "export the engine parent before its child",
                    ))
            })
            .transpose()?
            .into_iter()
            .collect();
        let tree = write_tree_files(git, repo, &files, revision.finalized_at)?;
        if crate::repo_mutation::parse_repo_provenance_trailer(&metadata.message)?.is_some() {
            return Err(Error::InvariantViolation(
                "export message must not supply its own provenance trailer",
            ));
        }
        let message = format!(
            "{}\n\n{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
            metadata.message.trim_end(),
            provenance.to_hex()
        );
        let oid = write_commit(
            git,
            repo,
            GitCommitRequest {
                tree,
                parents,
                author_name: metadata.author.to_hex(),
                author_email: format!("{}@actor.invalid", metadata.author.to_hex()),
                authored_at: i64::try_from(revision.finalized_at)
                    .map_err(|_| Error::ArithmeticOverflow("export timestamp"))?,
                message: message.into_bytes(),
                extra_headers: Vec::new(),
            },
            revision.finalized_at,
        )?;
        self.with_write_txn(|txn| {
            let key = export_key(repo, revision.revision_id);
            if let Some(old) = ENGINE_EXPORTS.get(&self.store, txn, &key)? {
                if old != oid.as_str() {
                    return Err(Error::InvariantViolation(
                        "finalized revision already has another Git projection",
                    ));
                }
            } else {
                ENGINE_EXPORTS.put(&self.store, txn, &key, &oid.as_str().to_owned())?;
            }
            Ok(())
        })?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        let intent = entity_id_from_hash_material(
            b"oneiron:engine-export-intent:v1",
            &[
                repo_id.as_bytes(),
                request.revision_id.as_bytes(),
                request.ref_name.as_str().as_bytes(),
                request
                    .expected_old_oid
                    .as_ref()
                    .map_or("", GitOid::as_str)
                    .as_bytes(),
                oid.as_str().as_bytes(),
            ],
        )?;
        let publication = OriginPublicationRequest {
            repo_id,
            repo: repo.clone(),
            ref_name: request.ref_name.clone(),
            expected_old_oid: request.expected_old_oid.clone(),
            new_oid: oid.clone(),
            required_objects: vec![oid],
            required_lfs_oids: Vec::new(),
            provenance_claim_id: intent,
            actor_id: metadata.author,
            occurred: TimeRange {
                start: revision.finalized_at,
                end: revision.finalized_at,
            },
            learned_at: revision.finalized_at,
        };
        self.put_claim(
            &intent,
            &origin_publication_intent_claim(&publication)?,
            publication.occurred,
            publication.learned_at,
        )?;
        match authority {
            Some(lease) => self.publish_origin_ref_authorized(git, publication, lease),
            None => self.publish_origin_ref(git, publication),
        }
    }
}

/// Writes a complete byte-preserving tree without moving a public ref.
pub(in crate::origin) fn write_tree_files(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    files: &BTreeMap<String, OriginTreeFile>,
    now: u64,
) -> Result<GitOid> {
    let mut directories: BTreeMap<String, Vec<GitTreeEntry>> = BTreeMap::new();
    directories.insert(String::new(), Vec::new());
    let mut total = 0_usize;
    for (path, file) in files {
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() > 128
            || parts.iter().any(|p| {
                p.is_empty() || matches!(*p, "." | ".." | ".git") || p.as_bytes().contains(&0)
            })
        {
            return Err(Error::InvariantViolation("unsafe exported file path"));
        }
        total = total
            .checked_add(file.content.len())
            .ok_or(Error::ArithmeticOverflow("export bytes"))?;
        if files.len() > 100_000
            || total > 128 * 1024 * 1024
            || !matches!(file.mode, 0o100644 | 0o100755 | 0o120000)
        {
            return Err(Error::IndexOverflow("export file bounds or mode"));
        }
        let mut plan = GitWirePlan::new();
        plan.write_blob(file.content.clone())?;
        let oid = write_one(git, repo, &plan, now)?;
        for end in 1..parts.len() {
            directories.entry(parts[..end].join("/")).or_default();
        }
        let parent = parts[..parts.len() - 1].join("/");
        directories
            .get_mut(&parent)
            .ok_or(Error::InvariantViolation("export parent missing"))?
            .push(GitTreeEntry {
                mode: file.mode,
                name: parts[parts.len() - 1].as_bytes().to_vec(),
                oid,
            });
    }
    let mut paths: Vec<_> = directories.keys().cloned().collect();
    paths.sort_by_key(|p| std::cmp::Reverse(p.split('/').count()));
    // The root and a one-segment directory share split count. Root must be last.
    paths.retain(|p| !p.is_empty());
    paths.push(String::new());
    for path in paths {
        let mut entries = directories
            .remove(&path)
            .ok_or(Error::InvariantViolation("export directory missing"))?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        if entries.windows(2).any(|w| w[0].name == w[1].name) {
            return Err(Error::InvariantViolation(
                "export path is both file and directory",
            ));
        }
        let mut plan = GitWirePlan::new();
        plan.write_tree(entries)?;
        let oid = write_one(git, repo, &plan, now)?;
        if path.is_empty() {
            return Ok(oid);
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", &path));
        directories
            .get_mut(parent)
            .ok_or(Error::InvariantViolation("export tree parent missing"))?
            .push(GitTreeEntry {
                mode: 0o040000,
                name: name.as_bytes().to_vec(),
                oid,
            });
    }
    Err(Error::InvariantViolation("export root missing"))
}
pub(in crate::origin) fn write_commit(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: GitCommitRequest,
    now: u64,
) -> Result<GitOid> {
    let mut plan = GitWirePlan::new();
    plan.write_commit(commit)?;
    write_one(git, repo, &plan, now)
}
fn write_one(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    plan: &GitWirePlan,
    now: u64,
) -> Result<GitOid> {
    let objects = git.write_objects(repo, plan, now)?;
    if objects.len() != 1 {
        return Err(Error::InvariantViolation(
            "GitWire object-only plan returned wrong count",
        ));
    }
    objects
        .into_iter()
        .next()
        .ok_or(Error::InvariantViolation("GitWire object missing"))
}
