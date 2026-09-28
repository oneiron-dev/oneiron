//! Draft-v1 `.jjconflict`-shape export. Typed open claims remain authoritative.
use super::export::{write_commit, write_tree_files};
use super::publication::{
    OriginKeepRefKind, OriginPublicationReceipt, OriginPublicationRequest,
    origin_publication_intent_claim,
};
use super::residence::OriginAuthorityLease;
use super::tree::{OriginTreeFile, read_tree_files};
use crate::Vault;
use crate::claim::ClaimSubject;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitCommitRequest, GitOid, GitRefName, GitWire, GitWireRepo, lock_repository,
};
use crate::repo_mutation::RepoConflictClaim;
use crate::temporal::TimeRange;
use std::collections::BTreeMap;

pub const CONFLICT_TREE_ENCODING: &str = "oneiron.conflict-tree.v1";
#[derive(Debug, Clone)]
pub struct ConflictTreeExport {
    pub open_claim_id: EntityId,
    pub ref_name: GitRefName,
    pub expected_old_oid: Option<GitOid>,
    pub actor_id: EntityId,
    pub now: u64,
}
impl Vault {
    /// Materializes and publishes one still-open conflict without requiring jj.
    pub fn export_repo_conflict(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        request: &ConflictTreeExport,
        authority: Option<&OriginAuthorityLease>,
    ) -> Result<OriginPublicationReceipt> {
        let _guard = lock_repository(repo.common_dir())?;
        let body = self
            .get_claim(&request.open_claim_id)?
            .ok_or(Error::EntityNotFound)?;
        let ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvariantViolation(
                "conflict requires a branch subject",
            ));
        };
        let conflict = self
            .repo_conflict_claims(&subject)?
            .into_iter()
            .find(|c| c.claim_id == request.open_claim_id)
            .ok_or(Error::InvariantViolation("conflict is not open"))?;
        // A tree from another repository is never a source for this projection.
        let source = git.open_repo(conflict.repo_ref.clone(), repo.repo_root())?;
        if source.identity() != repo.identity() {
            return Err(Error::InvariantViolation(
                "conflict belongs to another repository",
            ));
        }
        let files = conflict_files(git, repo, &conflict)?;
        let tree = write_tree_files(git, repo, &files, request.now)?;
        let commit = write_commit(
            git,
            repo,
            GitCommitRequest {
                tree,
                parents: request.expected_old_oid.clone().into_iter().collect(),
                author_name: request.actor_id.to_hex(),
                author_email: format!("{}@actor.invalid", request.actor_id.to_hex()),
                // Claim creation time, not wall time, keeps a repeated projection deterministic.
                authored_at: 0,
                message: format!(
                    "Conflict {}\n\nOneiron-Claim: {}\n",
                    conflict.claim_id.to_hex(),
                    conflict.claim_id.to_hex()
                )
                .into_bytes(),
                extra_headers: Vec::new(),
            },
            request.now,
        )?;
        for oid in [
            &conflict.base_tree,
            &conflict.ours_tree,
            &conflict.theirs_tree,
        ] {
            self.pin_origin_object(
                git,
                repo,
                OriginKeepRefKind::Conflict,
                &conflict.claim_id.to_hex(),
                &GitOid::parse_hex(oid)?,
                request.now,
            )?;
        }
        self.pin_origin_object(
            git,
            repo,
            OriginKeepRefKind::Conflict,
            &conflict.claim_id.to_hex(),
            &commit,
            request.now,
        )?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        let intent = entity_id_from_hash_material(
            b"oneiron:conflict-export-intent:v1",
            &[
                repo_id.as_bytes(),
                conflict.claim_id.as_bytes(),
                request.ref_name.as_str().as_bytes(),
                request
                    .expected_old_oid
                    .as_ref()
                    .map_or("", GitOid::as_str)
                    .as_bytes(),
                commit.as_str().as_bytes(),
            ],
        )?;
        let publication = OriginPublicationRequest {
            repo_id,
            repo: repo.clone(),
            ref_name: request.ref_name.clone(),
            expected_old_oid: request.expected_old_oid.clone(),
            new_oid: commit.clone(),
            required_objects: vec![commit],
            required_lfs_oids: Vec::new(),
            provenance_claim_id: intent,
            actor_id: request.actor_id,
            occurred: TimeRange {
                start: request.now,
                end: request.now,
            },
            learned_at: request.now,
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
fn conflict_files(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    conflict: &RepoConflictClaim,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    let base = read_tree_files(git, repo, &GitOid::parse_hex(&conflict.base_tree)?)?;
    let ours = read_tree_files(git, repo, &GitOid::parse_hex(&conflict.ours_tree)?)?;
    let theirs = read_tree_files(git, repo, &GitOid::parse_hex(&conflict.theirs_tree)?)?;
    if [&base, &ours, &theirs].iter().any(|files| {
        files
            .keys()
            .any(|path| path == ".jjconflict" || path.starts_with(".jjconflict/"))
    }) {
        return Err(Error::InvariantViolation(
            "conflict encoding namespace is already occupied",
        ));
    }
    let mut out = ours.clone();
    let mut descriptors = Vec::new();
    for path in &conflict.conflicted_paths {
        let encoded = path
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let prefix = format!(".jjconflict/{encoded}");
        let mut sides = serde_json::Map::new();
        for (name, files) in [("base", &base), ("ours", &ours), ("theirs", &theirs)] {
            let mut entries = Vec::new();
            for (source, file) in files
                .iter()
                .filter(|(p, _)| *p == path || p.starts_with(&format!("{path}/")))
            {
                let suffix = if source == path {
                    "file".to_owned()
                } else {
                    format!("tree/{}", &source[path.len() + 1..])
                };
                // Keep symlink targets as ordinary side blobs, never live links
                // into the checkout. Original mode stays in the manifest.
                out.insert(
                    format!("{prefix}/{name}/{suffix}"),
                    OriginTreeFile {
                        mode: 0o100644,
                        content: file.content.clone(),
                    },
                );
                entries.push(
                    serde_json::json!({"path": source, "mode": file.mode, "storage": suffix}),
                );
            }
            sides.insert(name.to_owned(), serde_json::Value::Array(entries));
        }
        out.retain(|p, _| {
            !(p == path || p.starts_with(&format!("{path}/")) || path.starts_with(&format!("{p}/")))
        });
        out.insert(path.clone(), OriginTreeFile { mode: 0o100644, content: format!("<<<<<<< UNRESOLVED {CONFLICT_TREE_ENCODING}\nclaim={}\nsides={prefix}\n>>>>>>>\n", conflict.claim_id.to_hex()).into_bytes() });
        descriptors.push(serde_json::json!({"path": path, "sides": sides}));
    }
    let manifest = serde_json::json!({"encoding": CONFLICT_TREE_ENCODING, "claim_id": conflict.claim_id.to_hex(),
        "base_tree": conflict.base_tree, "ours_tree": conflict.ours_tree, "theirs_tree": conflict.theirs_tree, "conflicts": descriptors});
    out.insert(
        ".jjconflict/manifest.json".into(),
        OriginTreeFile {
            mode: 0o100644,
            content: serde_json::to_vec(&manifest)
                .map_err(|_| Error::InvariantViolation("conflict manifest encode"))?,
        },
    );
    Ok(out)
}
