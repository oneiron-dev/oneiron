//! Historical queue GREEN contributes paths to the existing typed closer.
use super::*;
use crate::codebase::entity_id_from_hash_material;

const QUEUE_RESOLUTION_DOMAIN: &[u8] = b"oneiron:repo-queue-conflict-resolution:v1";

impl Vault {
    pub(crate) fn record_queue_repo_conflict_resolution(
        &self,
        repo: &RepoRef,
        open: &RepoConflictClaim,
        batch: &str,
        tree: &str,
        paths: Vec<String>,
    ) -> Result<(Vec<String>, bool)> {
        validate_git_ref_label(&open.branch)?;
        validate_git_object_hash(tree, "resolved tree must be a 40-hex object id")?;
        if !same_repository(repo, &open.repo_ref)
            || !paths
                .iter()
                .all(|path| open.conflicted_paths.contains(path))
        {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "queue resolution does not match the recorded conflict",
            )));
        }
        let body = self
            .get_claim(&open.claim_id)?
            .ok_or(Error::EntityNotFound)?;
        if body.predicate != PREDICATE_CONFLICT_OPEN
            || body.subject != ClaimSubject::Entity(open.subject)
            || decode_repo_conflict_open_value(&body.value)?.repo_ref != open.repo_ref
        {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "queue resolution must name its recorded branch conflict",
            )));
        }
        let key = super::super::oplog::repo_mutation_repo_key(repo);
        let id = entity_id_from_hash_material(
            QUEUE_RESOLUTION_DOMAIN,
            &[open.claim_id.as_bytes(), key.as_bytes(), batch.as_bytes()],
        )?;
        if let Some(body) = self.get_claim(&id)? {
            let saved = decode_repo_conflict_resolution_value(&body.value)?;
            if body.predicate != PREDICATE_CONFLICT_RESOLVED
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.subject != ClaimSubject::Entity(open.subject)
                || saved.open_conflict_claim_id != open.claim_id
                || saved.repo_ref != open.repo_ref
                || saved.branch != open.branch
                || saved.resolved_tree != tree
                || !paths.iter().all(|path| saved.resolved_paths.contains(path))
            {
                return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                    "queue conflict resolution claim id was reused",
                )));
            }
            supersede_repo_conflict_claim(self, id, open.claim_id, now_secs())?;
            return Ok((saved.resolved_paths, false));
        }
        // A typed member can close the native claim before its batch reaches
        // GREEN. The queue independently checks full GREEN path coverage.
        if body.lifecycle == ClaimLifecycleStatus::Superseded || paths.is_empty() {
            return Ok((paths, false));
        }
        let current = require_active_repo_conflict_claim(self, &open.claim_id, open.subject)?;
        if current != *open {
            return Err(Error::ConcurrentWrite(
                "recorded repository conflict changed",
            ));
        }
        let paths = normalize_repo_conflict_paths(paths)?;
        let value = RepoConflictResolutionValue {
            repo_ref: open.repo_ref.clone(),
            branch: open.branch.clone(),
            open_conflict_claim_id: open.claim_id,
            resolved_tree: tree.to_owned(),
            resolved_paths: paths.clone(),
        };
        put_repo_conflict_resolution_claim(self, id, open.subject, value)?;
        supersede_repo_conflict_claim(self, id, open.claim_id, now_secs())?;
        Ok((paths, true))
    }
}
