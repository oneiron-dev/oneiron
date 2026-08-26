use std::path::Path;
use std::sync::atomic::Ordering;

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, PREDICATE_CONFLICT_OPEN,
    PREDICATE_CONFLICT_RESOLVED, decode_claim_body, encode_claim_body,
};
use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;

use super::conflict_value::{
    RepoConflictOpenValue, RepoConflictResolutionValue, decode_repo_conflict_open_value,
    decode_repo_conflict_resolution_value, encode_repo_conflict_open_value,
    encode_repo_conflict_resolution_value, normalize_repo_conflict_paths,
    validate_repo_conflict_claim_value,
};
use super::git::{
    git_status_success, run_git, run_git_allow_exit_codes, validate_base_ref,
    validate_commit_message, validate_git_object_hash, validate_git_ref_label,
    validate_relative_repo_path,
};
use super::queue::{PreparedCommitFile, PreparedConflictResolution};
use super::support::{now_secs, utf8_trimmed};
use super::trailer::commit_message_with_provenance_trailer;
use super::types::{RepoConflictClaim, RepoConflictResolutionClaim};
use super::worktree::apply_prepared_commit_file;

impl Vault {
    /// Lists active typed repo conflict claims attached to a branch subject.
    pub fn repo_conflict_claims(
        &self,
        branch_subject: &EntityId,
    ) -> Result<Vec<RepoConflictClaim>> {
        let mut claims = Vec::new();
        for claim_id in self.claims_for_subject(branch_subject)? {
            let Some(body) = self.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_CONFLICT_OPEN
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.subject != ClaimSubject::Entity(*branch_subject)
            {
                continue;
            }
            let Ok(value) = decode_repo_conflict_open_value(&body.value) else {
                continue;
            };
            claims.push(RepoConflictClaim {
                claim_id,
                subject: *branch_subject,
                repo_ref: value.repo_ref,
                branch: value.branch,
                base_tree: value.base_tree,
                ours_tree: value.ours_tree,
                theirs_tree: value.theirs_tree,
                conflicted_paths: value.conflicted_paths,
            });
        }
        claims.sort_by(|left, right| {
            left.branch
                .cmp(&right.branch)
                .then_with(|| left.claim_id.as_bytes().cmp(right.claim_id.as_bytes()))
        });
        Ok(claims)
    }

    /// Lists typed conflict resolution claims attached to a branch subject.
    pub fn repo_conflict_resolution_claims(
        &self,
        branch_subject: &EntityId,
    ) -> Result<Vec<RepoConflictResolutionClaim>> {
        let mut claims = Vec::new();
        for claim_id in self.claims_for_subject(branch_subject)? {
            let Some(body) = self.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_CONFLICT_RESOLVED
                || body.subject != ClaimSubject::Entity(*branch_subject)
            {
                continue;
            }
            let Ok(value) = decode_repo_conflict_resolution_value(&body.value) else {
                continue;
            };
            claims.push(RepoConflictResolutionClaim {
                claim_id,
                subject: *branch_subject,
                repo_ref: value.repo_ref,
                branch: value.branch,
                open_conflict_claim_id: value.open_conflict_claim_id,
                resolved_tree: value.resolved_tree,
                resolved_paths: value.resolved_paths,
            });
        }
        claims.sort_by(|left, right| {
            left.branch
                .cmp(&right.branch)
                .then_with(|| left.claim_id.as_bytes().cmp(right.claim_id.as_bytes()))
        });
        Ok(claims)
    }
}

pub(super) fn record_repo_conflict(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    branch_subject: EntityId,
    branch_name: &str,
    ours_ref: &str,
    theirs_ref: &str,
) -> Result<EntityId> {
    validate_git_ref_label(branch_name)?;
    validate_base_ref(ours_ref)?;
    validate_base_ref(theirs_ref)?;

    let base_commit = merge_base_commit(repo_root, ours_ref, theirs_ref)?;
    let base_tree = tree_hash_for_ref(repo_root, &base_commit)?;
    let ours_tree = tree_hash_for_ref(repo_root, ours_ref)?;
    let theirs_tree = tree_hash_for_ref(repo_root, theirs_ref)?;
    let conflicted_paths = merge_conflicted_paths(
        repo_root,
        &base_commit,
        ours_ref,
        theirs_ref,
        &ours_tree,
        &theirs_tree,
    )?;
    if conflicted_paths.is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo conflict record requires at least one conflicted path",
        ));
    }

    let claim_id = EntityId::now();
    put_repo_conflict_open_claim(
        vault,
        claim_id,
        branch_subject,
        RepoConflictOpenValue {
            repo_ref: repo_ref.clone(),
            branch: branch_name.to_owned(),
            base_tree,
            ours_tree,
            theirs_tree,
            conflicted_paths,
        },
    )?;
    Ok(claim_id)
}

#[expect(
    clippy::too_many_arguments,
    reason = "operation payload fields stay explicit at the mutation boundary"
)]
pub(super) fn resolve_repo_conflict_file(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    branch_subject: EntityId,
    open_conflict_claim_id: EntityId,
    branch_name: &str,
    path: &str,
    content: &[u8],
    message: &str,
    provenance_claim_id: Option<EntityId>,
    prepared_commit: &PreparedCommitFile,
    prepared_resolution: &PreparedConflictResolution,
) -> Result<EntityId> {
    validate_git_ref_label(branch_name)?;
    validate_relative_repo_path(path)?;
    validate_commit_message(message)?;
    let open = require_active_repo_conflict_claim(vault, &open_conflict_claim_id, branch_subject)?;
    if open.repo_ref != *repo_ref || open.branch != branch_name {
        return Err(Error::InvalidRepoMutationRecord(
            "open conflict claim does not match this repo branch",
        ));
    }
    if !open
        .conflicted_paths
        .iter()
        .any(|conflict| conflict == path)
    {
        return Err(Error::InvalidRepoMutationRecord(
            "resolved path must be one of the recorded conflicted paths",
        ));
    }
    let current_branch = current_branch(repo_root)?;
    if current_branch != branch_name {
        return Err(Error::InvalidRepoMutationRecord(
            "repo conflict resolution must run on the recorded branch",
        ));
    }

    let _ = commit_message_with_provenance_trailer(message, provenance_claim_id)?;
    apply_prepared_commit_file(repo_root, path, content, prepared_commit)?;
    let resolved_tree = tree_hash_for_ref(repo_root, "HEAD")?;
    if resolved_tree != prepared_resolution.resolved_tree {
        return Err(Error::InvariantViolation(
            "prepared conflict resolution tree changed before claim write",
        ));
    }
    finish_repo_conflict_resolution(vault, repo_ref, repo_root, prepared_resolution)
}

pub(super) fn finish_repo_conflict_resolution(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    prepared: &PreparedConflictResolution,
) -> Result<EntityId> {
    validate_git_ref_label(&prepared.branch_name)?;
    validate_relative_repo_path(&prepared.path)?;
    validate_git_object_hash(
        &prepared.resolved_tree,
        "resolved tree must be a 40-hex object id",
    )?;
    if current_branch(repo_root)? != prepared.branch_name {
        return Err(Error::InvalidRepoMutationRecord(
            "prepared conflict resolution must finish on its recorded branch",
        ));
    }
    let value = RepoConflictResolutionValue {
        repo_ref: repo_ref.clone(),
        branch: prepared.branch_name.clone(),
        open_conflict_claim_id: prepared.open_conflict_claim_id,
        resolved_tree: prepared.resolved_tree.clone(),
        resolved_paths: normalize_repo_conflict_paths(vec![prepared.path.clone()])?,
    };
    let resolution_exists = match vault.get_claim(&prepared.resolution_claim_id)? {
        Some(body)
            if body.predicate == PREDICATE_CONFLICT_RESOLVED
                && body.lifecycle == ClaimLifecycleStatus::Active
                && body.subject == ClaimSubject::Entity(prepared.branch_subject)
                && decode_repo_conflict_resolution_value(&body.value)? == value =>
        {
            true
        }
        Some(_) => {
            return Err(Error::InvalidRepoMutationRecord(
                "prepared conflict resolution claim id was reused",
            ));
        }
        None => false,
    };
    let open = vault
        .get_claim(&prepared.open_conflict_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    if open.lifecycle == ClaimLifecycleStatus::Superseded {
        if resolution_exists
            && vault.edge_exists(
                &prepared.resolution_claim_id,
                EdgeKind::Supersedes,
                &prepared.open_conflict_claim_id,
            )?
        {
            return Ok(prepared.resolution_claim_id);
        }
        return Err(Error::InvalidRepoMutationRecord(
            "open conflict was superseded by another resolution",
        ));
    }
    if open.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::ClaimAlreadyClosed {
            status: open.lifecycle,
        });
    }
    let open = require_active_repo_conflict_claim(
        vault,
        &prepared.open_conflict_claim_id,
        prepared.branch_subject,
    )?;
    if open.repo_ref != *repo_ref
        || open.branch != prepared.branch_name
        || !open
            .conflicted_paths
            .iter()
            .any(|path| path == &prepared.path)
    {
        return Err(Error::InvalidRepoMutationRecord(
            "prepared conflict resolution does not match the open conflict",
        ));
    }
    if !resolution_exists {
        put_repo_conflict_resolution_claim(
            vault,
            prepared.resolution_claim_id,
            prepared.branch_subject,
            value,
        )?;
    }
    supersede_repo_conflict_claim(
        vault,
        prepared.resolution_claim_id,
        prepared.open_conflict_claim_id,
        now_secs(),
    )?;
    Ok(prepared.resolution_claim_id)
}

fn require_active_repo_conflict_claim(
    vault: &Vault,
    claim_id: &EntityId,
    branch_subject: EntityId,
) -> Result<RepoConflictClaim> {
    let body = vault.get_claim(claim_id)?.ok_or(Error::EntityNotFound)?;
    if body.predicate != PREDICATE_CONFLICT_OPEN
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.subject != ClaimSubject::Entity(branch_subject)
    {
        return Err(Error::InvalidRepoMutationRecord(
            "open conflict claim must be active and attached to the branch subject",
        ));
    }
    let value = decode_repo_conflict_open_value(&body.value)?;
    Ok(RepoConflictClaim {
        claim_id: *claim_id,
        subject: branch_subject,
        repo_ref: value.repo_ref,
        branch: value.branch,
        base_tree: value.base_tree,
        ours_tree: value.ours_tree,
        theirs_tree: value.theirs_tree,
        conflicted_paths: value.conflicted_paths,
    })
}

fn put_repo_conflict_open_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    value: RepoConflictOpenValue,
) -> Result<()> {
    let learned_at = now_secs();
    let body = ClaimBody::new(
        PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(branch_subject),
        encode_repo_conflict_open_value(&value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    put_engine_repo_conflict_claim(vault, claim_id, branch_subject, &body, learned_at)
}

fn put_repo_conflict_resolution_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    value: RepoConflictResolutionValue,
) -> Result<()> {
    let learned_at = now_secs();
    let body = ClaimBody::new(
        PREDICATE_CONFLICT_RESOLVED,
        ClaimSubject::Entity(branch_subject),
        encode_repo_conflict_resolution_value(&value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    validate_repo_conflict_claim_value(&body.predicate, &body.value)?;
    put_engine_repo_conflict_claim(vault, claim_id, branch_subject, &body, learned_at)
}

fn put_engine_repo_conflict_claim(
    vault: &Vault,
    claim_id: EntityId,
    branch_subject: EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<()> {
    let data = encode_claim_body(body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    if vault
        .store
        .entities
        .get(&wtxn, branch_subject.as_bytes())?
        .is_none()
    {
        return Err(Error::EntityNotFound);
    }
    let claim_of_weight = EdgeKind::ClaimOf
        .default_weight()
        .ok_or(Error::InvariantViolation(
            "ClaimOf edge missing default weight",
        ))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: claim_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::Edge {
                src: claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: branch_subject,
                weight: claim_of_weight,
                vad: Vad::NEUTRAL,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn supersede_repo_conflict_claim(
    vault: &Vault,
    new_id: EntityId,
    old_id: EntityId,
    now: u64,
) -> Result<()> {
    if new_id == old_id {
        return Err(Error::ClaimSelfSupersession);
    }
    let mut wtxn = vault.store.env.write_txn()?;
    let new_raw = vault
        .store
        .entities
        .get(&wtxn, new_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let new_header =
        EntityMetadataHeader::parse(&new_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if new_header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let new_body = decode_claim_body(&new_raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if new_body.predicate != PREDICATE_CONFLICT_RESOLVED
        || new_body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(Error::InvalidRepoMutationRecord(
            "new repo conflict claim must be an active resolution claim",
        ));
    }

    let old_raw = vault
        .store
        .entities
        .get(&wtxn, old_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let old_header =
        EntityMetadataHeader::parse(&old_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if old_header.entity_type != ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let mut old_body = decode_claim_body(&old_raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if old_body.predicate != PREDICATE_CONFLICT_OPEN {
        return Err(Error::InvalidRepoMutationRecord(
            "old repo conflict claim must be an open conflict claim",
        ));
    }
    if old_body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::ClaimAlreadyClosed {
            status: old_body.lifecycle,
        });
    }
    old_body.lifecycle = ClaimLifecycleStatus::Superseded;
    old_body.valid_to = Some(now);
    let data = encode_claim_body(&old_body)?;
    let supersedes_weight =
        EdgeKind::Supersedes
            .default_weight()
            .ok_or(Error::InvariantViolation(
                "Supersedes edge missing default weight",
            ))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now,
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: new_id,
                kind: EdgeKind::Supersedes,
                tgt: old_id,
                weight: supersedes_weight,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn merge_base_commit(repo_root: &Path, ours_ref: &str, theirs_ref: &str) -> Result<String> {
    let base = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "merge-base".to_owned(),
                ours_ref.to_owned(),
                theirs_ref.to_owned(),
            ],
        )?,
        "git merge-base must be UTF-8",
    )?;
    validate_git_object_hash(&base, "merge-base must be a 40-hex commit")?;
    Ok(base)
}

pub(super) fn tree_hash_for_ref(repo_root: &Path, git_ref: &str) -> Result<String> {
    let tree_ref = format!("{git_ref}^{{tree}}");
    let tree = utf8_trimmed(
        run_git(
            repo_root,
            &["rev-parse".to_owned(), "--verify".to_owned(), tree_ref],
        )?,
        "git tree hash must be UTF-8",
    )?;
    validate_git_object_hash(&tree, "tree hash must be a 40-hex object id")?;
    Ok(tree)
}

fn current_branch(repo_root: &Path) -> Result<String> {
    let branch = utf8_trimmed(
        run_git(
            repo_root,
            &["branch".to_owned(), "--show-current".to_owned()],
        )?,
        "git branch name must be UTF-8",
    )?;
    validate_git_ref_label(&branch)?;
    Ok(branch)
}

fn merge_conflicted_paths(
    repo_root: &Path,
    base_commit: &str,
    ours_ref: &str,
    theirs_ref: &str,
    ours_tree: &str,
    theirs_tree: &str,
) -> Result<Vec<String>> {
    let output = run_git_allow_exit_codes(
        repo_root,
        &[
            "merge-tree".to_owned(),
            "--write-tree".to_owned(),
            "--name-only".to_owned(),
            "--no-messages".to_owned(),
            "-z".to_owned(),
            "--merge-base".to_owned(),
            base_commit.to_owned(),
            ours_ref.to_owned(),
            theirs_ref.to_owned(),
        ],
        &[0, 1],
    )?;

    let mut paths = Vec::new();
    for token in output.split(|byte| *byte == 0) {
        if token.is_empty() {
            continue;
        }
        let Ok(path) = std::str::from_utf8(token) else {
            continue;
        };
        if validate_relative_repo_path(path).is_err() {
            continue;
        }
        if path_exists_in_tree(repo_root, ours_tree, path)?
            || path_exists_in_tree(repo_root, theirs_tree, path)?
        {
            paths.push(path.to_owned());
        }
    }
    normalize_repo_conflict_paths(paths)
}

fn path_exists_in_tree(repo_root: &Path, tree_hash: &str, path: &str) -> Result<bool> {
    validate_git_object_hash(tree_hash, "tree hash must be a 40-hex object id")?;
    validate_relative_repo_path(path)?;
    let spec = format!("{tree_hash}:{path}");
    git_status_success(repo_root, &["cat-file".to_owned(), "-e".to_owned(), spec])
}
