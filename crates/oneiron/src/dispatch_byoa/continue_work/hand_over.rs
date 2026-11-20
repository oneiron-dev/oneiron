//! The hand-over a continue starts: its ids, its job, and the pushed tip
//! it starts from (census L10-17).

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::checkout::CheckoutId;
use crate::codebase::{RepoRef, entity_id_from_hash_material};
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error};
use crate::git_wire::{GitRefName, GitWire};
use crate::memory::{MemoryError, MemoryResult};
use crate::origin::smart_http::origin_repo_dir;

use super::super::{
    ByoEndpointBackendFactory, ByoEndpointBinding, ByoEndpointSpec, ByoaEgressLease,
    ByoaEgressPort, ByoaError, ByoaResult,
};
use super::{
    ContinueOutsideWorkRequest, ERR_CONTINUE_CHECKOUT_ID, ERR_CONTINUE_JOB_ENCODE,
    ERR_CONTINUE_REF, HAND_OVER_CHECKOUT_DOMAIN, HAND_OVER_DOMAIN, HAND_OVER_JOB_KIND,
};

/// A continue reaches no endpoint: the door mints rows; no endpoint is
/// reached and no egress is leased.
pub(super) struct ContinueEndpoints;

impl ByoEndpointBackendFactory for ContinueEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<ByoEndpointBinding> {
        Err(ByoaError::Backend(
            "the continue door serves no endpoint connector".to_owned(),
        ))
    }
}

/// A continue takes no egress lease: it mints a row, and no traffic moves.
pub(super) struct ContinueEgress;

impl ByoaEgressPort for ContinueEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the continue door leases no egress".to_owned(),
        })
    }
}

/// The hand-over job the runner is handed, as JSON.
#[derive(Serialize)]
struct HandOverJob<'r> {
    kind: &'static str,
    conversation: &'r str,
    repo: &'r str,
    git_ref: &'r str,
    commit: &'r str,
    note: Option<&'r str>,
    instruction: String,
}

/// The hand-over id: the work's parent id, derived from the conversation,
/// the pushed coordinates and the runner. No attempt row answers to it; a
/// runner work's parent is only bytes in its id and its child's payload.
/// The same request twice derives the same binding
/// ([`RunnerWorkBindingId::of`] under [`CONTINUE_STEP_KEY`]); the same
/// hand-off under another runner derives its own, so it never answers the
/// first runner's work.
///
/// # Errors
///
/// A derived id the attempt queue refuses.
///
/// [`RunnerWorkBindingId::of`]: super::super::work_binding::RunnerWorkBindingId::of
/// [`CONTINUE_STEP_KEY`]: super::CONTINUE_STEP_KEY
pub(super) fn hand_over_id(
    repo: &str,
    git_ref: &str,
    commit: &str,
    runner: &str,
    conversation: EntityId,
) -> ByoaResult<AttemptId> {
    let id = entity_id_from_hash_material(
        HAND_OVER_DOMAIN,
        &[
            conversation.as_bytes(),
            repo.as_bytes(),
            git_ref.as_bytes(),
            commit.as_bytes(),
            runner.as_bytes(),
        ],
    )?;
    Ok(AttemptId::from_bytes(id.as_bytes())?)
}

/// The checkout a hand-over runs against, derived from the hand-over id.
///
/// # Errors
///
/// A derived id the checkout door refuses; a store failure.
pub(super) fn hand_over_checkout(hand_over: AttemptId) -> ByoaResult<CheckoutId> {
    let id = entity_id_from_hash_material(HAND_OVER_CHECKOUT_DOMAIN, &[hand_over.as_bytes()])?;
    CheckoutId::from_bytes(*id.as_bytes())
        .map_err(|_| super::super::error::invalid(ERR_CONTINUE_CHECKOUT_ID))
}

/// The hand-over job's bytes: the conversation, the pushed coordinates and
/// the instruction to recall the session through memory first.
///
/// # Errors
///
/// A job that does not encode.
pub(super) fn hand_over_job(request: &ContinueOutsideWorkRequest) -> MemoryResult<Vec<u8>> {
    let conversation = request.conversation.as_str();
    let repo = request.repo.as_str();
    let git_ref = request.git_ref.as_str();
    let commit = request.commit.as_str();
    let job = HandOverJob {
        kind: HAND_OVER_JOB_KIND,
        conversation,
        repo,
        git_ref,
        commit,
        note: request.note.as_deref(),
        instruction: format!(
            "Recall this session through Oneiron memory first: conversation \
             {conversation}. Then go on with its work in this checkout, which \
             holds commit {commit} of {git_ref}."
        ),
    };
    serde_json::to_vec(&job).map_err(|_| MemoryError::bad_request(ERR_CONTINUE_JOB_ENCODE))
}

/// The served store of `repo`: the directory this node serves it from.
///
/// # Errors
///
/// A repository this node serves nothing under; a store failure.
pub(super) fn served_store(vault: &Vault, repo: &str) -> MemoryResult<PathBuf> {
    match origin_repo_dir(vault, repo) {
        Ok(store) => Ok(store),
        Err(Error::Code(
            CodeError::GitHttpRepoNotFound { .. } | CodeError::GitHttpInvalidRepoName(_),
        )) => Err(MemoryError::not_found(format!(
            "this node serves no repository named {repo:?}"
        ))),
        Err(error) => Err(MemoryError::from(error)),
    }
}

/// The commit `git_ref` names now in the served `store`, peeled to a commit:
/// the pin the door reads the hand-off at. `None` for a ref that is not
/// there. The repo opens pinned at `commit`, the claimed tip: the proof
/// needs a commit the store holds, so a hand-off that never landed its
/// commit refuses here rather than reading no store at all.
///
/// # Errors
///
/// A ref that does not parse; a store that does not read; a store failure.
pub(super) fn pushed_tip(
    vault: &Vault,
    store: &Path,
    git_ref: &str,
    commit: &str,
) -> MemoryResult<Option<String>> {
    let name =
        GitRefName::parse_full(git_ref).map_err(|_| MemoryError::bad_request(ERR_CONTINUE_REF))?;
    let wire = GitWire::new(vault).map_err(MemoryError::from)?;
    let repo = wire
        .open_repo(
            RepoRef::LocalFolder {
                path: store.to_string_lossy().into_owned(),
                commit: commit.to_owned(),
            },
            store,
        )
        .map_err(MemoryError::from)?;
    let named = wire.read_ref(&repo, &name).map_err(MemoryError::from)?;
    let Some(named) = named else {
        return Ok(None);
    };
    let tip = wire
        .resolve_commit(&repo, named.as_str())
        .map_err(MemoryError::from)?;
    Ok(Some(tip.as_str().to_owned()))
}

/// Whether `commit` is a 40 lower-hex commit.
pub(super) fn commit_shaped(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
