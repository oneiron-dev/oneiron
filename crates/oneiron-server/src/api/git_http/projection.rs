//! The Git read recipient a host binds, apart from its push caller (FIX
//! 7608 slice 2b-ii-A, ASK 1).
//!
//! A verified agent reads as a masked recipient, named; an owner-grade
//! credential reads the stored history at the owner's own door; every other
//! verified caller reads as a masked recipient, with no agent claimed for
//! it unless the host proved one. Recipient identity never comes from a
//! request field; the optional reason and portable selection admit nothing.
//! `git_push` authority stays the push
//! caller's alone (FIX 7608 2b-ii-B2: every raw and lease route binds it).

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use oneiron::EntityId;
use oneiron::memory::RepoRevealRecipient;
use oneiron::origin::RepoPortableId;
use oneiron::origin::smart_http::RepoGitReadContext;

use crate::auth::CoreAuth;

/// CALL GIT-REVEAL-OPT-IN (FIX 7608 pre-flip, FIX 9328): the optional
/// request header a Git reader states its own reason for a marked file's
/// real bytes in (stock Git sends it with `http.extraHeader`). It supplies
/// the reason only, never an identity or a context; absent, it is today's
/// read.
pub(super) const REPO_GIT_REVEAL_WHY_HEADER: &str = "oneiron-repo-reveal-why";

/// An optional selection pair, never a credential or recipient proof.
const REPO_GIT_PORTABLE_HEADER: &str = "oneiron-repo-portable";
const REPO_GIT_PROJECT_HEADER: &str = "oneiron-repo-project";

/// The read recipient `auth`, a verified Git transport caller, is: masked
/// and named when the host proved an agent behind it (an agent's token is
/// never an exact read, whatever its grade), exact for an owner-grade
/// credential, else masked with no agent claimed.
pub(super) fn repo_git_read_context(
    auth: &CoreAuth,
    actual: Option<RepoRevealRecipient>,
) -> RepoGitReadContext {
    if actual.is_some() {
        return RepoGitReadContext::masked(actual);
    }
    if auth.is_owner_grade() {
        RepoGitReadContext::exact()
    } else {
        RepoGitReadContext::masked(actual)
    }
}

/// [`repo_git_read_context`] for `auth`, with the agent its verified
/// credential names when its actor class is an agent's.
pub(super) fn git_read_context_of(auth: &CoreAuth) -> RepoGitReadContext {
    let actual = (auth.actor_class() == Some("agent"))
        .then(|| auth.principal_ref())
        .flatten()
        .and_then(|id| oneiron::EntityId::from_hex(id).ok())
        .map(RepoRevealRecipient::proven_agent);
    repo_git_read_context(auth, actual)
}

/// [`git_read_context_of`] for `auth`, with the reader's own reason from
/// `headers` when it sent one ([`REPO_GIT_REVEAL_WHY_HEADER`]): it opts a
/// masked read with a proven recipient into the files a live grant
/// covers. A portable repo/project header pair supplies only selection data;
/// malformed or incomplete pairs are bad requests. It also answers the same
/// pair as the push selection beside the read context.
pub(super) fn git_read_context_for(
    auth: &CoreAuth,
    headers: &HeaderMap,
) -> Result<(RepoGitReadContext, Option<(RepoPortableId, EntityId)>), Response> {
    let why = headers
        .get(REPO_GIT_REVEAL_WHY_HEADER)
        .and_then(|value| value.to_str().ok());
    let read = git_read_context_of(auth).with_reveal_why(why);
    match (
        headers.get(REPO_GIT_PORTABLE_HEADER),
        headers.get(REPO_GIT_PROJECT_HEADER),
    ) {
        (None, None) => Ok((read, None)),
        (Some(portable), Some(project)) => {
            let parsed = portable
                .to_str()
                .ok()
                .and_then(RepoPortableId::from_hex)
                .zip(
                    project
                        .to_str()
                        .ok()
                        .and_then(|id| EntityId::from_hex(id).ok()),
                );
            match parsed {
                Some((portable, project)) => Ok((
                    read.with_portable_repo(portable, project),
                    Some((portable, project)),
                )),
                None => Err(invalid_portable_selection()),
            }
        }
        _ => Err(invalid_portable_selection()),
    }
}

fn invalid_portable_selection() -> Response {
    super::gate::text_response(
        StatusCode::BAD_REQUEST,
        "a portable repo selection needs a valid oneiron-repo-portable and oneiron-repo-project",
    )
}
