//! The Git read recipient a host binds, apart from its push caller (FIX
//! 7608 slice 2b-ii-A, ASK 1).
//!
//! A verified agent reads as a masked recipient, named; an owner-grade
//! credential reads the stored history at the owner's own door; every other
//! verified caller reads as a masked recipient, with no agent claimed for
//! it unless the host proved one. The context admits nothing and never
//! comes from a request field; `git_push` authority stays the push
//! caller's alone (FIX 7608 2b-ii-B2: every raw and lease route binds it).

use oneiron::memory::RepoRevealRecipient;
use oneiron::origin::smart_http::RepoGitReadContext;

use crate::auth::CoreAuth;

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
