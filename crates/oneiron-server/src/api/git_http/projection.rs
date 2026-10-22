//! The Git read recipient a host binds, apart from its push caller (FIX
//! 7608 slice 2b-ii-A, ASK 1).
//!
//! An owner-grade credential reads the stored history at the owner's own
//! door; every other verified caller reads as a masked recipient, with no
//! agent claimed for it unless the host proved one. The context admits
//! nothing and never comes from a request field; `git_push` authority
//! stays the push caller's alone.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the raw and lease Git routes bind it in 2b-ii-B"
)]

use oneiron::memory::RepoRevealRecipient;
use oneiron::origin::smart_http::RepoGitReadContext;

use crate::auth::CoreAuth;

/// The read recipient `auth`, a verified Git transport caller, is: exact
/// for an owner-grade credential, else masked with `actual` when the host
/// proved the agent behind it.
pub(super) fn repo_git_read_context(
    auth: &CoreAuth,
    actual: Option<RepoRevealRecipient>,
) -> RepoGitReadContext {
    if auth.is_owner_grade() {
        RepoGitReadContext::exact()
    } else {
        RepoGitReadContext::masked(actual)
    }
}
