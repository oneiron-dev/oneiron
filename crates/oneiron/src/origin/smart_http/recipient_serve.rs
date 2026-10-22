//! Who a Git read serves, as its host proved it (FIX 7608 slice 2b-ii-A,
//! ASK 1).
//!
//! A host binds each Git read's recipient apart from its push authority:
//! the owner at the owner's own door and an exact recipient read the
//! stored history; a run, an agent, a model or an MCP tool reads the
//! masked copy of a store that holds readable marks, and a store with none
//! is today's for every recipient. A `git_push` authority never grants a
//! read or a reveal. The context is a trusted-host contract like
//! `GitPushCaller`, not a grant: it holds no credential and is never read
//! from a request.
//!
//! In this slice every context still serves today's exchange: the exact
//! path delegates first, and the masked selection over the copy's frozen
//! read backend is wired with fetch, checkout and copy receive together.

use std::io::Read;
use std::sync::Arc;

use heed::RoTxn;

use super::bounds::ExchangeBounds;
use super::door::DoorSeam;
use super::push_admission::serve_bounded_as;
use super::serve::{ServeReport, ServeSink};
use super::serve_cmd::ServeRequest;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::GitPushCaller;
use crate::origin::residence::OriginAuthorityLease;
use crate::origin::secret_marks::{RepoSecretMarkLookup, for_each_repo_secret_mark_in_txn};
use crate::origin::secret_projection::RepoRevealRecipient;

/// The recipient a Git read serves, as its host proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoGitReadContext {
    masked: bool,
    actual: Option<RepoRevealRecipient>,
}

impl RepoGitReadContext {
    /// The owner at the owner's own door, or an exact recipient: the
    /// stored history.
    #[must_use]
    pub const fn exact() -> Self {
        Self {
            masked: false,
            actual: None,
        }
    }

    /// A run, an agent, a model or an MCP tool: the masked copy of a
    /// marked store, with the agent the host proved, when it proved one.
    #[must_use]
    pub const fn masked(actual: Option<RepoRevealRecipient>) -> Self {
        Self {
            masked: true,
            actual,
        }
    }

    /// Whether this read is a masked recipient's.
    #[must_use]
    pub const fn reads_masked(&self) -> bool {
        self.masked
    }

    /// The agent the host proved, when it proved one.
    #[must_use]
    pub const fn actual(&self) -> Option<&RepoRevealRecipient> {
        self.actual.as_ref()
    }
}

/// Whether the store `store` holds a readable mark, found in one walk with
/// nothing written: a store with none serves every recipient today's
/// history, with no copy made.
///
/// # Errors
/// A store failure, or a mark that does not decode.
#[allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the masked read selection calls it in 2b-ii-B"
)]
pub(crate) fn store_holds_readable_marks_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    store: &EntityId,
) -> Result<bool> {
    let mut found = false;
    for_each_repo_secret_mark_in_txn(
        vault,
        txn,
        RepoSecretMarkLookup::ReadableClaims,
        &mut |mark| {
            found |= mark.store_id == *store;
            Ok(())
        },
    )?;
    Ok(found)
}

/// [`serve_bounded_as`] for a read whose recipient `read` names. This slice
/// serves every recipient today's exchange: the exact path first, the
/// masked selection with its activation.
///
/// # Errors
/// As [`serve_bounded_as`].
#[expect(clippy::too_many_arguments)]
pub fn serve_bounded_for_recipient(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    bounds: ExchangeBounds,
    authority: Option<&OriginAuthorityLease>,
    caller: Option<&GitPushCaller>,
    read: &RepoGitReadContext,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let _ = read;
    serve_bounded_as(
        vault, repo_name, request, seam, bounds, authority, caller, body, sink,
    )
}
