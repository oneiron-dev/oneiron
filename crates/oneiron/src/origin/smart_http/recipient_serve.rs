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
//! The exact path delegates first, byte for byte; a masked context reaches
//! the selection that serves a marked store's masked copy and receives its
//! pushes into a private ingress (FIX 7608 slice 2b-ii-B2).
//!
//! CALL GIT-REVEAL-OPT-IN (FIX 9328): a masked context may carry the
//! reader's own explicit reason for real bytes, which only its host sets
//! from the reader's request. With a proven recipient and a valid reason,
//! the files a live grant covers are read at their stored bytes, each
//! delivered afresh with its receipts; an absent or invalid reason, or an
//! unknown recipient, is today's masked read, with no ask and no refusal.

use std::io::Read;
use std::sync::Arc;

use heed::RoTxn;

use super::bounds::ExchangeBounds;
use super::door::DoorSeam;
use super::push_admission::{ServeCaller, serve_bounded_as};
use super::serve::{ServeReport, ServeSink, ServeTerms, serve_request};
use super::serve_cmd::ServeRequest;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::GitPushCaller;
use crate::origin::residence::OriginAuthorityLease;
use crate::origin::secret_marks::{RepoSecretMarkLookup, for_each_repo_secret_mark_in_txn};
use crate::origin::secret_projection::RepoRevealRecipient;

pub(super) mod delivery;

/// The recipient a Git read serves, as its host proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoGitReadContext {
    masked: bool,
    actual: Option<RepoRevealRecipient>,
    why: Option<String>,
}

impl RepoGitReadContext {
    /// The owner at the owner's own door, or an exact recipient: the
    /// stored history.
    #[must_use]
    pub const fn exact() -> Self {
        Self {
            masked: false,
            actual: None,
            why: None,
        }
    }

    /// A run, an agent, a model or an MCP tool: the masked copy of a
    /// marked store, with the agent the host proved, when it proved one.
    #[must_use]
    pub const fn masked(actual: Option<RepoRevealRecipient>) -> Self {
        Self {
            masked: true,
            actual,
            why: None,
        }
    }

    /// This read with the reader's own explicit reason for a marked file's
    /// real bytes, as its host took it from the reader's request: it opts
    /// a masked read with a proven recipient into the files a live grant
    /// covers. An exact read reads the stored history whatever it says.
    #[must_use]
    pub fn with_reveal_why(mut self, why: Option<&str>) -> Self {
        self.why = why.map(str::to_owned);
        self
    }

    /// The reader's reason, when its host passed one.
    pub(crate) fn reveal_why(&self) -> Option<&str> {
        self.why.as_deref()
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

/// [`serve_bounded_as`] for a read whose recipient `read` names: an exact
/// recipient is [`serve_bounded_as`] itself; a masked one is served under
/// the same terms with its context, which selects the masked copy only
/// after the same push decision and only for a marked store.
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
    if !read.reads_masked() {
        return serve_bounded_as(
            vault, repo_name, request, seam, bounds, authority, caller, body, sink,
        );
    }
    let terms = ServeTerms {
        seam,
        authority,
        idle: bounds.idle,
        scan: bounds.scan,
        spill_floor: bounds.spill_floor,
        wait_for_repository: false,
        push_wait: Some(bounds.repository_wait),
        caller: ServeCaller::Host(caller),
        read: Some(read),
    };
    serve_request(vault, repo_name, request, terms, body, sink)
}
