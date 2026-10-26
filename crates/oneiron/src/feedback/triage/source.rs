//! Each triage source's state beside its continuation: what stopped its
//! last walk, and the retry time the source named. A source that fails
//! records it on its own row, and the sweep goes on to the next source.
use serde::{Deserialize, Serialize};

use super::{FeedbackTriageContinuation, SOURCES};
use crate::{EntityId, Error, Result, Vault};

/// What stopped a source's walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackTriageSourceErrorKind {
    /// The repository refused the deployment's credential, or wants one
    /// the deployment does not have: a 401, a 403 that is not a rate limit,
    /// or a 404. A managed vault has no credential for a private repository.
    AuthUnavailable,
    /// The source's rate limit: a 429, or a 403 with no requests left or
    /// with a `Retry-After`.
    RateLimited,
    /// Any other answer that is not a page.
    Upstream,
    /// No answer: the request did not complete.
    Transport,
    /// An answer the sweep cannot read: a page that does not parse, or a
    /// next page off the bound repository's listing.
    Unreadable,
    /// The engine's own failure while it walked the source.
    Engine,
}

/// What a source answered in place of a page, as the host read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedbackTriageSourceFault {
    /// What it was.
    pub kind: FeedbackTriageSourceErrorKind,
    /// The HTTP status, when the source answered.
    pub status: Option<u16>,
    /// Vault seconds the source named for a retry, when it named one.
    pub retry_after: Option<u64>,
}

/// What stopped a source's last walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageSourceError {
    /// What it was.
    pub kind: FeedbackTriageSourceErrorKind,
    /// The HTTP status, when the source answered.
    pub status: Option<u16>,
    /// 32 hex: the sweep that met it.
    pub sweep: EntityId,
    /// Vault seconds it was met.
    pub at: u64,
}

/// `source`'s row as `txn` reads it, or a fresh one `sweep` writes first.
pub(super) fn source_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &str,
    sweep: EntityId,
    now: u64,
) -> Result<FeedbackTriageContinuation> {
    let Some(row) = SOURCES.get(&vault.store, txn, &source.to_owned())? else {
        return Ok(FeedbackTriageContinuation {
            source: source.to_owned(),
            after: None,
            sweep,
            moved_at: now,
            github: None,
            completed_at: None,
            completed_by: None,
            error: None,
            retry_after: None,
            skipped: Vec::new(),
        });
    };
    if row.source != source {
        return Err(Error::CorruptedIndex("feedback triage source identity"));
    }
    Ok(row)
}

/// Applies `change` to `source`'s row in a write of its own.
pub(super) fn update_source_row(
    vault: &Vault,
    source: &str,
    sweep: EntityId,
    now: u64,
    change: impl FnOnce(&mut FeedbackTriageContinuation),
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let mut row = source_row_in_txn(vault, txn, source, sweep, now)?;
        change(&mut row);
        SOURCES.put(&vault.store, txn, &row.source, &row)
    })
}
