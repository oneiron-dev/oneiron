//! The feedback triage's GitHub issue sources (OF-420 T1; ARCH-0056: "GitHub
//! issues still work. We sweep both on a schedule with the triage skill").
//!
//! The deployment binds each repository it sweeps by its exact issues
//! endpoint; none is bound by default, and no other repository is read. The
//! host walks a bound repository's listing, every state and every page,
//! oldest first, and hands each page here. A page's items take the write an
//! inbox note takes, and the source's continuation moves in that write,
//! after them. A walk that reaches the last page starts the next one at the
//! first under a new generation, so a later sweep sees edits and reopens of
//! items the old cursor had passed.
//!
//! An item is named by its source, `github:<owner>/<repo>`, and its upstream
//! numeric id. Its revision is its `updated_at` and the BLAKE3 of its
//! canonical encoding, so a replayed page hands nothing off twice. Pull
//! requests the listing returns are kept, as their own kind. What a source
//! answers in place of a page is recorded on its row with any retry time it
//! named; its continuation stays, and a later sweep resumes there.
use serde::{Deserialize, Serialize};

use super::source::{FeedbackTriageSourceError, FeedbackTriageSourceFault, source_row_in_txn};
use super::{
    COACH_FEEDBACK_SWEEP_FACET, FeedbackTriageContinuation, FeedbackTriageHandoff,
    FeedbackTriageSourceRef, Revision, SOURCES, attempt_ref, binding_in_txn,
    hand_off_revision_in_txn, invalid_job,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::{Error, Result, Vault};

/// The prefix of a GitHub source's name, `github:<owner>/<repo>`.
pub const FEEDBACK_TRIAGE_GITHUB_PREFIX: &str = "github:";
/// The domain a GitHub item's revision digest is taken under.
const REVISION_DOMAIN: &[u8] = b"oneiron:feedback-triage:github-revision:v1";

/// A GitHub item's kind: a repository's issue listing returns its pull
/// requests too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubIssueKind {
    /// An issue.
    Issue,
    /// A pull request: the listing's entry carries a `pull_request` key.
    PullRequest,
}

/// One GitHub issue or pull request at one revision, as a sweep read it:
/// every field the triage keeps. Its canonical encoding is the bytes its
/// evidence ASSET keeps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubIssueRevision {
    /// The source the deployment bound it under: `github:<owner>/<repo>`.
    pub repo: String,
    /// The upstream numeric id.
    pub id: u64,
    /// The upstream node id.
    pub node_id: String,
    /// Its number in its repository.
    pub number: u64,
    /// Its page on the source.
    pub html_url: String,
    /// Its title, whole.
    pub title: String,
    /// Its body, whole; `None` when it has none.
    pub body: Option<String>,
    /// Its state as the source names it: `open` or `closed`.
    pub state: String,
    /// When the source last changed it, as the source names it.
    pub updated_at: String,
    /// Issue or pull request.
    pub kind: GithubIssueKind,
}

/// Where a GitHub source's walk resumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GithubSweepContinuation {
    /// The walk: one more each time a walk reaches the last page.
    pub generation: u64,
    /// The next page, as the last page's `Link: rel="next"` named it;
    /// `None` when the walk starts at the first page.
    pub next: Option<String>,
    /// The ETag the last page carried: HTTP evidence of the listing, never
    /// an item's revision.
    pub etag: Option<String>,
}

/// One page of a GitHub source's listing, as the host read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GithubIssuePage {
    /// The source: `github:<owner>/<repo>`.
    pub source: String,
    /// The continuation the page was read from; `None` before the source's
    /// first page.
    pub read: Option<GithubSweepContinuation>,
    /// Every item on the page, in listing order.
    pub items: Vec<GithubIssueRevision>,
    /// The next page's link; `None` on the last page.
    pub next: Option<String>,
    /// The ETag the page carried.
    pub etag: Option<String>,
}

fn not_github() -> Error {
    Error::InvalidConfig("not a GitHub feedback triage source".into())
}

/// Whether `source` names a GitHub source, `github:<owner>/<repo>`.
fn is_github_source(source: &str) -> bool {
    source
        .strip_prefix(FEEDBACK_TRIAGE_GITHUB_PREFIX)
        .and_then(|repo| repo.split_once('/'))
        .is_some_and(|(owner, name)| !owner.is_empty() && !name.is_empty() && !name.contains('/'))
}

/// An item's name and revision, and its canonical encoding: the bytes its
/// evidence keeps.
fn github_revision(issue: &GithubIssueRevision) -> Result<(FeedbackTriageSourceRef, Vec<u8>)> {
    let bytes = rmp_serde::to_vec_named(issue)
        .map_err(|_| Error::InvalidConfig("a GitHub feedback item did not encode".into()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_DOMAIN);
    hasher.update(&bytes);
    let digest = crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes());
    let source_ref = FeedbackTriageSourceRef {
        source: issue.repo.clone(),
        id: issue.id.to_string(),
        revision: format!("{}/{digest}", issue.updated_at),
    };
    Ok((source_ref, bytes))
}

/// The GitHub item `handoff` names, read back from its evidence ASSET and
/// checked against its revision.
pub(super) fn evidence_issue(
    vault: &Vault,
    handoff: &FeedbackTriageHandoff,
) -> Result<GithubIssueRevision> {
    if !is_github_source(&handoff.source_ref.source) {
        return Err(invalid_job());
    }
    let raw = {
        let txn = vault.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &handoff.evidence)?
    }
    .ok_or(Error::CorruptedIndex("feedback triage evidence missing"))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("feedback triage evidence header"))?;
    let mismatch = Error::CorruptedIndex("feedback triage evidence mismatch");
    if header.entity_type != crate::registry::ENTITY_TYPE_ASSET {
        return Err(mismatch);
    }
    let issue: GithubIssueRevision = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| rmp_serde::from_slice(bytes).ok())
        .ok_or(mismatch)?;
    if github_revision(&issue)?.0 != handoff.source_ref {
        return Err(Error::CorruptedIndex("feedback triage issue revision"));
    }
    Ok(issue)
}

impl Vault {
    /// Where the sweep resumes the GitHub source `source`: its row, or a
    /// fresh one, unwritten, before its first page. `None` when no skill is
    /// bound: the sweep then reads no source, as it reads no inbox.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; a name that is
    /// not a GitHub source's; storage errors.
    pub fn feedback_triage_source(
        &self,
        attempt: &DreamerAdmittedAttempt,
        source: &str,
    ) -> Result<Option<FeedbackTriageContinuation>> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        if !is_github_source(source) {
            return Err(not_github());
        }
        let sweep = attempt_ref(attempt.status.attempt.id)?;
        let txn = self.store.env.read_txn()?;
        if binding_in_txn(self, &txn)?.skill.is_none() {
            return Ok(None);
        }
        source_row_in_txn(self, &txn, source, sweep, self.now_recorded_at()).map(Some)
    }

    /// Hands off one page of a GitHub source in one write: each item's
    /// revision through the write an inbox note takes, then the source's
    /// continuation. It moves to the page's next link or, on the last page,
    /// back to the first under a new generation, and the page clears the
    /// source's error. The sweep's lease is renewed in this same write, and
    /// fenced there on the lease the walk was admitted under (FIX 7628).
    /// Answers the row as written, or `None`, writing nothing, when another
    /// walk moved the continuation since the page was read, when another
    /// walker holds the sweep now, or when no skill is bound now.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; a page that is
    /// not a GitHub source's, or holds another source's item; storage
    /// errors.
    pub fn record_feedback_triage_github_page(
        &self,
        attempt: &DreamerAdmittedAttempt,
        page: &GithubIssuePage,
        now: u64,
    ) -> Result<Option<FeedbackTriageContinuation>> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        if !is_github_source(&page.source) || page.items.iter().any(|item| item.repo != page.source)
        {
            return Err(not_github());
        }
        let revisions = page
            .items
            .iter()
            .map(github_revision)
            .collect::<Result<Vec<_>>>()?;
        let sweep = attempt.status.attempt.id;
        let run_id = attempt.status.attempt.run_id.as_deref();
        let sweep_ref = attempt_ref(sweep)?;
        self.with_write_txn_grouped(|txn| {
            if binding_in_txn(self, txn)?.skill.is_none() {
                return Ok(None);
            }
            // A stale walker lands no page: only the lease it was admitted
            // under, still held and renewed here, writes one.
            if !self.renew_feedback_sweep_in_txn(txn, attempt)? {
                return Ok(None);
            }
            let mut row = source_row_in_txn(self, txn, &page.source, sweep_ref, now)?;
            if row.github != page.read {
                return Ok(None);
            }
            for (source_ref, bytes) in revisions {
                let revision = Revision {
                    source_ref,
                    bytes: &bytes,
                    received_at: now,
                };
                hand_off_revision_in_txn(self, txn, sweep, run_id, revision, now)?;
            }
            let mut generation = page.read.as_ref().map_or(0, |read| read.generation);
            if page.next.is_none() {
                generation = generation
                    .checked_add(1)
                    .ok_or(Error::IndexOverflow("feedback triage sweep generation"))?;
                row.completed_at = Some(now);
                row.completed_by = Some(sweep_ref);
            }
            row.github = Some(GithubSweepContinuation {
                generation,
                next: page.next.clone(),
                etag: page.etag.clone(),
            });
            row.sweep = sweep_ref;
            row.moved_at = now;
            row.error = None;
            row.retry_after = None;
            SOURCES.put(&self.store, txn, &row.source, &row)?;
            Ok(Some(row))
        })
    }

    /// Records what a GitHub source answered in place of a page, with the
    /// retry time it named, if any, or the engine's own failure while it
    /// walked the source. Its continuation stays, and the sweep resumes it
    /// there once that time has passed. Like a page, it is written only
    /// under the lease the walk was admitted under, renewed in this write: a
    /// stale walker writes nothing over the current walker's row (FIX 7628).
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt; a name that is
    /// not a GitHub source's; storage errors.
    pub fn record_feedback_triage_source_error(
        &self,
        attempt: &DreamerAdmittedAttempt,
        source: &str,
        fault: &FeedbackTriageSourceFault,
        now: u64,
    ) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_SWEEP_FACET)?;
        if !is_github_source(source) {
            return Err(not_github());
        }
        let sweep = attempt_ref(attempt.status.attempt.id)?;
        self.with_write_txn_grouped(|txn| {
            if !self.renew_feedback_sweep_in_txn(txn, attempt)? {
                return Ok(());
            }
            let mut row = source_row_in_txn(self, txn, source, sweep, now)?;
            row.error = Some(FeedbackTriageSourceError {
                kind: fault.kind,
                status: fault.status,
                sweep,
                at: now,
            });
            row.retry_after = fault.retry_after;
            SOURCES.put(&self.store, txn, &row.source, &row)
        })
    }
}
