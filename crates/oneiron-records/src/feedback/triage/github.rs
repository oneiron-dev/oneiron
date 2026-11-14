//! Moved from `crates/oneiron/src/feedback/triage/github.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::feedback::triage::github::GithubSweepContinuation;
use serde::Deserialize;
use serde::Serialize;

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
