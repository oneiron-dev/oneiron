//! The feedback sweep's GitHub issue sources (OF-420 T1; ARCH-0056: "GitHub
//! issues still work. We sweep both on a schedule with the triage skill").
//! Each repository `[feedback.triage]` binds is walked from its stored
//! continuation to the last page of its issue listing: every state, oldest
//! first, every `Link: rel="next"` followed, with no page or item cap. Each
//! page goes to the engine, which hands off its items and moves the
//! continuation in one write. What a repository answers in place of a page
//! is recorded on its row with any retry time it named, and the walk stops
//! there; a later sweep resumes it once that time has passed. Pull requests
//! the listing returns are kept, as their own kind. An engine error during
//! the walk is recorded on the source's row too, and the walk returns it
//! (FIX 7629).
//!
//! A long walk renews the sweep's lease before each request, and the page or
//! error write renews it again under the lease it was admitted under (FIX
//! 7628). Once another walker holds the sweep, this walk stops at once and
//! its continuation stays owed to that walker.
//!
//! The deployment's feedback credential goes only to the origin of its own
//! `github_issue` destination, for a repository bound there; every other
//! repository is read without one, and a managed vault has none. A next
//! link off the bound repository's listing is never followed.
use std::time::{Duration, UNIX_EPOCH};

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::feedback::{
    FeedbackTriageSourceErrorKind, FeedbackTriageSourceFault, GithubIssueKind, GithubIssuePage,
    GithubIssueRevision, GithubSweepContinuation,
};
use reqwest::header::{ACCEPT, ETAG, HeaderMap, LINK, RETRY_AFTER, USER_AGENT};
use serde::Deserialize;
use serde::de::IgnoredAny;
use zeroize::Zeroizing;

use crate::feedback_delivery::FeedbackDestination;
use crate::server::SyncServer;

/// The first page's query: every state, oldest first so an edit never
/// reorders the walk, at GitHub's largest page. A page is a traversal unit,
/// never a total.
const FIRST_PAGE: &str = "state=all&sort=created&direction=asc&per_page=100";
/// What one request may take, as the feedback transport's client allows.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// GitHub Enterprise's prefix of its REST paths.
const ENTERPRISE_PREFIX: &str = "/api/v3/";

/// One repository `[feedback.triage]` binds.
pub(super) struct GithubIssueSource {
    /// `github:<owner>/<repo>`.
    name: String,
    /// The exact issues endpoint bound.
    url: reqwest::Url,
    /// The deployment's feedback credential: only for a repository on its
    /// `github_issue` destination's origin.
    bearer: Option<Zeroizing<String>>,
}

/// One entry of a repository's issue listing as GitHub sends it: the fields
/// the triage keeps. A pull request's entry carries a `pull_request` key.
#[derive(Deserialize)]
struct ListedIssue {
    id: u64,
    node_id: String,
    number: u64,
    html_url: String,
    title: String,
    body: Option<String>,
    state: String,
    updated_at: String,
    #[serde(default)]
    pull_request: Option<IgnoredAny>,
}

impl ListedIssue {
    fn revision(self, repo: &str) -> GithubIssueRevision {
        GithubIssueRevision {
            repo: repo.to_owned(),
            id: self.id,
            node_id: self.node_id,
            number: self.number,
            html_url: self.html_url,
            title: self.title,
            body: self.body,
            state: self.state,
            updated_at: self.updated_at,
            kind: if self.pull_request.is_some() {
                GithubIssueKind::PullRequest
            } else {
                GithubIssueKind::Issue
            },
        }
    }
}

/// How a skipped entry is named: `#<number>`, else `id <id>`, else its place
/// on the page. Nothing else of the entry is kept.
fn entry_name(entry: &serde_json::Value, place: usize) -> String {
    if let Some(number) = entry.get("number").and_then(serde_json::Value::as_u64) {
        return format!("#{number}");
    }
    if let Some(id) = entry.get("id").and_then(serde_json::Value::as_u64) {
        return format!("id {id}");
    }
    format!("entry {place}")
}

/// The client every source's walk shares: redirects off, as the feedback
/// transport's.
pub(super) fn client() -> oneiron::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| {
            oneiron::Error::InvalidConfig("the feedback sweep's HTTP client did not build".into())
        })
}

impl GithubIssueSource {
    /// Every repository `[feedback.triage]` binds, in its order. The config
    /// refused any other entry when it loaded.
    pub(super) fn bound(server: &SyncServer) -> Vec<Self> {
        // The credential, and the one origin it may go to.
        let credential = server
            .feedback
            .as_deref()
            .filter(|host| host.config.destination == FeedbackDestination::GithubIssue)
            .and_then(|host| {
                let origin = reqwest::Url::parse(&host.config.endpoint).ok()?.origin();
                Some((origin, host.bearer.as_ref()?))
            });
        server
            .feedback_triage
            .github_sources
            .iter()
            .filter_map(|endpoint| {
                let name = crate::config::github_issue_source(endpoint)?;
                let url = reqwest::Url::parse(endpoint).ok()?;
                let bearer = credential
                    .as_ref()
                    .filter(|(origin, _)| *origin == url.origin())
                    .map(|&(_, bearer)| bearer.clone());
                Some(Self { name, url, bearer })
            })
            .collect()
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// One page of the listing: the first while `from` names no next page,
    /// else the page it names. The page's body is read whole. What the
    /// repository answers in place of a page is the fault its row records.
    fn changes(
        &self,
        client: &reqwest::blocking::Client,
        from: Option<&GithubSweepContinuation>,
        now: u64,
    ) -> Result<GithubIssuePage, FeedbackTriageSourceFault> {
        let url = match from.and_then(|read| read.next.as_deref()) {
            Some(next) => self
                .follows(next)
                .ok_or(fault(FeedbackTriageSourceErrorKind::Unreadable, None))?,
            None => {
                let mut url = self.url.clone();
                url.set_query(Some(FIRST_PAGE));
                url
            }
        };
        let mut request = client
            .get(url.clone())
            .header(USER_AGENT, "oneiron-feedback")
            .header(ACCEPT, "application/vnd.github+json");
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.as_str());
        }
        let response = request
            .send()
            .map_err(|_| fault(FeedbackTriageSourceErrorKind::Transport, None))?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(refusal(status, response.headers(), now));
        }
        let unreadable = fault(FeedbackTriageSourceErrorKind::Unreadable, Some(status));
        let next = match next_link(response.headers(), unreadable)? {
            // A page that names itself next would be walked forever.
            Some(link) => match self.follows(&link) {
                Some(next) if next != url => Some(next.to_string()),
                _ => return Err(unreadable),
            },
            None => None,
        };
        let etag = header(response.headers(), ETAG.as_str()).map(str::to_owned);
        // Each entry parses on its own: one that does not is skipped by its
        // number, id or place, and the rest of the page goes on (FIX 7631).
        let listed: Vec<serde_json::Value> = response.json().map_err(|_| unreadable)?;
        let mut items = Vec::with_capacity(listed.len());
        let mut skipped = Vec::new();
        for (place, entry) in listed.into_iter().enumerate() {
            let named = entry_name(&entry, place);
            match serde_json::from_value::<ListedIssue>(entry) {
                Ok(issue) => items.push(issue.revision(&self.name)),
                Err(_) => skipped.push(named),
            }
        }
        Ok(GithubIssuePage {
            source: self.name.clone(),
            read: from.cloned(),
            items,
            next,
            etag,
            skipped,
        })
    }

    /// `link` when it is a page of this repository's listing: on the bound
    /// origin, at the bound path or GitHub's `/repositories/<id>/issues` form
    /// of it (under `/api/v3` when the bound path is), with no credentials or
    /// fragment. A link anywhere else is never followed, so the credential
    /// never leaves its origin.
    fn follows(&self, link: &str) -> Option<reqwest::Url> {
        let url = reqwest::Url::parse(link).ok()?;
        if url.origin() != self.url.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        if url.path() == self.url.path() {
            return Some(url);
        }
        let path = if self.url.path().starts_with(ENTERPRISE_PREFIX) {
            url.path().strip_prefix(ENTERPRISE_PREFIX)?
        } else {
            url.path().strip_prefix('/')?
        };
        let id = path
            .strip_prefix("repositories/")?
            .strip_suffix("/issues")?;
        (!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())).then_some(url)
    }
}

/// Walks `source` from its continuation to the last page of its listing,
/// one page and one write at a time. With no skill bound it reads nothing.
/// A source still inside a retry time it named waits for a later sweep.
/// What it answers in place of a page is recorded on its row and ends this
/// walk; an engine error ends it too, is recorded on its row, and returns.
/// Before each request the sweep's lease is renewed; a lease another walker
/// holds ends this walk, writing nothing more.
pub(super) fn sweep(
    server: &SyncServer,
    client: &reqwest::blocking::Client,
    admitted: &DreamerAdmittedAttempt,
    source: &GithubIssueSource,
) -> oneiron::Result<()> {
    let vault = server.vault();
    // `None`: no skill is bound, and the sweep reads no source. A read that
    // fails is recorded on the row as the later engine calls are (FIX 9367).
    let row = match vault.feedback_triage_source(admitted, source.name()) {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(()),
        Err(error) => return Err(engine_failed(vault, admitted, source, error)),
    };
    if row
        .retry_after
        .is_some_and(|at| at > vault.now_recorded_at())
    {
        return Ok(());
    }
    let mut read = row.github;
    loop {
        match vault.renew_feedback_triage_sweep(admitted) {
            Ok(true) => {}
            // Another walker holds the sweep: the continuation is its own.
            Ok(false) => return Ok(()),
            Err(error) => return Err(engine_failed(vault, admitted, source, error)),
        }
        let now = vault.now_recorded_at();
        let page = match source.changes(client, read.as_ref(), now) {
            Ok(page) => page,
            Err(fault) => {
                tracing::debug!(
                    source = source.name(),
                    kind = ?fault.kind,
                    status = ?fault.status,
                    "a feedback source answered no page"
                );
                return vault.record_feedback_triage_source_error(
                    admitted,
                    source.name(),
                    &fault,
                    now,
                );
            }
        };
        let last = page.next.is_none();
        let written = match vault.record_feedback_triage_github_page(admitted, &page, now) {
            Ok(written) => written,
            Err(error) => return Err(engine_failed(vault, admitted, source, error)),
        };
        // `None`: another walk moved the continuation since this one read
        // it, and goes on from there; another walker holds the sweep now;
        // or the skill was unbound meanwhile.
        let Some(row) = written else {
            return Ok(());
        };
        if last {
            return Ok(());
        }
        read = row.github;
    }
}

/// FIX 7629: the engine's own failure while it walked `source`, recorded on
/// the source's row as `Engine` at a fresh time, with no status and no retry
/// time. The walk answers `error` itself; a record that fails too cannot
/// make the store look sound, and is only logged by its kind.
fn engine_failed(
    vault: &oneiron::Vault,
    admitted: &DreamerAdmittedAttempt,
    source: &GithubIssueSource,
    error: oneiron::Error,
) -> oneiron::Error {
    let engine = fault(FeedbackTriageSourceErrorKind::Engine, None);
    let now = vault.now_recorded_at();
    if let Err(unrecorded) =
        vault.record_feedback_triage_source_error(admitted, source.name(), &engine, now)
    {
        tracing::warn!(
            source = source.name(),
            kind = ?error.kind(),
            record_kind = ?unrecorded.kind(),
            "a feedback source's engine error was not recorded on its row"
        );
    }
    error
}

fn fault(kind: FeedbackTriageSourceErrorKind, status: Option<u16>) -> FeedbackTriageSourceFault {
    FeedbackTriageSourceFault {
        kind,
        status,
        retry_after: None,
    }
}

/// What an answer that is not a page means for its source: a rate limit,
/// with the retry time it named; a credential the repository wants and the
/// deployment lacks; or any other refusal. GitHub sends its rate headers on
/// every answer, so only a 429, or a 403 with no requests left or with a
/// `Retry-After`, is a rate limit.
fn refusal(status: u16, headers: &HeaderMap, now: u64) -> FeedbackTriageSourceFault {
    let retry = header(headers, RETRY_AFTER.as_str());
    let exhausted = header(headers, "x-ratelimit-remaining") == Some("0");
    if status == 429 || (status == 403 && (exhausted || retry.is_some())) {
        let retry_after = retry
            .and_then(|value| retry_at(value, now))
            .or_else(|| header(headers, "x-ratelimit-reset").and_then(|value| value.parse().ok()));
        return FeedbackTriageSourceFault {
            kind: FeedbackTriageSourceErrorKind::RateLimited,
            status: Some(status),
            retry_after,
        };
    }
    let kind = if matches!(status, 401 | 403 | 404) {
        FeedbackTriageSourceErrorKind::AuthUnavailable
    } else {
        FeedbackTriageSourceErrorKind::Upstream
    };
    fault(kind, Some(status))
}

/// The vault second a `Retry-After` names: seconds from now, or an HTTP
/// date.
fn retry_at(value: &str, now: u64) -> Option<u64> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(now.saturating_add(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

/// `name`'s value, when it is text.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

/// The page's `Link: rel="next"` target; `None` on the last page. A Link
/// naming a next page the sweep cannot read is `unreadable`: the walk never
/// takes it for the end.
fn next_link(
    headers: &HeaderMap,
    unreadable: FeedbackTriageSourceFault,
) -> Result<Option<String>, FeedbackTriageSourceFault> {
    let mut next = None;
    for value in headers.get_all(LINK) {
        let value = value.to_str().map_err(|_| unreadable)?;
        for link in value.split(',') {
            let mut parts = link.split(';');
            let target = parts.next().unwrap_or_default().trim();
            let names_next = parts.any(|param| {
                param.trim().strip_prefix("rel=").is_some_and(|rel| {
                    rel.trim_matches('"')
                        .split_ascii_whitespace()
                        .any(|rel| rel.eq_ignore_ascii_case("next"))
                })
            });
            if !names_next {
                continue;
            }
            let target = target
                .strip_prefix('<')
                .and_then(|target| target.strip_suffix('>'))
                .ok_or(unreadable)?;
            if next.replace(target.to_owned()).is_some() {
                return Err(unreadable);
            }
        }
    }
    Ok(next)
}
