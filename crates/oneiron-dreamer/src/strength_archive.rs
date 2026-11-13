//! The consolidation strength archive (untangle 6.9c, F6): archives the
//! Dreamer's old, weak claims through derive batches.
//!
//! The job pages `vault.consolidation.strength.observations.page`. It keeps
//! a claim when the page judges its observed sources current, it has at
//! least one observed source, its evidence has been quiet for the policy's
//! window at the attempt's clock, and its strength scores strictly below the
//! policy's `archive_below`. It commits one page's kept claims as the
//! Archive items of one `vault.derive.commit`, each with the page's pins.
//! The engine rechecks every pin, source, fence and score in each item's
//! savepoint and refuses an item that no longer holds, with a receipt that
//! names why; a refusal lands nothing, and the job goes on.
//!
//! A repeat of the job archives nothing twice: an archived claim no longer
//! reads live, so no later page offers it.

use std::collections::BTreeMap;
use std::fmt;

use oneiron_remote::OneironClient;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The read the job pages.
pub const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.strength.observations.page";
/// The commit the job lands its Archive items with.
pub const DERIVE_COMMIT_VERB: &str = "vault.derive.commit";

/// The most claims one page offers, so one page's Archive items always fit
/// one derive batch (the engine takes at most 256 items).
const PAGE_LIMIT: u64 = 200;

/// The page's status for a claim whose observed sources all still read
/// unchanged.
const CURRENT: &str = "current";

/// What the host gives one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input {
    /// The attempt's clock, in Unix milliseconds: the quiet window and the
    /// recency signal are measured against it.
    pub now_ms: u64,
}

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Claims the pages offered.
    pub examined: u64,
    /// Archive items the engine landed.
    pub archived: u64,
    /// Archive items the engine refused, each with its receipt.
    pub refused: u64,
    /// Derive batches committed.
    pub batches: u64,
}

/// Why a run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The client refused a call; `code` and `message` are the engine's.
    Client {
        verb: &'static str,
        code: String,
        message: String,
    },
    /// A verb's answer did not read as the job reads it.
    Decode { verb: &'static str, message: String },
}

impl Error {
    /// The engine's code for a refused call, such as `LEASE_REQUIRED` or
    /// `FORBIDDEN`; `None` for an answer that did not decode.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Client { code, .. } => Some(code),
            Self::Decode { .. } => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client {
                verb,
                code,
                message,
            } => write!(formatter, "{verb} refused ({code}): {message}"),
            Self::Decode { verb, message } => write!(
                formatter,
                "{verb} answered what the strength archive cannot read: {message}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Runs the strength archive once over `client`, the job client of one
/// admitted strength attempt.
///
/// # Errors
///
/// [`Error::Client`] when the client refuses a call (the attempt's lease
/// ended, the Dreamer's reach is gone, a storage error); [`Error::Decode`]
/// when an answer does not read as a page or a commit view, or a page's
/// cursor does not advance. Batches committed before the error stay
/// committed.
pub fn run(client: &OneironClient, input: Input) -> Result<Outcome, Error> {
    let mut outcome = Outcome::default();
    let mut cursor: Option<String> = None;
    loop {
        let page = read_page(client, cursor.as_deref())?;
        outcome.examined += page.claims.len() as u64;
        let items = archive_items(&page, input.now_ms);
        if !items.is_empty() {
            let view = commit(client, items)?;
            outcome.batches += 1;
            for item in &view.items {
                if item.landed {
                    outcome.archived += 1;
                } else {
                    outcome.refused += 1;
                }
            }
        }
        match page.next {
            None => return Ok(outcome),
            Some(next) if cursor.as_deref() == Some(next.as_str()) => {
                return Err(Error::Decode {
                    verb: OBSERVATIONS_PAGE_VERB,
                    message: "the page cursor did not advance".to_owned(),
                });
            }
            Some(next) => cursor = Some(next),
        }
    }
}

fn read_page(client: &OneironClient, cursor: Option<&str>) -> Result<Page, Error> {
    let answer = call(
        client,
        OBSERVATIONS_PAGE_VERB,
        json!({ "cursor": cursor, "limit": PAGE_LIMIT }),
    )?;
    decode::<PageEnvelope>(OBSERVATIONS_PAGE_VERB, answer).map(|envelope| envelope.value)
}

/// Commits `items` as one batch. The bound client takes the batch itself:
/// its binding is the live run, so no `live_run` attachment wraps it.
fn commit(client: &OneironClient, items: Vec<Value>) -> Result<CommitView, Error> {
    let answer = call(
        client,
        DERIVE_COMMIT_VERB,
        json!({ "items": items, "sources": [] }),
    )?;
    decode(DERIVE_COMMIT_VERB, answer)
}

fn call(client: &OneironClient, verb: &'static str, input: Value) -> Result<Value, Error> {
    client
        .agent_verb(verb, input)
        .map_err(|error| Error::Client {
            verb,
            code: error.code,
            message: error.message,
        })
}

fn decode<T: DeserializeOwned>(verb: &'static str, answer: Value) -> Result<T, Error> {
    serde_json::from_value(answer).map_err(|error| Error::Decode {
        verb,
        message: error.to_string(),
    })
}

/// The Archive items for `page`'s kept claims, in page order.
fn archive_items(page: &Page, now_ms: u64) -> Vec<Value> {
    page.claims
        .iter()
        .filter_map(|claim| archive_item(page, claim, now_ms))
        .collect()
}

/// The Archive item for `claim`, or `None` when the job keeps the claim.
fn archive_item(page: &Page, claim: &ObservedClaim, now_ms: u64) -> Option<Value> {
    if claim.status != CURRENT {
        return None;
    }
    let (Some(observed), Some(pin)) = (claim.signals.as_ref(), claim.pin.as_ref()) else {
        return None;
    };
    if observed.source_count == 0 || !quiet(claim.last_activity_ms, now_ms, page.policy.quiet_ms) {
        return None;
    }
    let signals = StrengthSignals::from_observed(&claim.predicate, observed, now_ms, &page.config);
    let score = signals.score(&page.config.weights);
    if !score.is_finite() || score >= page.policy.archive_below {
        return None;
    }
    Some(json!({
        "kind": "archive",
        "spec": {
            "local": format!("archive-{}", claim.claim),
            "claim": { "stored": claim.claim },
            "signals": signals,
            "score": score,
            "observation_pin": pin,
            "policy_pin": page.policy_pin,
            "config_pin": page.config_pin,
        },
    }))
}

/// Whether evidence last active at `last_activity_ms` has been quiet for
/// `quiet_ms` at `now_ms`; a clock behind the activity is not quiet.
fn quiet(last_activity_ms: u64, now_ms: u64, quiet_ms: u64) -> bool {
    now_ms
        .checked_sub(last_activity_ms)
        .is_some_and(|age| age >= quiet_ms)
}

/// The four strength signals an Archive item carries.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
struct StrengthSignals {
    type_prior: f64,
    frequency: f64,
    recency: f64,
    diversity: f64,
}

impl StrengthSignals {
    /// The engine's signals for the page's evidence of one claim, computed
    /// as the engine computes them (`StrengthSignals::from_evidence` in
    /// `oneiron::dreamer_consolidation::selection`), operation for operation.
    fn from_observed(
        predicate: &str,
        observed: &ObservedSignals,
        now_ms: u64,
        config: &SelectionConfig,
    ) -> Self {
        Self {
            type_prior: config
                .type_priors
                .get(predicate)
                .copied()
                .unwrap_or(config.default_type_prior),
            frequency: (observed.source_count as f64 / config.frequency_scale as f64).min(1.0),
            recency: 1.0
                - (now_ms.saturating_sub(observed.latest_learned_at_ms) as f64
                    / config.recency_window_ms as f64)
                    .min(1.0),
            diversity: (observed.distinct_diversity as f64 / config.diversity_scale as f64)
                .min(1.0),
        }
    }

    /// The weighted sum the engine's `strength_score` computes, in its order.
    fn score(self, weights: &StrengthWeights) -> f64 {
        self.type_prior * weights.type_prior
            + self.frequency * weights.frequency
            + self.recency * weights.recency
            + self.diversity * weights.diversity
    }
}

/// The scoped-read answer around a page.
#[derive(Deserialize)]
struct PageEnvelope {
    value: Page,
}

/// One observations page: the fields the job reads.
#[derive(Deserialize)]
struct Page {
    policy: StrengthPolicy,
    policy_pin: String,
    config: SelectionConfig,
    config_pin: String,
    claims: Vec<ObservedClaim>,
    next: Option<String>,
}

/// The effective strength policy.
#[derive(Deserialize)]
struct StrengthPolicy {
    archive_below: f64,
    quiet_ms: u64,
}

/// The live selection config: the fields the strength score reads.
#[derive(Deserialize)]
struct SelectionConfig {
    weights: StrengthWeights,
    type_priors: BTreeMap<String, f64>,
    default_type_prior: f64,
    frequency_scale: u64,
    diversity_scale: u64,
    recency_window_ms: u64,
}

#[derive(Deserialize)]
struct StrengthWeights {
    type_prior: f64,
    frequency: f64,
    recency: f64,
    diversity: f64,
}

/// One observed claim as the page judges it.
#[derive(Deserialize)]
struct ObservedClaim {
    claim: String,
    predicate: String,
    last_activity_ms: u64,
    status: String,
    signals: Option<ObservedSignals>,
    pin: Option<String>,
}

#[derive(Deserialize)]
struct ObservedSignals {
    source_count: u64,
    latest_learned_at_ms: u64,
    distinct_diversity: u64,
}

/// A commit's answer: the fields the job counts.
#[derive(Deserialize)]
struct CommitView {
    items: Vec<CommitItem>,
}

#[derive(Deserialize)]
struct CommitItem {
    landed: bool,
}
