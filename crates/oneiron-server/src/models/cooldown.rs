//! Offers a provider refused for a quota or a limit (OF-305). Each rests in
//! a vault side table so a restart keeps it: a rate limit for a backoff that
//! doubles with each refusal in a row, with jitter, or for the wait it
//! names; a spent usage window until its reset; spent prepaid credit until
//! the owner tops up or clears it. Once every rung of a call has parked, a
//! spent window or credit leaves the owner a question ("add an account, top
//! up, wait, or use the usage left on another provider?"), read in
//! `GET /v1/ai/status`; a later rung that serves the call asks nothing.
//! Nothing here retries: the ladder hands the call on, and waits for the
//! first offer back while its deadline allows.
//!
//! An offer whose provider is down (a server error, a timeout, a cut stream,
//! an empty answer) rests for its health too, in memory: a short backoff
//! that doubles with each failure in a row. When the rest ends the offer is
//! on probation; a failure rests it again with one more strike, and
//! [`STABLE_SUCCESSES`] answers in a row over [`STABLE_SECS`] are a stable
//! recovery, which clears its strikes and tells [`OfferCooldowns::recoveries`]
//! so the memory work its outage stopped resumes. On probation it takes one
//! request at a time: the call that sends it holds the offer's probation
//! slot ([`ProbePermit`]) until the request ends, and a call that comes
//! meanwhile passes the offer to the next rung, or waits for that end.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::Duration;

use oneiron::llm::SpentKind;
use oneiron::llm::run_admission::OfferBinding;
use oneiron::{LlmRequest, ModelId, ModelLocality, Vault};
use serde::{Deserialize, Serialize};

use super::ladder::OfferLadder;
use super::status::{HealthState, LimitHold, RungHealth};

mod account_park;
mod offer_core;
mod quota_queue;
mod reply_budgets;
mod world_hold;

/// The engine's `MODEL_OFFER_COOLDOWN` side table: never replicated, and
/// runtime to a checkpoint, which keeps none.
const PREFIX: &str = "models:offer-cooldown:v1:";

/// The owner's open quota questions, one per parked offer, beside its rest
/// in the same table: this deployment's routing state too.
const QUESTION_PREFIX: &str = "models:offer-cooldown:v1:ask:";

/// A down provider's first health rest, in seconds; each failure in a row
/// doubles it.
const HEALTH_REST_SECS: u64 = 5;
/// The longest health rest, in seconds.
const HEALTH_REST_MAX_SECS: u64 = 60;
/// Answers in a row a recovering offer gives before its recovery is stable.
const STABLE_SUCCESSES: u32 = 3;
/// How long, in seconds, those answers span at least, from the first.
const STABLE_SECS: u64 = 30;
/// How long, in seconds, one probation request holds its offer's slot before
/// the slot is free again. Without it, a media job no poll came back for
/// would hold the slot until a restart.
const PROBE_HOLD_MAX_SECS: u64 = 1_800;

/// How long a wait for an offer back sleeps before it asks again whether
/// the call may still go out: well inside a stopped turn's grace.
pub(super) const WAIT_SLICE: Duration = Duration::from_secs(1);

/// What set a rest's end: the reset time the refusal named, the wait it
/// asked for, or the vault's default when it named neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ResetSource {
    ErrorTime,
    RetryAfter,
    Default,
    /// A rate limit that named no wait: the backoff for its refusals in a
    /// row.
    Backoff,
    /// Spent credit: parked until the owner clears it.
    Parked,
    /// A down provider: a health rest, for the backoff of its failures in a
    /// row.
    Unhealthy,
}

impl ResetSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ErrorTime => "error_time",
            Self::RetryAfter => "retry_after",
            Self::Default => "default",
            Self::Backoff => "backoff",
            Self::Parked => "parked",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// One offer's rest: when it is back in rotation, what set that, the
/// refusals in a row its backoff counts, and what was spent, if a window or
/// credit was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Rest {
    pub(super) until: u64,
    pub(super) source: ResetSource,
    #[serde(default)]
    pub(super) strikes: u32,
    #[serde(default)]
    pub(super) spent: Option<SpentKind>,
}

/// One offer's health after its provider was down: its failures in a row,
/// the end of its rest, and, once it answered again, its answers since and
/// when the first came. On probation, the one request out now.
#[derive(Clone, Copy, Debug, Default)]
struct Health {
    strikes: u32,
    until: u64,
    successes: u32,
    first_success_at: Option<u64>,
    probing: Option<Probe>,
}

/// The probation request out now: its slot's token and when it took it.
#[derive(Clone, Copy, Debug)]
struct Probe {
    token: u64,
    since: u64,
}

impl Health {
    /// The probation request out at `now`. A slot held past
    /// [`PROBE_HOLD_MAX_SECS`] is free again: its request is a job no poll
    /// came back for, and its end, if one comes, still counts.
    fn probe_out(&self, now: u64) -> Option<Probe> {
        self.probing
            .filter(|probe| now.saturating_sub(probe.since) < PROBE_HOLD_MAX_SECS)
    }

    fn rest(&self) -> Rest {
        Rest {
            until: self.until,
            source: ResetSource::Unhealthy,
            strikes: self.strikes,
            spent: None,
        }
    }
}

/// Why a call may not send to an offer right now, found at the send: its
/// health rest began after the walk judged it, or it is on probation and its
/// one probation request is out. `seen` is the health version at that
/// moment, so a wait for the request's end cannot miss it.
pub(super) enum ProbeBlocked {
    Resting(Rest),
    Busy { seen: u64 },
}

/// The right to send one request to an offer now (OF-305), held until the
/// request ends. A recovering offer grants one at a time: its probation
/// request. Dropping the permit frees that slot for the next call and
/// credits nothing. A healthy offer's permit holds no slot.
pub(super) struct ProbePermit {
    rests: Arc<OfferCooldowns>,
    key: String,
    /// The token of the probation slot this permit holds.
    slot: Option<u64>,
}

impl ProbePermit {
    /// The request answered: [`OfferCooldowns::succeeded`].
    pub(super) fn answered(self) {
        self.rests.succeeded_at(&self.key);
    }

    /// The request met its provider down: [`OfferCooldowns::failed_down`].
    pub(super) fn down(self) {
        self.rests.failed_down_at(&self.key);
    }
}

impl Drop for ProbePermit {
    fn drop(&mut self) {
        if let Some(token) = self.slot.take() {
            self.rests.release_probe(&self.key, token);
        }
    }
}

/// What a limit refusal said, for its offer's rest.
#[derive(Clone, Copy, Debug)]
pub(super) struct Refusal<'a> {
    pub(super) retry_after: Option<u64>,
    pub(super) resets_at: &'a [u64],
    pub(super) spent: Option<SpentKind>,
}

/// The owner's question about one parked offer (OF-305, OF-375): which
/// offer, what was spent, when it is back if it comes back, and the choices
/// the owner has. The host renders the words. A person-rung decision call
/// can produce this record later; the store is the queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaQuestion {
    pub id: String,
    pub asked_at: u64,
    pub provider: String,
    pub model: String,
    pub route: String,
    pub spent: SpentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
    pub choices: Vec<QuotaChoice>,
    /// The models on other providers with usage left when it was asked,
    /// that a `use_fallback` answer names one of.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<QuotaFallback>,
    /// The account parked with the offer, when its spent credit parks every
    /// offer billed to it (FIX 564): a top-up answer puts them all back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// A model on another provider with usage left: what a quota question's
/// `use_fallback` answer may send the parked offer's calls to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaFallback {
    pub provider: String,
    /// Its engine model id, `provider/name@revision`.
    pub model: String,
}

/// A configured model, as the runtime built it, that the owner may name as
/// a parked offer's fallback: a chat model by its own id, or one rung of a
/// media seat.
pub(super) struct FallbackRung {
    pub(super) provider: String,
    pub(super) model: ModelId,
    pub(super) ladder: Weak<OfferLadder>,
}

/// One answer the owner may give a quota question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaChoice {
    /// Wait for the window's reset; the offer stays parked until then.
    Wait,
    /// The owner topped up the account: the offer is back now.
    TopUp,
    /// The owner added another account or seat: the parked offer stays
    /// parked until its own reset or top-up.
    AddAccount,
    /// The owner added pay-as-you-go to the account: the offer is back now.
    PayAsYouGo,
    /// Use the usage left on another provider: while the offer is parked,
    /// its calls go to the model the answer names, one of the question's
    /// `fallbacks`. Setting it is the permission, paid models included.
    UseFallback,
}

impl QuotaChoice {
    /// Whether the owner's answer puts the offer back in rotation now.
    fn unparks(self) -> bool {
        matches!(self, Self::TopUp | Self::PayAsYouGo)
    }
}

/// Where a parked offer is, for its question: the rung that met the
/// refusal.
#[derive(Clone, Copy, Debug)]
pub(super) struct Asked<'a> {
    pub(super) provider: &'a str,
    pub(super) wire_model: &'a str,
}

/// Where a ladder keeps its offers' rests, and asks whether a call's world
/// may leave the device. Without a vault nothing is kept: a refusal still
/// hands its call on, and the next call starts fresh.
pub struct OfferCooldowns {
    vault: Option<Arc<Vault>>,
    /// The configured models a parked offer may fall back to.
    fallbacks: RwLock<Vec<FallbackRung>>,
    /// Each offer whose provider was down and has not stably recovered,
    /// by its row's key. In memory: a restart starts every offer healthy.
    health: Mutex<BTreeMap<String, Health>>,
    /// The next probation slot's token.
    probes: AtomicU64,
    /// The health version: it moves each time a probation request ends, for
    /// the calls that wait for one.
    health_changed: tokio::sync::watch::Sender<u64>,
    /// The count of stable recoveries, for the work an outage stopped.
    recovered: tokio::sync::watch::Sender<u64>,
    /// Which prefixes its offers hold warm in their providers' prompt
    /// caches (FIX 6029). In memory: a restart starts every prefix cold.
    pub(super) warmth: super::ladder::cache_warmth::CacheWarmth,
    /// The vault's model byte budgets its ladders' chat replies are read on
    /// (FIX 10626), the rows' defaults without a server.
    budgets: super::ModelHostBudgets,
    /// A test's vault clock, which a call's wait moves to the end it waited
    /// for, as time would.
    #[cfg(test)]
    waits_move: Option<Arc<oneiron::store::ports::ManualClock>>,
}

impl OfferCooldowns {
    #[must_use]
    pub fn unkept() -> Arc<Self> {
        Arc::new(Self {
            vault: None,
            fallbacks: RwLock::default(),
            health: Mutex::default(),
            probes: AtomicU64::new(0),
            health_changed: tokio::sync::watch::Sender::new(0),
            recovered: tokio::sync::watch::Sender::new(0),
            warmth: super::ladder::cache_warmth::CacheWarmth::default(),
            budgets: super::ModelHostBudgets::unhosted(),
            #[cfg(test)]
            waits_move: None,
        })
    }

    /// Rests kept in `vault`'s side table, on its clock, judged by its
    /// world settings.
    #[must_use]
    pub fn in_vault(vault: Arc<Vault>) -> Arc<Self> {
        Self::in_vault_with(vault, super::ModelHostBudgets::unhosted())
    }

    /// [`Self::in_vault`] for a vault on the test's `clock`: a call that
    /// waits for an offer back finds the clock at that offer's end.
    #[cfg(test)]
    pub(super) fn in_vault_on(
        vault: Arc<Vault>,
        clock: Arc<oneiron::store::ports::ManualClock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vault: Some(vault),
            fallbacks: RwLock::default(),
            health: Mutex::default(),
            probes: AtomicU64::new(0),
            health_changed: tokio::sync::watch::Sender::new(0),
            recovered: tokio::sync::watch::Sender::new(0),
            warmth: super::ladder::cache_warmth::CacheWarmth::default(),
            budgets: super::ModelHostBudgets::unhosted(),
            waits_move: Some(clock),
        })
    }

    /// Waits `wait`, for the offer back `at` then, asking `may_send` each
    /// slice of it: once it says no, the wait ends there. A call that passed
    /// an offer whose probation request was out at health version `seen`
    /// also stops waiting once that version moves (OF-305), so it never
    /// misses the request's end. Returns how long it waited.
    pub(super) async fn wait(
        &self,
        wait: Duration,
        at: u64,
        seen: Option<u64>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> Duration {
        let start = tokio::time::Instant::now();
        // An open call's wait for a probation request has no end of its own
        // (FIX 8213): only that request's end, or its caller, stops it.
        let end = start.checked_add(wait);
        let mut changed = self.health_changed.subscribe();
        loop {
            let left = end.map_or(WAIT_SLICE, |end| {
                end.saturating_duration_since(tokio::time::Instant::now())
            });
            if left.is_zero() {
                break;
            }
            if !may_send() || seen.is_some_and(|seen| *changed.borrow_and_update() != seen) {
                return start.elapsed();
            }
            let slice = left.min(WAIT_SLICE);
            if seen.is_some() {
                let _ = tokio::time::timeout(slice, changed.changed()).await;
            } else {
                tokio::time::sleep(slice).await;
            }
        }
        self.waited_until(at);
        wait
    }

    #[cfg(test)]
    fn waited_until(&self, at: u64) {
        if let Some(clock) = &self.waits_move {
            clock.set(at);
        }
    }

    #[cfg(not(test))]
    fn waited_until(&self, _at: u64) {}
}

/// Whether an offer takes the work off the device: a provider's own cloud.
/// The vault's own server and an in-process model keep it here.
pub(super) fn leaves_device(offer: &OfferBinding) -> bool {
    offer.locality == ModelLocality::ThirdParty
}

/// The end of a rest that starts `now`, under the vault's default and
/// longest rest, for the `strikes`-th refusal in a row. The backoff's
/// jitter comes from the offer's `key` and the time, so two offers refused
/// together come back apart.
fn rest_end(
    now: u64,
    (default_secs, max_secs): (u64, u64),
    refusal: Refusal<'_>,
    strikes: u32,
    key: &str,
) -> Rest {
    let rest = |until: u64, source: ResetSource| Rest {
        until,
        source,
        strikes,
        spent: refusal.spent,
    };
    if refusal.spent == Some(SpentKind::Credit) {
        return rest(u64::MAX, ResetSource::Parked);
    }
    let longest = now.saturating_add(max_secs);
    if let Some(reset) = refusal.resets_at.iter().find(|reset| **reset > now) {
        // A spent window is parked until its reset, however far.
        let until = if refusal.spent == Some(SpentKind::Window) {
            *reset
        } else {
            (*reset).min(longest)
        };
        return rest(until, ResetSource::ErrorTime);
    }
    if let Some(seconds) = refusal.retry_after.filter(|seconds| *seconds > 0) {
        // A spent window said as Retry-After rests until it resets, however
        // far, as one said as a reset time does (FIX 7795); a rate limit's
        // keeps the vault's longest rest.
        let until = now.saturating_add(seconds);
        let until = if refusal.spent == Some(SpentKind::Window) {
            until
        } else {
            until.min(longest)
        };
        return rest(until, ResetSource::RetryAfter);
    }
    if strikes == 0 {
        return rest(
            now.saturating_add(default_secs).min(longest),
            ResetSource::Default,
        );
    }
    let backoff = default_secs
        .max(1)
        .saturating_mul(1u64 << strikes.min(32))
        .min(max_secs.max(1));
    let mut digest = blake3::Hasher::new();
    digest.update(key.as_bytes());
    digest.update(&now.to_le_bytes());
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest.finalize().as_bytes()[..8]);
    let jitter = u64::from_le_bytes(seed) % (backoff / 4 + 1);
    rest(
        now.saturating_add(backoff.saturating_add(jitter))
            .min(longest),
        ResetSource::Backoff,
    )
}

/// Where question `id` is kept.
fn question_key(id: &str) -> String {
    format!("{QUESTION_PREFIX}{id}")
}

/// Where the owner's fallback for the offer question `id` asked about is
/// kept.
/// One row per deployment: the adapter and origin it goes out on, whose key
/// pays, and the model it is asked for.
fn key(offer: &OfferBinding, wire_model: &str) -> String {
    let mut digest = blake3::Hasher::new();
    for part in [
        offer.route.adapter(),
        offer.route.origin(),
        offer.credential_binding.as_deref().unwrap_or_default(),
        wire_model,
    ] {
        digest.update(part.as_bytes());
        digest.update(&[0]);
    }
    format!("{PREFIX}{}", digest.finalize().to_hex())
}
