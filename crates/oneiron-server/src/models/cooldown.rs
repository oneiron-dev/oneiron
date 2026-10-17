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
            #[cfg(test)]
            waits_move: None,
        })
    }

    /// Rests kept in `vault`'s side table, on its clock, judged by its
    /// world settings.
    #[must_use]
    pub fn in_vault(vault: Arc<Vault>) -> Arc<Self> {
        Arc::new(Self {
            vault: Some(vault),
            fallbacks: RwLock::default(),
            health: Mutex::default(),
            probes: AtomicU64::new(0),
            health_changed: tokio::sync::watch::Sender::new(0),
            recovered: tokio::sync::watch::Sender::new(0),
            #[cfg(test)]
            waits_move: None,
        })
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
        let end = start + wait;
        let mut changed = self.health_changed.subscribe();
        loop {
            let left = end.saturating_duration_since(tokio::time::Instant::now());
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

    /// The offer serving `wire_model`'s rest, while it rests: a limit's,
    /// else its health's. An unreadable row leaves the offer in rotation:
    /// the worst it costs is one more refusal.
    pub(super) fn resting(&self, offer: &OfferBinding, wire_model: &str) -> Option<Rest> {
        let vault = self.vault.as_ref()?;
        let key = key(offer, wire_model);
        self.limit_rest(vault, &key)
            .or_else(|| self.health_rest(&key, vault.now_recorded_at()))
    }

    /// The health rest of the offer at `key`, while it runs.
    fn health_rest(&self, key: &str, now: u64) -> Option<Rest> {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let held = health.get(key).filter(|held| held.until > now)?;
        Some(held.rest())
    }

    /// The health version, when the offer serving `wire_model` is on
    /// probation with its one probation request out. Read-only: it takes no
    /// slot.
    pub(super) fn probing(&self, offer: &OfferBinding, wire_model: &str) -> Option<u64> {
        let now = self.now()?;
        let key = key(offer, wire_model);
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health
            .get(&key)
            .filter(|held| held.until <= now && held.probe_out(now).is_some())?;
        Some(*self.health_changed.borrow())
    }

    /// The permit to send one request to the offer serving `wire_model` now
    /// (OF-305). Taken right before the request goes out, and held until it
    /// ends. An offer with no health row gets a permit that holds nothing.
    /// One whose health rest still runs is blocked. One on probation after
    /// its rest gets its one probation slot, and is busy while another call
    /// holds that slot.
    pub(super) fn try_probe(
        self: &Arc<Self>,
        offer: &OfferBinding,
        wire_model: &str,
    ) -> Result<ProbePermit, ProbeBlocked> {
        let mut permit = ProbePermit {
            rests: Arc::clone(self),
            key: key(offer, wire_model),
            slot: None,
        };
        let Some(now) = self.now() else {
            return Ok(permit);
        };
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = health.get_mut(&permit.key) else {
            return Ok(permit);
        };
        if held.until > now {
            return Err(ProbeBlocked::Resting(held.rest()));
        }
        if held.probe_out(now).is_some() {
            return Err(ProbeBlocked::Busy {
                seen: *self.health_changed.borrow(),
            });
        }
        let token = self.probes.fetch_add(1, Ordering::Relaxed);
        held.probing = Some(Probe { token, since: now });
        drop(health);
        permit.slot = Some(token);
        Ok(permit)
    }

    /// Frees the probation slot `token` holds on the offer at `key`, unless a
    /// stable recovery already cleared its row, and tells every waiting call
    /// that the offer's health changed.
    fn release_probe(&self, key: &str, token: u64) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = health.get_mut(key)
            && held.probing.is_some_and(|probe| probe.token == token)
        {
            held.probing = None;
        }
        self.health_changed
            .send_modify(|seen| *seen = seen.wrapping_add(1));
    }

    /// The live health of the offer serving `wire_model`, for the status
    /// route: whether it is healthy, down or recovering, and any limit rest
    /// it is held by. Read-only: it takes no probation slot and probes
    /// nothing.
    pub(super) fn offer_health(&self, offer: &OfferBinding, wire_model: &str) -> RungHealth {
        let mut status = RungHealth {
            state: HealthState::Healthy,
            strikes: 0,
            until: None,
            successes: 0,
            probing: false,
            limit: None,
        };
        let Some(vault) = self.vault.as_ref() else {
            return status;
        };
        let key = key(offer, wire_model);
        status.limit = self.limit_rest(vault, &key).map(|rest| LimitHold {
            until: rest.until,
            reset: rest.source.as_str(),
            spent: rest.spent,
        });
        let now = vault.now_recorded_at();
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = health.get(&key) {
            status.strikes = held.strikes;
            status.successes = held.successes;
            status.probing = held.probe_out(now).is_some();
            if held.until > now {
                status.state = HealthState::Down;
                status.until = Some(held.until);
            } else {
                status.state = HealthState::Recovering;
            }
        }
        status
    }

    /// The limit rest kept at `key`, while it runs.
    fn limit_rest(&self, vault: &Vault, key: &str) -> Option<Rest> {
        let rest = match vault.sync_state_get(key) {
            Ok(Some(bytes)) => rmp_serde::from_slice::<Rest>(&bytes).ok(),
            Ok(None) => None,
            Err(_) => {
                tracing::warn!(
                    reason = "cooldown_unreadable",
                    "an offer's cooldown could not be read; it stays in rotation"
                );
                None
            }
        }?;
        (rest.until > vault.now_recorded_at()).then_some(rest)
    }

    /// Rests the offer serving `wire_model` after a limit refusal: spent
    /// credit parks it until the owner clears it; a spent window rests it
    /// until the first reset the refusal names that is still ahead; a rate
    /// limit rests it until that reset or for the wait it asks, never past
    /// the vault's longest rest, and with neither for a backoff that doubles
    /// with each refusal in a row from the vault's default, with jitter. A
    /// rest already running longer stays. The owner's question waits until
    /// every rung of the call has parked ([`Self::ask`]). `None` when no
    /// vault keeps rests or the write failed.
    pub(super) fn rest(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
        refusal: Refusal<'_>,
    ) -> Option<Rest> {
        let vault = self.vault.as_ref()?;
        let policy = vault.provider_cooldown_policy().unwrap_or_default();
        let now = vault.now_recorded_at();
        let key = key(offer, wire_model);
        let kept = vault.try_with_write_txn_grouped(|txn| {
            let running = vault
                .sync_state_get_in_write_txn(txn, &key)?
                .and_then(|bytes| rmp_serde::from_slice::<Rest>(&bytes).ok());
            // A refusal soon after the last rest ended is one more in a row.
            let strikes = running
                .filter(|running| running.until.saturating_add(policy.max_secs) >= now)
                .map_or(0, |running| running.strikes.saturating_add(1));
            let rest = rest_end(
                now,
                (policy.default_secs, policy.max_secs),
                refusal,
                strikes,
                &key,
            );
            if let Some(running) = running.filter(|running| running.until >= rest.until) {
                return Ok(running);
            }
            let bytes = rmp_serde::to_vec_named(&rest)
                .map_err(|_| oneiron::Error::InvariantViolation("encode an offer's cooldown"))?;
            vault.sync_state_put_in_write_txn(txn, &key, &bytes)?;
            Ok::<_, oneiron::Error>(rest)
        });
        match kept {
            Ok(rest) => Some(rest),
            Err(_) => {
                tracing::warn!(
                    reason = "cooldown_unwritable",
                    "an offer's cooldown could not be kept; the next call may reach it"
                );
                None
            }
        }
    }

    /// Rests the offer serving `wire_model` for its health after its provider
    /// was down: for a backoff that doubles with each failure in a row from
    /// [`HEALTH_REST_SECS`] up to [`HEALTH_REST_MAX_SECS`], with jitter. A
    /// failure while it recovers is one more in a row, and its answers since
    /// count no more. A probation slot that is held stays held until its
    /// request ends. `None` when no vault keeps rests.
    pub(super) fn failed_down(&self, offer: &OfferBinding, wire_model: &str) -> Option<Rest> {
        self.failed_down_at(&key(offer, wire_model))
    }

    fn failed_down_at(&self, key: &str) -> Option<Rest> {
        let now = self.now()?;
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let held = health.entry(key.to_owned()).or_default();
        let strikes = held.strikes.saturating_add(1);
        let backoff = HEALTH_REST_SECS
            .saturating_mul(1u64 << (strikes - 1).min(16))
            .min(HEALTH_REST_MAX_SECS);
        let mut digest = blake3::Hasher::new();
        digest.update(key.as_bytes());
        digest.update(&now.to_le_bytes());
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&digest.finalize().as_bytes()[..8]);
        let until = now
            .saturating_add(backoff)
            .saturating_add(u64::from_le_bytes(seed) % (backoff / 4 + 1));
        *held = Health {
            strikes,
            until,
            successes: 0,
            first_success_at: None,
            probing: held.probing,
        };
        tracing::warn!(
            strikes,
            until,
            "a provider is down; its offer rests for its health"
        );
        Some(Rest {
            until,
            source: ResetSource::Unhealthy,
            strikes,
            spent: None,
        })
    }

    /// The offer serving `wire_model` answered. One that was down counts the
    /// answer toward its recovery; its [`STABLE_SUCCESSES`]-th in a row, at
    /// least [`STABLE_SECS`] after the first, is a stable recovery: its
    /// strikes clear and [`Self::recoveries`] hears it.
    pub(super) fn succeeded(&self, offer: &OfferBinding, wire_model: &str) {
        self.succeeded_at(&key(offer, wire_model));
    }

    fn succeeded_at(&self, key: &str) {
        let Some(now) = self.now() else {
            return;
        };
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = health.get_mut(key) else {
            return;
        };
        held.successes = held.successes.saturating_add(1);
        let first = *held.first_success_at.get_or_insert(now);
        if held.successes < STABLE_SUCCESSES || now.saturating_sub(first) < STABLE_SECS {
            return;
        }
        let strikes = held.strikes;
        health.remove(key);
        drop(health);
        tracing::info!(
            strikes,
            "a provider recovered stably; the work its outage stopped resumes"
        );
        self.recovered
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Hears each stable recovery of an offer whose provider was down.
    #[must_use]
    pub fn recoveries(&self) -> tokio::sync::watch::Receiver<u64> {
        self.recovered.subscribe()
    }

    /// The configured models a parked offer may fall back to, as the
    /// runtime built them.
    pub(super) fn offer_fallbacks(&self, rungs: Vec<FallbackRung>) {
        *self
            .fallbacks
            .write()
            .unwrap_or_else(PoisonError::into_inner) = rungs;
    }

    /// The owner's question about the offer `asked` names, parked on a spent
    /// window or spent credit (`rest`), asked once every rung of the call
    /// that met it has parked: which offer, what was spent, when it is back,
    /// and the choices. `use_fallback` is among them while a model on a
    /// provider outside the call's ladder (`own`) has usage left and `fits`
    /// the call: it speaks the seat's wire, keeps a role's work on the device
    /// when it must stay there, and accepts the request. A question already
    /// open stays as it was asked. Nothing when the rest spent nothing or no
    /// vault keeps rests.
    pub(super) fn ask(
        &self,
        offer: &OfferBinding,
        rest: Rest,
        asked: Asked<'_>,
        own: &[&str],
        fits: &dyn Fn(&OfferLadder) -> bool,
    ) {
        let (Some(vault), Some(spent)) = (self.vault.as_ref(), rest.spent) else {
            return;
        };
        let id = key(offer, asked.wire_model)
            .trim_start_matches(PREFIX)
            .to_owned();
        if matches!(vault.sync_state_get(&question_key(&id)), Ok(Some(_))) {
            return;
        }
        let fallbacks = self.usage_left(own, fits);
        let mut choices = match spent {
            SpentKind::Window => vec![
                QuotaChoice::Wait,
                QuotaChoice::AddAccount,
                QuotaChoice::PayAsYouGo,
            ],
            SpentKind::Credit => vec![QuotaChoice::TopUp, QuotaChoice::AddAccount],
        };
        if !fallbacks.is_empty() {
            choices.push(QuotaChoice::UseFallback);
        }
        let question = QuotaQuestion {
            id,
            asked_at: vault.now_recorded_at(),
            provider: asked.provider.to_owned(),
            model: asked.wire_model.to_owned(),
            route: format!("{}@{}", offer.route.adapter(), offer.route.origin()),
            spent,
            resets_at: (rest.source != ResetSource::Parked).then_some(rest.until),
            choices,
            fallbacks,
        };
        let kept = rmp_serde::to_vec_named(&question)
            .ok()
            .map(|bytes| vault.sync_state_put(&question_key(&question.id), &bytes));
        if !matches!(kept, Some(Ok(()))) {
            tracing::warn!(
                reason = "quota_question_unwritable",
                "a parked offer's quota question could not be kept"
            );
        }
    }

    /// The models on providers other than `own` whose offers are in rotation
    /// now and that `fits` the parked call.
    fn usage_left(&self, own: &[&str], fits: &dyn Fn(&OfferLadder) -> bool) -> Vec<QuotaFallback> {
        self.fallbacks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|rung| !own.contains(&rung.provider.as_str()))
            .filter(|rung| {
                rung.ladder
                    .upgrade()
                    .is_some_and(|ladder| !ladder.rests_now() && fits(ladder.as_ref()))
            })
            .map(|rung| QuotaFallback {
                provider: rung.provider.clone(),
                model: rung.model.as_str().to_owned(),
            })
            .collect()
    }

    /// The model the owner named for the offer serving `wire_model` while it
    /// is parked (`use_fallback`), while the runtime serves it.
    pub(super) fn fallback_for(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
    ) -> Option<Arc<OfferLadder>> {
        let vault = self.vault.as_ref()?;
        let key = key(offer, wire_model);
        let model = vault
            .model_fallback(key.trim_start_matches(PREFIX))
            .ok()??;
        self.fallbacks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|rung| rung.model.as_str() == model.as_str())?
            .ladder
            .upgrade()
    }

    /// The owner's open quota questions, oldest first. An unreadable row is
    /// skipped.
    #[must_use]
    pub fn questions(&self) -> Vec<QuotaQuestion> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let now = vault.now_recorded_at();
        let mut questions: Vec<QuotaQuestion> = vault
            .sync_state_keys_with_prefix(QUESTION_PREFIX)
            .unwrap_or_default()
            .iter()
            .filter_map(|key| vault.sync_state_get(key).ok().flatten())
            .filter_map(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok())
            // A window that reset answered its own question.
            .filter(|question| question.resets_at.is_none_or(|reset| reset > now))
            .collect();
        questions.sort_by_key(|question| question.asked_at);
        questions
    }

    /// The owner's answer to question `id`: it closes the question, a
    /// top-up or pay-as-you-go puts its offer back in rotation now, and
    /// `use_fallback` keeps `fallback` (one of the question's fallbacks) as
    /// where the offer's calls go while it is parked. `false` when no such
    /// question is open, the choice is not one it offers, or a
    /// `use_fallback` names no model it offers.
    pub fn answer(
        &self,
        id: &str,
        choice: QuotaChoice,
        fallback: Option<&str>,
    ) -> oneiron::Result<bool> {
        let Some(vault) = &self.vault else {
            return Ok(false);
        };
        let question = vault
            .sync_state_get(&question_key(id))?
            .and_then(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok());
        let Some(question) = question.filter(|question| question.choices.contains(&choice)) else {
            return Ok(false);
        };
        if choice == QuotaChoice::UseFallback {
            let Some(model) = fallback.filter(|model| {
                question
                    .fallbacks
                    .iter()
                    .any(|offered| offered.model == *model)
            }) else {
                return Ok(false);
            };
            vault.set_model_fallback(&question.id, model)?;
        }
        if choice.unparks() {
            vault.sync_state_delete(&format!("{PREFIX}{}", question.id))?;
        }
        vault.sync_state_delete(&question_key(&question.id))?;
        Ok(true)
    }

    /// Now, on the clock rests are kept on.
    pub(super) fn now(&self) -> Option<u64> {
        self.vault.as_ref().map(|vault| vault.now_recorded_at())
    }

    /// The longest a call waits for a cooling chain's first offer back. No
    /// wait when nothing keeps rests.
    pub(super) fn max_wait_secs(&self) -> u64 {
        self.vault.as_ref().map_or(0, |vault| {
            vault
                .provider_cooldown_policy()
                .unwrap_or_default()
                .max_wait_secs
        })
    }

    /// Whether a fallback may take `request` off the device (world privacy,
    /// "Models": no silent fallback to a cloud model). A call that names its
    /// world goes where the world settings' one judge lets that world go,
    /// and only for a world this vault holds. One that names none may carry
    /// any world's text, so it goes only while no world stays on the device.
    /// A call nobody can judge here stays; with no vault, no world's text
    /// is here to keep.
    pub(super) fn world_may_leave(&self, request: &LlmRequest) -> bool {
        let world = request.envelope.scope.world;
        match &self.vault {
            Some(vault) => matches!(vault.model_call_may_leave_device(world), Ok(true)),
            None => world.is_none(),
        }
    }
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
        return rest(
            now.saturating_add(seconds).min(longest),
            ResetSource::RetryAfter,
        );
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
