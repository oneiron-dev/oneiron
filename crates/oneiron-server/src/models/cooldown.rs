//! Offers a provider refused for a quota or a limit (OF-305). Each rests in
//! a vault side table so a restart keeps it: a rate limit for a backoff that
//! doubles with each refusal in a row, with jitter, or for the wait it
//! names; a spent usage window until its reset; spent prepaid credit until
//! the owner tops up or clears it. A spent window or credit also leaves the
//! owner a question ("add an account, top up, or wait?"), read in
//! `GET /v1/ai/status`. Nothing here retries: the ladder hands the call on,
//! and waits for the first offer back while its deadline allows.
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::SpentKind;
use oneiron::llm::run_admission::OfferBinding;
use oneiron::{LlmRequest, ModelLocality, Vault};
use serde::{Deserialize, Serialize};

/// The engine's `MODEL_OFFER_COOLDOWN` side table: never replicated, and
/// runtime to a checkpoint, which keeps none.
const PREFIX: &str = "models:offer-cooldown:v1:";

/// The owner's open quota questions, one per parked offer, beside its rest
/// in the same table: this deployment's routing state too.
const QUESTION_PREFIX: &str = "models:offer-cooldown:v1:ask:";

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
}

impl ResetSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ErrorTime => "error_time",
            Self::RetryAfter => "retry_after",
            Self::Default => "default",
            Self::Backoff => "backoff",
            Self::Parked => "parked",
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
            waits_move: Some(clock),
        })
    }

    /// Waits `wait`, for the offer back `at` then, asking `may_send` each
    /// slice of it: once it says no, the wait ends there.
    pub(super) async fn wait(&self, wait: Duration, at: u64, may_send: &(dyn Fn() -> bool + Sync)) {
        let end = tokio::time::Instant::now() + wait;
        loop {
            let left = end.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            if !may_send() {
                return;
            }
            tokio::time::sleep(left.min(WAIT_SLICE)).await;
        }
        self.waited_until(at);
    }

    #[cfg(test)]
    fn waited_until(&self, at: u64) {
        if let Some(clock) = &self.waits_move {
            clock.set(at);
        }
    }

    #[cfg(not(test))]
    fn waited_until(&self, _at: u64) {}

    /// When the offer serving `wire_model` is back in rotation, while it
    /// rests. An unreadable row leaves the offer in rotation: the worst it
    /// costs is one more refusal.
    pub(super) fn resting(&self, offer: &OfferBinding, wire_model: &str) -> Option<u64> {
        let vault = self.vault.as_ref()?;
        let rest = match vault.sync_state_get(&key(offer, wire_model)) {
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
        (rest.until > vault.now_recorded_at()).then_some(rest.until)
    }

    /// Rests the offer serving `wire_model` after a limit refusal: spent
    /// credit parks it until the owner clears it; a spent window rests it
    /// until the first reset the refusal names that is still ahead; a rate
    /// limit rests it until that reset or for the wait it asks, never past
    /// the vault's longest rest, and with neither for a backoff that doubles
    /// with each refusal in a row from the vault's default, with jitter. A
    /// rest already running longer stays. A spent window or credit leaves
    /// the owner its question. `None` when no vault keeps rests or the write
    /// failed.
    pub(super) fn rest(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
        refusal: Refusal<'_>,
        asked: Asked<'_>,
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
            if let Some(spent) = rest.spent {
                let question = QuotaQuestion {
                    id: key.trim_start_matches(PREFIX).to_owned(),
                    asked_at: now,
                    provider: asked.provider.to_owned(),
                    model: wire_model.to_owned(),
                    route: format!("{}@{}", offer.route.adapter(), offer.route.origin()),
                    spent,
                    resets_at: (rest.source != ResetSource::Parked).then_some(rest.until),
                    choices: match spent {
                        SpentKind::Window => vec![
                            QuotaChoice::Wait,
                            QuotaChoice::AddAccount,
                            QuotaChoice::PayAsYouGo,
                        ],
                        SpentKind::Credit => vec![QuotaChoice::TopUp, QuotaChoice::AddAccount],
                    },
                };
                let bytes = rmp_serde::to_vec_named(&question).map_err(|_| {
                    oneiron::Error::InvariantViolation("encode a quota question")
                })?;
                vault.sync_state_put_in_write_txn(txn, &question_key(&question.id), &bytes)?;
            }
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

    /// The owner's answer to question `id`: it closes the question, and a
    /// top-up or pay-as-you-go puts its offer back in rotation now. `false`
    /// when no such question is open or the choice is not one it offers.
    pub fn answer(&self, id: &str, choice: QuotaChoice) -> oneiron::Result<bool> {
        let Some(vault) = &self.vault else {
            return Ok(false);
        };
        let question = vault
            .sync_state_get(&question_key(id))?
            .and_then(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok());
        let Some(question) = question.filter(|question| question.choices.contains(&choice)) else {
            return Ok(false);
        };
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
        return rest(now.saturating_add(seconds).min(longest), ResetSource::RetryAfter);
    }
    if strikes == 0 {
        return rest(now.saturating_add(default_secs).min(longest), ResetSource::Default);
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
        now.saturating_add(backoff.saturating_add(jitter)).min(longest),
        ResetSource::Backoff,
    )
}

/// Where question `id` is kept.
fn question_key(id: &str) -> String {
    format!("{QUESTION_PREFIX}{id}")
}

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
