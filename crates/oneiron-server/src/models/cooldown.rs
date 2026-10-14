//! Offers a provider refused for a quota or a limit (OF-305). Each rests
//! until its reset, in a vault side table so a restart keeps it, and is back
//! in rotation by itself once that time passes. Nothing here retries: the
//! ladder hands the call on, once per offer.
use std::sync::Arc;

use oneiron::llm::run_admission::OfferBinding;
use oneiron::{LlmRequest, ModelLocality, ProviderCooldownPolicy, Vault};
use serde::{Deserialize, Serialize};

/// The engine's `MODEL_OFFER_COOLDOWN` side table: LIVE, never replicated
/// or exported.
const PREFIX: &str = "models:offer-cooldown:v1:";

/// What set a rest's end: the reset time the refusal named, the wait it
/// asked for, or the vault's default when it named neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ResetSource {
    ErrorTime,
    RetryAfter,
    Default,
}

impl ResetSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ErrorTime => "error_time",
            Self::RetryAfter => "retry_after",
            Self::Default => "default",
        }
    }
}

/// One offer's rest: when it is back in rotation, and what set that.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Rest {
    pub(super) until: u64,
    pub(super) source: ResetSource,
}

/// Where a ladder keeps its offers' rests, and asks whether a call's world
/// may leave the device. Without a vault nothing is kept: a refusal still
/// hands its call on, and the next call starts fresh.
pub struct OfferCooldowns {
    vault: Option<Arc<Vault>>,
}

impl OfferCooldowns {
    #[must_use]
    pub fn unkept() -> Arc<Self> {
        Arc::new(Self { vault: None })
    }

    /// Rests kept in `vault`'s side table, on its clock, judged by its
    /// world settings.
    #[must_use]
    pub fn in_vault(vault: Arc<Vault>) -> Arc<Self> {
        Arc::new(Self { vault: Some(vault) })
    }

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

    /// Rests the offer serving `wire_model` after a limit refusal: until the
    /// first reset the refusal names that is still ahead, else for the wait
    /// it asks, else for the vault's default, and never past the vault's
    /// longest rest. A rest already running longer stays. `None` when no
    /// vault keeps rests or the write failed.
    pub(super) fn rest(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
        retry_after: Option<u64>,
        resets_at: &[u64],
    ) -> Option<Rest> {
        let vault = self.vault.as_ref()?;
        let policy = vault.provider_cooldown_policy().unwrap_or_default();
        let rest = rest_end(vault.now_recorded_at(), policy, retry_after, resets_at);
        let key = key(offer, wire_model);
        let kept = vault.try_with_write_txn_grouped(|txn| {
            let running = vault
                .sync_state_get_in_write_txn(txn, &key)?
                .and_then(|bytes| rmp_serde::from_slice::<Rest>(&bytes).ok())
                .filter(|running| running.until >= rest.until);
            if let Some(running) = running {
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

    /// Whether a fallback may take `request` off the device: it names no
    /// world, or the world settings' one judge lets its world go to another
    /// machine. A world nobody can judge here stays on the device.
    pub(super) fn world_may_leave(&self, request: &LlmRequest) -> bool {
        let Some(world) = request.envelope.scope.world else {
            return true;
        };
        self.vault
            .as_ref()
            .is_some_and(|vault| matches!(vault.world_is_device_only(world), Ok(false)))
    }
}

/// Whether an offer takes the work off the device: a provider's own cloud.
/// The vault's own server and an in-process model keep it here.
pub(super) fn leaves_device(offer: &OfferBinding) -> bool {
    offer.locality == ModelLocality::ThirdParty
}

/// The end of a rest that starts `now`.
fn rest_end(
    now: u64,
    policy: ProviderCooldownPolicy,
    retry_after: Option<u64>,
    resets_at: &[u64],
) -> Rest {
    let longest = now.saturating_add(policy.max_secs);
    let (until, source) = match resets_at.iter().find(|reset| **reset > now) {
        Some(reset) => (*reset, ResetSource::ErrorTime),
        None => match retry_after.filter(|seconds| *seconds > 0) {
            Some(seconds) => (now.saturating_add(seconds), ResetSource::RetryAfter),
            None => (
                now.saturating_add(policy.default_secs),
                ResetSource::Default,
            ),
        },
    };
    Rest {
        until: until.min(longest),
        source,
    }
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
