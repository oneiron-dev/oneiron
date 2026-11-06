//! Per-call routing state for a core-owned unrecorded run.

use super::*;

impl OfferCooldowns {
    pub(in crate::models) fn unrecorded_view(&self) -> Arc<Self> {
        let fallbacks = self
            .fallbacks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|rung| FallbackRung {
                provider: rung.provider.clone(),
                model: rung.model.clone(),
                ladder: rung.ladder.clone(),
            })
            .collect();
        Arc::new(Self {
            vault: self.vault.clone(),
            local_rests: Some(Mutex::default()),
            fallbacks: RwLock::new(fallbacks),
            health: Mutex::default(),
            probes: AtomicU64::new(0),
            health_changed: tokio::sync::watch::Sender::new(0),
            recovered: tokio::sync::watch::Sender::new(0),
            warmth: super::super::ladder::cache_warmth::CacheWarmth::default(),
            budgets: self.budgets.unrecorded_view(),
        })
    }

    pub(in crate::models) fn is_unrecorded(&self) -> bool {
        self.local_rests.is_some()
    }

    pub(super) fn local_rest(
        &self,
        local: &Mutex<BTreeMap<String, Rest>>,
        vault: &Vault,
        offer: &OfferBinding,
        wire_model: &str,
        refusal: Refusal<'_>,
    ) -> Rest {
        let policy = vault.provider_cooldown_policy().unwrap_or_default();
        let now = vault.now_recorded_at();
        let key = key(offer, wire_model);
        let mut local = local.lock().unwrap_or_else(PoisonError::into_inner);
        let running = local.get(&key).copied();
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
        if account_park::parks_account(&rest) {
            let row = account_park::row(&account_park::id(offer));
            let running = local.get(&row).copied();
            if running.is_none_or(|running| running.until < rest.until) {
                local.insert(row, rest);
            }
        }
        if let Some(running) = running.filter(|running| running.until >= rest.until) {
            return running;
        }
        local.insert(key, rest);
        rest
    }
}
