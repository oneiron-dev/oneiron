//! Offer cooldown health, quota and fallback operations.

use super::*;

impl OfferCooldowns {
    /// The offer serving `wire_model`'s rest, while it rests: a limit's,
    /// else its health's. An unreadable row leaves the offer in rotation:
    /// the worst it costs is one more refusal.
    pub(in crate::models) fn resting(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
    ) -> Option<Rest> {
        let vault = self.vault.as_ref()?;
        let key = key(offer, wire_model);
        self.limit_rest(vault, &key)
            .or_else(|| self.limit_rest(vault, &account_park::row(&account_park::id(offer))))
            .or_else(|| self.health_rest(&key, vault.now_recorded_at()))
    }

    /// The health rest of the offer at `key`, while it runs.
    pub(super) fn health_rest(&self, key: &str, now: u64) -> Option<Rest> {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        let held = health.get(key).filter(|held| held.until > now)?;
        Some(held.rest())
    }

    /// The health version, when the offer serving `wire_model` is on
    /// probation with its one probation request out. Read-only: it takes no
    /// slot.
    pub(in crate::models) fn probing(&self, offer: &OfferBinding, wire_model: &str) -> Option<u64> {
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
    pub(in crate::models) fn try_probe(
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
    pub(super) fn release_probe(&self, key: &str, token: u64) {
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
    pub(in crate::models) fn offer_health(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
    ) -> RungHealth {
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
        let account = account_park::row(&account_park::id(offer));
        status.limit = self
            .limit_rest(vault, &key)
            .or_else(|| self.limit_rest(vault, &account))
            .map(|rest| LimitHold {
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
    pub(super) fn limit_rest(&self, vault: &Vault, key: &str) -> Option<Rest> {
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
    pub(in crate::models) fn rest(
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
            // Spent credit parks every offer of its account (FIX 564).
            if account_park::parks_account(&rest) {
                account_park::park_in_txn(vault, txn, offer, rest)?;
            }
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
    pub(in crate::models) fn failed_down(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
    ) -> Option<Rest> {
        self.failed_down_at(&key(offer, wire_model))
    }

    pub(super) fn failed_down_at(&self, key: &str) -> Option<Rest> {
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
    pub(in crate::models) fn succeeded(&self, offer: &OfferBinding, wire_model: &str) {
        self.succeeded_at(&key(offer, wire_model));
    }

    pub(super) fn succeeded_at(&self, key: &str) {
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
    pub(in crate::models) fn offer_fallbacks(&self, rungs: Vec<FallbackRung>) {
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
    /// when it must stay there, and accepts the request. A question still
    /// open stays as it was asked; one whose window has reset answered
    /// itself, so a later spent window of the same offer asks again (FIX
    /// 9512), read and replaced in one write. With the call's `principal`
    /// it is asked as a person-only decision (FIX 562). Nothing when the
    /// rest spent nothing or no vault keeps rests.
    pub(in crate::models) fn ask(
        &self,
        offer: &OfferBinding,
        rest: Rest,
        asked: Asked<'_>,
        own: &[&str],
        fits: &dyn Fn(&OfferLadder) -> bool,
        principal: Option<oneiron::EntityId>,
    ) {
        let (Some(vault), Some(spent)) = (self.vault.as_ref(), rest.spent) else {
            return;
        };
        let id = key(offer, asked.wire_model)
            .trim_start_matches(PREFIX)
            .to_owned();
        let row = question_key(&id);
        let now = vault.now_recorded_at();
        let open = |bytes: Option<Vec<u8>>| {
            bytes
                .and_then(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok())
                .is_some_and(|asked| asked.resets_at.is_none_or(|reset| reset > now))
        };
        if open(vault.sync_state_get(&row).ok().flatten()) {
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
            asked_at: now,
            provider: asked.provider.to_owned(),
            model: asked.wire_model.to_owned(),
            route: format!("{}@{}", offer.route.adapter(), offer.route.origin()),
            spent,
            resets_at: (rest.source != ResetSource::Parked).then_some(rest.until),
            choices,
            fallbacks,
            account: account_park::parks_account(&rest).then(|| account_park::id(offer)),
        };
        // With the call's principal known, the question is a person-only
        // decision whose queue keeps the same row (FIX 562).
        let kept = match principal {
            Some(principal) => quota_queue::ask(vault, principal, &question),
            None => quota_queue::keep(vault, &question),
        };
        if kept.is_err() {
            tracing::warn!(
                reason = "quota_question_unwritable",
                "a parked offer's quota question could not be kept"
            );
        }
    }

    /// The models on providers other than `own` whose offers are in rotation
    /// now and that `fits` the parked call.
    pub(super) fn usage_left(
        &self,
        own: &[&str],
        fits: &dyn Fn(&OfferLadder) -> bool,
    ) -> Vec<QuotaFallback> {
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
    pub(in crate::models) fn fallback_for(
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

    /// Every model [`Self::fallback_for`] may answer with, whichever the
    /// owner names now or later (FIX 7257): each configured one the runtime
    /// still serves. None while no vault keeps the owner's choice, as that
    /// finds none then. Read-only.
    pub(in crate::models) fn fallback_ladders(&self) -> Vec<Arc<OfferLadder>> {
        if self.vault.is_none() {
            return Vec::new();
        }
        self.fallbacks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|rung| rung.ladder.upgrade())
            .collect()
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
            if let Some(account) = &question.account {
                account_park::unpark(vault, account)?;
            }
        }
        vault.sync_state_delete(&question_key(&question.id))?;
        Ok(true)
    }

    /// Now, on the clock rests are kept on.
    pub(in crate::models) fn now(&self) -> Option<u64> {
        self.vault.as_ref().map(|vault| vault.now_recorded_at())
    }

    /// The longest a call waits for a cooling chain's first offer back. No
    /// wait when nothing keeps rests.
    pub(in crate::models) fn max_wait_secs(&self) -> u64 {
        self.vault.as_ref().map_or(0, |vault| {
            vault
                .provider_cooldown_policy()
                .unwrap_or_default()
                .max_wait_secs
        })
    }

    /// Whether a fallback may take `request` to `endpoint`, where the
    /// offer it falls back to sends it ([`Self::world_hold`]).
    pub(in crate::models) fn world_may_leave(
        &self,
        request: &LlmRequest,
        endpoint: &oneiron::settings::ReadDestination,
    ) -> bool {
        self.world_hold(request, endpoint).is_none()
    }
}
