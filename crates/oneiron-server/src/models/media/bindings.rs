//! Media voice bindings, clone queries and retry hints.
//! Entry: RungVoices::new.
//! RungVoices, RetryHint and MediaRuntime stay in the parent; this module owns the listed impls.

use super::{
    Arc, AtomicUsize, BankVoiceBinding, FatalLlmError, HostedCloner, LlmResult, MEDIA_RUN,
    MediaRuntime, MediaVoice, ModelId, OfferCooldowns, Ordering, PROVIDER_UNAVAILABLE_RETRY_SECS,
    PayerPerson, RetryHint, RunAdmission, RungVoices, SonioxRung, Vault, undeclared_run,
};

impl RungVoices {
    /// The bindings `bound` takes, or `None` when no rung holds the voice.
    pub(crate) fn new(vault: Arc<Vault>, bound: Vec<(ModelId, BankVoiceBinding)>) -> Option<Self> {
        (!bound.is_empty()).then(|| Self {
            vault,
            bound,
            sent: AtomicUsize::new(usize::MAX),
        })
    }

    /// The one rung that holds the voice, when only one does: the call is
    /// that rung's alone.
    pub(crate) fn only_rung(&self) -> Option<&ModelId> {
        match self.bound.as_slice() {
            [(rung, _)] => Some(rung),
            _ => None,
        }
    }

    /// The voice as the first rung that holds it renders it.
    pub(crate) fn first_voice(&self) -> Option<MediaVoice> {
        self.bound.first().map(|(_, binding)| binding.voice())
    }

    /// Whether `rung` held the voice when the call was admitted.
    pub(in crate::models) fn holds(&self, rung: &ModelId) -> bool {
        self.bound.iter().any(|(model, _)| model == rung)
    }

    /// The voice the call goes out in on `rung`: that rung's own binding,
    /// while it is still current. `None` when the rung holds none, or the
    /// voice was withdrawn or re-recorded since.
    pub(in crate::models) fn send_on(&self, rung: &ModelId) -> Option<MediaVoice> {
        let (at, (_, binding)) = self
            .bound
            .iter()
            .enumerate()
            .find(|(_, (model, _))| model == rung)?;
        if !binding.is_current(&self.vault) {
            return None;
        }
        self.sent.store(at, Ordering::Relaxed);
        Some(binding.voice())
    }

    /// Whether the binding the call last went out in is still current: an
    /// answer rendered in a voice withdrawn or re-recorded meanwhile is not
    /// handed back.
    pub(crate) fn answered_current(&self) -> bool {
        self.bound
            .get(self.sent.load(Ordering::Relaxed))
            .is_some_and(|(_, binding)| binding.is_current(&self.vault))
    }

    /// Whether no binding is current any more: the voice was withdrawn or
    /// re-recorded everywhere while the call waited.
    pub(crate) fn withdrawn(&self) -> bool {
        self.bound
            .iter()
            .all(|(_, binding)| !binding.is_current(&self.vault))
    }
}

impl MediaRuntime {
    /// The live socket rung `model` (a rung's engine id) opens, when it
    /// hears live.
    pub(in crate::models) fn live_rung(&self, model: &str) -> Option<Arc<SonioxRung>> {
        self.live_asr.get(model).cloned()
    }

    /// Where the media offers' rests are kept, when a vault keeps them: a
    /// live hearing's limit rests its offer there too (FIX 9515).
    pub(in crate::models) fn rests(&self) -> Option<Arc<OfferCooldowns>> {
        self.rests.clone()
    }

    /// The clone wire of hosted render target `target`, when it is one.
    #[must_use]
    pub fn voice_cloner(&self, target: &str) -> Option<Arc<HostedCloner>> {
        self.cloners.get(target).cloned()
    }

    /// A run of its own on the media meter for a voice clone's calls (FIX
    /// 3009): the clone wire admits and settles each one on it.
    pub fn clone_run(&self) -> LlmResult<RunAdmission> {
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        Ok(undeclared_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
        ))
    }

    /// [`Self::clone_run`], billed to `payer` when an acting payer's own
    /// account or consent explicitly funds the clone (FIX 9421): each permit
    /// binds that PERSON and account, as a room-funded media call's does.
    /// `None` is [`Self::clone_run`] itself, the vault's run as before; the
    /// creator stays the run's initiator either way, never its payer by
    /// having made the voice.
    pub fn clone_run_funded(&self, payer: Option<PayerPerson>) -> LlmResult<RunAdmission> {
        match payer {
            None => self.clone_run(),
            Some(payer) => self.media_run(Some(payer)),
        }
    }

    /// Whether `target` renders from a banked identity's reference clip on
    /// each call (a `voxcpm2` worker) rather than from a recorded clone.
    #[must_use]
    pub fn renders_from_refs(&self, target: &str) -> bool {
        self.reference_targets.contains(target)
    }
}

impl RetryHint {
    /// Seconds until the first of the call's offers is back from its rest,
    /// at least one; [`PROVIDER_UNAVAILABLE_RETRY_SECS`] when none rests for
    /// a known time.
    pub(crate) fn seconds(&self) -> u64 {
        let Some(rests) = &self.rests else {
            return PROVIDER_UNAVAILABLE_RETRY_SECS;
        };
        self.offers
            .iter()
            .filter_map(|(offer, wire_model)| rests.resting(offer, wire_model))
            .map(|rest| rest.until)
            // A parked offer is back when the owner answers, not at a time.
            .filter(|until| *until != u64::MAX)
            .min()
            .zip(rests.now())
            .map_or(PROVIDER_UNAVAILABLE_RETRY_SECS, |(back, now)| {
                back.saturating_sub(now).max(1)
            })
    }
}
