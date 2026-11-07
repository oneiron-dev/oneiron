//! The generation walk of one chat call: its entry points, the walk rung
//! by rung, and the send to one rung. Moved whole from `ladder.rs`
//! (FIX 4933); the bodies are as they were.
use super::*;

impl OfferLadder {
    /// One call under `run`, rung by rung. Each rung that is reached is
    /// admitted, sent through the run's gate and settled on its own: an
    /// answer pays its usage (or its reservation when it reports none), a
    /// rung that failed after it went out pays its reservation. `selector`
    /// is what the caller named, for the receipt (the ladder's id if none).
    pub async fn generate(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmResponse> {
        self.generate_while(run, request, selector, &|| true).await
    }

    /// [`Self::generate`], asking `may_send` before each rung is admitted,
    /// the first one's too, and again once it is admitted, since admission
    /// can wait on the run's receipts, and through a wait for an offer back.
    /// Once it says no, no rung is sent (an admitted one settles unstarted,
    /// for nothing), and the call fails with the last rung's error (an
    /// invalid request when none went out).
    pub async fn generate_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<LlmResponse> {
        self.generate_by(run, request, selector, may_send, self.host_wait())
            .await
    }

    /// [`Self::generate_while`] for a caller with its own deadline: the
    /// call waits for offers back for at most `wait_budget` in all, the
    /// vault's longest wait or not (OF-305: a rate-limited chain backs off
    /// and retries until the caller's deadline).
    pub async fn generate_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        let deadline = CallDeadline::waits_within(wait_budget);
        self.generate_by(run, request, selector, may_send, deadline)
            .await
    }

    /// [`Self::generate_exact_within`] waiting as [`Self::generate_while`]
    /// does, for the vault's longest wait: a call a durable seat bound,
    /// which its one model answers or nothing does.
    pub async fn generate_exact(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<LlmResponse> {
        let budget = Duration::from_secs(self.rests.max_wait_secs());
        self.generate_exact_within(run, request, selector, &|| true, budget)
            .await
    }

    /// [`Self::generate_exact`], asking `may_send` as
    /// [`Self::generate_while`] does, on the vault's longest wait (FIX 11749).
    pub async fn generate_exact_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<LlmResponse> {
        self.generate_exact_by(run, request, selector, may_send, self.host_wait())
            .await
    }

    /// [`Self::generate_within`] for a caller that must know the model it
    /// named is the one that answered (an exact-model decision, OF-184):
    /// only a ladder that is one picked model takes the call, and no owner's
    /// fallback does. A seat's ladder refuses it as an invalid request.
    pub async fn generate_exact_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        let deadline = CallDeadline::waits_within(wait_budget);
        self.generate_exact_by(run, request, selector, may_send, deadline)
            .await
    }

    /// [`Self::generate`], with the model of the rung that answered, the
    /// owner's fallback included: the executor a caller stamps on the
    /// attempt it ran for (OF-540).
    pub async fn generate_served(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
    ) -> LlmResult<(LlmResponse, ModelId)> {
        self.generate_served_by(run, request, selector, &|| true, self.host_wait())
            .await
    }

    /// [`Self::generate_within`], with the model of the rung that answered,
    /// the owner's fallback included: the model a decision's receipt names
    /// (FIX 2730), on the caller's own deadline.
    pub async fn generate_served_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<(LlmResponse, ModelId)> {
        let deadline = CallDeadline::waits_within(wait_budget);
        self.generate_served_by(run, request, selector, may_send, deadline)
            .await
    }

    /// [`Self::generate`] for a caller whose request carries sources each
    /// destination must be admitted to (FIX 8714): every rung the call
    /// reaches, the first and a picked one included, and the owner's
    /// fallback, is sent only what `sources` admits for that rung's own
    /// destination, judged before it is admitted and again right before it
    /// is sent ([`SourceAdmission`]).
    pub(crate) async fn generate_admitted(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        sources: &dyn SourceAdmission,
    ) -> LlmResult<LlmResponse> {
        let sources = Some(sources);
        let deadline = self.host_wait();
        self.generate_from(run, request, selector, &|| true, deadline, true, sources)
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::generate_within`]; once every rung has parked, a call whose
    /// parked offer has the owner's fallback goes there, when
    /// `may_fall_back` (a fallback's own call falls back no further). Boxed,
    /// since a fallback's call is this one again. Each rung, the fallback's
    /// included, is sent what `sources` admits for it, when a caller opted
    /// in (FIX 8714).
    #[expect(
        clippy::too_many_arguments,
        reason = "one walk takes its call, its gate, its budget, its fallback and its sources"
    )]
    pub(super) fn generate_from<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: LlmRequest,
        selector: Option<&'a str>,
        may_send: &'a (dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
        may_fall_back: bool,
        sources: Option<&'a dyn SourceAdmission>,
    ) -> ServedFuture<'a> {
        Box::pin(async move {
            self.walk_generate(
                run,
                request,
                selector,
                may_send,
                deadline,
                may_fall_back,
                sources,
                RungPrompt::Configured,
            )
            .await
        })
    }

    /// The walk of one chat call; its rung puts `prompt` first (FIX 6255).
    #[expect(
        clippy::too_many_arguments,
        reason = "one walk takes its call, gate, budget, fallback, sources and prompt"
    )]
    pub(super) async fn walk_generate(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
        may_fall_back: bool,
        sources: Option<&dyn SourceAdmission>,
        prompt: RungPrompt<'_>,
    ) -> LlmResult<(LlmResponse, ModelCallBinding)> {
        self.admits(&request)?;
        // The run is live until this call ends: the host stays awake for it.
        let _awake = oneiron_vault_contract::host_adapters::run_awake();
        let routes = self.rests.world_routes(&request);
        let call = Call {
            run,
            request: &request,
            selector,
            needs: Needs::Chat {
                request: &request,
                stream: false,
            },
            routes: &routes,
            deadline,
        };
        let mut walk = Walk::default();
        // The chain, each rung at most once a pass; then, while only rests
        // stopped it, the owner's fallback, or a wait for its first offer
        // back and the chain again, until the waits would pass the call's
        // budget.
        for pass in 0.. {
            if pass > 0 {
                if may_fall_back && let Some(target) = self.fallback(call, &walk) {
                    let fallback = self.fallback_call(&target, &walk);
                    let mut fell_request = request.clone();
                    fell_request.model = fallback.model().clone();
                    let fell = fallback
                        .generate_from(
                            run,
                            fell_request,
                            Some(selector.unwrap_or(self.name.as_str())),
                            may_send,
                            deadline,
                            false,
                            sources,
                        )
                        .await;
                    if fell.is_err() {
                        self.ask_parked(&walk, call.needs, call.run.principal());
                    }
                    return fell;
                }
                let Some(back) = self.waits_for(call, &mut walk).filter(|_| may_send()) else {
                    break;
                };
                self.wait_back(back, may_send).await;
            }
            let mut sent = vec![false; self.rungs.len()];
            loop {
                if !may_send() || deadline.expired() {
                    return Err(self.ended(call, walk));
                }
                let Some(index) = self.next_rung(call, &sent, &mut walk) else {
                    break;
                };
                sent[index] = true;
                match self
                    .send(call, index, may_send, sources, prompt, &mut walk)
                    .await?
                {
                    Sent::Answer(response, sent_call) => {
                        let binding = ModelCallBinding::for_rung(&self.rungs[index], sent_call);
                        return Ok((response, binding));
                    }
                    Sent::Failed | Sent::Held => {}
                    Sent::Stopped => return Err(self.ended(call, walk)),
                }
            }
        }
        Err(self.ended(call, walk))
    }

    /// Sends the call to the rung at `index`, with what `sources` admits for
    /// that rung's destination when a caller opted in (FIX 8714), the rung
    /// putting `prompt` first (FIX 6255). A failure that ends the call is
    /// the error.
    pub(super) async fn send(
        &self,
        call: Call<'_>,
        index: usize,
        may_send: &(dyn Fn() -> bool + Sync),
        sources: Option<&dyn SourceAdmission>,
        prompt: RungPrompt<'_>,
        walk: &mut Walk,
    ) -> LlmResult<Sent> {
        let mut rung = prompt.rung(&self.rungs[index]);
        let offered = match source_admission::offered(sources, call.request, &rung.offer) {
            Ok(offered) => offered,
            Err(reason) => {
                self.hold(call, index, walk, reason);
                return Ok(Sent::Held);
            }
        };
        let call = Call {
            request: offered.as_ref().unwrap_or(call.request),
            ..call
        };
        // Held through every admitted wire attempt and its settlement.
        let _lease = match self.hold_worker(index).await {
            Ok(lease) => lease,
            Err(error) => {
                self.failed(index, error, false, walk)?;
                return Ok(Sent::Failed);
            }
        };
        let rung_run = call.run.with_work_context({
            let mut context = call.run.work_context();
            context.physical = physical_for(&rung.offer.binding);
            context
        });
        loop {
            if !may_send() {
                return Ok(Sent::Stopped);
            }
            if call.deadline.expired() {
                return Err(CallDeadline::expiry());
            }
            let (bound, permit) =
                self.admit(&rung_run, &rung, call.request, call.selector, false)?;
            if !may_send() {
                settle_failed(permit);
                return Ok(Sent::Stopped);
            }
            if !self.route_admitted(call.routes, index) {
                settle_failed(permit);
                self.refuse_route(call, index, walk);
                return Ok(Sent::Held);
            }
            if let Some(reason) = self.kept_on_device(index, call.request) {
                settle_failed(permit);
                self.hold(call, index, walk, reason);
                return Ok(Sent::Held);
            }
            if let Some(reason) = source_admission::lapsed(sources, &rung.offer) {
                settle_failed(permit);
                self.hold(call, index, walk, reason);
                return Ok(Sent::Held);
            }
            let Some(_probe) = self.probe_unless_managed(index, walk) else {
                settle_failed(permit);
                return Ok(Sent::Held);
            };
            let gate = rung_run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
            let warmth = cache_warmth::Sending::of(&rung, &bound);
            let sent = gate.generate(bound, permit.lease());
            let Some(answered) = call
                .deadline
                .bound(super::http::holding_chat_replies(
                    self.rests.reply_budgets(),
                    sent,
                ))
                .await
            else {
                settle_failed(permit);
                return Err(CallDeadline::expiry());
            };
            match answered {
                Ok(mut response) => {
                    warmth.answered(&self.rests);
                    self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
                    permit.settle(CallOutcome::Answered(&response.usage))?;
                    response.usage = self.answered(index, walk, response.usage);
                    if prompt.noted() {
                        rung.note_answered(call.request);
                    }
                    // FIX 4933: the call as this rung sent it, for its binding.
                    let sent_call = Arc::new(rung.bind(call.request.clone()));
                    return Ok(Sent::Answer(response, sent_call));
                }
                Err(error) => {
                    // The alternate wire is the same offer, sent where that
                    // offer sends: taken only while the rung sits within
                    // the ladder's locality ceiling (FIX 12735); else the
                    // rung fails as any failure does.
                    let fallback = rung
                        .offer
                        .backend
                        .fallback(&error)
                        .filter(|_| self.rung_within_ceiling(index));
                    let sent = settle_failed(permit);
                    if let Some(backend) = fallback {
                        // The failed wire keeps its own truthful receipt. Its
                        // alternate is the same offer, freshly admitted, not
                        // another ladder rung or a provider-health failure.
                        walk.passed.push((
                            index,
                            Passed::Failed {
                                kind: failure_kind(&error),
                                sent,
                            },
                        ));
                        walk.last = Some(error);
                        rung.offer.backend = backend;
                        continue;
                    }
                    self.failed(index, error, sent, walk)?;
                    return Ok(Sent::Failed);
                }
            }
        }
    }
}
