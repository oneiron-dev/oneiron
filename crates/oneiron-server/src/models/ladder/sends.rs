//! The send to one rung: a generated call's (`OfferLadder::send`) and a
//! stream's (`OfferLadder::stream_rung`), with their admission, send and
//! settlement in the order they had. Moved whole from `generation.rs` and
//! `ladder.rs`; the bodies are as they were.
use super::*;

impl OfferLadder {
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
            let warmth = cache_warmth::Sending::of(&self.rests, &rung, &bound);
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
                    warmth.answered(&self.rests, &response.usage);
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

    /// Streams the rung at `index` to the caller. The call is over once the
    /// rung answers, fails after it has spoken, fails in a way that ends the
    /// call, or the caller stops reading; a rung that fails before its first
    /// event hands the call on.
    pub(super) async fn stream_rung(
        &self,
        context: Call<'_>,
        index: usize,
        (mut call, mut permit): (LlmRequest, RunPermit),
        walk: &mut Walk,
        events: &Sender<LlmResult<LlmStreamEvent>>,
        binding: &mut Option<oneshot::Sender<ModelCallBinding>>,
    ) -> Flow {
        let mut rung = self.rungs[index].clone();
        // A managed worker's lease, held as long as the probe (FIX 8315).
        let _lease = match self.hold_worker(index).await {
            Ok(lease) => lease,
            Err(error) => {
                settle_failed(permit);
                return match self.failed(index, error, false, walk) {
                    Ok(()) => Flow::On,
                    Err(error) => {
                        let _ = events.send(Err(error)).await;
                        Flow::Ended
                    }
                };
            }
        };
        // Held until the stream ends, however it ends.
        let Some(_probe) = self.probe_unless_managed(index, walk) else {
            settle_failed(permit);
            return Flow::On;
        };
        let rung_run = context.run.with_work_context({
            let mut context = context.run.work_context();
            context.physical = physical_for(&rung.offer.binding);
            context
        });
        loop {
            let gate = rung_run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
            let warmth = cache_warmth::Sending::of(&self.rests, &rung, &call);
            let ended = match gate.stream(call, permit.lease()) {
                Ok(stream) => {
                    let budgets = self.rests.reply_budgets();
                    super::http::holding_chat_replies(budgets, forward(stream, events)).await
                }
                Err(error) => Ended::Failed {
                    error,
                    spoken: false,
                },
            };
            return match ended {
                Ended::Done {
                    message,
                    usage,
                    finish_reason,
                    reply_assertions,
                } => {
                    warmth.answered(&self.rests, &usage);
                    self.rests.succeeded(&rung.offer.binding, &rung.wire_model);
                    let done = match permit.settle(CallOutcome::Answered(&usage)) {
                        Ok(_) => {
                            // The answering rung's binding, sent before its Done
                            // on this same task, so a capture site that sees Done
                            // already finds it (FIX 12743). A denied settle sends
                            // no Done and resolves nothing.
                            if let Some(tx) = binding.take() {
                                let sent_call = Arc::new(rung.bind(context.request.clone()));
                                let _ = tx.send(ModelCallBinding::for_rung(
                                    &self.rungs[index],
                                    sent_call,
                                ));
                            }
                            Ok(LlmStreamEvent::Done {
                                message,
                                usage: self.answered(index, walk, usage),
                                finish_reason,
                                reply_assertions,
                            })
                        }
                        Err(denied) => Err(denied.into()),
                    };
                    let _ = events.send(done).await;
                    Flow::Ended
                }
                Ended::Failed {
                    error,
                    spoken: true,
                } => {
                    settle_failed(permit);
                    // Its stream was the answer, never sent again; a limit it
                    // met still rests it, as does an outage.
                    if self.rest_if_limited(index, &error).is_none() && provider_down(&error) {
                        self.rests
                            .failed_down(&rung.offer.binding, &rung.wire_model);
                    }
                    let _ = events.send(Err(error)).await;
                    Flow::Ended
                }
                Ended::Failed {
                    error,
                    spoken: false,
                } => {
                    // The same offer's alternate wire, within the ceiling
                    // alone, as a generation's (FIX 12735).
                    let fallback = rung
                        .offer
                        .backend
                        .fallback(&error)
                        .filter(|_| self.rung_within_ceiling(index));
                    let sent = settle_failed(permit);
                    if let Some(backend) = fallback {
                        walk.passed.push((
                            index,
                            Passed::Failed {
                                kind: failure_kind(&error),
                                sent,
                            },
                        ));
                        walk.last = Some(error);
                        rung.offer.backend = backend;
                        (call, permit) = match self.admit(
                            &rung_run,
                            &rung,
                            context.request,
                            context.selector,
                            true,
                        ) {
                            Ok(next) => next,
                            Err(error) => {
                                let _ = events.send(Err(error)).await;
                                return Flow::Ended;
                            }
                        };
                        if context.deadline.expired() {
                            settle_failed(permit);
                            let _ = events.send(Err(CallDeadline::expiry())).await;
                            return Flow::Ended;
                        }
                        if !self.route_admitted(context.routes, index) {
                            settle_failed(permit);
                            self.refuse_route(context, index, walk);
                            return Flow::On;
                        }
                        if let Some(reason) = self.kept_on_device(index, context.request) {
                            settle_failed(permit);
                            self.hold(context, index, walk, reason);
                            return Flow::On;
                        }
                        continue;
                    }
                    match self.failed(index, error, sent, walk) {
                        Ok(()) => Flow::On,
                        Err(error) => {
                            let _ = events.send(Err(error)).await;
                            Flow::Ended
                        }
                    }
                }
                Ended::Gone => Flow::Ended,
            };
        }
    }
}
