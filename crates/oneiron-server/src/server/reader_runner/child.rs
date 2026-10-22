//! Execution and settlement of claimed reader children and summary jobs.
//! The two `Child` impls keep their seat, clock, and meter behavior together.
//! Child and shared-state definitions stay in the parent module.

use super::{
    AgentDispatcher, AgentVerbDoor, Arc, BudgetDenied, BudgetGuard, CallClass, CallEnvelope,
    CallPurpose, Child, ContentPart, Duration, ENGINE_EXECUTOR_PURPOSE_NAME, EngineExecutorError,
    EngineExecutorStatus, EngineNativeExecutor, HostSelfDispatcher, Instant, JsCodeModeRuntime,
    LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality,
    ModelSeat, ModelTierRef, OffRecordSession, READER_CHILD_READ_ONLY, ReaderJobKind, ReaderJobs,
    ReaderRunEnd, ResponseFormat, SCOPED_CHILD_PARENT_LEASE_LOST, SUMMARY_PURPOSE_NAME,
    SUMMARY_READ_BYTES_PER_TOKEN, ScopedChildDoor, ScopedChildPorts, ScopedChildProfile, SeatKind,
    SeatTask, Shared, SpendScopeId, SummarizeRecipe, SummaryRead, TierPrecedence, Unseated, Vault,
    birth_under_inherited_list, ensure_inherited_model_list, reader_task_brief, run_seat,
    scope_funding, scoped_child_service, session_seat_or_seatless, summarize_input,
    summarize_prompt, summary_exceeds_window, summary_token_budget, unix_millis_now,
};

impl Child {
    /// What is left of this job's time at `now_ms`, in milliseconds: to the
    /// cutoff its first spawn fixed (`reader_job_cutoff`) and, while its
    /// parent's host lends a live clock, to that clock too, less the fold
    /// reserve fixed at that spawn for a read or a scoped child. A summary is
    /// the fold the reserve is kept for, so it runs to the whole clock. No
    /// reserve is taken twice and no time is added.
    fn left_ms(&self, now_ms: u64) -> u64 {
        let binding = &self.job.binding;
        let left = binding.child_cutoff_unix_ms.saturating_sub(now_ms);
        let Some(clock) = self.clock else {
            return left;
        };
        let reserve = match self.job.kind {
            ReaderJobKind::Summarize { .. } => 0,
            ReaderJobKind::Read | ReaderJobKind::ScopedAgent { .. } => {
                binding.deadline.fold_reserve_ms
            }
        };
        left.min(clock.remaining_ms().saturating_sub(reserve))
    }

    /// How a scoped child that borrowed its parent attempt's lease ends when
    /// that lease no longer holds (`ReaderJobs::scoped_parent_holds`),
    /// checked before its seat and each model entry, as its dispatcher
    /// checks it before each read and port; `None` while it holds, and for
    /// every job that borrowed none. Its settle checks the lease again.
    fn parent_lease_lost(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
    ) -> Option<ReaderRunEnd> {
        let job = &self.job;
        if job.scoped_parent_lease().is_none() {
            return None;
        }
        let holds = match (session, self.session.as_ref()) {
            (Some(session), Some((_, participant))) => {
                ReaderJobs::for_session(session, *participant)
                    .and_then(|jobs| jobs.scoped_parent_holds(job.task, job.generation))
            }
            (Some(_), None) => Ok(false),
            (None, _) => ReaderJobs::canonical(vault).scoped_parent_holds(job.task, job.generation),
        };
        match holds {
            Ok(true) => None,
            Ok(false) => Some(ReaderRunEnd::Failed(
                SCOPED_CHILD_PARENT_LEASE_LOST.to_owned(),
            )),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a scoped child's parent lease was not read");
                Some(ReaderRunEnd::Failed("reader_binding_failed".to_owned()))
            }
        }
    }

    /// Runs the child and settles it as its run ended.
    pub(super) fn run_and_settle(&self, shared: &Shared, vault: &Arc<Vault>) {
        let job = &self.job;
        // A scoped child's door is its loan, Grant-checked at each call
        // (FIX 7507); the read child's door never stands in for it.
        let door: Arc<dyn AgentVerbDoor> = match &job.kind {
            ReaderJobKind::ScopedAgent { .. } => {
                Arc::new(ScopedChildDoor::new(Arc::clone(vault), job.clone()))
            }
            ReaderJobKind::Read | ReaderJobKind::Summarize { .. } => {
                Arc::new(crate::api::ReaderChildDoor::new(
                    Arc::clone(vault),
                    shared.seats.caller(job.binding.parent_run),
                ))
            }
        };
        let settled = match &self.session {
            None => {
                let end = self.metered(vault, None, door);
                ReaderJobs::canonical(vault).complete(
                    job.task,
                    job.generation,
                    end,
                    unix_millis_now(),
                )
            }
            Some((session_ref, participant)) => {
                // A session that is gone took the child's rows with its
                // overlay: there is nothing left to settle.
                let Ok(session) = vault.off_record_session_vault().bind(session_ref) else {
                    return;
                };
                let end = self.metered(vault, Some(&session), door);
                ReaderJobs::for_session(&session, *participant).and_then(|jobs| {
                    jobs.complete(job.task, job.generation, end, unix_millis_now())
                })
            }
        };
        if let Err(error) = settled {
            tracing::warn!(%error, task = %job.task.to_hex(), "a reader child was not settled; its cutoff settles it");
        }
    }

    /// Runs the child, or a summary job's one model call, on its meter
    /// ([`Child::meter`]), and records what it used on its child scope once
    /// the run ends when it spends under one.
    fn metered(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        door: Arc<dyn AgentVerbDoor>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        // A scoped child its own host profiled (FIX 7508) runs on that
        // profile's backend and its parent's meter, never the host's.
        if let Some(profile) = self.profile() {
            return self.metered_on_profile(vault, session, door, &profile);
        }
        let (guard, recorded) = match self.meter(vault) {
            Ok(meter) => meter,
            Err(end) => return end,
        };
        // A child under a room-paid scope bills its root's payer, bound
        // before its first call (OF-531). One with no payer it can bill ends
        // with that typed reason before any call, never on the vault owner's
        // account.
        let payer = match scope_funding(vault, recorded.as_ref(), false) {
            Ok(payer) => payer,
            Err(fault) => {
                tracing::info!(%fault, task = %job.task.to_hex(), "a reader child has no payer to bill");
                return ReaderRunEnd::Failed(fault.reason().to_owned());
            }
        };
        let Some(backend) = self.provider.reader_backend(guard.clone(), payer) else {
            return ReaderRunEnd::Failed("reader_meter_unbound".to_owned());
        };
        let end = match &job.kind {
            ReaderJobKind::Read => {
                self.run(vault, session, backend.as_ref(), &guard, door, None, None)
            }
            // A scoped child runs as a read child's run does, with its lent
            // ports bound; one whose authority or ports do not hold ends
            // before any call, never as a read child.
            ReaderJobKind::ScopedAgent { .. } => {
                match scoped_child_service(vault, self.provider.as_ref(), job) {
                    Ok(ports) => {
                        self.run(vault, session, backend.as_ref(), &guard, door, ports, None)
                    }
                    Err(end) => end,
                }
            }
            ReaderJobKind::Summarize {
                recipe,
                window_tokens,
                ..
            } => self.run_summarize_job(
                vault,
                session,
                backend.as_ref(),
                door.as_ref(),
                recipe,
                *window_tokens,
            ),
        };
        if let Some(scope) = recorded
            && let Err(error) =
                AgentDispatcher::new(vault).record_guard_spend(&scope, guard.read().used_units)
        {
            tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's spend was not recorded");
        }
        end
    }

    /// The guard a child's model calls spend on, and the child scope what it
    /// used is recorded on afterwards. Under a scope: a guard of what its
    /// own child scope may still spend. On the host's meter: the host's
    /// shared guard, which settles each call itself as it does the parent's,
    /// so nothing is recorded after; a provider with none to lend fails the
    /// child `reader_meter_unbound`.
    fn meter(&self, vault: &Vault) -> Result<(BudgetGuard, Option<SpendScopeId>), ReaderRunEnd> {
        let job = &self.job;
        if job.binding.spend.scope().is_none() {
            return self
                .provider
                .host_meter()
                .map(|guard| (guard, None))
                .ok_or_else(|| ReaderRunEnd::Failed("reader_meter_unbound".to_owned()));
        }
        let scope = SpendScopeId::for_attempt(&job.attempt);
        match AgentDispatcher::new(vault).guard_for_scope(&scope) {
            Ok(guard) => Ok((guard, Some(scope))),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a reader child's meter did not open");
                Err(ReaderRunEnd::Failed("reader_meter_failed".to_owned()))
            }
        }
    }

    /// The dispatcher bound to this job's run on its route, `session`'s room
    /// or base, at the generation its runner claimed the job at.
    fn bind<'s>(
        &self,
        vault: &'s Vault,
        session: Option<&'s OffRecordSession<'s>>,
    ) -> oneiron::Result<HostSelfDispatcher<'s>> {
        let job = &self.job;
        job.binding
            .actor
            .write_actor()
            .and_then(|actor| match session {
                Some(session) => {
                    HostSelfDispatcher::for_off_record_session(session, actor, job.run.to_hex())
                }
                None => HostSelfDispatcher::new(vault, actor, job.run.to_hex()),
            })
            .and_then(|dispatcher| dispatcher.with_reader_child(job.task, job.generation))
    }

    /// The seat a job's model calls are bound to, born under its own run on
    /// the route `bound`, its dispatcher, captured, as a run's is: on base
    /// for a canonical job (`run_seat`), where a manifest-backed vault
    /// refuses a seatless executor, and on its room's route for a job in an
    /// off-record session (`run_seat_on`, FIX 2594), never base. A session
    /// job whose seat is not born there runs its configured model, as before
    /// (`session_seat_or_seatless`). A read and a summary alike are held to
    /// the list their spawning run froze (`birth_under_inherited_list`, FIX
    /// 4539), and so is a seatless one's configured model
    /// ([`Child::held_to_list`]). Its pick runs inside its parent's clock
    /// where that clock binds ([`Child::seat_parent_at`], FIX 8230), and a
    /// canonical job whose birth fails under it ends at its cutoff
    /// ([`Child::unseated`]).
    fn seat(
        &self,
        vault: &Vault,
        bound: &HostSelfDispatcher<'_>,
        task: &str,
        purpose: CallPurpose,
        min_context_tokens: u64,
        locality: ModelLocality,
    ) -> Result<Option<ModelSeat>, Unseated> {
        let job = &self.job;
        let parent_at = self.seat_parent_at();
        let born = || -> Result<Option<ModelSeat>, String> {
            let inherited = &job.binding.listed;
            let prior = if inherited.is_empty() {
                None
            } else {
                bound
                    .model_seat_receipt(job.run)
                    .map_err(|error| error.to_string())?
            };
            birth_under_inherited_list(
                job.run,
                inherited,
                prior.as_ref().map(|receipt| &receipt.model),
                |listed| {
                    let seat_task = |facet: &str| SeatTask {
                        kind: SeatKind::Child,
                        warm_scope: format!("reader-run:{}", job.run.to_hex()),
                        task: task.to_owned(),
                        purpose: purpose.clone(),
                        facet: facet.to_owned(),
                        required: Vec::new(),
                        min_context_tokens,
                        locality,
                        override_model: None,
                        override_effort: None,
                        listed,
                    };
                    let provider = self.provider.as_ref();
                    match self.session {
                        None => run_seat(vault, provider, job.run, parent_at, seat_task),
                        Some(_) => {
                            provider.run_seat_on(vault, bound, job.run, parent_at, seat_task)
                        }
                    }
                },
            )
        };
        match self.session {
            None => born().map_err(|error| self.unseated(parent_at.is_some(), error)),
            Some(_) => Ok(session_seat_or_seatless(job.task, born())),
        }
    }

    /// `seat_parent_at` (CALLS, open, FIX 8230): the cutoff a child's seat
    /// pick runs inside, projected once per birth from what is left of its
    /// time ([`Child::left_ms`]: its job's cutoff and its parent's live
    /// clock, the fold reserve taken once, no new window), the monotonic
    /// sample before the wall one. Only a parent due before one seat budget
    /// ends lends it, so the pick's budget is min(seat budget, parent time
    /// left) and the cap binds whenever it is lent; one already due lends
    /// now. With more left, the pick runs on its own budget, as before. The
    /// cutoff bounds how long the pick deliberates; no candidate is
    /// filtered by it.
    fn seat_parent_at(&self) -> Option<Instant> {
        let origin = Instant::now();
        let left = Duration::from_millis(self.left_ms(unix_millis_now()));
        let budget = self.provider.seat_decisions()?.budget;
        if left < budget {
            Some(origin + left)
        } else {
            None
        }
    }

    /// How a canonical job whose seat was not born ends (CALLS, open, FIX
    /// 8230): at its cutoff when its parent's clock bound the pick
    /// (`capped`: [`Child::seat_parent_at`] lent it) or is spent now, as its
    /// run would end at its first entry; otherwise `reader_seat_failed`, as
    /// before. A birth the parent's clock did not bind ends as it does today.
    fn unseated(&self, capped: bool, error: String) -> Unseated {
        if capped || self.left_ms(unix_millis_now()) == 0 {
            tracing::info!(%error, task = %self.job.task.to_hex(), "a reader child's seat was not born inside its parent's clock; it ends at its cutoff");
            return Unseated::Cutoff;
        }
        Unseated::Failed(error)
    }

    /// A seatless job runs its configured `model` only when the list its
    /// spawning run froze admits it (`ensure_inherited_model_list`, FIX 5070
    /// under FIX 6030's ruling that the engine enforces only the list): one
    /// off the list ends failed, its reason the refusal naming the list. An
    /// empty list admits any model, as before.
    fn held_to_list(&self, model: &ModelId) -> Result<(), ReaderRunEnd> {
        ensure_inherited_model_list(&self.job.binding.listed, model).map_err(|refused| {
            tracing::info!(%refused, task = %self.job.task.to_hex(), "a seatless job's configured model is off its inherited list");
            ReaderRunEnd::Failed(refused.to_string())
        })
    }

    /// The child's run: a fresh sandbox and a dispatcher bound to its job
    /// and door, and a scoped child's to its lent `ports`, entered again
    /// after each yielded slice until it ends or its cutoff comes. The
    /// cutoff stops the run at its next await; a running step is not cut.
    /// A profiled child's config takes its `profile`'s model before its
    /// seat is born (FIX 7508).
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per axis the runner binds a child's run to"
    )]
    pub(super) fn run(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        backend: &dyn LlmBackend,
        guard: &BudgetGuard,
        door: Arc<dyn AgentVerbDoor>,
        ports: Option<Arc<dyn ScopedChildPorts>>,
        profile: Option<&ScopedChildProfile>,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let provider = self.provider.as_ref();
        let failed = |reason: &str, error: &dyn std::fmt::Display| {
            tracing::warn!(%error, task = %job.task.to_hex(), reason, "a reader child did not run");
            ReaderRunEnd::Failed(reason.to_owned())
        };
        let bound = self
            .bind(vault, session)
            .and_then(|dispatcher| match ports {
                Some(ports) => dispatcher.with_scoped_child_ports(ports),
                None => Ok(dispatcher),
            });
        let dispatcher = match bound {
            Ok(dispatcher) => dispatcher.with_agent_verb_door(door),
            Err(error) => return failed("reader_binding_failed", &error),
        };
        // A scoped child whose borrowed parent lease is gone takes no seat.
        if let Some(end) = self.parent_lease_lost(vault, session) {
            return end;
        }
        // Read on the job's route: a session child's first start is its
        // room's record's.
        let brief = reader_task_brief(job);
        let mut config = match provider.executor_config_on(vault, &dispatcher, job.run, &brief) {
            Ok(config) => config,
            Err(error) => return failed("reader_config_failed", &error),
        };
        if let Some(profile) = profile {
            profile.bind_config(&mut config);
        }
        let purpose = CallPurpose::Other {
            name: ENGINE_EXECUTOR_PURPOSE_NAME.into(),
        };
        let seat = match self.seat(
            vault,
            &dispatcher,
            &config.task,
            purpose,
            1,
            config.model_locality,
        ) {
            Ok(seat) => seat,
            Err(Unseated::Cutoff) => return ReaderRunEnd::Cutoff,
            Err(Unseated::Failed(error)) => return failed("reader_seat_failed", &error),
        };
        // The seat binds its model and effort into the config and the
        // executor alike; a seatless child runs its configured model, held
        // to its inherited list.
        if let Some(seat) = &seat {
            config.model = seat.model().clone();
            config.model_locality = seat.locality();
            config.seat_effort = Some(seat.effort());
        } else if let Err(end) = self.held_to_list(&config.model) {
            return end;
        }
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(error) => return failed("reader_reactor_failed", &error),
        };
        let mut runtime = provider.reader_runtime();
        let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
        let executor = match session {
            Some(session) => EngineNativeExecutor::for_off_record_session(
                session,
                backend,
                provider.lease(),
                runtime,
                &dispatcher,
            ),
            None => Ok(EngineNativeExecutor::new(
                vault,
                backend,
                provider.lease(),
                runtime,
                &dispatcher,
            )),
        };
        // An executor error's text can quote what the vault holds.
        let Ok(mut executor) = executor else {
            return failed("reader_binding_failed", &"the run's executor did not bind");
        };
        if let Some(seat) = &seat {
            executor = executor.with_model_seat(seat);
        }
        loop {
            // Its cutoff and its parent's live clock bound each entry, and a
            // lost parent lease admits none.
            let left = self.left_ms(unix_millis_now());
            if left == 0 {
                return ReaderRunEnd::Cutoff;
            }
            if let Some(end) = self.parent_lease_lost(vault, session) {
                return end;
            }
            let ran = reactor.block_on(async {
                tokio::time::timeout(Duration::from_millis(left), executor.run(&config)).await
            });
            let error = match ran {
                Err(_) => return ReaderRunEnd::Cutoff,
                Ok(Ok(outcome)) => match outcome.status {
                    EngineExecutorStatus::Complete => return ReaderRunEnd::Completed,
                    EngineExecutorStatus::Yielded { .. } => continue,
                    EngineExecutorStatus::Waiting(_) => {
                        return ReaderRunEnd::Failed("reader_child_waited".to_owned());
                    }
                    EngineExecutorStatus::WindowFull { .. } => {
                        return ReaderRunEnd::Failed("window_full".to_owned());
                    }
                },
                Ok(Err(error)) => error,
            };
            return match error {
                // The run's last step committed; the trailing bubble it may
                // not say is refused after that.
                EngineExecutorError::HostRefused { code } if code == READER_CHILD_READ_ONLY => {
                    ReaderRunEnd::Completed
                }
                EngineExecutorError::Llm(LlmError::BudgetDenied(BudgetDenied::Exhausted)) => {
                    ReaderRunEnd::SpendExhausted
                }
                _ if guard.read().remaining_units == 0 => ReaderRunEnd::SpendExhausted,
                _ => {
                    tracing::warn!(task = %job.task.to_hex(), "a reader child's run failed");
                    ReaderRunEnd::Failed("reader_run_failed".to_owned())
                }
            };
        }
    }
}

impl Child {
    /// A summary job's one model call (code-mode-summary-sdk-v1), never
    /// inside a parent's step: each member read with the checks a child's
    /// `src` read makes (the job live, the door's rows, the member's taint
    /// now), counted with the executor's tokenizer against half the model's
    /// window, then one generate on the job's own meter, its text stored as
    /// the job's finding. A group past the window fails
    /// `group_exceeds_window`, and the helper splits it.
    fn run_summarize_job(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        backend: &dyn LlmBackend,
        door: &dyn AgentVerbDoor,
        recipe: &SummarizeRecipe,
        window_tokens: u64,
    ) -> ReaderRunEnd {
        let job = &self.job;
        let failed = |reason: &str| ReaderRunEnd::Failed(reason.to_owned());
        let jobs = match session {
            Some(session) => match self.session.as_ref() {
                Some((_, participant)) => match ReaderJobs::for_session(session, *participant) {
                    Ok(jobs) => jobs,
                    Err(_) => return failed("reader_binding_failed"),
                },
                None => return failed("reader_binding_failed"),
            },
            None => ReaderJobs::canonical(vault),
        };
        let budget = summary_token_budget(window_tokens);
        let members = match jobs.summary_members(
            job.task,
            job.generation,
            budget.saturating_mul(SUMMARY_READ_BYTES_PER_TOKEN),
        ) {
            Ok(SummaryRead::Members(members)) => members,
            Ok(SummaryRead::Refused(reason)) => return ReaderRunEnd::Failed(reason),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's members were not read");
                return failed("summary_read_failed");
            }
        };
        for member in &members {
            if !matches!(door.withholds_retained(member.rows.as_deref()), Ok(false)) {
                return failed("result_withheld");
            }
        }
        let prompt = summarize_prompt(recipe);
        let input = summarize_input(
            members
                .iter()
                .map(|member| (member.handle.as_str(), member.text.as_str())),
        );
        let tokens = (oneiron::count_context_pack_tokens(&prompt)
            + oneiron::count_context_pack_tokens(&input)) as u64;
        if tokens > budget {
            return ReaderRunEnd::Failed(summary_exceeds_window(tokens, window_tokens));
        }
        // Its config and seat are read on its own route, through a
        // dispatcher bound to the job as a child's run is.
        let bound = match self.bind(vault, session) {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's dispatcher did not bind");
                return failed("reader_binding_failed");
            }
        };
        let config = match self
            .provider
            .executor_config_on(vault, &bound, job.run, "summarize")
        {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's config did not bind");
                return failed("reader_config_failed");
            }
        };
        // Its seat sees only models whose window holds the window the group
        // was sized against.
        let seat = match self.seat(
            vault,
            &bound,
            &config.task,
            CallPurpose::Other {
                name: SUMMARY_PURPOSE_NAME.to_owned(),
            },
            window_tokens,
            config.model_locality,
        ) {
            Ok(seat) => seat,
            Err(Unseated::Cutoff) => return ReaderRunEnd::Cutoff,
            Err(Unseated::Failed(error)) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary's seat was not born");
                return failed("reader_seat_failed");
            }
        };
        // A seatless summary calls its configured model, held to its
        // inherited list.
        if seat.is_none()
            && let Err(end) = self.held_to_list(&config.model)
        {
            return end;
        }
        let purpose = CallPurpose::Other {
            name: SUMMARY_PURPOSE_NAME.to_owned(),
        };
        let mut request = LlmRequest {
            model: config.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: oneiron::llm::Scope::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(SUMMARY_PURPOSE_NAME.to_owned()),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: config.model_locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text { text: prompt }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text { text: input }],
                },
            ],
            tools: Vec::new(),
            params: std::collections::BTreeMap::new(),
            provider_options: std::collections::BTreeMap::new(),
        };
        if let Some(seat) = &seat {
            seat.bind(&mut request);
        }
        let reactor = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(reactor) => reactor,
            Err(_) => return failed("reader_reactor_failed"),
        };
        // A summary runs to its parent's outer cutoff, into the fold
        // reserve, and to its live clock when its host lent one.
        let left = self.left_ms(unix_millis_now());
        if left == 0 {
            return ReaderRunEnd::Cutoff;
        }
        let lease = self.provider.lease();
        let generated = reactor.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(left),
                backend.generate(request, lease),
            )
            .await
        });
        let response = match generated {
            Err(_) => return ReaderRunEnd::Cutoff,
            Ok(Err(LlmError::BudgetDenied(BudgetDenied::Exhausted))) => {
                return ReaderRunEnd::SpendExhausted;
            }
            Ok(Err(_)) => {
                tracing::warn!(task = %job.task.to_hex(), "a summary's model call failed");
                return failed("summary_call_failed");
            }
            Ok(Ok(response)) => response,
        };
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        if text.trim().is_empty() {
            return failed("summary_empty");
        }
        match jobs.store_summary(job.task, job.generation, &text) {
            Ok(Ok(())) => ReaderRunEnd::Completed,
            Ok(Err(reason)) => ReaderRunEnd::Failed(reason),
            Err(error) => {
                tracing::warn!(%error, task = %job.task.to_hex(), "a summary was not stored");
                failed("summary_store_failed")
            }
        }
    }
}
