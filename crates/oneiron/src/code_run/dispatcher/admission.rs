//! The admission of the run door and its answered dispatch bracket.
//! Entry: `HostSelfDispatcher::dispatch_bound`.
//! `HostSelfDispatcher` state is defined by `code_run::dispatcher`.

use super::*;
use crate::code_run::AgentVerbDoor;

impl HostSelfDispatcher<'_> {
    /// [`Self::admit_run_call`] for `call`'s effect, after the bound door
    /// admits the exact run row `call` was made through when its effect is
    /// shared by several rows (FIX EXECUTE-CALLER-CODE).
    ///
    /// # Errors
    ///
    /// As [`Self::admit_run_call`].
    pub(crate) fn admit_self_call(
        &self,
        call: &SelfCall,
    ) -> Result<std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal>> {
        if let (Some(row), Some(door)) = (call.shared_effect_row(), &self.agent_verbs)
            && let Err(refusal) = door.admit_run_row(row)
        {
            return Ok(Err(refusal));
        }
        self.admit_run_call(RunCall::Bridge(call.effect()))
    }

    /// Asks the bound door to admit one call the run serves itself. A run
    /// whose host binds no door admits it as its own.
    ///
    /// # Errors
    ///
    /// A refusal spelled as a gate's outcome word is that gate's
    /// [`crate::error::GateError::GateWriteRejected`]: replay tells a door's
    /// refusal, which the guest handles, from a gate's, which halts the run's
    /// bridge, by that word alone.
    pub(crate) fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal>> {
        self.admit_door_call(self.agent_verbs.as_deref(), call, false)
    }

    /// [`Self::admit_run_call`] for `call`, a `self.skills.call`. The outer
    /// call a credential-bound host projection entered for its caller
    /// (`outer`) is that caller's own: the bound door admits it with
    /// [`crate::code_run::AgentVerbDoor::admit_outer_skill_call`]. The
    /// skill's body's own calls are admitted as run calls.
    ///
    /// # Errors
    ///
    /// As [`Self::admit_run_call`].
    pub(crate) fn admit_skill_call(
        &self,
        call: &SelfCall,
        outer: bool,
    ) -> Result<std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal>> {
        let outer = outer && matches!(call, SelfCall::SkillsCall(_));
        self.admit_door_call(
            self.agent_verbs.as_deref(),
            RunCall::Bridge(call.effect()),
            outer,
        )
    }

    fn admit_door_call(
        &self,
        door: Option<&dyn AgentVerbDoor>,
        call: RunCall,
        outer_skill_call: bool,
    ) -> Result<std::result::Result<Option<ScopedReadActorKey>, AgentVerbRefusal>> {
        // A slip-woken program's call holds only while its slip admits it
        // (FIX 8717), door or none.
        if let RunCall::Bridge(effect) = call
            && let Some(code) = self.program_authority_refusal(effect.as_str())?
        {
            return Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code,
                reason_codes: Vec::new(),
            }));
        }
        let Some(door) = door else {
            return Ok(Ok(None));
        };
        // Speech is admitted with where this run's storage lands it.
        let admitted = match call {
            RunCall::Bridge(SelfEffect::SkillsCall) if outer_skill_call => {
                door.admit_outer_skill_call()
            }
            RunCall::Bridge(effect) if effect.is_speech() => {
                door.admit_run_speech(effect, self.storage.speech_destination())
            }
            RunCall::Bridge(_) | RunCall::RecordedOutput => door.admit_run_call(call),
        };
        if let Err(refusal) = &admitted
            && let Some(rejected) = gate_rejection(&refusal.code, &refusal.reason_codes)
        {
            return Err(rejected);
        }
        Ok(admitted)
    }

    /// The actual read key for a host turn. Only an unbound door derives one
    /// from the real WriteActor class; a bound door's no-read answer becomes
    /// an explicit read-nothing key and never falls back to that actor.
    pub(crate) fn host_turn_read_key(&self) -> ScopedReadActorKey {
        let actor = self.actor();
        let actor_ref = actor.entity_ref().to_hex();
        let class = actor.actor_class().gate_actor_class();
        match &self.agent_verbs {
            Some(door) => door
                .host_turn_read_key()
                .or_else(|| ScopedReadActorKey::read_nothing(actor_ref.clone(), class)),
            None => ScopedReadActorKey::with_actor_class(actor_ref.clone(), class)
                .or_else(|| ScopedReadActorKey::read_nothing(actor_ref.clone(), class)),
        }
        .expect("a host-stamped actor yields a turn read key")
    }

    /// Asks the bound door whether a result the run retained, produced from
    /// `rows`, stays on this device for its caller now. A run whose host
    /// binds no door withholds nothing.
    pub(crate) fn withholds_retained(
        &self,
        rows: Option<&[EntityId]>,
    ) -> std::result::Result<bool, AgentVerbRefusal> {
        match &self.agent_verbs {
            Some(door) => door.withholds_retained(rows),
            None => Ok(false),
        }
    }

    /// Whether the guest reads again the answer a recorded call got, served
    /// from `rows` (FIX 7703). The bound door admits both the read and its
    /// producer (FIX CODE-MODE-LENDING-W11), and the answer must not stay
    /// on this device for the door's caller now.
    pub(crate) fn releases_recorded_answer(
        &self,
        rows: Option<&[EntityId]>,
        producer: RecordedProducer,
    ) -> bool {
        let door = self.agent_verbs.as_deref();
        admit_recorded_answer(door).is_ok()
            && matches!(self.admit_recorded_producer(door, producer), Ok(Ok(())))
            && matches!(self.withholds_retained(rows), Ok(false))
    }

    /// Rechecks the producer's door admission without dispatching it.
    ///
    /// # Errors
    ///
    /// A program-authority read fails, or the bridge admission returns a
    /// gate-word refusal as a gate rejection.
    pub(crate) fn admit_recorded_producer(
        &self,
        door: Option<&dyn AgentVerbDoor>,
        producer: RecordedProducer,
    ) -> Result<std::result::Result<(), AgentVerbRefusal>> {
        let Some(door) = door else {
            return Ok(Ok(()));
        };
        match producer {
            RecordedProducer::Descriptor => Ok(Ok(())),
            RecordedProducer::Unidentified => Ok(Err(AgentVerbRefusal {
                hook_notice: None,
                code: RECORDED_ANSWER_UNIDENTIFIED.to_owned(),
                reason_codes: Vec::new(),
            })),
            RecordedProducer::Bridge {
                effect,
                row,
                outer_skill_call,
            } => {
                if let Some(row) = row
                    && let Err(refusal) = door.admit_run_row(row)
                {
                    return Ok(Err(refusal));
                }
                self.admit_door_call(Some(door), RunCall::Bridge(effect), outer_skill_call)
                    .map(|admitted| admitted.map(drop))
            }
            RecordedProducer::Verb(verb) => {
                if let Some(code) = self.program_authority_refusal(verb.as_str())? {
                    return Ok(Err(AgentVerbRefusal {
                        hook_notice: None,
                        code,
                        reason_codes: Vec::new(),
                    }));
                }
                // The storage route, not the verb's name, tells a room call
                // from the same verb served through a canonical tool.
                if matches!(self.storage, ExecutorStorage::Session(_))
                    && self.scoped_child_spec().is_none()
                {
                    return Ok(if verb.session_read().is_some() {
                        door.admit_session_read(verb).map(drop)
                    } else if verb.overlay_write() {
                        door.admit_session_write(verb).map(drop)
                    } else {
                        Err(AgentVerbRefusal {
                            hook_notice: None,
                            code: crate::code_run::AGENT_VERB_SESSION_BOUND.to_owned(),
                            reason_codes: Vec::new(),
                        })
                    });
                }
                Ok(door.admit_recorded_verb(verb))
            }
        }
    }

    /// The values base custody holds now, which a recorded call's row is
    /// compared with when its call is made again (FIX
    /// REPLAY-COMPARE-KNOWN-MATCHER): a matcher, never the store.
    ///
    /// # Errors
    ///
    /// The custody read's.
    pub(crate) fn base_known_values(
        &self,
    ) -> Result<Option<std::sync::Arc<crate::store::known_value_index::KnownValues>>> {
        self.storage.base_known_values()
    }

    pub(super) fn dispatch_bound(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        // This call's own frame of the seats it resolves (FIX 9180): it
        // closes on every exit, and an outer call's frame stays as it was.
        let _seats = self.spawn_capture.open();
        // A hook's view of an earlier call is never this call's, nor is its
        // read-world capture (FIX 6130), nor the skill bodies its producer
        // witnessed (FIX 3608).
        *self.hook_view.borrow_mut() = None;
        *self.task_refusal_output.borrow_mut() = None;
        *self.skill_bodies.borrow_mut() = None;
        self.uncover_read_worlds();
        // A leased run's writes in this call are its own derivations (OF-540).
        let _run_writes = self
            .agent_lease
            .as_ref()
            .map(crate::skill_attribution::enter_run_writes);
        // The call holds its leased run's tool witness open (OF-568 L5).
        let _tool = self.activity_tool();
        // The descriptor bridge answers before the policy probe and the door:
        // a descriptor is no effect, so neither rules on it. Its own verb
        // hooks run around it on canonical storage, reading as the run's
        // actor; with none bound to it, it performs no read.
        if matches!(call, SelfCall::Context(_)) {
            return self.dispatch_hooked(call, site, None);
        }
        // The halt rule and the door rule inside the bracket: a run whose
        // participant left the room hears `NotInRoom`, never their verdict.
        // The off-record rule reads the whole call: an anonymous room tells
        // its five room reads from every other verb by it (FIX 5166).
        self.storage.answered(|| {
            self.enforce_off_record_effect_policy(&call)?;
            // A reader child reads its source and reports; a scoped child
            // also calls the ports its parent lent it (FIX 7507). Neither
            // makes any other call.
            if let Some(refused) = self
                .reader_child_refusal(call.effect())
                .or_else(|| self.scoped_child_refusal(&call))
            {
                return Ok((refused, None));
            }
            // A step that can no longer close commits nothing more.
            if let Some(site) = site
                && let Some(refused) = self.refusal_past_an_unmet_write(site, Some(&call))?
            {
                return Ok((
                    SelfDispatchOutcome::Denied(SelfDeniedResult {
                        effect: call.effect(),
                        ..refused
                    }),
                    None,
                ));
            }
            // A bound door rules on every call the run serves itself, not only
            // on the verb calls it runs, so its ceiling and credential hold at
            // each. A verb call meets it in `dispatch_agent_verb`: at the
            // door's own call, or before a kept receipt answers it.
            let read_as = if matches!(call, SelfCall::AgentVerb(_)) {
                None
            } else {
                match self.admit_self_call(&call)? {
                    Ok(read_as) => read_as,
                    Err(refusal) => {
                        return Ok((
                            SelfDispatchOutcome::Denied(SelfDeniedResult {
                                hook_notice: None,
                                effect: call.effect(),
                                outcome: refusal.code,
                                reason_codes: refusal.reason_codes,
                            }),
                            None,
                        ));
                    }
                }
            };
            self.dispatch_hooked(call, site, read_as)
        })
    }
}

/// Asks `door` whether the run reads back an answer it recorded, as the
/// door rules now (FIX 7703): a write's kept answer, or the answer of a
/// call that a resumed pending step's program already made. A run whose
/// host binds no door reads its own.
pub(super) fn admit_recorded_answer(
    door: Option<&dyn crate::code_run::AgentVerbDoor>,
) -> std::result::Result<(), AgentVerbRefusal> {
    match door {
        Some(door) => door.admit_run_call(RunCall::RecordedOutput).map(drop),
        None => Ok(()),
    }
}

/// The gate rejection a door's refusal is when it is spelled as a gate's
/// outcome word, as `admit_run_call` says. It keeps each of the door's
/// `reason_codes` that is a gate's own stable code, so the guest learns why
/// the gate refused (FIX CODE-MODE-DENIAL-REASONS); a gate rejection holds
/// only those static codes, and any other code the door gave is not a gate's.
pub(super) fn gate_rejection(code: &str, reason_codes: &[String]) -> Option<crate::Error> {
    crate::error::GateDenialOutcome::parse(code).map(|outcome| {
        crate::Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: outcome.as_str(),
            reason_codes: reason_codes
                .iter()
                .filter_map(|reason| crate::error::GateDenialReason::from_code(reason))
                .map(crate::error::GateDenialReason::as_str)
                .collect(),
        })
    })
}
