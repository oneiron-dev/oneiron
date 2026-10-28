//! The admission of the run door and its answered dispatch bracket.
//! Entry: `HostSelfDispatcher::dispatch_bound`.
//! `HostSelfDispatcher` state is defined by `code_run::dispatcher`.

use super::*;

impl HostSelfDispatcher<'_> {
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
        // A slip-woken program's call holds only while its slip admits it
        // (FIX 8717), door or none.
        if let RunCall::Bridge(effect) = call
            && let Some(code) = self.program_authority_refusal(effect.as_str())?
        {
            return Ok(Err(AgentVerbRefusal { code }));
        }
        let Some(door) = &self.agent_verbs else {
            return Ok(Ok(None));
        };
        let admitted = door.admit_run_call(call);
        if let Err(refusal) = &admitted
            && let Some(rejected) = gate_rejection(&refusal.code)
        {
            return Err(rejected);
        }
        Ok(admitted)
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

    pub(super) fn dispatch_bound(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        // This call's own frame of the seats it resolves (FIX 9180): it
        // closes on every exit, and an outer call's frame stays as it was.
        let _seats = self.spawn_capture.open();
        // A hook's view of an earlier call is never this call's, nor is its
        // read-world capture (FIX 6130).
        *self.hook_view.borrow_mut() = None;
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
        self.storage.answered(|| {
            self.enforce_off_record_effect_policy(call.effect())?;
            // A reader child reads its source and reports; a scoped child
            // also calls the ports its parent lent it (FIX 7507). Neither
            // makes any other call.
            if let Some(refused) = self
                .reader_child_refusal(call.effect())
                .or_else(|| self.scoped_child_refusal(&call))
            {
                return Ok(refused);
            }
            // A step that can no longer close commits nothing more.
            if let Some(site) = site
                && let Some(refused) = self.refusal_past_an_unmet_write(site, Some(&call))?
            {
                return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                    effect: call.effect(),
                    ..refused
                }));
            }
            // A bound door rules on every call the run serves itself, not only
            // on the verb calls it runs, so its ceiling and credential hold at
            // each. A verb call meets it in `dispatch_agent_verb`: at the
            // door's own call, or before a kept receipt answers it.
            let read_as = if matches!(call, SelfCall::AgentVerb(_)) {
                None
            } else {
                match self.admit_run_call(RunCall::Bridge(call.effect()))? {
                    Ok(read_as) => read_as,
                    Err(refusal) => {
                        return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                            effect: call.effect(),
                            outcome: refusal.code,
                            reason_codes: Vec::new(),
                        }));
                    }
                }
            };
            self.dispatch_hooked(call, site, read_as)
        })
    }
}

/// The gate rejection a door's refusal is when it is spelled as a gate's
/// outcome word, as `admit_run_call` says.
pub(super) fn gate_rejection(code: &str) -> Option<crate::Error> {
    crate::error::GateDenialOutcome::parse(code).map(|outcome| {
        crate::Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: outcome.as_str(),
            reason_codes: Vec::new(),
        })
    })
}
