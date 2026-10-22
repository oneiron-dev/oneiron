//! Shared action execution under the principal and binding of the host.
//! Entry: `ActionRegistry::execute`.
//! `ActionRegistry` and action values are defined by `code_run::actions`.

use super::*;

impl ActionRegistry {
    pub fn execute_ui(
        &self,
        vault: &Vault,
        actor: WriteActor,
        action: &GeneratedUiValidatedAction,
        idempotency_key: &str,
    ) -> Result<ActionDispatch> {
        self.execute_ui_bound(
            vault,
            actor,
            action,
            idempotency_key,
            ActionHostBinding::default(),
        )
    }
    /// [`Self::execute_ui`] under the host's binding: its verb door and,
    /// when it authenticated the owner on its own, that proof.
    pub fn execute_ui_bound(
        &self,
        vault: &Vault,
        actor: WriteActor,
        action: &GeneratedUiValidatedAction,
        idempotency_key: &str,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        let GeneratedUiValidatedAction::DeterministicTool { emitter, action } = action else {
            return Err(invalid("UI action is not a deterministic tool"));
        };
        let call = AgentActionCall {
            verb_id: action.command().clone(),
            args: action.args().iter().map(ActionArgument::from_ui).collect(),
            idempotency_key: idempotency_key.to_owned(),
        };
        self.execute(vault, actor, emitter, &call, binding)
    }
    /// One call from either caller, as the host authenticated it: a person's
    /// own app button (a human view) or an agent's call (an agent task). The
    /// credential binds actor, principal and binding; the call names only
    /// the verb, its arguments and its idempotency key.
    pub fn execute_call(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        self.execute(vault, actor, principal, call, binding)
    }
    pub fn execute_agent(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
    ) -> Result<ActionDispatch> {
        if principal.kind() != LensActingPrincipalKind::AgentTask {
            return Err(invalid("agent action requires an agent principal"));
        }
        self.execute(vault, actor, principal, call, ActionHostBinding::default())
    }
    /// Executes an agent chat action under an INDEPENDENT authenticated-owner
    /// witness bound by the host, never by a transcript or action argument.
    /// `surface` is where the host authenticated the owner's say-so: an owner
    /// setting the action changes records it in his act (FIX 4626), audit
    /// only.
    pub fn execute_agent_with_owner(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
    ) -> Result<ActionDispatch> {
        if principal.kind() != LensActingPrincipalKind::AgentTask {
            return Err(invalid("agent action requires an agent principal"));
        }
        let binding = ActionHostBinding {
            verb_door: None,
            owner: Some(owner),
            owner_surface: Some(surface),
            live_run: None,
            planner: None,
        };
        self.execute(vault, actor, principal, call, binding)
    }
    pub(super) fn execute<'a>(
        &self,
        vault: &'a Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        request: &AgentActionCall,
        binding: ActionHostBinding<'a>,
    ) -> Result<ActionDispatch> {
        let ActionHostBinding {
            verb_door,
            owner,
            owner_surface,
            live_run,
            planner,
        } = binding;
        let registered = self.registered(request.verb_id.as_str())?;
        // Unbound, a run row would read past the caller's own read key.
        if matches!(registered.build, ActionBuild::Run(_)) && verb_door.is_none() {
            return Err(invalid("a run-row action runs only under a host's door"));
        }
        if let ActionBuild::Run(verb) = registered.build
            && super::run_verb_call::LIVE_RUN_VERBS.contains(&verb)
            && live_run.is_none()
        {
            return Err(invalid("this run row needs its caller's live run"));
        }
        // The run's lease, read live: a lapsed one acts and replays nothing.
        let leased = live_run
            .as_ref()
            .map(|run| run.leased_record(vault))
            .transpose()?;
        validate_action_principal(actor, principal)?;
        if request.idempotency_key.trim().is_empty()
            || request.idempotency_key.len() > 256
            || registered.definition.args_schema.len() != request.args.len()
            || request
                .args
                .iter()
                .zip(&registered.definition.args_schema)
                .any(|(arg, kind)| !arg.fits(*kind, registered.build))
        {
            return Err(invalid("action arguments do not match declared schema"));
        }
        let read_receipt = action_read_receipt(vault, principal, request)?;
        check_ceiling(vault, actor, registered.definition.required_ceiling)?;
        let (run_id, seed) = action_identity(actor, request, registered, &leased)?;
        // A live run's lease, read live again before a replayed answer
        // returns and before any effect: one that moved on meanwhile does
        // neither.
        let lease_holds = || {
            live_run
                .as_ref()
                .map_or(Ok(()), |run| run.leased_record(vault).map(drop))
        };
        let previous = vault.get_code_run_replay_record(&run_id)?;
        let frozen = previous.as_ref().map_or_else(
            || crate::unix_seconds_now().saturating_mul(1000),
            |record| record.determinism.frozen_unix_ms,
        );
        let call = match registered.build {
            ActionBuild::Factory(factory) => factory(
                ActionBuildContext {
                    effect_id: run_id,
                    actor,
                    frozen_unix_ms: frozen,
                },
                &request.args,
            )?,
            ActionBuild::Verb(verb) => build_sdk_verb(verb, &request.args)?,
            ActionBuild::Run(verb) => build_run_verb(verb, &request.args, frozen)?,
        }
        .with_bridge_stamp(0, frozen);
        if matches!(call, SelfCall::WakePolicyWrite(_)) {
            let proof = owner.ok_or(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "wake policy action needs host owner proof",
            )))?;
            let txn = vault.store.env.read_txn()?;
            crate::dreamer_runner::maintenance::validate_owner_in_txn(vault, &txn, proof)?;
        }
        if let Some(record) = previous {
            if record.determinism.rng_seed != seed {
                return Err(invalid("idempotency key reused with changed action"));
            }
            if record.bridge_calls.is_empty() {
                return Err(Error::ConcurrentWrite(
                    "shared action is in flight or needs reconciliation",
                ));
            }
            lease_holds()?;
            let refusal = record
                .bridge_calls
                .first()
                .and_then(|row| super::payload::refusal_words(&row.outcome));
            // The receipt the first dispatch's row stated, stated again by
            // the door's caller: the replay runs no row (FIX 8159).
            let row_receipt = record
                .bridge_calls
                .first()
                .and_then(|row| super::payload::row_receipt(&row.outcome));
            // A replayed search keeps only the hits this caller reads now.
            let key = principal.selected_read_key();
            return record
                .replay_cursor()
                .dispatch(call)
                .and_then(|outcome| replay_read::rescoped(vault, key, outcome, read_receipt))
                .map(|(outcome, read_receipt)| {
                    if let (Some(door), Some(receipt)) = (&verb_door, &row_receipt) {
                        door.replay_row_receipt(receipt);
                    }
                    ActionDispatch {
                        outcome,
                        read_receipt,
                        refusal,
                    }
                });
        }
        lease_holds()?;
        // Reserve the EXISTING replay record before effects. A crash or racing
        // caller sees an incomplete record and fails closed, never re-dispatches.
        let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(frozen, seed));
        let generation = vault.put_code_run_replay_record_if_generation(&record, None)?;
        let dispatcher = match &leased {
            Some(record) => GatedActorWrite::for_action_attempt(
                vault,
                actor,
                run_id.to_hex(),
                record,
                live_run
                    .as_ref()
                    .and_then(crate::task_verb::HostBinding::executor_run),
            )?,
            None => GatedActorWrite::new(vault, actor, run_id.to_hex())?,
        };
        let dispatcher = match owner {
            Some(proof) => dispatcher
                .with_authenticated_owner(proof)
                .with_owner_surface(owner_surface),
            None => dispatcher,
        };
        let worded = verb_door.clone();
        let dispatcher = match verb_door {
            Some(door) => dispatcher.with_agent_verb_door(door),
            None => dispatcher,
        };
        let dispatcher = match planner {
            Some(planner) => dispatcher.with_planner(planner),
            None => dispatcher,
        };
        let result = dispatcher.dispatch_for_executor_run(
            super::ExecutorCallSite {
                run_id,
                seq: 0,
                step_start: 0,
                earlier: &[],
            },
            call.clone(),
        );
        // The seats a spawn resolved ride its row, a failure's too (FIX 9180).
        let seats = dispatcher.take_spawn_seats();
        let recorded = match &result {
            Ok(outcome) => outcome.clone(),
            Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                outcome,
                reason_codes,
            })) => SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: call.effect(),
                outcome: (*outcome).to_owned(),
                reason_codes: reason_codes.iter().map(|r| (*r).to_owned()).collect(),
            }),
            Err(error) => SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: error.to_string(),
            }),
        };
        // A refused row's own words ride on its record, so a retry under the
        // same key answers with them, not with the code alone.
        let refusal = match &recorded {
            SelfDispatchOutcome::Denied(denied) => worded
                .as_deref()
                .and_then(|door| door.refusal_words())
                .filter(|words| words.code == denied.outcome),
            _ => None,
        };
        let mut row = CodeRunBridgeCall::record(0, &call, &recorded, frozen, frozen)?
            .with_spawn_seats(seats);
        if let Some(words) = &refusal {
            super::payload::word_refusal(&mut row.outcome, words);
        }
        // The call receipt its row's reply stated rides on its record too, so
        // a retry under the same key states it again (FIX 8159).
        if let Some(receipt) = worded.as_deref().and_then(|door| door.row_receipt()) {
            super::payload::keep_row_receipt(&mut row.outcome, &receipt);
        }
        record.bridge_calls.push(row);
        vault.put_code_run_replay_record_if_generation(&record, Some(generation))?;
        result.map(|outcome| ActionDispatch {
            outcome,
            read_receipt,
            refusal,
        })
    }
}

/// The action principal is the host actor, of the kind its class acts as.
fn validate_action_principal(actor: WriteActor, principal: &LensPrincipalBinding) -> Result<()> {
    let expected_kind = match actor.actor_class() {
        EdgeActorClass::Agent => LensActingPrincipalKind::AgentTask,
        EdgeActorClass::System => LensActingPrincipalKind::SystemJob,
        EdgeActorClass::Human => LensActingPrincipalKind::HumanView,
    };
    if principal.principal_ref() != actor.entity_ref().to_hex() || principal.kind() != expected_kind
    {
        return Err(invalid("action principal does not match host actor"));
    }
    Ok(())
}

/// The receipt of the principal read of every entity the action names; a
/// target outside its read scope refuses the action.
fn action_read_receipt(
    vault: &Vault,
    principal: &LensPrincipalBinding,
    request: &AgentActionCall,
) -> Result<ScopedReadReceipt> {
    let targets: Vec<_> = request
        .args
        .iter()
        .filter_map(|arg| match arg {
            ActionArgument::Entity { id } => Some(PointRead::id(*id)),
            _ => None,
        })
        .collect();
    let targets = vault
        .scoped_read(principal.selected_read_key().clone())
        .read(&targets, None)?;
    if targets.value.iter().any(Option::is_none) {
        return Err(invalid("action target is outside principal read scope"));
    }
    let read_receipt = targets.receipt;
    Ok(read_receipt)
}

/// The run id and seed of the action: its actor, verb and idempotency key,
/// and the try of a live run, hashed; the definition and arguments seeded.
fn action_identity(
    actor: WriteActor,
    request: &AgentActionCall,
    registered: &RegisteredVerb,
    leased: &Option<crate::attempt_queue::AttemptRecord>,
) -> Result<(EntityId, [u8; 32])> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:shared-action:v1");
    for part in [
        actor.entity_ref().as_bytes().as_slice(),
        request.verb_id.as_str().as_bytes(),
        request.idempotency_key.as_bytes(),
    ] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    // A live run's action is that try's own: another try, or another
    // lease of it, never replays its answer.
    if let Some(record) = &leased {
        hash.update(b"live-run");
        hash.update(record.id.as_bytes());
        hash.update(&record.attempt_count.to_be_bytes());
    }
    let digest = hash.finalize();
    let run_id = EntityId::from_bytes(
        digest.as_bytes()[..16]
            .try_into()
            .map_err(|_| invalid("action identity"))?,
    )?;
    let seed = *blake3::hash(
        &serde_json::to_vec(&(&registered.definition, &request.args))
            .map_err(|_| invalid("action encoding"))?,
    )
    .as_bytes();
    Ok((run_id, seed))
}
