use super::*;
use crate::claim::ScopedReadActorKey;
use crate::code_run::SelfMemoryPutClaimCall;
use crate::lens::*;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
use crate::{ClaimCandidate, ClaimSubject, TimeRange};
use rmpv::Value;
fn build(ctx: ActionBuildContext, args: &[ActionArgument]) -> Result<SelfCall> {
    let [ActionArgument::Text(value)] = args else {
        return Err(invalid("text"));
    };
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(ctx.actor.entity_ref()),
        Value::from(value.as_str()),
        1.0,
    );
    let at = ctx.frozen_unix_ms / 1000;
    Ok(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        ctx.effect_id,
        candidate,
        TimeRange { start: at, end: at },
        at,
    )))
}
#[test]
fn ui_event_and_agent_call_share_definition_gate_effect_and_replay() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = entity(0x66);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    let actor = WriteActor::new(actor, EdgeActorClass::Agent);
    let read = ScopedReadActorKey::with_actor_class(actor.entity_ref().to_hex(), "agent")
        .ok_or_else(|| invalid("reader"))?;
    let principal = LensPrincipalBinding::agent_task(
        actor.entity_ref().to_hex(),
        read.clone(),
        vec![read.clone()],
    )?;
    let command = SelfUiAction {
        command: SelfUiActionId::new("remember")?,
        args: vec![SelfUiValue::Text(LensText::new("Ada")?)],
    };
    let node = LensNode::with_fallback_text(
        LensAtomId::new("save")?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new("save")?,
            label: LensText::new("Save")?,
            action: command.clone(),
        })),
        LensText::new("Save")?,
    );
    let card_id = LensRenderId::new("action-card")?;
    let card = GeneratedUiCard::interactive(
        card_id.clone(),
        GeneratedLens::new(node)?,
        vec![GeneratedUiActionDeclaration {
            element_id: LensAtomId::new("save")?,
            action_id: command.command.clone(),
            tier: GeneratedUiActionTier::DeterministicTool,
            action: command.clone(),
        }],
        GeneratedUiStateSnapshot::default(),
    )?;
    let render = card.render()?;
    let frame = LensRenderFrame::new(card_id.clone(), principal.clone());
    let event = GeneratedUiActionEvent {
        card_id,
        element_id: LensAtomId::new("save")?,
        action_id: command.command.clone(),
        patch: Vec::new(),
        occurred_at: 1,
    };
    let validated = frame.validate_action_event(
        &vault.scoped_read(read),
        &principal,
        &render,
        &render.state,
        &event,
    )?;
    let definition = ActionVerbDefinition {
        id: command.command.clone(),
        args_schema: vec![ActionArgKind::Text],
        required_ceiling: AgentCeiling::Proposed,
    };
    let wire = serde_json::to_vec(&definition).unwrap();
    assert_eq!(
        serde_json::from_slice::<ActionVerbDefinition>(&wire).unwrap(),
        definition
    );
    let mut registry = ActionRegistry::default();
    registry.register(definition, build)?;
    let call = AgentActionCall {
        verb_id: command.command,
        args: vec![ActionArgument::Text(LensText::new("Ada")?)],
        idempotency_key: "one-click".into(),
    };
    assert_eq!(
        registry.resolve_ui(&validated)?,
        registry.resolve(call.verb_id.as_str())?
    );
    let ui = registry.execute_ui(&vault, actor, &validated, &call.idempotency_key)?;
    let before = vault.store.gate_decisions(100)?;
    let agent = registry.execute_agent(&vault, actor, &principal, &call)?;
    assert_eq!(ui, agent);
    assert_eq!(vault.store.gate_decisions(100)?, before);
    let SelfDispatchOutcome::MemoryWrite(result) = ui else {
        return Err(invalid("expected memory write"));
    };
    assert_eq!(
        vault.get_claim(&result.id)?.unwrap().value,
        Value::from("Ada")
    );
    assert!(registry.resolve("unknown").is_err());
    registry.register(
        ActionVerbDefinition {
            id: SelfUiActionId::new("auto-only")?,
            args_schema: vec![ActionArgKind::Text],
            required_ceiling: AgentCeiling::Auto,
        },
        build,
    )?;
    let above = AgentActionCall {
        verb_id: SelfUiActionId::new("auto-only")?,
        ..call.clone()
    };
    assert!(matches!(
        registry.execute_agent(&vault, actor, &principal, &above),
        Err(Error::Gate(
            crate::error::GateError::GateWriteRejected { .. }
        ))
    ));
    let changed = AgentActionCall {
        args: vec![ActionArgument::Text(LensText::new("changed")?)],
        ..call
    };
    assert!(
        registry
            .execute_agent(&vault, actor, &principal, &changed)
            .is_err()
    );
    Ok(())
}

#[test]
fn authorized_agent_edits_inference_rows_and_next_call_uses_them() -> Result<()> {
    use crate::llm::{
        CallClass, CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, ResponseFormat,
        TierPrecedence,
    };
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let agent = entity(0x76);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let actor = WriteActor::new(agent, EdgeActorClass::Agent);
    let read = ScopedReadActorKey::with_actor_class(agent.to_hex(), "agent")
        .ok_or_else(|| invalid("reader"))?;
    let principal = LensPrincipalBinding::agent_task(agent.to_hex(), read.clone(), vec![read])?;
    let mut registry = ActionRegistry::default();
    registry.register_inference_defaults()?;
    let read_call = AgentActionCall {
        verb_id: SelfUiActionId::new("inference.defaults.read")?,
        args: vec![],
        idempotency_key: "read-before".into(),
    };
    assert!(
        registry
            .execute_agent(&vault, actor, &principal, &read_call)
            .is_err()
    );
    let raw = crate::code_run::GatedActorWrite::new(&vault, actor, "raw-attempt")?;
    assert!(raw.dispatch(SelfCall::InferenceDefaultsRead).is_err());
    assert!(
        raw.dispatch(SelfCall::InferenceDefaultsReplace(
            serde_json::to_string(&vault.purpose_default_table()?).unwrap(),
        ))
        .is_err()
    );
    crate::code_run::tests::install_exact_actor_ceiling(&vault, agent, "auto")?;
    let SelfDispatchOutcome::InferenceDefaults(initial) =
        registry.execute_agent(&vault, actor, &principal, &read_call)?
    else {
        return Err(invalid("missing inference rows"));
    };
    let mut edited = crate::llm::PurposeDefaultTable::from_json(initial.as_bytes())?;
    edited
        .purposes
        .get_mut(&CallPurpose::Consolidation)
        .unwrap()
        .tier = ModelTierRef("resident-consolidation".into());
    let replacement = serde_json::to_string(&edited).unwrap();
    let change = AgentActionCall {
        verb_id: SelfUiActionId::new("inference.defaults.replace")?,
        args: vec![ActionArgument::Text(LensText::new(replacement)?)],
        idempotency_key: "edit-once".into(),
    };
    let SelfDispatchOutcome::InferenceDefaults(active) =
        registry.execute_agent(&vault, actor, &principal, &change)?
    else {
        return Err(invalid("missing edited inference rows"));
    };
    assert_eq!(
        crate::llm::PurposeDefaultTable::from_json(active.as_bytes())?,
        edited
    );
    let mut request = crate::llm::LlmRequest {
        model: crate::llm::ModelId::new("test/own@r1").unwrap(),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
    };
    let host = crate::llm::HostInferenceContext {
        binding: crate::llm::HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality: ModelLocality::OwnServer,
        },
        extraction_egress: None,
    };
    request = vault
        .authorize_model_role(
            crate::llm::manifest::ModelRole::GenerativeReasoner,
            request,
            &host,
        )?
        .into_request();
    assert_eq!(
        request.envelope.tier.resolved().as_str(),
        "resident-consolidation"
    );
    let mut widening = edited;
    widening
        .voice
        .get_mut(&crate::llm::VoiceLane::AsrBatch)
        .unwrap()
        .locality = ModelLocality::ThirdParty;
    let disallowed = AgentActionCall {
        args: vec![ActionArgument::Text(LensText::new(
            serde_json::to_string(&widening).unwrap(),
        )?)],
        idempotency_key: "cannot-widen".into(),
        ..change
    };
    assert!(
        registry
            .execute_agent(&vault, actor, &principal, &disallowed)
            .is_err()
    );
    assert_eq!(
        vault.purpose_default_table()?.purposes[&CallPurpose::Consolidation]
            .tier
            .as_str(),
        "resident-consolidation"
    );
    Ok(())
}
struct PolicyReceiptExecutor;
impl crate::dreamer_wake::DreamerAttemptExecutor for PolicyReceiptExecutor {
    async fn execute(
        &mut self,
        _attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        _ctx: &mut crate::dreamer_wake::WakeAttemptContext<'_>,
    ) -> Result<crate::dreamer_wake::DreamerAttemptExecution> {
        panic!("policy receipt must never enter the consolidation partition executor")
    }
}

#[test]
fn agent_chat_action_needs_host_owner_proof_then_v1_policy_runs() -> Result<()> {
    use crate::dreamer_runner::DreamerConsolidationScope;
    use crate::dreamer_wake::{
        DreamerWakeDriver, RunWakePass, WakeCancellation, WakeIdleState, WakePassDeadline,
        WakePolicyDecision, WakeRecipe,
    };
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (_foreign_dir, foreign) = open_test_vault_with(embedding_test_config());
    let agent_id = entity(0x51);
    let owner_id = entity(0x52);
    let foreign_owner_id = entity(0x53);
    for id in [agent_id, owner_id] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    foreign.put_entity(
        &foreign_owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"foreign owner",
    )?;
    let agent = WriteActor::new(agent_id, EdgeActorClass::Agent);
    let read = ScopedReadActorKey::with_actor_class(agent_id.to_hex(), "agent")
        .ok_or_else(|| invalid("agent reader"))?;
    let principal = LensPrincipalBinding::agent_task(agent_id.to_hex(), read.clone(), vec![read])?;
    let mut registry = ActionRegistry::default();
    registry.register_dreamer_wake_policy()?;
    let mut policy = vault.dreamer_wake_policy()?;
    policy.wake_grain_turns = 100;
    policy.new_records = 1;
    let text = serde_json::to_string(&policy).expect("policy row json");
    let call = AgentActionCall {
        verb_id: SelfUiActionId::new("dreamer.wake_policy.set")?,
        args: vec![ActionArgument::Text(LensText::new(text)?)],
        idempotency_key: "owner-asked-in-chat".into(),
    };
    assert!(matches!(
        registry.execute_agent(&vault, agent, &principal, &call),
        Err(Error::Gate(
            crate::error::GateError::ConsentOwnerNotAuthenticated(_)
        ))
    ));
    assert_ne!(vault.dreamer_wake_policy()?, policy);
    let foreign_proof = foreign.authenticate_owner(
        foreign_owner_id,
        &foreign_owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    assert!(matches!(
        registry.execute_agent_with_owner(
            &vault,
            agent,
            &principal,
            &AgentActionCall {
                idempotency_key: "foreign-owner".into(),
                ..call.clone()
            },
            &foreign_proof
        ),
        Err(Error::Gate(
            crate::error::GateError::ConsentOwnerNotAuthenticated(_)
        ))
    ));
    let owner_proof = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let result =
        registry.execute_agent_with_owner(&vault, agent, &principal, &call, &owner_proof)?;
    assert_eq!(result, SelfDispatchOutcome::WakePolicyWritten(policy));
    assert_eq!(vault.dreamer_wake_policy()?, policy);
    assert_eq!(
        registry.execute_agent_with_owner(&vault, agent, &principal, &call, &owner_proof)?,
        result
    );

    // A transcript-shaped claim to owner authentication is only input data;
    // the strict row decoder rejects it rather than minting a proof.
    let mut forged = serde_json::to_value(policy).expect("policy value");
    forged["principal_authenticated"] = serde_json::Value::Bool(true);
    let spoofed = AgentActionCall {
        args: vec![ActionArgument::Text(LensText::new(forged.to_string())?)],
        idempotency_key: "spoofed-owner".into(),
        ..call.clone()
    };
    assert!(
        registry
            .execute_agent_with_owner(&vault, agent, &principal, &spoofed, &owner_proof)
            .is_err()
    );
    assert_eq!(vault.dreamer_wake_policy()?, policy);

    let mut turn = Vec::new();
    rmpv::encode::write_value(&mut turn, &Value::Map(vec![("spkr".into(), "user".into())]))
        .expect("turn body");
    vault.put_entity(
        &entity(0x54),
        crate::registry::ENTITY_TYPE_TURN,
        TimeRange { start: 2, end: 2 },
        2,
        &turn,
    )?;
    let wake = vault.enqueue_due_dreamer_wake(
        WakeIdleState {
            running_turns: false,
            live_background_work: false,
            compute_available: true,
            last_inbound_at: 0,
        },
        100,
    )?;
    assert_eq!(
        wake.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave
        }
    );
    assert!(wake.attempt.is_some());
    let mut driver = DreamerWakeDriver::new(
        &vault,
        "agent-chat-policy",
        WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let report = crate::dreamer_wake::block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: crate::dreamer_wake::WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "agent-chat-policy".into(),
            budget_total_units: 1_000,
            reserve_units: 10,
            now: 100,
            host_scope: None,
        },
        &mut PolicyReceiptExecutor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    assert_eq!(
        vault.dreamer_wake_recipe_inputs()?[0].recipe,
        WakeRecipe::Weave
    );
    // Even an identical replay cannot use a now-revoked owner witness.
    vault.delete_entity_with_reason(&owner_id, crate::deletion::DeleteReason::UserDelete)?;
    assert!(matches!(
        registry.execute_agent_with_owner(&vault, agent, &principal, &call, &owner_proof,),
        Err(Error::Gate(
            crate::error::GateError::ConsentOwnerNotAuthenticated(_)
        ))
    ));
    Ok(())
}

#[test]
fn policy_action_replay_refuses_cross_effect_success() {
    let policy: crate::dreamer_wake::DreamerWakePolicy =
        serde_json::from_str(include_str!("../../dreamer_wake/wake_policy_defaults.json"))
            .expect("default row");
    let write = SelfCall::WakePolicyWrite(crate::code_run::SelfWakePolicyWriteCall::new(policy));
    assert!(
        CodeRunBridgeCall::record(
            0,
            &write,
            &SelfDispatchOutcome::MemoryWrite(crate::code_run::SelfMemoryWriteResult {
                id: entity(0x65)
            }),
            0,
            0
        )
        .is_err()
    );
    let search = SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("query", 1));
    assert!(
        CodeRunBridgeCall::record(
            0,
            &search,
            &SelfDispatchOutcome::WakePolicyWritten(policy),
            0,
            0
        )
        .is_err()
    );
}
