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
    let SelfDispatchOutcome::MemoryWrite(result) = ui.outcome else {
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
fn build_about(ctx: ActionBuildContext, args: &[ActionArgument]) -> Result<SelfCall> {
    let [ActionArgument::Entity { .. }, text] = args else {
        return Err(invalid("entity and text"));
    };
    build(ctx, std::slice::from_ref(text))
}
#[test]
fn code_run_read_action_returns_the_scoped_read_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = entity(0x67);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    let target = entity(0x68);
    let mut about = crate::ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(actor),
        Value::from("the entity an action names"),
        1.0,
        crate::ClaimApprovalStatus::Approved,
        crate::ClaimLifecycleStatus::Active,
    )?;
    about.source = Some(crate::ClaimSource::UserStated);
    vault.put_claim(&target, &about, TimeRange { start: 1, end: 1 }, 1)?;
    let actor = WriteActor::new(actor, EdgeActorClass::Agent);
    let key = ScopedReadActorKey::with_actor_class(actor.entity_ref().to_hex(), "agent")
        .ok_or_else(|| invalid("reader"))?;
    let principal = LensPrincipalBinding::agent_task(
        actor.entity_ref().to_hex(),
        key.clone(),
        vec![key.clone()],
    )?;
    let mut registry = ActionRegistry::default();
    registry.register(
        ActionVerbDefinition {
            id: SelfUiActionId::new("remember-about")?,
            args_schema: vec![ActionArgKind::Entity, ActionArgKind::Text],
            required_ceiling: AgentCeiling::Proposed,
        },
        build_about,
    )?;
    let call = AgentActionCall {
        verb_id: SelfUiActionId::new("remember-about")?,
        args: vec![
            ActionArgument::Entity { id: target },
            ActionArgument::Text(LensText::new("Ada")?),
        ],
        idempotency_key: "read-action".into(),
    };
    // Without a read grant the principal's ceiling denies everything, so the
    // entity argument is withheld and the action refuses before any effect.
    let denied = vault.scoped_read(key.clone()).read_receipt(None, 0)?;
    assert!(denied.narrowed_axes.contains(&"deny_all".to_owned()));
    assert!(matches!(
        registry.execute_agent(&vault, actor, &principal, &call),
        Err(Error::InvalidConfig(_))
    ));
    assert!(vault.claims_for_subject(&actor.entity_ref())?.len() == 1);
    // Granted, the dispatch carries the principal's own receipt of its read.
    crate::test_util::authorize_readers(&vault, &[actor.entity_ref().to_hex().as_str()]);
    let dispatch = registry.execute_agent(&vault, actor, &principal, &call)?;
    assert!(matches!(
        dispatch.outcome,
        SelfDispatchOutcome::MemoryWrite(_)
    ));
    assert_eq!(
        dispatch.read_receipt,
        vault.scoped_read(key).read_receipt(None, 0)?
    );
    assert!(!dispatch.read_receipt.applied.deny_all);
    assert_eq!(dispatch.read_receipt.suppressed_count, 0);
    Ok(())
}
