//! Client interactions remain frame-bound plans behind the existing write gate.
use super::*;
use crate::Result;
use crate::surface_event::{
    SURFACE_EVENT_SCHEMA_VERSION, SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAction,
    SurfaceEventSource, SurfaceInteractionKind, SurfaceSourceApp,
};
use crate::test_util::entity as test_entity_id;

#[test]
fn native_interaction_requires_the_frame_target_and_produces_only_a_mediated_write() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target = test_entity_id(11);
    put_person(&vault, &target)?;
    let (key, mut frame) = viewer_frame("card-1")?;
    let read = vault.scoped_read(key);
    let token = frame.mint_backing_ref(
        &read,
        handle("selected-person"),
        LensHandleRole::ActionTarget,
        backing_target_for(&vault, &target, LensBackingTargetKind::Entity)?,
    )?;
    let command = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("selected-person"))],
    };
    let card = GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![LensNode::with_fallback_text(
            id("save"),
            button_atom("save", command.clone()),
            text("Save"),
        )]))?,
        vec![declaration(
            "save",
            "remember",
            GeneratedUiActionTier::DeterministicTool,
            command,
        )],
        GeneratedUiStateSnapshot::default(),
    )?;
    let render = card.render()?;
    let event = GeneratedUiActionEvent {
        card_id: render_id("card-1"),
        element_id: id("save"),
        action_id: action_id("remember"),
        patch: vec![],
        occurred_at: 7,
    };
    let surface = SurfaceEvent {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        event_id: "click-1".into(),
        channel: "web".into(),
        receiving_address_or_handle: "native-view".into(),
        workspace_ref: None,
        receiving_identity_ref: "web-identity".into(),
        actor_ref: "receiving-agent".into(),
        facet_ref: None,
        subject_ref: None,
        counterparty: SurfaceCounterpartyStamp::Known {
            counterparty_ref: frame.principal().principal_ref().into(),
        },
        source: SurfaceEventSource::new(SurfaceSourceApp::Web, "viewer"),
        action: SurfaceEventAction::Interaction {
            interaction: SurfaceInteractionKind::Tap,
            target_ref: Some(token.ref_id().as_str().into()),
        },
        correlation_id: "click-1".into(),
        payload_ref: None,
        received_at: 7,
        foreign_inbound: false,
        claims_not_instructions: false,
        identity_retiring: false,
    };
    let dispatch = |surface: &SurfaceEvent, event: &GeneratedUiActionEvent| {
        frame.dispatch_surface_event(
            &read,
            frame.principal(),
            &render,
            &render.state,
            surface,
            event,
        )
    };
    let mediated = dispatch(&surface, &event)?;
    assert_eq!(mediated.chokepoint(), LensGateWriteChokepoint::EvaluateGate);
    assert_eq!(mediated.action().command().as_str(), "remember");
    let LensApprovedActionArg::BackingRef(backing) = &mediated.action().args()[0] else {
        panic!("backing ref")
    };
    assert_eq!(backing.target().entity_id(), &target);
    let mut forged = surface.clone();
    forged.action = SurfaceEventAction::Interaction {
        interaction: SurfaceInteractionKind::Tap,
        target_ref: Some("ref-forged".into()),
    };
    assert!(dispatch(&forged, &event).is_err());
    forged = surface.clone();
    forged.foreign_inbound = true;
    assert!(dispatch(&forged, &event).is_err());
    assert!(
        dispatch(
            &surface,
            &GeneratedUiActionEvent {
                card_id: render_id("another-frame"),
                ..event
            }
        )
        .is_err()
    );
    Ok(())
}
