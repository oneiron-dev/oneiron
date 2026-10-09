//! Atom-kit catalog and mediation-auth tests: principal-held keys, backing-ref
//! tokens, and host-bound action handles.

use super::*;
use crate::test_util::entity as test_entity_id;
use crate::{Result, claim::ScopedReadActorKey};

#[test]
fn render_principal_key_selection_must_be_held_by_principal() {
    let human_key = actor_key("human-viewer");
    let agent_key = ScopedReadActorKey::with_actor_class("task-agent", "agent").expect("agent key");

    let human = LensPrincipalBinding::human_view(
        "human-viewer",
        human_key.clone(),
        vec![human_key.clone()],
    )
    .expect("human binding");
    assert_eq!(human.kind(), LensActingPrincipalKind::HumanView);
    assert_eq!(human.selected_read_key(), &human_key);

    let agent =
        LensPrincipalBinding::agent_task("task-agent", agent_key.clone(), vec![agent_key.clone()])
            .expect("agent binding");
    assert_eq!(agent.kind(), LensActingPrincipalKind::AgentTask);

    assert!(
        LensPrincipalBinding::agent_task("task-agent", human_key, vec![agent_key]).is_err(),
        "over-scope render key selection must fail containment"
    );
    assert!(
        LensPrincipalBinding::human_view(" ", actor_key("viewer"), vec![actor_key("viewer")])
            .is_err(),
        "blank principal refs cannot bind a render"
    );
    assert!(
        LensPrincipalBinding::human_view("viewer", actor_key("viewer"), Vec::new()).is_err(),
        "principal bindings must name at least one held read key"
    );
    assert!(
        LensPrincipalBinding::human_view(
            "viewer-a",
            actor_key("viewer-a"),
            vec![actor_key("viewer-b")]
        )
        .is_err(),
        "held read keys must belong to the acting principal"
    );
    assert!(
        LensPrincipalBinding::human_view(
            "viewer",
            ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key"),
            vec![ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key")]
        )
        .is_err(),
        "human renders must not bind an agent-class read key"
    );
}

#[test]
fn forged_and_foreign_backing_ref_tokens_do_not_resolve() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(7);
    put_person(&vault, &target_id)?;
    install_viewer_base_grant(&vault)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
    let token = frame.mint_backing_ref(
        &scoped_read,
        handle("visible-person"),
        LensHandleRole::ActionTarget,
        backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;

    let resolved = frame.resolve_backing_ref_token(&scoped_read, &token)?;
    assert_eq!(resolved.target().entity_id(), &target_id);

    let foreign_token = LensBackingRefToken {
        render_id: render_id("render-b"),
        ref_id: token.ref_id().clone(),
    };
    assert!(
        frame
            .resolve_backing_ref_token(&scoped_read, &foreign_token)
            .is_err(),
        "a token minted for another render must not select this render's target"
    );

    let forged_token = LensBackingRefToken {
        render_id: render_id("render-a"),
        ref_id: backing_ref_id("ref-999"),
    };
    assert!(
        frame
            .resolve_backing_ref_token(&scoped_read, &forged_token)
            .is_err(),
        "a token absent from the host backing table must not resolve"
    );

    let other_key = actor_key("other-viewer");
    let other_read = vault.scoped_read(other_key);
    assert!(
        frame
            .resolve_backing_ref_token(&other_read, &token)
            .is_err(),
        "render-bound selections must be rechecked under the acting principal key"
    );

    Ok(())
}

#[test]
fn lens_actions_resolve_only_host_bound_handles() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(8);
    put_person(&vault, &target_id)?;
    install_viewer_base_grant(&vault)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
    let target = backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?;
    let expected_short_ref = target.short_ref();
    frame.mint_backing_ref(
        &scoped_read,
        handle("selected-person"),
        LensHandleRole::ActionTarget,
        target.clone(),
    )?;
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("selected-person"),
                LensHandleRole::ActionTarget,
                target.clone(),
            )
            .is_err(),
        "one handle must not bind multiple backing refs in a render"
    );
    frame.mint_backing_ref(
        &scoped_read,
        handle("visible-set"),
        LensHandleRole::EntitySet,
        target,
    )?;

    let action = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("selected-person"))],
    };
    let approved = frame.approve_action(&scoped_read, &action)?;
    assert_eq!(approved.command().as_str(), "remember");
    match &approved.args()[0] {
        LensApprovedActionArg::BackingRef(backing_ref) => {
            assert_eq!(backing_ref.target().entity_id(), &target_id);
            assert_eq!(backing_ref.target().short_ref(), expected_short_ref);
        }
        other => panic!("expected host backing ref, got {other:?}"),
    }

    let forged = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("cl999"))],
    };
    assert!(
        frame.approve_action(&scoped_read, &forged).is_err(),
        "lens-supplied ids that were never host-bound must fail at the action boundary"
    );
    let wrong_role = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("visible-set"))],
    };
    assert!(
        frame.approve_action(&scoped_read, &wrong_role).is_err(),
        "only action-target handles can become approved backing refs"
    );

    Ok(())
}

#[test]
fn backing_refs_recheck_short_ref_and_target_kind_under_scoped_read() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let subject_id = test_entity_id(9);
    let claim_id = test_entity_id(10);
    put_person(&vault, &subject_id)?;
    put_profile_claim(&vault, &claim_id, &subject_id)?;
    install_viewer_base_grant(&vault)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);

    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("wrong-kind"),
                LensHandleRole::ActionTarget,
                backing_target_for(&vault, &subject_id, LensBackingTargetKind::Claim)?,
            )
            .is_err(),
        "claim backing refs must resolve to claim entities"
    );
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("claim-as-entity"),
                LensHandleRole::ActionTarget,
                backing_target_for(&vault, &claim_id, LensBackingTargetKind::Entity)?,
            )
            .is_err(),
        "entity backing refs must not hide claim targets"
    );

    let mut drifted = backing_target_for(&vault, &subject_id, LensBackingTargetKind::Entity)?;
    drifted.entity_id = claim_id;
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("drifted-short-ref"),
                LensHandleRole::ActionTarget,
                drifted,
            )
            .is_err(),
        "short refs must hydrate back to the host-selected entity"
    );

    Ok(())
}
