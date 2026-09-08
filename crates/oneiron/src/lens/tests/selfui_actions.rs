//! self.ui action-pipeline tests: typed events, forgery rejection, state binds,
//! tiers, and card lifecycle.

use super::*;
use crate::Result;
use crate::test_util::entity as test_entity_id;
use serde_json::json;

#[test]
fn typed_action_event_matches_declared_set() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);

    let card = remind_card()?;
    let render = card.render()?;
    assert_eq!(
        render.protocol_version, 2,
        "the wire version is bumped to 2"
    );
    assert_eq!(
        LENS_ATOM_KIT_VERSION, 3,
        "the atom-kit version moves to 3 for result_set"
    );
    assert_eq!(render.actions.len(), 1);
    assert_eq!(render.lifecycle.phase, GeneratedUiCardPhase::Active);

    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &toggle_event(set_remind(true)),
    )?;
    let GeneratedUiValidatedAction::Local { state, .. } = &validated else {
        panic!("a local declaration must resolve to a local state result");
    };
    assert_eq!(
        state.get(&state_key("remind")),
        Some(&SelfUiStateValue::Bool(true))
    );

    for (event, reason) in [
        (
            GeneratedUiActionEvent {
                action_id: action_id("reminder.dismiss"),
                ..toggle_event(Vec::new())
            },
            "undeclared action ids never resolve",
        ),
        (
            GeneratedUiActionEvent {
                element_id: id("root"),
                ..toggle_event(Vec::new())
            },
            "a declared action resolves only for its own element",
        ),
        (
            GeneratedUiActionEvent {
                element_id: id("ghost"),
                ..toggle_event(Vec::new())
            },
            "the named element must exist in the render",
        ),
        (
            GeneratedUiActionEvent {
                card_id: render_id("card-2"),
                ..toggle_event(Vec::new())
            },
            "an event must name the card it was rendered from",
        ),
    ] {
        assert!(
            frame
                .validate_action_event(
                    &scoped_read,
                    frame.principal(),
                    &render,
                    &render.state,
                    &event,
                )
                .is_err(),
            "{reason}"
        );
    }

    // An action id is declared exactly once: a duplicate never reaches a frame.
    let duplicated = declaration(
        "remind",
        "reminder.toggle",
        GeneratedUiActionTier::Local,
        action("reminder.toggle"),
    );
    assert!(
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![remind_toggle()]))?,
            vec![duplicated.clone(), duplicated],
            [(state_key("remind"), SelfUiStateValue::Bool(false))]
                .into_iter()
                .collect(),
        )
        .is_err(),
        "an action id must be declared exactly once"
    );

    // The embedded SelfUiAction must match the manifest entry exactly.
    let mut drifted = render.clone();
    drifted.actions[0].action = action("reminder.snooze");
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &drifted,
                &drifted.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "a declaration whose command differs from the element's embedded action is not resolvable"
    );
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_ok(),
        "the drift rejection is caused by the drift, not by the event"
    );

    // A declaration is only offered on a surface that can actually render its control.
    let degraded = card.render_for_surface(&GeneratedUiSurfaceCapabilities::text_only())?;
    assert!(
        degraded.actions.is_empty(),
        "a degraded element offers no action manifest entry"
    );

    Ok(())
}

#[test]
fn forged_action_and_actor_are_rejected() -> Result<()> {
    // Positive control: the honest shape parses, so the rejections below are the
    // forged field's doing and not a malformed baseline.
    let honest = json!({
        "cardId": "card-1",
        "elementId": "remind",
        "actionId": "reminder.toggle",
        "occurredAt": 1
    });
    let parsed: GeneratedUiActionEvent =
        serde_json::from_value(honest).expect("the honest event shape decodes");
    assert_eq!(parsed.occurred_at, 1);
    assert!(parsed.patch.is_empty());

    // Nothing about authority is expressible on the wire.
    for forged in [
        json!({ "actor": "user:root" }),
        json!({ "authority": "owner" }),
        json!({ "command": "vault.delete" }),
        json!({ "approval": true }),
        json!({ "emitter": "user:root" }),
        json!({ "source": "trusted" }),
        json!({ "script": "alert(1)" }),
        json!({ "url": "https://attacker.example" }),
    ] {
        let mut event = json!({
            "cardId": "card-1",
            "elementId": "remind",
            "actionId": "reminder.toggle",
            "occurredAt": 1
        });
        for (key, value) in forged.as_object().expect("forged field object") {
            event
                .as_object_mut()
                .expect("event object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiActionEvent>(event).is_err(),
            "action events must not carry {forged}"
        );
    }

    // The patch op is closed too: nothing rides alongside path/value.
    assert!(
        serde_json::from_value::<GeneratedUiStatePatch>(
            json!({ "op": "replace", "path": "/$state/remind", "value": {"type":"bool","value":true} })
        )
        .is_ok(),
        "the honest patch shape decodes"
    );
    assert!(
        serde_json::from_value::<GeneratedUiStatePatch>(json!({
            "op": "replace",
            "path": "/$state/remind",
            "value": {"type":"bool","value":true},
            "actor": "user:root"
        }))
        .is_err(),
        "state patches must not smuggle extra fields"
    );

    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = remind_card()?.render()?;

    // The emitter is stamped from the host frame, never supplied alongside the event.
    let intruder_key = actor_key("intruder");
    let intruder = LensPrincipalBinding::human_view(
        "intruder",
        intruder_key.clone(),
        vec![intruder_key.clone()],
    )?;
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                &intruder,
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "only the frame's own principal binding may stamp a validated action"
    );
    assert!(
        frame
            .validate_action_event(
                &vault.scoped_read(intruder_key),
                frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "the read key must be the acting principal's selected key"
    );
    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &toggle_event(Vec::new()),
    )?;
    assert_eq!(
        validated.emitter(),
        frame.principal(),
        "every validated action carries the host-bound emitter"
    );

    // A render minted for a different frame is not this frame's to adjudicate.
    let foreign_frame = LensRenderFrame::new(render_id("card-9"), frame.principal().clone());
    assert!(
        foreign_frame
            .validate_action_event(
                &scoped_read,
                foreign_frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "a render must belong to the frame validating its events"
    );

    // State paths are exact: undeclared keys, wrapper segments, and nesting all fail.
    for (path, reason) in [
        ("/$state/secret", "undeclared keys are rejected"),
        (
            "/$state/values/remind",
            "there is no values wrapper segment",
        ),
        ("/$state/remind/nested", "state paths are never nested"),
        ("/remind", "paths must be rooted at /$state/"),
        ("/$state/", "an empty key is not a state key"),
    ] {
        let event = toggle_event(vec![GeneratedUiStatePatch::Replace {
            path: path.to_string(),
            value: SelfUiStateValue::Bool(true),
        }]);
        assert!(
            frame
                .validate_action_event(
                    &scoped_read,
                    frame.principal(),
                    &render,
                    &render.state,
                    &event,
                )
                .is_err(),
            "{path}: {reason}"
        );
    }

    // Declared types are fixed, and remove/replace need a present key.
    let retyped = toggle_event(vec![GeneratedUiStatePatch::Replace {
        path: "/$state/remind".to_string(),
        value: SelfUiStateValue::Text(text("yes")),
    }]);
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &retyped,
            )
            .is_err(),
        "a patch may not change a declared $state type"
    );
    let removed_twice = toggle_event(vec![
        GeneratedUiStatePatch::Remove {
            path: "/$state/remind".to_string(),
        },
        GeneratedUiStatePatch::Replace {
            path: "/$state/remind".to_string(),
            value: SelfUiStateValue::Bool(true),
        },
    ]);
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &removed_twice,
            )
            .is_err(),
        "replace must address a present key"
    );

    // Archived cards are terminal for events too.
    let archived = GeneratedUiRender::interactive(
        render.card_id,
        render.catalog,
        render.root,
        render.nodes,
        render.actions,
        render.state,
        GeneratedUiCardLifecycle::new(
            GeneratedUiCardPhase::Archived,
            4,
            Some(GeneratedUiArchiveReason::Expired),
        )?,
    )?;
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &archived,
                &archived.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "an archived card accepts no further events"
    );

    Ok(())
}

#[test]
fn local_state_bind_round_trip() -> Result<()> {
    let card = remind_card()?;
    let card_value = serde_json::to_value(&card).expect("card encodes");
    assert_eq!(
        card_value["$state"]["remind"],
        json!({ "type": "bool", "value": false }),
        "$state is the flattened key map itself"
    );
    assert!(
        card_value["$state"].get("values").is_none(),
        "$state must never serialize a values wrapper"
    );
    assert_eq!(
        card_value["tree"]["root"]["children"][0]["$bind"][0],
        json!({ "stateKey": "remind", "property": "checked" }),
        "node bindings ride the literal $bind wire key"
    );
    let decoded: GeneratedUiCard = serde_json::from_value(card_value).expect("card decodes");
    assert_eq!(decoded, card);

    let render = decoded.render()?;
    let render_value = serde_json::to_value(&render).expect("render encodes");
    assert_eq!(
        render_value["$state"]["remind"],
        json!({"type":"bool","value":false})
    );
    assert_eq!(
        render_value["lifecycle"],
        json!({"phase":"active","revision":0})
    );
    assert_eq!(
        render_value["nodes"][1]["$bind"][0],
        json!({ "stateKey": "remind", "property": "checked" })
    );
    let render_round_trip: GeneratedUiRender =
        serde_json::from_value(render_value).expect("render decodes");
    assert_eq!(render_round_trip, render);

    // card_state_update carries the manifest, flattened $state, and lifecycle.
    let segments = render.segments();
    let Some(GeneratedUiSegment::CardStateUpdate(update)) = segments.last() else {
        panic!("the segment stream must end with card_state_update");
    };
    assert_eq!(update.data_model.actions, render.actions);
    assert_eq!(update.data_model.state, render.state);
    assert_eq!(update.data_model.lifecycle, render.lifecycle);
    assert_eq!(GeneratedUiRender::from_segments(&segments)?, render);

    // The hand-written LensNode seed carries $bind through both msgpack forms.
    let named = rmp_serde::to_vec_named(&card.tree).expect("msgpack encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&named).expect("msgpack decode"),
        card.tree
    );
    let positional = rmp_serde::to_vec(&card.tree).expect("positional msgpack encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&positional).expect("positional msgpack decode"),
        card.tree
    );

    // Bindings must reference a declared key whose type the property accepts.
    let bound = |binding: SelfUiBinding, value: SelfUiStateValue| -> Result<GeneratedUiCard> {
        let mut toggle = remind_toggle();
        toggle.state_bindings = vec![binding];
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![toggle]))?,
            vec![declaration(
                "remind",
                "reminder.toggle",
                GeneratedUiActionTier::Local,
                action("reminder.toggle"),
            )],
            [(state_key("remind"), value)].into_iter().collect(),
        )
    };
    assert!(
        bound(
            SelfUiBinding {
                state_key: state_key("nope"),
                property: SelfUiBindableProperty::Checked,
            },
            SelfUiStateValue::Bool(false),
        )
        .is_err(),
        "$bind must reference a declared $state key"
    );
    assert!(
        bound(
            SelfUiBinding {
                state_key: state_key("remind"),
                property: SelfUiBindableProperty::Text,
            },
            SelfUiStateValue::Bool(false),
        )
        .is_err(),
        "the bindable-property table is closed over value types"
    );

    // $bind belongs to controls only.
    let mut plain =
        LensNode::with_fallback_text(id("note"), LensAtom::StatusDot(status()), text("note"));
    plain.state_bindings = vec![SelfUiBinding {
        state_key: state_key("remind"),
        property: SelfUiBindableProperty::Checked,
    }];
    assert!(
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![plain]))?,
            Vec::new(),
            [(state_key("remind"), SelfUiStateValue::Bool(false))]
                .into_iter()
                .collect(),
        )
        .is_err(),
        "$bind descriptors are only valid on self.ui controls"
    );

    // There is no evaluator: computed/expression keys are not part of the closed shape.
    let bare = json!({
        "protocolVersion": GENERATED_UI_WIRE_VERSION,
        "catalog": "lens_atom_kit",
        "cardId": "card-1",
        "tree": {
            "kit_version": LENS_ATOM_KIT_VERSION,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": {
                "id": "root",
                "atom": { "kind": "throbber", "props": { "label": "loading" } },
                "fallbackText": "loading"
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedUiCard>(bare.clone()).is_ok(),
        "the baseline card without interactivity still decodes"
    );
    for evaluator_key in ["$computed", "$expr", "$script"] {
        let mut attempted = bare.clone();
        attempted.as_object_mut().expect("card object").insert(
            evaluator_key.to_string(),
            json!({ "remind": "state.remind" }),
        );
        assert!(
            serde_json::from_value::<GeneratedUiCard>(attempted).is_err(),
            "{evaluator_key} is not a generated-ui field"
        );
    }

    Ok(())
}

#[test]
fn action_tiers_do_not_auto_forward() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(11);
    put_person(&vault, &target_id)?;

    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);
    frame.mint_backing_ref(
        &scoped_read,
        handle("selected-person"),
        LensHandleRole::ActionTarget,
        backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;

    let remember = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("selected-person"))],
    };
    let summarize = SelfUiAction {
        command: action_id("summarize"),
        args: vec![SelfUiValue::Text(text("today"))],
    };

    let card = GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![
            remind_toggle(),
            LensNode::with_fallback_text(
                id("save"),
                button_atom("save", remember.clone()),
                text("Save"),
            ),
            LensNode::with_fallback_text(
                id("ask"),
                button_atom("ask", summarize.clone()),
                text("Ask"),
            ),
        ]))?,
        vec![
            declaration(
                "remind",
                "reminder.toggle",
                GeneratedUiActionTier::Local,
                action("reminder.toggle"),
            ),
            declaration(
                "save",
                "remember",
                GeneratedUiActionTier::DeterministicTool,
                remember.clone(),
            ),
            declaration(
                "ask",
                "summarize",
                GeneratedUiActionTier::ModelRoundTrip,
                summarize,
            ),
        ],
        [(state_key("remind"), SelfUiStateValue::Bool(false))]
            .into_iter()
            .collect(),
    )?;
    let render = card.render()?;

    let event = |element: &str, action_name: &str, patch: Vec<GeneratedUiStatePatch>| {
        GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id(element),
            action_id: action_id(action_name),
            patch,
            occurred_at: 7,
        }
    };
    let validate = |event: &GeneratedUiActionEvent| {
        frame.validate_action_event(
            &scoped_read,
            frame.principal(),
            &render,
            &render.state,
            event,
        )
    };

    // local: the typed state snapshot moves, and nothing else does.
    let local = validate(&event("remind", "reminder.toggle", set_remind(true)))?;
    let GeneratedUiValidatedAction::Local { state, .. } = &local else {
        panic!("the local tier must stay local");
    };
    assert_eq!(
        state.get(&state_key("remind")),
        Some(&SelfUiStateValue::Bool(true))
    );

    // deterministic_tool: a typed existing-verb trigger, still behind the write chokepoint.
    let deterministic = validate(&event("save", "remember", Vec::new()))?;
    let GeneratedUiValidatedAction::DeterministicTool {
        action: approved, ..
    } = &deterministic
    else {
        panic!("the deterministic tier must yield an approved action");
    };
    assert_eq!(approved.command().as_str(), "remember");
    let LensApprovedActionArg::BackingRef(backing_ref) = &approved.args()[0] else {
        panic!("handle args resolve through the host backing table");
    };
    assert_eq!(backing_ref.target().entity_id(), &target_id);
    let mediated = approved
        .clone()
        .into_host_mediated_write(LensGateWriteChokepoint::EvaluateGate);
    assert_eq!(
        mediated.chokepoint(),
        LensGateWriteChokepoint::EvaluateGate,
        "a deterministic write still has to be routed through a named gate chokepoint"
    );

    // model_round_trip: exactly the four structured callback fields, and no tool call.
    let model = validate(&event("ask", "summarize", Vec::new()))?;
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = &model else {
        panic!("the model tier must yield an agent callback");
    };
    assert_eq!(callback.action_name.as_str(), "summarize");
    assert_eq!(
        callback.resolved_params,
        vec![LensApprovedActionArg::Text(text("today"))]
    );
    assert_eq!(callback.source_card_id, render_id("card-1"));
    assert_eq!(callback.source_element_id, id("ask"));

    // Trigger tiers take their arguments from the declaration alone.
    for element_and_action in [("save", "remember"), ("ask", "summarize")] {
        assert!(
            validate(&event(
                element_and_action.0,
                element_and_action.1,
                set_remind(true)
            ))
            .is_err(),
            "only local actions may carry a $state patch"
        );
    }

    // And a local action can never reach the host backing table.
    assert!(
        GeneratedUiCard::card(
            render_id("card-1"),
            card_root(vec![LensNode::with_fallback_text(
                id("save"),
                button_atom("save", remember.clone()),
                text("Save"),
            )]),
        )?
        .with_interactivity(
            vec![declaration(
                "save",
                "remember",
                GeneratedUiActionTier::Local,
                remember,
            )],
            GeneratedUiStateSnapshot::default(),
        )
        .is_err(),
        "a local action may not declare host handle arguments"
    );

    Ok(())
}

#[test]
fn card_lifecycle_transition_table() -> Result<()> {
    use GeneratedUiArchiveReason::{Completed, Dismissed, Expired};
    use GeneratedUiCardPhase::{Active, Archived, Generating, Responded};

    // The canonical sequence, with the revision advancing on every hop.
    let generating = GeneratedUiCardLifecycle::new(Generating, 0, None)?;
    let active = generating.transition(Active, None)?;
    let responded = active.transition(Responded, None)?;
    let archived = responded.transition(Archived, Some(Completed))?;
    assert_eq!(
        (active.revision, responded.revision, archived.revision),
        (1, 2, 3)
    );
    assert_eq!(archived.archive_reason, Some(Completed));

    // Completion and expiry are archive reasons, not competing phases.
    let expired = active.transition(Archived, Some(Expired))?;
    assert_eq!(expired.phase, Archived);
    assert_eq!(expired.archive_reason, Some(Expired));

    // Archived is terminal.
    for phase in [Generating, Active, Responded, Archived] {
        assert!(archived.transition(phase, None).is_err());
        assert!(archived.transition(phase, Some(Dismissed)).is_err());
    }

    // Backwards and self transitions are illegal.
    assert!(responded.transition(Active, None).is_err());
    assert!(active.transition(Generating, None).is_err());
    assert!(active.transition(Active, None).is_err());

    // Archive reasons are required on archived and forbidden everywhere else.
    assert!(active.transition(Archived, None).is_err());
    assert!(active.transition(Responded, Some(Completed)).is_err());
    assert!(GeneratedUiCardLifecycle::new(Archived, 1, None).is_err());
    assert!(GeneratedUiCardLifecycle::new(Active, 1, Some(Completed)).is_err());

    // The same table holds on the wire.
    assert!(
        serde_json::from_value::<GeneratedUiCardLifecycle>(
            json!({ "phase": "archived", "revision": 2 })
        )
        .is_err(),
        "archived lifecycles must name their reason"
    );
    assert!(
        serde_json::from_value::<GeneratedUiCardLifecycle>(
            json!({ "phase": "active", "revision": 2, "archiveReason": "expired" })
        )
        .is_err(),
        "archive reasons never ride a non-archived phase"
    );

    // The initial completed tree emits active; later revisions ride the same stream.
    let render = remind_card()?.render()?;
    assert_eq!(render.lifecycle, GeneratedUiCardLifecycle::initial());
    let responded_render = GeneratedUiRender::interactive(
        render.card_id.clone(),
        render.catalog,
        render.root.clone(),
        render.nodes.clone(),
        render.actions.clone(),
        render.state.clone(),
        render.lifecycle.transition(Responded, None)?,
    )?;
    let segments = responded_render.segments();
    let update =
        serde_json::to_value(segments.last().expect("card_state_update")).expect("segment encodes");
    assert_eq!(
        update["payload"]["dataModel"]["lifecycle"],
        json!({ "phase": "responded", "revision": 1 }),
        "the lifecycle revision is observable in card_state_update"
    );
    assert_eq!(
        GeneratedUiRender::from_segments(&segments)?,
        responded_render
    );

    Ok(())
}

#[test]
fn card_lifecycle_is_required_on_the_wire_and_gated_at_validate() -> Result<()> {
    use GeneratedUiArchiveReason::{Dismissed, Expired};
    use GeneratedUiCardPhase::{Active, Archived, Responded};

    let render = remind_card()?.render()?;
    let archived_lifecycle = render
        .lifecycle
        .transition(Responded, None)?
        .transition(Archived, Some(Dismissed))?;
    let archived = GeneratedUiRender::interactive(
        render.card_id.clone(),
        render.catalog,
        render.root.clone(),
        render.nodes.clone(),
        render.actions.clone(),
        render.state,
        archived_lifecycle.clone(),
    )?;
    let data_model = |lifecycle: GeneratedUiCardLifecycle| GeneratedUiDataModel {
        root: archived.root.clone(),
        node_count: archived.nodes.len(),
        catalog: archived.catalog,
        actions: archived.actions.clone(),
        state: archived.state.clone(),
        lifecycle,
    };
    let without_lifecycle = |value: &serde_json::Value| {
        let mut object = value
            .as_object()
            .expect("v2 payloads encode as objects")
            .clone();
        object
            .remove("lifecycle")
            .expect("lifecycle rides the v2 wire");
        serde_json::Value::Object(object)
    };

    // An archived card whose lifecycle is missing must be rejected at parse. Healing it
    // to active/rev 0 would resurrect a terminal card at a closed-schema boundary.
    let encoded_render = serde_json::to_value(&archived).expect("render encodes");
    assert_eq!(encoded_render["lifecycle"]["phase"], json!("archived"));
    assert!(
        serde_json::from_value::<GeneratedUiRender>(without_lifecycle(&encoded_render)).is_err(),
        "a render without a lifecycle must not parse as active/rev 0"
    );
    let encoded_model =
        serde_json::to_value(data_model(archived_lifecycle)).expect("data model encodes");
    assert!(
        serde_json::from_value::<GeneratedUiDataModel>(without_lifecycle(&encoded_model)).is_err(),
        "a data model without a lifecycle must not parse as active/rev 0"
    );

    // The engine may not emit lifecycles its own reader rejects: both halves of the
    // phase/reason invariant are gated at validate, not only at parse.
    for smuggled in [
        GeneratedUiCardLifecycle {
            phase: Active,
            revision: 1,
            archive_reason: Some(Expired),
        },
        GeneratedUiCardLifecycle {
            phase: Archived,
            revision: 1,
            archive_reason: None,
        },
    ] {
        let mut forged_render = archived.clone();
        forged_render.lifecycle = smuggled.clone();
        assert!(
            forged_render.validate().is_err(),
            "render validate must gate the lifecycle phase/reason invariant"
        );
        assert!(
            data_model(smuggled).validate().is_err(),
            "data model validate must gate the lifecycle phase/reason invariant"
        );
    }

    Ok(())
}
