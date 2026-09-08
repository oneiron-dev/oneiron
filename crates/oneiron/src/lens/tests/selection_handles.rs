//! Selection and handle-discipline tests: resolution paths, read handles,
//! staleness, and callback context.

use super::*;
use crate::Result;
use crate::test_util::entity as test_entity_id;
use proptest::prelude::*;
use serde_json::json;

#[test]
fn selecting_a_bound_atom_returns_structured_read_reach() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(12);
    let (viewer_key, frame, expected_short_ref) =
        selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "people", "visible-set"),
    )?;

    assert_eq!(read_handle.render_id(), &render_id("card-1"));
    assert_eq!(read_handle.atom_id(), &id("people"));
    assert_eq!(read_handle.reach(), LensReadReach::EntitySet);
    assert_eq!(read_handle.target_kind(), LensBackingTargetKind::Entity);
    assert_eq!(
        read_handle.short_ref(),
        expected_short_ref,
        "the short ref is a locator the principal already resolves under ScopedRead"
    );

    // The payload is exactly that metadata: a locator, never the stored body it locates.
    let encoded = serde_json::to_value(&read_handle).expect("read handle encodes");
    let mut keys = encoded
        .as_object()
        .expect("read handles encode as objects")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "atomId",
            "backingToken",
            "reach",
            "renderId",
            "shortRef",
            "targetKind"
        ]
    );
    let entity_hex = target_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let flat = encoded.to_string();
    for leaked in ["person", entity_hex.as_str(), "screenshot", "authority"] {
        assert!(
            !flat.contains(leaked),
            "a read handle must not disclose {leaked}"
        );
    }

    // Serialize-only: a read handle is engine-issued and can never be re-submitted.
    assert!(
        serde_json::from_value::<serde_json::Value>(encoded)
            .expect("json round trips as a value")
            .is_object(),
        "the encoded shape stays plain data with no client-side constructor"
    );

    Ok(())
}

#[test]
fn selection_requests_never_carry_a_target() {
    // Positive control: the honest shape is three names and nothing else.
    let honest = json!({
        "cardId": "card-1",
        "atomId": "people",
        "handle": "visible-set"
    });
    let parsed: LensAtomSelectionRequest =
        serde_json::from_value(honest.clone()).expect("the honest selection shape decodes");
    assert_eq!(parsed.card_id, render_id("card-1"));
    assert_eq!(parsed.atom_id, id("people"));
    assert_eq!(parsed.handle, handle("visible-set"));

    for forged in [
        json!({ "entityId": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "body": "the note says ..." }),
        json!({ "screenshot": "data:image/png;base64,AAAA" }),
        json!({ "writeToken": "tok-1" }),
        json!({ "authority": "owner" }),
        json!({ "query": "claim.subject == person" }),
        json!({ "shortRef": "ab:01" }),
        json!({ "target": { "entityId": "x" } }),
        json!({ "role": "action_target" }),
        json!({ "backingToken": { "render_id": "card-1", "ref_id": "ref-0" } }),
    ] {
        let mut request = honest.clone();
        for (key, value) in forged.as_object().expect("forged field object") {
            request
                .as_object_mut()
                .expect("request object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "atom selections must not carry {forged}"
        );
    }

    // Missing names are not healed either: all three are required.
    for absent in ["cardId", "atomId", "handle"] {
        let mut request = honest.clone();
        request
            .as_object_mut()
            .expect("request object")
            .remove(absent);
        assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "a selection without {absent} must not decode"
        );
    }
}

#[test]
fn selection_proves_one_resolution_path() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(13);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &render,
                &selection("card-1", "people", "visible-set")
            )
            .is_ok(),
        "the honest triple resolves, so every rejection below is the forgery's doing"
    );

    // Arbitrary ids never sweep past the render: only the exact triple resolves.
    for (card, atom, name, reason) in [
        (
            "card-2",
            "people",
            "visible-set",
            "a selection names its own card",
        ),
        (
            "card-1",
            "ghost",
            "visible-set",
            "the atom must exist in the render",
        ),
        (
            "card-1",
            "root",
            "visible-set",
            "another node's binding is not this one's",
        ),
        (
            "card-1",
            "people",
            "cl999",
            "an unadvertised handle resolves to nothing",
        ),
        (
            "card-1",
            "people",
            "visible-person",
            "a host row the node never advertised is not selectable",
        ),
    ] {
        assert!(
            frame
                .select_atom(&scoped_read, &render, &selection(card, atom, name))
                .is_err(),
            "{reason}"
        );
    }

    // A node that advertises the same handle twice is ambiguous about its reach.
    let duplicated = selectable_render(
        "card-1",
        "people",
        vec![
            binding("visible-set", LensHandleRole::EntitySet),
            binding("visible-set", LensHandleRole::Timeline),
        ],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &duplicated,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "duplicate node bindings must not resolve to either reach"
    );

    // The node's declared role has to be the role the host actually bound.
    let role_swapped = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::Timeline)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &role_swapped,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "a node cannot relabel the reach of a host-minted row"
    );

    // A render this frame never emitted is not this frame's to select from.
    let foreign_render = selectable_render(
        "card-9",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &foreign_render,
                &selection("card-9", "people", "visible-set")
            )
            .is_err(),
        "a render must belong to the frame resolving its selections"
    );

    // Another principal's read key never drives this frame.
    assert!(
        frame
            .select_atom(
                &vault.scoped_read(actor_key("intruder")),
                &render,
                &selection("card-1", "people", "visible-set"),
            )
            .is_err(),
        "selections resolve only under the acting principal's selected read key"
    );

    Ok(())
}

#[test]
fn action_target_bindings_never_become_read_handles() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(14);
    let (viewer_key, frame, _) =
        selection_fixture(&vault, &target_id, LensHandleRole::ActionTarget)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::ActionTarget)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &render,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "an action-target binding is reach for the action backchannel, not a selection"
    );
    assert!(
        LensReadReach::try_from(LensHandleRole::ActionTarget).is_err(),
        "the read-reach enum excludes ActionTarget by construction"
    );
    for (role, reach) in [
        (LensHandleRole::ClaimSet, LensReadReach::ClaimSet),
        (LensHandleRole::EntitySet, LensReadReach::EntitySet),
        (LensHandleRole::Timeline, LensReadReach::Timeline),
        (LensHandleRole::QueryResult, LensReadReach::QueryResult),
    ] {
        assert_eq!(LensReadReach::try_from(role)?, reach);
    }

    // The same row still resolves through the action path it was minted for.
    let approved = frame.approve_action(
        &scoped_read,
        &SelfUiAction {
            command: action_id("remember"),
            args: vec![SelfUiValue::Handle(handle("visible-set"))],
        },
    )?;
    assert!(
        matches!(&approved.args()[0], LensApprovedActionArg::BackingRef(_)),
        "selection and approval stay separate paths over one backing table"
    );

    Ok(())
}

#[test]
fn read_handles_reresolve_and_never_widen() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(15);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "people", "visible-set"),
    )?;

    let resolved = frame.resolve_read_handle(&scoped_read, &render, &read_handle)?;
    assert_eq!(resolved.target().entity_id(), &target_id);
    assert_eq!(resolved.handle(), &handle("visible-set"));

    // Switching principals fails the handle rather than widening its scope.
    assert!(
        frame
            .resolve_read_handle(
                &vault.scoped_read(actor_key("intruder")),
                &render,
                &read_handle
            )
            .is_err(),
        "an issued handle is re-checked under the acting principal at use time"
    );

    // A later render revision that drops or relabels the binding revokes the handle.
    for (later, reason) in [
        (
            selectable_render("card-1", "people", Vec::new())?,
            "a node that stopped advertising the handle stops honoring it",
        ),
        (
            selectable_render(
                "card-1",
                "people",
                vec![binding("visible-set", LensHandleRole::ActionTarget)],
            )?,
            "a relabelled binding cannot launder read reach into action reach",
        ),
        (
            selectable_render(
                "card-1",
                "elsewhere",
                vec![binding("visible-set", LensHandleRole::EntitySet)],
            )?,
            "the handle's own atom must still carry the binding",
        ),
    ] {
        assert!(
            frame
                .resolve_read_handle(&scoped_read, &later, &read_handle)
                .is_err(),
            "{reason}"
        );
    }

    // A target whose stored content moved no longer hydrates the short ref the handle
    // was issued against: the handle fails rather than following the entity forward.
    vault.put_entity(
        &target_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 2, end: 2 },
        2,
        b"person, revised",
    )?;
    assert!(
        frame
            .resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "a stale short ref stops resolving instead of widening onto the new content"
    );

    // A twin frame over the same render id never host-minted that token. A twin that
    // *did* mint one is the harder case, covered next.
    let twin = LensRenderFrame::new(render_id("card-1"), frame.principal().clone());
    assert!(
        twin.resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "a token is only resolvable through the backing table that minted it"
    );

    Ok(())
}

/// A frame is not a capability. Render ids derive from card ids, so re-rendering a card
/// yields a *second* frame with the same render id, and `ref-{len}` numbers every
/// backing table from zero — a later frame's first mint carries the very token an older
/// handle holds. Nothing in the token separates the two rows, so re-resolution has to
/// re-prove the metadata the handle recorded at issue time.
#[test]
fn stale_handles_never_launder_onto_a_later_frames_row() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let issued_id = test_entity_id(18);
    let other_id = test_entity_id(19);
    put_person(&vault, &other_id)?;

    let (viewer_key, frame, issued_short_ref) =
        selection_fixture(&vault, &issued_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let entity_set_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let action_target_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::ActionTarget)],
    )?;
    let timeline_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::Timeline)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &entity_set_render,
        &selection("card-1", "people", "visible-set"),
    )?;

    // Each twin re-mints the issued handle's token under a row it never proved: a
    // different target, action reach, or different read reach over the same target.
    for (role, target_id, render, reason) in [
        (
            LensHandleRole::EntitySet,
            &other_id,
            &entity_set_render,
            "a same-named row over a different entity is not the row the handle proved",
        ),
        (
            LensHandleRole::ActionTarget,
            &issued_id,
            &action_target_render,
            "a row rebound as an action target never keeps honoring a read handle",
        ),
        (
            LensHandleRole::Timeline,
            &issued_id,
            &timeline_render,
            "a row that kept the target but changed reach cannot re-scope an issued handle",
        ),
    ] {
        let (_, mut twin) = viewer_frame("card-1")?;
        let token = twin.mint_backing_ref(
            &scoped_read,
            handle("visible-set"),
            role,
            backing_target_for(&vault, target_id, LensBackingTargetKind::Entity)?,
        )?;
        assert_eq!(
            &token,
            frame.backing_refs()[0].token(),
            "the twin's first mint collides with the token the issued handle carries, \
             so the rejection below is the metadata re-proof's doing"
        );
        assert!(
            twin.resolve_read_handle(&scoped_read, render, &read_handle)
                .is_err(),
            "{reason}"
        );
    }

    // The twin frames are healthy hosts, not broken ones: reach a twin issues itself
    // resolves through it, and it points where that twin bound it.
    let (_, mut twin) = viewer_frame("card-1")?;
    twin.mint_backing_ref(
        &scoped_read,
        handle("visible-set"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &other_id, LensBackingTargetKind::Entity)?,
    )?;
    let reissued = twin.select_atom(
        &scoped_read,
        &entity_set_render,
        &selection("card-1", "people", "visible-set"),
    )?;
    assert_eq!(
        twin.resolve_read_handle(&scoped_read, &entity_set_render, &reissued)?
            .target()
            .entity_id(),
        &other_id,
    );
    assert_eq!(read_handle.short_ref(), issued_short_ref);
    assert_ne!(
        reissued.short_ref(),
        read_handle.short_ref(),
        "the two handles differ only in the metadata re-resolution now re-proves"
    );

    Ok(())
}

#[test]
fn selected_read_context_rides_a_callback_without_becoming_approval() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(16);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    // One node is both the model-tier control and the selectable atom.
    let summarize = SelfUiAction {
        command: action_id("summarize"),
        args: vec![SelfUiValue::Text(text("today"))],
    };
    let mut ask = LensNode::with_fallback_text(
        id("ask"),
        button_atom("ask", summarize.clone()),
        text("Ask"),
    );
    ask.bindings = vec![binding("visible-set", LensHandleRole::EntitySet)];
    let render = GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![ask]))?,
        vec![declaration(
            "ask",
            "summarize",
            GeneratedUiActionTier::ModelRoundTrip,
            summarize,
        )],
        GeneratedUiStateSnapshot::default(),
    )?
    .render()?;

    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "ask", "visible-set"),
    )?;
    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id("ask"),
            action_id: action_id("summarize"),
            patch: Vec::new(),
            occurred_at: 3,
        },
    )?;
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = &validated else {
        panic!("the model tier must yield an agent callback");
    };
    assert!(
        callback.selected_context.is_empty(),
        "a validated action carries no selection the host did not attach"
    );

    let carried = frame.with_selected_context(
        &scoped_read,
        &render,
        callback.clone(),
        vec![read_handle.clone()],
    )?;
    assert_eq!(carried.selected_context, vec![read_handle.clone()]);
    assert_eq!(
        carried.resolved_params,
        vec![LensApprovedActionArg::Text(text("today"))],
        "context never becomes a resolved parameter"
    );
    assert_eq!(carried.action_name.as_str(), "summarize");

    // A callback minted by another render is not this frame's to enrich.
    let foreign_callback = GeneratedUiAgentCallback {
        source_card_id: render_id("card-9"),
        ..carried
    };
    assert!(
        frame
            .with_selected_context(
                &scoped_read,
                &render,
                foreign_callback,
                vec![read_handle.clone()]
            )
            .is_err(),
        "selected context must ride a callback from this render frame"
    );

    // Attaching is a re-proof: a handle the current render no longer honors is refused.
    assert!(
        frame
            .with_selected_context(
                &scoped_read,
                &selectable_render("card-1", "ask", Vec::new())?,
                callback.clone(),
                vec![read_handle],
            )
            .is_err(),
        "context is re-resolved at attach time, never trusted from an earlier turn"
    );

    Ok(())
}

#[test]
fn bound_control_values_stay_inside_their_declared_domain() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);

    let mode = || {
        let mut node = LensNode::with_fallback_text(
            id("mode"),
            LensAtom::SelfUi(SelfUiControl::Select(SelectControl {
                id: control_id("mode"),
                label: text("Mode"),
                options: ["fast", "careful"]
                    .into_iter()
                    .map(|value| SelfUiOption {
                        value: option_value(value),
                        label: text(value),
                    })
                    .collect(),
                selected: None,
                action: action("mode.pick"),
            })),
            text("Mode"),
        );
        node.state_bindings = vec![SelfUiBinding {
            state_key: state_key("mode"),
            property: SelfUiBindableProperty::Selected,
        }];
        node
    };
    let level = || {
        let mut node = LensNode::with_fallback_text(
            id("level"),
            LensAtom::SelfUi(SelfUiControl::Slider(SliderControl {
                id: control_id("level"),
                label: text("Level"),
                min: finite(0.0),
                max: finite(10.0),
                step: finite(0.5),
                value: finite(5.0),
                action: action("level.set"),
            })),
            text("Level"),
        );
        node.state_bindings = vec![SelfUiBinding {
            state_key: state_key("level"),
            property: SelfUiBindableProperty::Value,
        }];
        node
    };
    let card = |chosen: &str, at: f64| -> Result<GeneratedUiCard> {
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![mode(), level()]))?,
            vec![
                declaration(
                    "mode",
                    "mode.pick",
                    GeneratedUiActionTier::Local,
                    action("mode.pick"),
                ),
                declaration(
                    "level",
                    "level.set",
                    GeneratedUiActionTier::Local,
                    action("level.set"),
                ),
            ],
            [
                (
                    state_key("mode"),
                    SelfUiStateValue::Token(option_value(chosen)),
                ),
                (state_key("level"), SelfUiStateValue::Number(finite(at))),
            ]
            .into_iter()
            .collect(),
        )
    };

    // Assembly already refuses a bound value the control itself could never hold.
    assert!(card("fast", 5.0).is_ok(), "the honest card assembles");
    for (chosen, at, reason) in [
        (
            "sloppy",
            5.0,
            "a bound token must be one of the control's own options",
        ),
        (
            "fast",
            5.25,
            "a bound number must land on the slider's step grid",
        ),
        (
            "fast",
            11.0,
            "a bound number must stay inside the slider's range",
        ),
        ("fast", -0.5, "the range is closed below too"),
    ] {
        assert!(card(chosen, at).is_err(), "{reason}");
    }

    // And the same domain holds against a client patch, where the type agrees but the
    // value does not: type equality was never the whole conformance rule.
    let render = card("fast", 5.0)?.render()?;
    let event = |element: &str, action_name: &str, patch: Vec<GeneratedUiStatePatch>| {
        GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id(element),
            action_id: action_id(action_name),
            patch,
            occurred_at: 5,
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
    let replace = |key: &str, value: SelfUiStateValue| {
        vec![GeneratedUiStatePatch::Replace {
            path: format!("/$state/{key}"),
            value,
        }]
    };

    assert!(
        validate(&event(
            "mode",
            "mode.pick",
            replace("mode", SelfUiStateValue::Token(option_value("careful"))),
        ))
        .is_ok(),
        "an offered option is still selectable"
    );
    assert!(
        validate(&event(
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(7.5))),
        ))
        .is_ok(),
        "an on-grid number is still settable"
    );

    for (element, action_name, patch, reason) in [
        (
            "mode",
            "mode.pick",
            replace("mode", SelfUiStateValue::Token(option_value("sloppy"))),
            "a patch must not select an option the control never offered",
        ),
        (
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(5.25))),
            "a patch must not move a slider off its declared step",
        ),
        (
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(10.5))),
            "a patch must not move a slider past its declared max",
        ),
        (
            "mode",
            "mode.pick",
            vec![GeneratedUiStatePatch::Remove {
                path: "/$state/mode".to_string(),
            }],
            "a patch must not strand a bound control with no value",
        ),
    ] {
        assert!(
            validate(&event(element, action_name, patch)).is_err(),
            "{reason}"
        );
    }

    Ok(())
}

proptest! {
    #[test]
    fn generated_ui_fuzz_rejects_extra_atom_selection_fields(
        field in "[a-zA-Z][a-zA-Z0-9_]{0,16}",
        value in "[a-zA-Z0-9 :/._-]{0,32}",
    ) {
        prop_assume!(!["cardId", "atomId", "handle"].contains(&field.as_str()));

        let mut request = json!({
            "cardId": "card-1",
            "atomId": "people",
            "handle": "visible-set"
        });
        request
            .as_object_mut()
            .expect("request object")
            .insert(field, json!(value));

        prop_assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "an atom selection carries three names and nothing else"
        );
    }
}
