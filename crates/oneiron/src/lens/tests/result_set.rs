//! Result-set atom tests: catalog negotiation, selection, render validation, and
//! gated dispatch.

use super::*;
use crate::Result;
use serde_json::json;

#[test]
fn lens_envelope_accepts_supported_versions_and_rejects_underdeclaration() -> Result<()> {
    let v2_node = serde_json::to_value(v2_only_root()).expect("node encodes");
    let v3_node = serde_json::to_value(standalone_result_set_root()).expect("node encodes");

    for (version, root, reason) in [
        (2, &v2_node, "the oldest supported envelope still decodes"),
        (3, &v2_node, "a v2 tree may over-declare up to the constant"),
        (3, &v3_node, "a v3 tree decodes at its own version"),
    ] {
        let envelope = json!({
            "kit_version": version,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": root,
        });
        let lens: GeneratedLens =
            serde_json::from_value(envelope).unwrap_or_else(|error| panic!("{reason}: {error}"));
        assert_eq!(lens.kit_version(), version, "{reason}");
    }

    // Under-declaration is caught after decode, against the atoms actually present.
    let error = serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": 2,
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
        "root": &v3_node,
    }))
    .expect_err("an under-declared envelope must not decode");
    assert!(
        error.to_string().contains("must be at least 3"),
        "under-declaration is rejected by contained atoms, not by the constant: {error}"
    );

    // Below the contained minimum the tree validator still refuses: version
    // negotiation is decided against the atoms actually present, not the constant.
    for version in [0u16, 1] {
        let error = serde_json::from_value::<GeneratedLens>(json!({
            "kit_version": version,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": &v2_node,
        }))
        .expect_err("an under-declared envelope must not decode");
        assert!(
            error.to_string().contains("must be at least 2"),
            "the contained-atom floor is what rejects it: {error}"
        );
    }

    // Above the running constant the body is *not* rejected any more. ONE-1431 moved
    // that call from decode time to load time: a future-stamped body decodes, stays
    // mountable as last-good, and queues regeneration against the live pair.
    for version in [LENS_ATOM_KIT_VERSION + 1, u16::MAX] {
        let decoded = serde_json::from_value::<GeneratedLens>(json!({
            "kit_version": version,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": &v2_node,
        }))
        .unwrap_or_else(|error| panic!("a future-stamped body still decodes: {error}"));
        assert_eq!(decoded.kit_version(), version);
        assert!(
            matches!(
                lens_load_action(decoded.version_stamp(), LensVersionStamp::current()),
                LensLoadAction::MountLastGoodAndQueueRegeneration { .. }
            ),
            "a body outside the running window queues regeneration instead of failing"
        );
    }

    // The positional (msgpack seq) deserializer carries the same pair.
    let lens = GeneratedLens::new(standalone_result_set_root())?;
    let positional = rmp_serde::to_vec(&lens).expect("positional encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&positional).expect("positional decode"),
        lens
    );

    Ok(())
}

#[test]
fn result_set_explicit_selection_is_rendered_id_set() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    let plan = frame.validate_result_set_action(
        &scoped_read,
        &render,
        &result_set_event("archive", explicit(&["row-2", "row-1"])),
    )?;

    let GeneratedUiResultSetScope::Explicit { row_ids, selected } = plan.scope() else {
        panic!("an explicit selection must resolve to an explicit scope");
    };
    assert_eq!(
        row_ids
            .iter()
            .map(LensResultSetRowId::as_str)
            .collect::<Vec<_>>(),
        ["row-1", "row-2"],
        "the plan records the deduplicated row-id set, not the client's ordering"
    );
    assert_eq!(selected.len(), 2);
    for read_handle in selected {
        assert_eq!(
            read_handle.atom_id(),
            &id("results"),
            "reach is issued against the rendered result set, never a sibling node"
        );
        assert_eq!(read_handle.render_id(), &render_id("card-1"));
        assert_eq!(read_handle.reach(), LensReadReach::ClaimSet);
        assert_eq!(read_handle.target_kind(), LensBackingTargetKind::Claim);
    }

    // Row ids are opaque echoes: only handles the *rendered atom* named are resolved.
    let entity_rows = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "people")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    let plan = frame.validate_result_set_action(
        &scoped_read,
        &entity_rows,
        &result_set_event("archive", explicit(&["row-1"])),
    )?;
    let GeneratedUiResultSetScope::Explicit { selected, .. } = plan.scope() else {
        panic!("an explicit selection must resolve to an explicit scope");
    };
    assert_eq!(selected[0].reach(), LensReadReach::EntitySet);

    // Timeline, query-result, and action-target rows are not selectable row reach.
    for (name, role, reason) in [
        (
            "history",
            LensHandleRole::Timeline,
            "a timeline row is not claim-set or entity-set reach",
        ),
        (
            "filter",
            LensHandleRole::QueryResult,
            "a query-result row is select-all reach, not row reach",
        ),
    ] {
        let render = result_set_card_with(
            result_set_atom(
                vec![result_set_row("row-1", name)],
                GeneratedUiResultSetSelectAll::Disabled {},
                &["archive"],
            ),
            vec![binding(name, role)],
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool,
            )],
        )?
        .render()?;
        assert!(
            frame
                .validate_result_set_action(
                    &scoped_read,
                    &render,
                    &result_set_event("archive", explicit(&["row-1"])),
                )
                .is_err(),
            "{reason}"
        );
    }

    Ok(())
}

#[test]
fn result_set_rejects_empty_duplicate_and_foreign_row_ids() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &render,
                &result_set_event("archive", explicit(&["row-1"])),
            )
            .is_ok(),
        "the honest single-row selection is the positive control"
    );

    for (selection, reason) in [
        (explicit(&[]), "an explicit fire with zero rows is invalid"),
        (
            explicit(&["row-1", "row-1"]),
            "a repeated row id is never counted twice",
        ),
        (
            explicit(&["row-9"]),
            "a row id absent from this rendered atom resolves to nothing",
        ),
        (
            explicit(&["row-1", "row-9"]),
            "one foreign id poisons the whole selection",
        ),
    ] {
        assert!(
            frame
                .validate_result_set_action(
                    &scoped_read,
                    &render,
                    &result_set_event("archive", selection)
                )
                .is_err(),
            "{reason}"
        );
    }

    // An empty result set is a valid atom; it just has no row to fire against.
    let empty = result_set_card_with(
        result_set_atom(Vec::new(), GeneratedUiResultSetSelectAll::Disabled {}, &[]),
        Vec::new(),
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?;
    assert!(empty.render().is_ok(), "an empty result set is valid");

    Ok(())
}

#[test]
fn result_set_select_all_uses_declared_host_predicate() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    let plan = frame.validate_result_set_action(
        &scoped_read,
        &render,
        &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
    )?;
    let GeneratedUiResultSetScope::Predicate { predicate } = plan.scope() else {
        panic!("select-all must resolve to a predicate scope");
    };
    assert_eq!(
        predicate.reach(),
        LensReadReach::QueryResult,
        "the predicate is the host's declared query-result handle"
    );
    assert_eq!(predicate.atom_id(), &id("results"));

    // Disabled select-all rejects the event outright.
    let disabled = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "claim-a")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("claim-a", LensHandleRole::ClaimSet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &disabled,
                &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
            )
            .is_err(),
        "a disabled select-all has no predicate to take"
    );

    // A predicate the node advertised at any other role is not select-all reach.
    let wrong_role = result_set_card_with(
        result_set_atom(Vec::new(), within_filter("people"), &["archive"]),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &wrong_role,
                &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
            )
            .is_err(),
        "select-all requires exactly query-result reach"
    );

    Ok(())
}

#[test]
fn result_set_free_form_filter_is_unrepresentable() {
    // Positive control: a select-all event is a mode tag and nothing else.
    let honest = json!({
        "action": {
            "cardId": "card-1",
            "elementId": "archive",
            "actionId": "archive",
            "occurredAt": 1
        },
        "selection": { "mode": "all_within_filter" }
    });
    let parsed: GeneratedUiResultSetActionEvent =
        serde_json::from_value(honest.clone()).expect("the honest select-all event decodes");
    assert_eq!(
        parsed.selection,
        GeneratedUiResultSetSelection::AllWithinFilter {}
    );

    for forged in [
        json!({ "query": "claim.subject == person" }),
        json!({ "expression": "1 == 1" }),
        json!({ "filter": { "where": "all" } }),
        json!({ "where": "all" }),
        json!({ "entity_id": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "entityId": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "body": "the note says ..." }),
        json!({ "predicate_handle": "filter" }),
        json!({ "replacement_handle": "other-filter" }),
        json!({ "row_ids": ["row-1"] }),
    ] {
        let mut event = honest.clone();
        let selection = event
            .get_mut("selection")
            .and_then(serde_json::Value::as_object_mut)
            .expect("selection object");
        for (key, value) in forged.as_object().expect("forged field object") {
            selection.insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiResultSetActionEvent>(event).is_err(),
            "a select-all selection must not carry {forged}"
        );
    }

    // The same closure holds on the explicit arm and on the whole event envelope.
    for forged in [
        json!({ "mode": "explicit", "row_ids": ["row-1"], "query": "x" }),
        json!({ "mode": "explicit", "row_ids": ["row-1"], "predicate_handle": "filter" }),
        json!({ "mode": "explicit" }),
        json!({ "mode": "unbounded" }),
        json!({ "row_ids": ["row-1"] }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiResultSetSelection>(forged.clone()).is_err(),
            "an explicit selection must not decode as {forged}"
        );
    }
    for forged in [
        json!({ "actor": "owner" }),
        json!({ "authority": "owner" }),
        json!({ "command": "archive" }),
        json!({ "approval": "granted" }),
        json!({ "verb": "gated_actor_write" }),
        json!({ "source": "agent" }),
        json!({ "chokepoint": "evaluate_gate" }),
    ] {
        let mut event = honest.clone();
        for (key, value) in forged.as_object().expect("forged field object") {
            event
                .as_object_mut()
                .expect("event object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiResultSetActionEvent>(event).is_err(),
            "a result-set action event must not carry {forged}"
        );
    }

    // A rendered atom's select-all is equally closed.
    for forged in [
        json!({ "mode": "within_filter", "predicate_handle": "filter", "query": "x" }),
        json!({ "mode": "within_filter" }),
        json!({ "mode": "disabled", "predicate_handle": "filter" }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiResultSetSelectAll>(forged.clone()).is_err(),
            "a select-all declaration must not decode as {forged}"
        );
    }
}

#[test]
fn result_set_render_rejects_duplicate_row_ids_and_undeclared_handles() {
    assert!(
        result_set_card().is_ok(),
        "the honest result-set card is the positive control"
    );

    // Duplicate row ids never reach a render, in the atom or on the wire.
    assert!(
        LensAtom::result_set(result_set_atom(
            vec![
                result_set_row("row-1", "claim-a"),
                result_set_row("row-1", "claim-b"),
            ],
            GeneratedUiResultSetSelectAll::Disabled {},
            &[],
        ))
        .is_err(),
        "duplicate row ids are rejected at construction"
    );
    assert!(
        serde_json::from_value::<LensAtom>(json!({
            "kind": "result_set",
            "props": {
                "rows": [
                    { "id": "row-1", "label": "a", "target_handle": "claim-a" },
                    { "id": "row-1", "label": "b", "target_handle": "claim-b" }
                ],
                "select_all": { "mode": "disabled" }
            }
        }))
        .is_err(),
        "duplicate row ids are rejected on the wire"
    );

    // Every handle a row or a select-all names must be one this node declared once.
    for (atom, bindings, reason) in [
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                GeneratedUiResultSetSelectAll::Disabled {},
                &[],
            ),
            Vec::new(),
            "a row handle the node never advertised resolves to nothing",
        ),
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                GeneratedUiResultSetSelectAll::Disabled {},
                &[],
            ),
            vec![
                binding("claim-a", LensHandleRole::ClaimSet),
                binding("claim-a", LensHandleRole::EntitySet),
            ],
            "an ambiguous double declaration offers no single reach",
        ),
        (
            result_set_atom(Vec::new(), within_filter("filter"), &[]),
            Vec::new(),
            "an undeclared select-all predicate is rejected too",
        ),
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                within_filter("filter"),
                &[],
            ),
            vec![binding("claim-a", LensHandleRole::ClaimSet)],
            "declaring the rows does not declare the predicate",
        ),
    ] {
        assert!(
            GeneratedLens::new(result_set_node("results", atom, bindings)).is_err(),
            "{reason}"
        );
    }
}

#[test]
fn result_set_action_bar_accepts_only_tier2_gated_writes() {
    assert!(
        result_set_card().is_ok(),
        "a deterministic-tool, self.ui-hosted action is allowlistable"
    );
    assert!(
        result_set_card_with(
            result_set_atom(Vec::new(), GeneratedUiResultSetSelectAll::Disabled {}, &[]),
            Vec::new(),
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_ok(),
        "an empty action bar is valid"
    );

    let bar = |ids: &[&str]| {
        result_set_atom(
            vec![result_set_row("row-1", "claim-a")],
            GeneratedUiResultSetSelectAll::Disabled {},
            ids,
        )
    };
    let claim_a = || vec![binding("claim-a", LensHandleRole::ClaimSet)];

    for (tier, reason) in [
        (
            GeneratedUiActionTier::Local,
            "a local action is not a gated write",
        ),
        (
            GeneratedUiActionTier::ModelRoundTrip,
            "a model round trip is a trigger, not a gated write",
        ),
    ] {
        assert!(
            result_set_card_with(
                bar(&["archive"]),
                claim_a(),
                vec![archive_declaration(tier)]
            )
            .is_err(),
            "{reason}"
        );
    }
    assert!(
        result_set_card_with(
            bar(&["archive"]),
            claim_a(),
            vec![declaration(
                "archive",
                "purge",
                GeneratedUiActionTier::DeterministicTool,
                action("archive.selected"),
            )],
        )
        .is_err(),
        "an undeclared action id cannot be allowlisted"
    );
    assert!(
        result_set_card_with(
            bar(&["archive", "archive"]),
            claim_a(),
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_err(),
        "an action bar must not repeat an id"
    );

    // Nor may two result sets in the same card claim the same action id.
    let two_sets = card_root(vec![
        result_set_node("results", bar(&["archive"]), claim_a()),
        result_set_node("mirror", bar(&["archive"]), claim_a()),
        archive_button(),
    ]);
    assert!(
        GeneratedLens::new(two_sets).is_err(),
        "one action id must be allowlisted by at most one result set"
    );

    // The landed gates still decide what is interactive: the atom hosts no action, so a
    // declaration naming the result set element is rejected as a non-self.ui element.
    assert!(
        result_set_card_with(
            bar(&["archive"]),
            claim_a(),
            vec![declaration(
                "results",
                "archive",
                GeneratedUiActionTier::DeterministicTool,
                action("archive.selected"),
            )],
        )
        .is_err(),
        "generated-ui action declarations must still reference a self.ui control"
    );
}

#[test]
fn result_set_scope_is_rechecked_before_dispatch() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, people_id) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;
    let event = result_set_event("archive", explicit(&["row-1"]));

    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &render, &event)
            .is_ok(),
        "the honest dispatch is the positive control"
    );

    // A later render revision that drops the row, drops the binding, moves the atom, or
    // swaps the predicate fails closed rather than reusing proved reach.
    for (later, reason) in [
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-2", "claim-b")],
                    within_filter("filter"),
                    &["archive"],
                ),
                claim_rows_bindings(),
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "a removed row is not selectable",
        ),
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-1", "claim-a")],
                    GeneratedUiResultSetSelectAll::Disabled {},
                    &["archive"],
                ),
                vec![binding("claim-a", LensHandleRole::Timeline)],
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "a relabelled binding cannot launder claim-set reach",
        ),
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-1", "claim-a")],
                    within_filter("filter"),
                    &[],
                ),
                claim_rows_bindings(),
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "an action the result set no longer allowlists resolves to nothing",
        ),
    ] {
        assert!(
            frame
                .dispatch_result_set_action(&scoped_read, &later.render()?, &event)
                .is_err(),
            "{reason}"
        );
    }

    // A switched principal, a cross-render frame, and a twin frame all fail closed.
    assert!(
        frame
            .dispatch_result_set_action(&vault.scoped_read(actor_key("intruder")), &render, &event)
            .is_err(),
        "dispatch re-checks the acting principal"
    );
    let twin = LensRenderFrame::new(render_id("card-1"), frame.principal().clone());
    assert!(
        twin.dispatch_result_set_action(&scoped_read, &render, &event)
            .is_err(),
        "a frame that never minted the row cannot dispatch against it"
    );

    // A target whose stored content moved stops hydrating the short ref the plan proved.
    let moved = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "people")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &moved, &event)
            .is_ok(),
        "the entity scope dispatches before the target moves"
    );
    vault.put_entity(
        &people_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 2, end: 2 },
        2,
        b"person, revised",
    )?;
    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &moved, &event)
            .is_err(),
        "a stale short ref stops resolving instead of following the entity forward"
    );

    Ok(())
}

#[test]
fn result_set_has_no_push_delivery() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);

    // Construct.
    let card = result_set_card()?;
    let render = card.render()?;
    let event = result_set_event("archive", explicit(&["row-1"]));

    // Tick, then fire. The only value either step yields is a plan and then one
    // host-mediated write: no board update, subscription, WAKE/CARRIER frame,
    // owner-feed frame, or transport output exists to be produced.
    let plan = frame.validate_result_set_action(&scoped_read, &render, &event)?;
    let write: LensHostMediatedWrite =
        frame.dispatch_result_set_action(&scoped_read, &render, &event)?;
    assert!(matches!(
        plan.scope(),
        GeneratedUiResultSetScope::Explicit { .. }
    ));
    assert_eq!(
        write.chokepoint(),
        LensGateWriteChokepoint::CheckClaimPolicyForWrite,
        "the receipt names a host write chokepoint, not a delivery channel"
    );

    // Nothing a result set puts on the wire names a push channel.
    for encoded in [
        serde_json::to_string(&card).expect("card encodes"),
        serde_json::to_string(&render).expect("render encodes"),
        serde_json::to_string(&card.segments()?).expect("segments encode"),
        serde_json::to_string(&event).expect("event encodes"),
    ] {
        for pushed in [
            "subscription",
            "subscribe",
            "wake",
            "carrier",
            "tag_sub",
            "board",
            "feed",
            "dispatcher",
        ] {
            assert!(
                !encoded.to_ascii_lowercase().contains(pushed),
                "a result set must not name {pushed}"
            );
        }
    }

    // And lens execution still links zero write imports, so no push path is reachable.
    for import in [
        LensHostImport::VaultWrite,
        LensHostImport::BatchWrite,
        LensHostImport::EvaluateGate,
        LensHostImport::CheckClaimPolicyForWrite,
    ] {
        assert!(
            LensExecutionBoundary::read_only(vec![LensHostImport::ScopedRead, import]).is_err(),
            "lens execution must expose zero write imports"
        );
    }

    Ok(())
}
