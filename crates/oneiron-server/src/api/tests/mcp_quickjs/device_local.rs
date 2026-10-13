//! DEC-0005 in code mode: a run's result is an MCP result, judged at release
//! by the rows its verb calls served and its steps name, as every other
//! result is; its own search reads from where its caller sits.

use super::*;

/// One `execute_code` call on `/mcp` under `credential`, as `run_ref`.
fn run_request(actor: oneiron::EntityId, credential: &str, run_ref: &str) -> Request<Body> {
    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "write_memory"),
        json!({"run_ref": run_ref, "task": "state a favorite drink in a world"}),
    );
    mcp_endpoint_call_request("/mcp", credential, run_ref, "execute_code", args)
}

/// A run whose guest states `claim` about `subject` in `world`.
fn state_in(
    claim: oneiron::EntityId,
    subject: oneiron::EntityId,
    world: oneiron::EntityId,
) -> String {
    format!(
        "await self.memory.claim_upsert({{id: '{}', predicate: 'profile.favorite_drink', \
         subject_ref: '{}', value: 'sencha', confidence: 1, source: 'user_stated', \
         world_ref: '{}'}}); finish('stated');",
        claim.to_hex(),
        subject.to_hex(),
        world.to_hex()
    )
}

/// A code run's result names the claim its guest stated in a world, by the
/// receipt's short ref alone. Once that world turns device-local while the
/// run waits to release its result, off this device the result is refused:
/// the caller reads that it changed, never the receipt. While the world is
/// portable the receipt goes out.
#[tokio::test]
async fn a_code_run_off_this_device_releases_no_row_its_world_made_device_local() {
    let actor = seeded_test_entity_id(0x0024_66d1);
    let subject = seeded_test_entity_id(0x0024_66d2);
    let world = seeded_test_entity_id(0x0024_66d3);
    let portable = seeded_test_entity_id(0x0024_66d4);
    let kept = seeded_test_entity_id(0x0024_66d5);
    let mode = code_mode_server(vec![
        state_in(portable, subject, world),
        state_in(kept, subject, world),
    ]);
    for (id, kind) in [
        (subject, oneiron::registry::ENTITY_TYPE_PERSON),
        (world, oneiron::registry::ENTITY_TYPE_WORLD),
    ] {
        mode.vault
            .put_entity(
                &id,
                kind,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"quickjs",
            )
            .unwrap();
    }
    let credential = "quickjs-device-local";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-portable"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let steps = body["result"]["structuredContent"]["steps"].to_string();
    assert!(steps.contains("claim_short_id"), "{steps}");
    assert!(!steps.contains(&portable.to_hex()), "{steps}");
    assert!(
        mode.vault.get_claim(&portable).unwrap().is_some(),
        "{steps}"
    );

    crate::api::mcp_gateway::release_hook::arm(world);
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-kept"),
    )
    .await;
    assert!(mode.vault.get_claim(&kept).unwrap().is_some(), "{body}");
    assert!(body.get("result").is_none(), "{body}");
    assert_mcp_structured_error(&body, "mcp_result_changed");
    assert!(!body.to_string().contains("claim_short_id"), "{body}");
}

/// One claim about `subject` in `world` by `actor`, its text indexed.
fn put_indexed_claim(
    vault: &oneiron::Vault,
    actor: oneiron::EntityId,
    claim: oneiron::EntityId,
    subject: oneiron::EntityId,
    world: Option<oneiron::EntityId>,
    text: &str,
) {
    vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .claim_upsert(&oneiron::memory::ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.favorite_lamp".into(),
            subject_ref: subject.to_hex(),
            value: json!(text),
            confidence: 1.0,
            source: "user_stated".into(),
            world_ref: world.map(|world| world.to_hex()),
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .unwrap();
    vault
        .batch()
        .text(&claim, &[("body", text)])
        .commit()
        .unwrap();
}

/// Sol R6 F2: a run's own `self.memory.search` reads from where its caller
/// sits. Off this device it finds no claim of a world already device-local,
/// so the run's result goes out, naming the portable claim only.
#[tokio::test]
async fn a_code_runs_search_off_this_device_finds_no_device_local_claim() {
    let actor = seeded_test_entity_id(0x0024_66e1);
    let subject = seeded_test_entity_id(0x0024_66e2);
    let world = seeded_test_entity_id(0x0024_66e3);
    let portable = seeded_test_entity_id(0x0024_66e4);
    let kept = seeded_test_entity_id(0x0024_66e5);
    let mode = code_mode_server(vec![
        "await self.memory.search({query: 'orchid'}); finish('searched');".to_owned(),
    ]);
    for (id, kind) in [
        (subject, oneiron::registry::ENTITY_TYPE_PERSON),
        (world, oneiron::registry::ENTITY_TYPE_WORLD),
    ] {
        mode.vault
            .put_entity(
                &id,
                kind,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"quickjs",
            )
            .unwrap();
    }
    let credential = "quickjs-device-local-search";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    put_indexed_claim(&mode.vault, actor, portable, subject, None, "orchid lamp");
    put_indexed_claim(
        &mode.vault,
        actor,
        kept,
        subject,
        Some(world),
        "orchid lantern",
    );
    mode.vault.set_world_device_only(world, true).unwrap();

    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-search"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let steps = body["result"]["structuredContent"]["steps"].to_string();
    assert!(steps.contains("memory_search"), "{steps}");
    assert!(steps.contains(&portable.to_hex()), "{steps}");
    assert!(!steps.contains(&kept.to_hex()), "{steps}");
}

/// One active claim about `subject` in `world`, under its own `predicate`.
fn put_world_claim(
    vault: &oneiron::Vault,
    subject: oneiron::EntityId,
    predicate: &str,
    world: oneiron::EntityId,
) -> oneiron::EntityId {
    let id = oneiron::EntityId::now();
    let mut body = oneiron::ClaimBody::new(
        predicate,
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from("orchid"),
        0.8,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    vault
        .put_claim(&id, &body, oneiron::TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    id
}

/// Astra F1: a run's failure is released as its result is. A guest catches
/// its stale supersession's refusal and finishes, yet the run fails with the
/// refusal, which names the chain's current head. Off this device, once the
/// chain's world is device-local, that failure leaves as its code alone;
/// while the world is portable it names the head.
#[tokio::test]
async fn a_failed_code_run_off_this_device_names_no_device_local_row() {
    let actor = seeded_test_entity_id(0x0024_66f1);
    let subject = seeded_test_entity_id(0x0024_66f2);
    let world = seeded_test_entity_id(0x0024_66f3);
    let fresh = seeded_test_entity_id(0x0024_66f4);
    let mode = code_mode_server(Vec::new());
    for (id, kind) in [
        (subject, oneiron::registry::ENTITY_TYPE_PERSON),
        (world, oneiron::registry::ENTITY_TYPE_WORLD),
    ] {
        mode.vault
            .put_entity(
                &id,
                kind,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"quickjs",
            )
            .unwrap();
    }
    let credential = "quickjs-device-local-failure";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let head = put_world_claim(&mode.vault, subject, "profile.favorite_lamp", world);
    let successor = put_world_claim(&mode.vault, subject, "profile.favorite_lantern", world);
    mode.vault.supersede_claim(&successor, &head, 3).unwrap();
    let script = format!(
        "try {{ await self.memory.supersede_claim({{oldId: '{}', newId: '{}', now: 5}}); }} \
         catch (error) {{}} finish('');",
        head.to_hex(),
        fresh.to_hex()
    );
    mode.backend
        .scripts
        .lock()
        .unwrap()
        .extend([script.clone(), script]);

    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-failed-portable"),
    )
    .await;
    assert_mcp_structured_error(&body, "code_run_failed");
    assert!(body.to_string().contains("current head"), "{body}");

    mode.vault.set_world_device_only(world, true).unwrap();
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-failed-kept"),
    )
    .await;
    assert!(body.get("result").is_none(), "{body}");
    assert_mcp_structured_error(&body, "code_run_failed");
    let text = body.to_string();
    assert!(!text.contains("current head"), "{text}");
    assert!(!text.contains(&head.to_hex()), "{text}");
}

/// Astra F2: a run's record keeps beside each verb answer the rows it was
/// derived from, and a re-entered run's replayed answers are released by
/// them. Calibration pairs recorded while their subject's world was portable
/// spell none of its rows; once that world is device-local, re-entering the
/// finished run off this device reads that its result changed, not the
/// pairs.
#[tokio::test]
async fn a_replayed_code_run_off_this_device_releases_no_answer_a_device_local_row_produced() {
    let owner = seeded_test_entity_id(0x0024_6701);
    let holder = seeded_test_entity_id(0x0024_6702);
    let world = seeded_test_entity_id(0x0024_6703);
    let mode = code_mode_server(Vec::new());
    mode.vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"quickjs",
        )
        .unwrap();
    let credential = "quickjs-device-local-outcomes";
    for (credential, actor) in [(credential, owner), ("quickjs-outcomes-holder", holder)] {
        register_mcp_actor(
            &mode.server,
            credential,
            actor,
            oneiron::EdgeActorClass::Human,
        )
        .await;
    }
    // The holder's answer binds the holder; the outcomes are about a claim
    // in the world it is linked to.
    let about = put_world_claim(&mode.vault, holder, "test.orchid_outcome", world);
    mode.vault
        .put_edge(&holder, oneiron::EdgeKind::About, &about, 1.0)
        .unwrap();
    let (handle, answered) =
        oneiron::test_support::settle_outcome_ask(&mode.vault, owner, holder, Some("about"))
            .unwrap();
    for offset in [30, 31] {
        let at = answered + offset;
        let body = oneiron::ClaimBody::new(
            "outcome.earned",
            oneiron::ClaimSubject::Entity(about),
            rmpv::Value::from("won"),
            1.0,
            oneiron::ClaimApprovalStatus::Approved,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        mode.vault
            .put_claim(
                &oneiron::EntityId::now(),
                &body,
                oneiron::TimeRange { start: at, end: at },
                at,
            )
            .unwrap();
    }
    mode.backend.scripts.lock().unwrap().push_back(format!(
        "const pairs = await self.memory.tasks.outcomes({{group_ref: '{}'}}); \
         finish(String(pairs.length));",
        handle.group_ref.to_hex()
    ));

    let (_, body) = route_json(
        mode.server.clone(),
        run_request(owner, credential, "quickjs-outcomes"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["result"]["status"], "complete", "{body}");
    let steps = structured["steps"].to_string();
    assert!(steps.contains("agent_verb"), "{steps}");
    assert!(!steps.contains(&about.to_hex()), "{steps}");

    mode.vault.set_world_device_only(world, true).unwrap();
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(owner, credential, "quickjs-outcomes"),
    )
    .await;
    assert!(body.get("result").is_none(), "{body}");
    assert_mcp_structured_error(&body, "mcp_result_changed");
}
