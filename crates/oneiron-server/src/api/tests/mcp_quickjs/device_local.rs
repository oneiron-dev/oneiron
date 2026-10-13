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
