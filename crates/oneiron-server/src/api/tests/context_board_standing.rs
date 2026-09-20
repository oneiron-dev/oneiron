//! The real session endpoint cannot fill context before a registered standing floor.
use super::*;

#[tokio::test]
async fn registered_agent_floor_is_enforced_at_session_entry() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x2054_0001);
    let world = seeded_test_entity_id(0x2054_0002);
    let at = oneiron::TimeRange { start: 1, end: 1 };
    server
        .vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            1,
            b"actor",
        )
        .unwrap();
    server
        .vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            at,
            1,
            b"world",
        )
        .unwrap();
    let owner_actor = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    server
        .vault
        .open_standing_block(&owner, actor, world, "identity", 64)
        .unwrap();
    let actor_ref = actor.to_hex();
    let request = |body: &Value, typed: bool| {
        let class = if typed { ";actor_class=agent" } else { "" };
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!("scope=core:read;principal_ref={actor_ref}{class}")),
            Some(body),
        )
    };
    let body = json!({"standing":{"world_ref":world.to_hex(),"token_budget":8192}});
    let (status, first) = route_json(server.clone(), request(&body, true)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["standing"]["world_ref"], world.to_hex());
    assert_eq!(first["standing"]["reserved_tokens"], 64);
    assert_eq!(first["standing"]["other_context_tokens"], 8128);
    assert_eq!(first["standing"]["compiled"], "");
    let (status, second) = route_json(server.clone(), request(&body, true)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["standing"], second["standing"]);
    for invalid in [
        json!({}),
        json!({"standing":{"token_budget":63}}),
        json!({"standing":{"token_budget":8192,"block_tokens":32}}),
        json!({"standing":{"token_budget":64},"retrieval":{"query":"anything"}}),
    ] {
        let (status, _) = route_json(server.clone(), request(&invalid, true)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = route_json(server.clone(), request(&body, false)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
