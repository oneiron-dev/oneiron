//! Reaction HTTP toggle/list/inbox projection and context admission.
use super::*;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange};

async fn call(
    server: Arc<SyncServer>,
    actor: EntityId,
    method: &str,
    uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let token = crate::auth::mint_core_token_v2(
        "secret",
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
    route_json(
        server,
        Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&payload).expect("JSON")))
            .expect("request"),
    )
    .await
}

#[tokio::test]
async fn reaction_routes_roundtrip_pills_signals_and_membership_visibility() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        ..Default::default()
    });
    let owner = server.vault.ensure_embedded_owner_actor().expect("owner");
    let member = EntityId::now();
    let late = EntityId::now();
    for id in [member, late] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"member",
            )
            .expect("person");
    }
    let room = EntityId::now();
    let memory = server.vault.memory(owner, EdgeActorClass::Human);
    let witnessed = memory
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 100,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "reaction route".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .expect("message");
    let message = memory
        .get_entity(&witnessed.message_short_ids[0])
        .expect("read")
        .expect("message")
        .id_hex;
    for (person, joined) in [(owner, 50), (member, 50), (late, 150)] {
        server
            .vault
            .batch()
            .edge_with_created_at(&person, EdgeKind::ParticipatesIn, &room, 1.0, joined)
            .commit()
            .expect("membership");
    }
    let toggle = format!(
        "/v1/core/conversations/{}/records/{message}/reactions",
        room.to_hex()
    );
    let listing = format!(
        "/v1/core/conversations/{}/records?with=reactions",
        room.to_hex()
    );
    let (status, put) = call(
        server.clone(),
        member,
        "POST",
        &toggle,
        json!({"glyph":"👀", "at":200}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    assert_eq!(put["state"], "put");
    let (status, pills) = call(server.clone(), member, "GET", &listing, json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{pills}");
    assert_eq!(
        pills["items"][0]["reactions"],
        json!([{"glyph":"👀", "count":1, "by":[member.to_hex()], "mine":true}])
    );
    assert_eq!(pills["items"][0]["reactions_outbound"], "first_party_only");
    let (status, hidden) = call(server.clone(), late, "GET", &listing, json!(null)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hidden["items"], json!([]));
    let inbox = format!("/v1/core/persons/{}/reactions?since=0", owner.to_hex());
    let (status, signals) = call(server.clone(), owner, "GET", &inbox, json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{signals}");
    assert_eq!(signals["items"][0]["kind"], "reaction.put");
    let (status, denied) = call(server.clone(), member, "GET", &inbox, json!(null)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    let pack =
        json!({"query":"reaction route", "reaction_signals":{"person":owner.to_hex(),"since":0}});
    let (status, owner_pack) =
        owner_json(server.clone(), "POST", "/v1/core/context-pack", Some(&pack)).await;
    assert_eq!(status, StatusCode::OK, "{owner_pack}");
    assert_eq!(owner_pack["reaction_signals"][0]["kind"], "reaction.put");
    // Bound-but-unidentified present readers are not owner-only rosters.
    let (status, clamped) = call(
        server.clone(),
        owner,
        "POST",
        "/v1/core/context-pack",
        pack.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{clamped}");
    assert_eq!(clamped["reaction_signals"], json!([]));
    let (status, denied) = call(
        server.clone(),
        member,
        "POST",
        "/v1/core/context-pack",
        pack,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    let (status, revoked) = call(
        server.clone(),
        member,
        "POST",
        &toggle,
        json!({"glyph":"👀", "at":201}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(revoked["reaction_id"], put["reaction_id"]);
    let (_, pills) = call(server.clone(), member, "GET", &listing, json!(null)).await;
    assert_eq!(pills["items"][0]["reactions"], json!([]));
    let (_, signals) = call(server, owner, "GET", &inbox, json!(null)).await;
    assert!(
        signals["items"]
            .as_array()
            .expect("signals")
            .iter()
            .any(|row| row["kind"] == "reaction.revoked")
    );
}
