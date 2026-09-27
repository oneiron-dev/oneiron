//! HTTP reaction toggle and grouped pills on the MESSAGE children of listed TURNs.
use super::*;
use oneiron::conversation::{ConversationBody, HistoryChoice};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{EdgeActorClass, EntityId, TimeRange, WriteActor};

#[tokio::test]
async fn reaction_route_groups_in_one_listing_and_revocation_removes_pill() {
    let (_dir, server) = test_server();
    let alice = EntityId::now();
    server
        .vault
        .put_entity(
            &alice,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    let room = EntityId::now();
    server
        .vault
        .create_conversation(room, &ConversationBody::default(), actor, 1)
        .unwrap();
    server
        .vault
        .join_member(room, alice, actor, 2, HistoryChoice::None)
        .unwrap();
    let message = EntityId::now();
    server
        .vault
        .memory(alice, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "hello".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    let path = format!("/v1/core/messages/{}/reactions", message.to_hex());
    let request = json!({"by":alice.to_hex(),"glyph":"👀","occurred_at":20,
        "actor":{"entity_ref":alice.to_hex(),"actor_class":"human"}});
    let (status, first) =
        route_json(server.clone(), json_request("POST", &path, request.clone())).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["event"], "reaction.put");
    let list = format!(
        "/v1/core/conversations/{}/records?with=reactions&viewer={}",
        room.to_hex(),
        alice.to_hex()
    );
    let (status, page) = route_json(
        server.clone(),
        Request::builder().uri(&list).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["records"][0]["id"], message.to_hex());
    assert_eq!(page["records"][0]["reactions"][0]["glyph"], "👀");
    assert_eq!(page["records"][0]["reactions"][0]["count"], 1);
    assert_eq!(page["records"][0]["reactions"][0]["mine"], true);
    assert_eq!(page["reactions_outbound"], "first_party_only");
    let (status, pack) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({"query":"hello", "limit":10,
            "signals_since":0, "signals_person":alice.to_hex()}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    assert_eq!(pack["signals"][0]["event"], "reaction.put");
    assert_eq!(pack["signals"][0]["message"], message.to_hex());
    let (status, removed) = route_json(server.clone(), json_request("POST", &path, request)).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["event"], "reaction.revoked");
    let query = json!({"query":"hello", "limit":10, "signals_since":0,
        "signals_person":alice.to_hex(), "signals_limit":1});
    let (status, first_signals) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/context-pack", query.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_signals}");
    assert_eq!(first_signals["signals"][0]["event"], "reaction.put");
    let after = first_signals["signals_next"]
        .as_str()
        .expect("more signal events");
    let mut next_query = query;
    next_query["signals_after"] = json!(after);
    let (status, second_signals) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/context-pack", next_query),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_signals}");
    assert_eq!(second_signals["signals"][0]["event"], "reaction.revoked");
    assert!(second_signals["signals_next"].is_null());
    let (status, page) = route_json(
        server.clone(),
        Request::builder().uri(&list).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page["records"][0]["reactions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reaction_routes_have_openapi_and_security_policy() {
    let spec = generated_spec();
    assert!(spec["paths"]["/v1/core/messages/{message}/reactions"]["post"]["security"].is_array());
    assert!(spec["components"]["schemas"]["ReactionToggleRequest"].is_object());
}

#[tokio::test]
async fn first_party_append_record_is_reactable_without_witness_child() {
    let (_dir, server) = test_server();
    let alice = EntityId::now();
    server
        .vault
        .put_entity(
            &alice,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    oneiron::conversation_dag::test_support::put_dag_test_policy(&server.vault, actor, true)
        .unwrap();
    let room = EntityId::now();
    server
        .vault
        .create_conversation(room, &ConversationBody::default(), actor, 1)
        .unwrap();
    server
        .vault
        .join_member(room, alice, actor, 2, HistoryChoice::None)
        .unwrap();
    let path = format!("/v1/core/conversations/{}/records", room.to_hex());
    let (status, appended) = route_json(
        server.clone(),
        json_request(
            "POST",
            &path,
            json!({"actor":{"entity_ref":alice.to_hex(),"actor_class":"human"},
            "advance":true,"occurred_start":10,"body":{"txt":"hello"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{appended}");
    let id = appended["id"].as_str().unwrap();
    let (status, put) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/messages/{id}/reactions"),
            json!({"by":alice.to_hex(),"glyph":"👀","occurred_at":20,
            "actor":{"entity_ref":alice.to_hex(),"actor_class":"human"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let (status, page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!("{path}?with=reactions&viewer={}", alice.to_hex()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["records"][0]["id"], id);
    assert_eq!(page["records"][0]["reactions"][0]["count"], 1);
    let signals = server.vault.reactions_since(alice, 0).unwrap();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].message.to_hex(), id);
}
