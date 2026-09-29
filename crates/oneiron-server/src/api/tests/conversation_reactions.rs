//! HTTP reactions: put and remove, grouped pills on listed records, grouped
//! lines on context-packed messages, and the agent signal feed.
use super::*;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{EdgeActorClass, EntityId, TimeRange, WriteActor};

fn person(server: &SyncServer, name: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .unwrap();
    server
        .vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .unwrap();
    id
}

/// A room with Alice and Bob and one message by Alice.
fn room(server: &SyncServer, body: ConversationBody) -> (EntityId, EntityId, EntityId, EntityId) {
    let alice = person(server, "Alice");
    let bob = person(server, "Bob");
    let actor = WriteActor::new(alice, EdgeActorClass::Human);
    let room = EntityId::now();
    server
        .vault
        .create_conversation(room, &body, actor, 1)
        .unwrap();
    for (at, member) in [(2, alice), (3, bob)] {
        server
            .vault
            .join_member(room, member, actor, at, HistoryChoice::Share)
            .unwrap();
    }
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
                content: "hello about the friday plan".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    (room, alice, bob, message)
}

fn actor(person: EntityId) -> Value {
    json!({"entity_ref": person.to_hex(), "actor_class": "human"})
}

#[tokio::test]
async fn reaction_route_puts_groups_signals_and_removes() {
    let (_dir, server) = test_server();
    let (room, alice, bob, message) = room(&server, ConversationBody::default());
    let path = format!("/v1/core/messages/{}/reactions", message.to_hex());
    let put = json!({"by": bob.to_hex(), "glyph": "👀", "occurred_at": 20, "actor": actor(bob)});
    let (status, first) =
        route_json(server.clone(), json_request("POST", &path, put.clone())).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["event"], "reaction.put");
    let (status, again) = route_json(server.clone(), json_request("POST", &path, put)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["event"], "reaction.replayed");
    assert_eq!(again["id"], first["id"]);

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
    assert_eq!(page["records"][0]["reactions"][0]["mine"], false);
    assert_eq!(page["reactions_outbound"], "first_party_only");

    let removal = json!({"by": bob.to_hex(), "glyph": "👀", "remove": true, "actor": actor(bob)});
    let (status, removed) = route_json(server.clone(), json_request("POST", &path, removal)).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["event"], "reaction.revoked");
    assert_eq!(removed["id"], first["id"]);

    // Alice's next turn reads the put and the removal, one per page.
    let query = json!({"query": "friday plan", "limit": 10, "signals_since": 0,
        "signals_person": alice.to_hex(), "signals_limit": 1});
    let (status, first_signals) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/context-pack", query.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_signals}");
    assert_eq!(first_signals["signals"][0]["event"], "reaction.put");
    assert_eq!(first_signals["signals"][0]["message"], message.to_hex());
    assert_eq!(first_signals["signals"][0]["by"], bob.to_hex());
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

#[tokio::test]
async fn context_packed_message_carries_its_grouped_reactions() {
    let (_dir, server) = auth_test_server();
    let (_room, alice, bob, message) = room(&server, ConversationBody::default());
    for (by, glyph) in [(bob, "👀"), (alice, "👀"), (bob, "🎉")] {
        server
            .vault
            .react(oneiron::reaction::ReactionInput {
                message,
                by,
                glyph: glyph.to_owned(),
                occurred_at: 20,
                actor: WriteActor::new(by, EdgeActorClass::Human),
            })
            .unwrap();
    }
    let (status, pack) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({"query": "friday plan", "limit": 10, "view": "full"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    let packed = pack["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entity| entity["id"] == message.to_hex())
        .unwrap_or_else(|| panic!("the message is packed: {pack}"))
        .clone();
    assert_eq!(
        packed["fields"]["reactions"],
        json!(["👀×2 (Bob, Alice)", "🎉×1 (Bob)"]),
        "{packed}"
    );
}

#[tokio::test]
async fn reaction_route_refuses_another_persons_reaction_and_paging_without_since() {
    let (_dir, server) = test_server();
    let (_room, alice, bob, message) = room(&server, ConversationBody::default());
    let path = format!("/v1/core/messages/{}/reactions", message.to_hex());
    let (status, forged) = route_json(
        server.clone(),
        json_request(
            "POST",
            &path,
            json!({"by": bob.to_hex(), "glyph": "👀", "occurred_at": 20, "actor": actor(alice)}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{forged}");
    let (status, paged) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({"query": "friday", "limit": 10, "signals_limit": 5}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{paged}");
}

#[tokio::test]
async fn first_party_append_record_is_reactable_without_a_witness_child() {
    let (_dir, server) = test_server();
    let alice = person(&server, "Alice");
    let bob = person(&server, "Bob");
    let owner = WriteActor::new(alice, EdgeActorClass::Human);
    oneiron::conversation_dag::test_support::put_dag_test_policy(&server.vault, owner, true)
        .unwrap();
    let room = EntityId::now();
    server
        .vault
        .create_conversation(room, &ConversationBody::default(), owner, 1)
        .unwrap();
    for (at, member) in [(2, alice), (3, bob)] {
        server
            .vault
            .join_member(room, member, owner, at, HistoryChoice::None)
            .unwrap();
    }
    let path = format!("/v1/core/conversations/{}/records", room.to_hex());
    let (status, appended) = route_json(
        server.clone(),
        json_request(
            "POST",
            &path,
            json!({"actor": actor(alice), "advance": true, "occurred_start": 10,
                "body": {"txt": "hello"}}),
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
            json!({"by": bob.to_hex(), "glyph": "👀", "occurred_at": 20, "actor": actor(bob)}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let (status, page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!("{path}?with=reactions&viewer={}", bob.to_hex()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["records"][0]["id"], id);
    assert_eq!(page["records"][0]["reactions"][0]["count"], 1);
    assert_eq!(page["records"][0]["reactions"][0]["mine"], true);
}

#[tokio::test]
async fn mirrored_reaction_route_goes_through_the_signed_mirror_machine() {
    let (_dir, server) = test_server();
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"reaction route host").unwrap();
    server.vault.ensure_host_root_slip(&issuer).unwrap();
    server
        .vault
        .provision_engine_machine_identities(&issuer)
        .unwrap();
    let (room, _alice, bob, message) = room(
        &server,
        ConversationBody {
            kind: ConversationKind::Mirror,
            external_id: Some("slack:C1".into()),
            ..Default::default()
        },
    );
    let path = format!("/v1/core/messages/{}/reactions", message.to_hex());
    let add = json!({"by": bob.to_hex(), "glyph": "👍", "occurred_at": 20, "actor": actor(bob),
        "external": {"connector": "slack", "id": "g-1"}});
    let (status, put) = route_json(server.clone(), json_request("POST", &path, add)).await;
    assert_eq!(status, StatusCode::OK, "{put}");
    assert_eq!(put["event"], "reaction.put");
    let id = EntityId::from_hex(put["id"].as_str().unwrap()).unwrap();
    let history = server.vault.reaction_history(message, bob, "👍").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, id);
    assert_eq!(
        history[0]
            .external_id
            .as_ref()
            .map(|external| external.id.as_str()),
        Some("g-1")
    );
    let remove = json!({"by": bob.to_hex(), "glyph": "👍", "remove": true, "actor": actor(bob),
        "external": {"connector": "slack", "id": "g-1"}});
    let (status, removed) = route_json(server.clone(), json_request("POST", &path, remove)).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["event"], "reaction.revoked");
    assert_eq!(server.vault.reactions_outbound(room).unwrap(), "mirrored");
}

#[test]
fn reaction_route_has_openapi_and_security_policy() {
    let spec = generated_spec();
    assert!(spec["paths"]["/v1/core/messages/{message}/reactions"]["post"]["security"].is_array());
    for schema in [
        "ReactionRequest",
        "ReactionResponse",
        "DagReactionRecord",
        "CoreReactionSignal",
        "SurfaceReactionPayload",
    ] {
        assert!(
            spec["components"]["schemas"][schema].is_object(),
            "{schema}"
        );
    }
}
