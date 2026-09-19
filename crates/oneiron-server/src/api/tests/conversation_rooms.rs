//! Room, membership, addressing, thread and listing routes through the HTTP router.
use super::*;
#[tokio::test]
async fn conversation_rooms_members_threads_and_filters_round_trip() {
    let (_dir, server) = test_server();
    let actor = server.vault.ensure_embedded_owner_actor().unwrap();
    let person = oneiron::EntityId::now();
    server
        .vault
        .batch()
        .put(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({})).unwrap(),
        )
        .commit()
        .unwrap();
    let (status,room)=route_json(server.clone(),json_request("POST","/v1/core/conversations",json!({"actor":actor,"body":{"kind":"mirror","external_id":"remote-room","member_ids":[actor]}}))).await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let id = room["id"].as_str().unwrap();
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (status, members) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{id}/members"),
            json!({"actor":actor,"person_id":person,"action":"join","history":"none","at":at}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{members}");
    assert_eq!(members["member_ids"].as_array().unwrap().len(), 2);
    let (status,record)=route_json(server.clone(),json_request("POST",&format!("/v1/core/conversations/{id}/records"),json!({"actor":actor,"at":at+1,"body":{"txt":"room transcript needle","addr":"direct","to":[actor]}}))).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    let trunk = record["id"].as_str().unwrap();
    let head = server
        .vault
        .conversation_head(oneiron::EntityId::from_hex(id).unwrap())
        .unwrap();
    let (status, reply) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{id}/records/{trunk}/thread"),
            json!({"actor":actor,"at":at+2,"body":{"txt":"thread reply"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["thread"]["count"], 1);
    assert_eq!(
        server
            .vault
            .conversation_head(oneiron::EntityId::from_hex(id).unwrap())
            .unwrap(),
        head
    );
    let (status, records) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{id}/records?as={}&with=thread_meta",
                person.to_hex()
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{records}");
    assert_eq!(records["items"].as_array().unwrap().len(), 2);
    assert_eq!(records["items"][0]["thread_meta"]["count"], 1);
    let (status, rooms) = route_json(
        server.clone(),
        Request::builder()
            .uri("/v1/core/conversations?kind=mirror&external_id=remote-room&limit=10&countMode=exact")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rooms}");
    assert_eq!(rooms["items"].as_array().unwrap().len(), 1);
    let session = oneiron::EntityId::now();
    server
        .vault
        .batch()
        .put(
            &session,
            oneiron::registry::ENTITY_TYPE_SESSION,
            oneiron::TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&json!({})).unwrap(),
        )
        .commit()
        .unwrap();
    let (status, mode) = route_json(
        server.clone(),
        json_request(
            "PATCH",
            &format!("/v1/core/sessions/{}", session.to_hex()),
            json!({"actor":actor,"mode":"council"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{mode}");
    let (status, presence) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/sessions/{}/presence", session.to_hex()),
            json!({"actor":actor,"ids":[person]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{presence}");
    assert_eq!(presence["active_participant_ids"], json!([person]));
}

#[tokio::test]
async fn conversation_member_writes_require_scoped_actor_class() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = server.vault.ensure_embedded_owner_actor().unwrap();
    let room = oneiron::EntityId::now();
    let writer = oneiron::WriteActor::new(actor, oneiron::EdgeActorClass::Human);
    server
        .vault
        .create_conversation(
            room,
            &oneiron::conversation::ConversationBody::default(),
            writer,
            1,
        )
        .unwrap();
    let uri = format!("/v1/core/conversations/{}/members", room.to_hex());
    let actor_hex = actor.to_hex();
    let body = json!({"actor":actor,"person_id":actor,"action":"join","at":2});
    for claims in [
        "scope=core:write,core:auth".to_owned(),
        format!("scope=core:write,core:auth;principal_ref={actor_hex}"),
    ] {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz("POST", &uri, test_bearer(&claims), Some(&body)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(server.vault.membership_ledger(room).unwrap().is_empty());
        assert!(server.vault.members(room).unwrap().is_empty());
    }
    let claims = format!("scope=core:write;principal_ref={actor_hex};actor_class=human");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz("POST", &uri, test_bearer(&claims), Some(&body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(server.vault.members(room).unwrap(), vec![actor]);
}
