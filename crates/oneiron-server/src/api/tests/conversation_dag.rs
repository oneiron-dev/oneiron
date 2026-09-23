//! Wire-level DAG, summary and reply-strip acceptance.

use super::*;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, TimeRange, WriteActor};

fn setup() -> (tempfile::TempDir, Arc<SyncServer>, Value) {
    let (dir, server) = test_server();
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    server
        .vault
        .put_entity(
            &actor.entity_ref(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({"name": "author"})).unwrap(),
        )
        .unwrap();
    oneiron::conversation_dag::test_support::put_dag_test_policy(&server.vault, actor, true)
        .unwrap();
    (
        dir,
        server,
        json!({"entity_ref": actor.entity_ref().to_hex(), "actor_class": "human"}),
    )
}

async fn post(server: &Arc<SyncServer>, path: &str, body: Value) -> Value {
    let (status, value) = route_json(server.clone(), json_request("POST", path, body)).await;
    assert_eq!(status, StatusCode::OK, "{value:?}");
    value
}

async fn get(server: &Arc<SyncServer>, path: &str) -> Value {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    let (status, value) = route_json(server.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "{value:?}");
    value
}

#[tokio::test]
async fn dag_routes_roundtrip_trunk_thread_fork_scope_migration_and_auth() {
    let (_dir, server, actor) = setup();
    let conv = post(
        &server,
        "/v1/core/conversations",
        json!({"body": {"name": "conversation"}}),
    )
    .await;
    let path = format!("/v1/core/conversations/{}", conv["id"].as_str().unwrap());
    let records = format!("{path}/records");
    let root = post(
        &server,
        &records,
        json!({"advance": true, "body": {"txt": "question"}, "actor": actor}),
    )
    .await;
    assert_eq!(root["head"], root["id"]);
    assert!(root["parent"].is_null());
    let trunk = post(
        &server,
        &records,
        json!({"parent": root["id"], "advance": true, "body": {"txt": "next"}, "actor": actor}),
    )
    .await;
    let thread = post(
        &server,
        &records,
        json!({"parent": root["id"], "advance": false, "body": {"txt": "thread"}, "actor": actor}),
    )
    .await;
    assert_eq!(thread["head"], trunk["id"]);
    let first = get(&server, &format!("{path}/records?limit=1")).await;
    assert_eq!(first["root"], root["id"]);
    assert_eq!(first["page"]["next"], root["id"]);
    assert_eq!(first["main_line"], json!([root["id"]]));
    let second = get(
        &server,
        &format!(
            "{path}/records?limit=1&after={}",
            root["id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(second["main_line"], json!([trunk["id"]]));
    post(
        &server,
        &format!("{path}/head"),
        json!({"record": thread["id"]}),
    )
    .await;
    let scope = post(
        &server,
        &format!("{path}/scope"),
        json!({"path": "canonical"}),
    )
    .await;
    assert_eq!(scope["records"], json!([root["id"], thread["id"]]));
    let branch = post(
        &server,
        &format!("{path}/scope"),
        json!({"path": {"branch": trunk["id"]}}),
    )
    .await;
    assert_eq!(branch["records"], json!([root["id"], trunk["id"]]));
    let expanded = post(
        &server,
        &format!("{path}/scope"),
        json!({"path": {"branch": trunk["id"]}, "include_forks": true}),
    )
    .await;
    let expanded_records = expanded["records"].as_array().unwrap();
    assert_eq!(expanded_records.len(), 3);
    assert_eq!(
        expanded_records
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            root["id"].as_str().unwrap(),
            trunk["id"].as_str().unwrap(),
            thread["id"].as_str().unwrap()
        ]
        .into()
    );
    let migrated = post(&server, &format!("{path}/migrate-dag"), json!({})).await;
    assert_eq!(migrated["migrated"], false);
    let (status, error) = route_json(server.clone(), json_request("POST", &records,
        json!({"parent": root["id"], "advance": true, "body": {"txt": "wrong"}, "actor": actor}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_envelope(&error, "INVALID_STATE");
    let (status, _) = route_json(
        server.clone(),
        json_request(
            "POST",
            &records,
            json!({"advance": false, "body": {"txt": "missing actor"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_auth_dir, protected) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let (status, _) = route_json(
        protected,
        json_request(
            "POST",
            &records,
            json!({"advance": true, "body": {}, "actor": actor}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn summary_routes_return_all_300_covers_drill_and_engine_bound_late_reply() {
    let (_dir, server, actor) = setup();
    let conv = post(
        &server,
        "/v1/core/conversations",
        json!({"body": {"name": "conversation"}}),
    )
    .await;
    let path = format!("/v1/core/conversations/{}", conv["id"].as_str().unwrap());
    let root = post(
        &server,
        &format!("{path}/records"),
        json!({"advance": true, "body": {"txt": "asking turn"}, "actor": actor}),
    )
    .await;
    let turn_path = format!("/v1/core/turns/{}", root["id"].as_str().unwrap());
    let session = post(
        &server,
        &format!("{turn_path}/sub-sessions"),
        json!({"actor": actor}),
    )
    .await;
    assert_eq!(
        get(&server, &format!("{turn_path}/sub-sessions")).await["sessions"],
        json!([session["session"]])
    );
    // Build the volume through the same public engine append door; the route
    // adapter itself was exercised above. No 300 redundant HTTP requests.
    let conv_id = EntityId::from_hex(conv["id"].as_str().unwrap()).unwrap();
    let asking = EntityId::from_hex(root["id"].as_str().unwrap()).unwrap();
    let session_id = EntityId::from_hex(session["session"].as_str().unwrap()).unwrap();
    let writer = WriteActor::new(
        EntityId::from_hex(actor["entity_ref"].as_str().unwrap()).unwrap(),
        EdgeActorClass::Human,
    );
    let mut parent = asking;
    let mut covers = Vec::new();
    for n in 0..300 {
        let record = server
            .vault
            .append_dag_record(&oneiron::conversation_dag::AppendRecord {
                conversation: conv_id,
                parent: Some(parent),
                reply_to: None,
                advance: false,
                kind: ENTITY_TYPE_TURN,
                occurred: TimeRange {
                    start: n + 10,
                    end: n + 10,
                },
                learned_at: n + 10,
                body: rmp_serde::to_vec_named(&json!({"txt": "retained"})).unwrap(),
                text: vec![],
                session: Some(session_id),
                actor: writer,
            })
            .unwrap();
        parent = record.id;
        covers.push(parent.to_hex());
    }
    let scope = json!({"path": {"sub_session": session["session"]}});
    assert_eq!(
        post(&server, &format!("{path}/scope"), scope.clone()).await["records"],
        json!(covers)
    );
    let current = post(&server, &format!("{path}/records"), json!({"parent": root["id"], "advance": true, "body": {"txt": "continued"}, "actor": actor})).await;
    oneiron::conversation_dag::test_support::put_dag_test_policy(&server.vault, writer, false)
        .unwrap();
    let request = json!({"scope": scope, "text": "caller result", "actor": actor, "land_on": root["id"], "as_record": true});
    let before = server
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_SUMMARY)
        .unwrap();
    let (status, _) = route_json(
        server.clone(),
        json_request("POST", &format!("{path}/summaries"), request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        server
            .vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_SUMMARY)
            .unwrap(),
        before
    );
    oneiron::conversation_dag::test_support::put_dag_test_policy(&server.vault, writer, true)
        .unwrap();
    let summary = post(&server, &format!("{path}/summaries"), request).await;
    let all = get(
        &server,
        &format!(
            "/v1/core/summaries/{}/covers",
            summary["summary"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(all["covers"], json!(covers));
    let drilled = get(
        &server,
        &format!(
            "/v1/core/claims/{}/drill",
            summary["claim"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(drilled["records"], all["covers"]);
    let reply = get(
        &server,
        &format!(
            "/v1/core/turns/{}?with=reply_strip",
            summary["record"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(reply["reply_to"]["record"], root["id"]);
    assert_eq!(reply["reply_strip"]["record"], root["id"]);
    assert_eq!(reply["reply_strip"]["text"], "asking turn");
    assert_eq!(reply["reply_strip"]["stale"], false);
    let reply_id = EntityId::from_hex(summary["record"].as_str().unwrap()).unwrap();
    assert_eq!(server.vault.head(&conv_id).unwrap(), Some(reply_id));
    assert_eq!(
        server
            .vault
            .targets(&reply_id, oneiron::EdgeKind::Parent, None)
            .unwrap(),
        [EntityId::from_hex(current["id"].as_str().unwrap()).unwrap()]
    );
    assert_eq!(
        post(&server, &format!("{path}/scope"), scope).await["records"],
        json!(covers)
    );
}

#[test]
fn dag_routes_are_registered_in_openapi() {
    use utoipa::OpenApi;
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    for (path, method) in [
        ("/v1/core/conversations/{conversation_id}/records", "post"),
        ("/v1/core/conversations/{conversation_id}/records", "get"),
        ("/v1/core/conversations/{conversation_id}/head", "post"),
        ("/v1/core/conversations/{conversation_id}/scope", "post"),
        (
            "/v1/core/conversations/{conversation_id}/migrate-dag",
            "post",
        ),
        ("/v1/core/turns/{turn_id}/sub-sessions", "post"),
        ("/v1/core/turns/{turn_id}/sub-sessions", "get"),
        ("/v1/core/conversations/{conversation_id}/summaries", "post"),
        ("/v1/core/summaries/{summary_id}/covers", "get"),
        ("/v1/core/claims/{claim_id}/drill", "get"),
    ] {
        assert!(doc["paths"][path][method].is_object(), "{method} {path}");
    }
}

#[tokio::test]
async fn dag_writes_require_complete_matching_identity_on_scoped_credentials() {
    let (_dir, server, actor) = setup();
    let conv = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let records = format!(
        "/v1/core/conversations/{}/records",
        conv["id"].as_str().unwrap()
    );
    let principal = actor["entity_ref"].as_str().unwrap();
    let other = EntityId::now().to_hex();
    for claims in [
        "scope=core:write".to_owned(),
        format!("scope=core:write;principal_ref={principal}"),
        "scope=core:write;actor_class=human".to_owned(),
        format!("scope=core:write;principal_ref={other};actor_class=human"),
        format!("scope=core:write;principal_ref={principal};actor_class=agent"),
    ] {
        let token = crate::auth::mint_core_token_v2("unused-in-dev", &claims);
        let mut request = json_request(
            "POST",
            &records,
            json!({"advance": true, "body": {"txt": "refused"}, "actor": actor}),
        );
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let (status, error) = route_json(server.clone(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{claims}: {error:?}");
        assert_error_envelope(&error, "FORBIDDEN");
    }
    let token = crate::auth::mint_core_token_v2(
        "unused-in-dev",
        &format!("scope=core:write;principal_ref={principal};actor_class=human"),
    );
    let mut request = json_request(
        "POST",
        &records,
        json!({"advance": true, "body": {"txt": "bound"}, "actor": actor}),
    );
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let (status, body) = route_json(server.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        get(
            &server,
            &format!(
                "/v1/core/conversations/{}/records",
                conv["id"].as_str().unwrap()
            )
        )
        .await["main_line"],
        json!([body["id"]])
    );
}

#[tokio::test]
async fn records_thread_and_canonical_share_the_typed_dag() {
    let (_dir, server, actor) = setup();
    let conversation = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let path = format!(
        "/v1/core/conversations/{}",
        conversation["id"].as_str().unwrap()
    );
    let root = post(
        &server,
        &format!("{path}/records"),
        json!({
            "advance": true, "body": {"txt": "question"}, "actor": actor
        }),
    )
    .await;
    let thread_path = format!("{path}/records/{}/thread", root["id"].as_str().unwrap());
    let reply = post(
        &server,
        &thread_path,
        json!({"advance": false, "body": {"txt": "answer"}, "actor": actor}),
    )
    .await;
    let thread = get(&server, &thread_path).await;
    assert_eq!(thread["replies"], json!([reply["id"]]));
    assert_eq!(thread["count"], 1);
    let canonical = get(&server, &format!("{path}/canonical")).await;
    assert_eq!(canonical["records"], json!([root["id"]]));
    for uri in [format!("{path}/dag"), format!("{path}/dag/records")] {
        let response = api_routes(server.clone())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
