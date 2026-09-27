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

#[tokio::test]
async fn list_preview_falls_back_only_through_selected_dag_ancestors() {
    let (_dir, server, actor) = setup();
    let room = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let records = format!(
        "/v1/core/conversations/{}/records",
        room["id"].as_str().unwrap()
    );
    let root = post(
        &server,
        &records,
        json!({
            "advance": true, "body": {"txt": "selected ancestor"}, "actor": actor,
            "occurred_start": 100_u64, "learned_at": 100_u64,
        }),
    )
    .await;
    let hidden_head = post(
        &server,
        &records,
        json!({
            "parent": root["id"], "advance": true, "body": {}, "actor": actor,
            "occurred_start": 101_u64, "learned_at": 101_u64,
        }),
    )
    .await;
    let inactive_fork = post(&server, &records, json!({
        "parent": root["id"], "advance": false, "body": {"txt": "inactive branch"}, "actor": actor,
        "occurred_start": 102_u64, "learned_at": 102_u64,
    })).await;
    assert_eq!(inactive_fork["head"], hidden_head["id"]);
    let thread = post(
        &server,
        &format!("{records}/{}/thread", root["id"].as_str().unwrap()),
        json!({
            "actor": actor, "advance": false, "body": {"txt": "thread reply"}, "occurred_start": 103_u64,
        }),
    )
    .await;
    assert_eq!(thread["head"], hidden_head["id"]);
    let list = get(&server, "/v1/core/conversations?limit=20").await;
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == room["id"])
        .unwrap();
    assert_eq!(row["lastMessageSnippet"], "selected ancestor");
}

#[tokio::test]
async fn list_preview_traverses_deleted_selected_shells_without_losing_other_rooms() {
    let (_dir, server, actor) = setup();
    let mut expected = Vec::new();
    for (case, text) in [
        ("deleted_head", "visible root"),
        ("deleted_middle", "earlier root"),
        ("deleted_root", "live child"),
        ("unrelated", "other room"),
    ] {
        let room = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
        let records = format!(
            "/v1/core/conversations/{}/records",
            room["id"].as_str().unwrap()
        );
        let root_text = if case == "deleted_root" {
            "deleted root"
        } else {
            text
        };
        let root = post(
            &server,
            &records,
            json!({
                "advance": true, "body": {"txt": root_text}, "actor": actor,
            }),
        )
        .await;
        let mut deleted = None;
        if case == "deleted_head" {
            let head = post(&server, &records, json!({
                "parent": root["id"], "advance": true, "body": {"txt": "erased head"}, "actor": actor,
            })).await;
            deleted = Some(head["id"].as_str().unwrap().to_owned());
        } else if case == "deleted_middle" {
            let middle = post(&server, &records, json!({
                "parent": root["id"], "advance": true, "body": {"txt": "erased middle"}, "actor": actor,
            })).await;
            post(
                &server,
                &records,
                json!({
                    "parent": middle["id"], "advance": true, "body": {}, "actor": actor,
                }),
            )
            .await;
            deleted = Some(middle["id"].as_str().unwrap().to_owned());
        } else if case == "deleted_root" {
            post(
                &server,
                &records,
                json!({
                    "parent": root["id"], "advance": true, "body": {"txt": text}, "actor": actor,
                }),
            )
            .await;
            deleted = Some(root["id"].as_str().unwrap().to_owned());
        }
        if let Some(id) = deleted {
            let id = EntityId::from_hex(&id).unwrap();
            server
                .vault
                .delete_entity_with_reason(&id, oneiron::DeleteReason::UserDelete)
                .unwrap();
            assert!(server.vault.is_deleted_shell(&id).unwrap());
        }
        expected.push((room["id"].as_str().unwrap().to_owned(), text));
    }
    let list = get(&server, "/v1/core/conversations?limit=20").await;
    let rows = list["items"].as_array().unwrap();
    for (id, text) in expected {
        let row = rows.iter().find(|row| row["id"] == id).unwrap();
        assert_eq!(row["lastMessageSnippet"], text, "room {id}");
    }
}

#[tokio::test]
async fn list_preview_walks_deleted_ordinary_session_turns_and_keeps_other_rooms() {
    let (_dir, server, actor) = setup();
    let session = match server.vault.mint_session(100).expect("ordinary session") {
        oneiron::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected new session, got {other:?}"),
    };
    let mut expected = Vec::new();
    for (case, text) in [
        ("head", "session root"),
        ("ancestor", "session child"),
        ("unrelated", "other session room"),
    ] {
        let room = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
        let records = format!(
            "/v1/core/conversations/{}/records",
            room["id"].as_str().unwrap()
        );
        let root = post(
            &server,
            &records,
            json!({
                "advance": true, "session": session.to_hex(), "actor": actor,
                "body": {"txt": if case == "ancestor" { "deleted ancestor" } else { text }},
            }),
        )
        .await;
        let mut deleted = None;
        if case != "unrelated" {
            let child = post(
                &server,
                &records,
                json!({
                    "parent": root["id"], "advance": true, "session": session.to_hex(),
                    "body": {"txt": if case == "head" { "deleted head" } else { text }},
                    "actor": actor,
                }),
            )
            .await;
            deleted = Some(if case == "head" {
                child["id"].clone()
            } else {
                root["id"].clone()
            });
        }
        if let Some(id) = deleted {
            let id = EntityId::from_hex(id.as_str().unwrap()).unwrap();
            server
                .vault
                .delete_entity_with_reason(&id, oneiron::DeleteReason::UserDelete)
                .unwrap();
            assert!(server.vault.is_deleted_shell(&id).unwrap());
        }
        expected.push((room["id"].as_str().unwrap().to_owned(), text));
    }
    let list = get(&server, "/v1/core/conversations?limit=20").await;
    for (room, text) in expected {
        let row = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == room)
            .unwrap();
        assert_eq!(row["lastMessageSnippet"], text, "room {room}");
    }
}

#[tokio::test]
async fn selected_preview_lifecycle_matrix_keeps_retained_shape_separate_from_content() {
    for head_deleted in [false, true] {
        for ancestor_deleted in [false, true] {
            for session_deleted in [false, true] {
                let (_dir, server, actor) = setup();
                let session = match server.vault.mint_session(100).unwrap() {
                    oneiron::session_lifecycle::SessionMintOutcome::Minted(id) => id,
                    other => panic!("expected new ordinary session: {other:?}"),
                };
                let room = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
                let records = format!(
                    "/v1/core/conversations/{}/records",
                    room["id"].as_str().unwrap()
                );
                let root = post(
                    &server,
                    &records,
                    json!({
                        "advance": true, "actor": actor, "session": session.to_hex(),
                        "body": {"txt": "selected root"},
                    }),
                )
                .await;
                let head = post(&server, &records, json!({
                    "parent": root["id"], "advance": true, "actor": actor, "session": session.to_hex(),
                    "body": {"txt": "selected head"},
                })).await;
                let fork = post(
                    &server,
                    &records,
                    json!({
                        "parent": root["id"], "advance": false, "actor": actor,
                        "body": {"txt": "inactive fork"},
                    }),
                )
                .await;
                assert_eq!(fork["head"], head["id"]);
                post(
                    &server,
                    &format!("{records}/{}/thread", root["id"].as_str().unwrap()),
                    json!({
                        "actor": actor, "advance": false, "body": {"txt": "off-line thread"},
                    }),
                )
                .await;
                let spawned = post(
                    &server,
                    &format!(
                        "/v1/core/turns/{}/sub-sessions",
                        root["id"].as_str().unwrap()
                    ),
                    json!({"actor": actor}),
                )
                .await;
                post(
                    &server,
                    &records,
                    json!({
                        "parent": root["id"], "advance": false, "actor": actor,
                        "session": spawned["session"], "body": {"txt": "worker branch"},
                    }),
                )
                .await;
                let other = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
                let other_records = format!(
                    "/v1/core/conversations/{}/records",
                    other["id"].as_str().unwrap()
                );
                post(
                    &server,
                    &other_records,
                    json!({
                        "advance": true, "actor": actor, "body": {"txt": "unrelated room"},
                    }),
                )
                .await;
                for (deleted, row) in [(head_deleted, &head), (ancestor_deleted, &root)] {
                    if deleted {
                        server
                            .vault
                            .delete_entity_with_reason(
                                &EntityId::from_hex(row["id"].as_str().unwrap()).unwrap(),
                                oneiron::DeleteReason::UserDelete,
                            )
                            .unwrap();
                    }
                }
                if session_deleted {
                    server
                        .vault
                        .delete_entity_with_reason(&session, oneiron::DeleteReason::UserDelete)
                        .unwrap();
                    assert!(server.vault.is_deleted_shell(&session).unwrap());
                }
                let list = get(&server, "/v1/core/conversations?limit=20").await;
                let rows = list["items"].as_array().unwrap();
                let selected = rows.iter().find(|row| row["id"] == room["id"]).unwrap();
                let expected = if !head_deleted {
                    Some("selected head")
                } else if !ancestor_deleted {
                    Some("selected root")
                } else {
                    None
                };
                assert_eq!(
                    selected["lastMessageSnippet"].as_str(),
                    expected,
                    "head_deleted={head_deleted}, ancestor_deleted={ancestor_deleted}, session_deleted={session_deleted}"
                );
                assert_eq!(
                    rows.iter().find(|row| row["id"] == other["id"]).unwrap()["lastMessageSnippet"],
                    "unrelated room"
                );
            }
        }
    }
}

#[tokio::test]
async fn empty_room_remains_listable_after_dag_read() {
    let (_dir, server, actor) = setup();
    let empty = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let healthy = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let healthy_records = format!(
        "/v1/core/conversations/{}/records",
        healthy["id"].as_str().unwrap()
    );
    post(
        &server,
        &healthy_records,
        json!({
            "advance": true, "actor": actor, "body": {"txt": "healthy room content"},
        }),
    )
    .await;
    let empty_records = format!(
        "/v1/core/conversations/{}/records",
        empty["id"].as_str().unwrap()
    );
    let dag = get(&server, &empty_records).await;
    assert!(dag["head"].is_null());
    assert_eq!(dag["main_line"], json!([]));
    let list = get(&server, "/v1/core/conversations?limit=20").await;
    let rows = list["items"].as_array().unwrap();
    assert!(
        rows.iter().find(|row| row["id"] == empty["id"]).unwrap()["lastMessageSnippet"].is_null()
    );
    assert_eq!(
        rows.iter().find(|row| row["id"] == healthy["id"]).unwrap()["lastMessageSnippet"],
        "healthy room content"
    );
}

#[tokio::test]
async fn room_with_only_deleted_childof_turns_lists_after_dag_migration() {
    let (_dir, server, actor) = setup();
    let empty = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    let turn = post(
        &server,
        &format!(
            "/v1/core/conversations/{}/turns",
            empty["id"].as_str().unwrap()
        ),
        json!({"body": {"txt": "erased legacy text"}}),
    )
    .await;
    let turn_id = EntityId::from_hex(turn["id"].as_str().unwrap()).unwrap();
    server
        .vault
        .delete_entity_with_reason(&turn_id, oneiron::DeleteReason::UserDelete)
        .unwrap();
    assert!(server.vault.is_deleted_shell(&turn_id).unwrap());
    let healthy = post(&server, "/v1/core/conversations", json!({"body": {}})).await;
    post(
        &server,
        &format!(
            "/v1/core/conversations/{}/records",
            healthy["id"].as_str().unwrap()
        ),
        json!({"advance": true, "actor": actor, "body": {"txt": "healthy retained text"}}),
    )
    .await;
    let dag = get(
        &server,
        &format!(
            "/v1/core/conversations/{}/records",
            empty["id"].as_str().unwrap()
        ),
    )
    .await;
    assert!(dag["head"].is_null());
    assert_eq!(dag["main_line"], json!([]));
    let list = get(&server, "/v1/core/conversations?limit=20").await;
    let rows = list["items"].as_array().unwrap();
    assert!(
        rows.iter().find(|row| row["id"] == empty["id"]).unwrap()["lastMessageSnippet"].is_null()
    );
    assert_eq!(
        rows.iter().find(|row| row["id"] == healthy["id"]).unwrap()["lastMessageSnippet"],
        "healthy retained text"
    );
}
