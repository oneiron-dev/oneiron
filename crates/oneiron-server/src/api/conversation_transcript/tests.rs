//! A loopback page reads an imported coding session from the vault alone,
//! with the dev-mode credential a local navigator holds: the session's folder
//! and start time on the conversation list, its words in order from the
//! transcript, and recall hits that name their conversation.

use axum::http::StatusCode;
use oneiron::EntityId;
use oneiron::ingest::history::{HistoryFile, HistorySource};
use oneiron::store::GateDecisionId;
use serde_json::{Value, json};

use crate::api::tests::{core_request_with_authz, route_json, test_server};
use crate::server::SyncServer;

type Server = std::sync::Arc<SyncServer>;

const IMPORTED_AT: u64 = 1_800_000_000;
const SESSION: &str = "5c2d8e41-1111-4222-8333-944455556666";
const FOLDER: &str = "/home/dev/projects/garden";
/// 2026-09-25T06:00:00Z, when the session's first line was logged.
const STARTED: u64 = 1_790_316_000;
const LOG: [&str; 4] = [
    r#"{"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"user","message":{"role":"user","content":"Repot the basil."},"uuid":"e3000000-0000-4000-8000-000000000001","timestamp":"2026-09-25T06:00:00.000Z"}"#,
    r#"{"parentUuid":"e3000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The basil is repotted."}]},"uuid":"e3000000-0000-4000-8000-000000000002","timestamp":"2026-09-25T06:00:20.000Z"}"#,
    r#"{"parentUuid":"e3000000-0000-4000-8000-000000000002","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"user","message":{"role":"user","content":"Water the basil too."},"uuid":"e3000000-0000-4000-8000-000000000003","timestamp":"2026-09-25T06:01:00.000Z"}"#,
    r#"{"parentUuid":"e3000000-0000-4000-8000-000000000003","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The basil is watered."}]},"uuid":"e3000000-0000-4000-8000-000000000004","timestamp":"2026-09-25T06:01:30.000Z"}"#,
];

/// The unverified bearer a loopback dev-mode server accepts.
fn bearer(principal: EntityId) -> String {
    format!(
        "Bearer v2.scope=core:read;principal_ref={};actor_class=human.00",
        principal.to_hex()
    )
}

async fn call(
    server: &Server,
    principal: EntityId,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    route_json(
        server.clone(),
        core_request_with_authz(method, uri, bearer(principal), body),
    )
    .await
}

/// A test server holding one Claude Code session imported through the owner
/// door; returns the owner the loopback page reads as.
fn imported_session() -> (tempfile::TempDir, Server, EntityId) {
    let (dir, server) = test_server();
    let actor = server.vault.ensure_embedded_owner_actor().expect("owner");
    let owner = server
        .vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("authenticate the owner");
    let file = HistoryFile {
        stem: SESSION.to_owned(),
        parent: None,
    };
    for conversation in HistorySource::ClaudeCode
        .decode(&LOG.join("\n"), &file)
        .expect("decode the log")
    {
        let report = server
            .vault
            .import_history(
                &owner,
                HistorySource::ClaudeCode,
                &conversation,
                IMPORTED_AT,
            )
            .expect("import the session");
        assert_eq!(report.new, 4, "{report:?}");
    }
    (dir, server, actor)
}

/// The session's row in the full conversation list.
async fn listed(server: &Server, actor: EntityId) -> Value {
    let (status, list) = call(
        server,
        actor,
        "GET",
        "/v1/core/conversations?view=full&limit=50",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|row| row["import_conversation"] == SESSION)
        .expect("the imported session is listed")
        .clone()
}

#[tokio::test]
async fn an_imported_session_lists_its_folder_and_start_time() {
    let (_dir, server, actor) = imported_session();
    let row = listed(&server, actor).await;
    assert_eq!(row["import_cwd"], FOLDER, "{row}");
    assert_eq!(row["occurred"], json!({"start": STARTED, "end": STARTED}));
}

#[tokio::test]
async fn a_loopback_reader_reads_an_imported_session_in_order() {
    let (_dir, server, actor) = imported_session();
    let id = listed(&server, actor).await["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();
    let transcript = format!("/v1/core/conversations/{id}/transcript");
    let (status, page) = call(&server, actor, "GET", &transcript, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let said: Vec<(&str, &str, u64)> = page["turns"]
        .as_array()
        .expect("turns")
        .iter()
        .flat_map(|turn| turn["messages"].as_array().expect("messages"))
        .map(|message| {
            (
                message["role"].as_str().expect("role"),
                message["text"].as_str().expect("text"),
                message["occurred"].as_u64().expect("occurred"),
            )
        })
        .collect();
    assert_eq!(
        said,
        [
            ("user", "Repot the basil.", STARTED),
            ("companion", "The basil is repotted.", STARTED + 20),
            ("user", "Water the basil too.", STARTED + 60),
            ("companion", "The basil is watered.", STARTED + 90),
        ]
    );
    assert_eq!(page["next"], Value::Null);
    assert!(page["narrowing"].is_object(), "the read's receipt: {page}");

    // An id that names no conversation the reader may read opens nothing. (In
    // a vault with no authority root every human PERSON reads as its owner, so
    // a scoped reader's transcript is checked in the engine, on a rooted vault.)
    let elsewhere = format!("/v1/core/conversations/{}/transcript", actor.to_hex());
    let (status, body) = call(&server, actor, "GET", &elsewhere, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["narrowing"].is_object(),
        "a refused read says it narrowed: {body}"
    );
}

#[tokio::test]
async fn a_recall_hit_names_its_conversation() {
    let (_dir, server, actor) = imported_session();
    let id = listed(&server, actor).await["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();
    let (status, pack) = call(
        &server,
        actor,
        "POST",
        "/v1/core/facade/recall",
        Some(&json!({"query": "basil", "effort": "light", "limit": 10})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    let hits = pack["items"].as_array().expect("items");
    assert!(
        hits.iter().any(|item| item["kind"] == "TURN"),
        "recall finds the session's turns: {pack}"
    );
    for item in hits.iter().filter(|item| item["kind"] == "TURN") {
        assert_eq!(item["conversation_id"], id.as_str(), "{item}");
    }
}
