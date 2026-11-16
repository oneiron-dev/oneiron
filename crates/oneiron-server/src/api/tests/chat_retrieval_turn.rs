//! A live chat turn's board recall names, on its retrieval run, the TURN the
//! user's words are witnessed in and that TURN's conversation (FIX
//! RETRIEVAL-TURN-CONVENTION-HOST-STAMP), the convention the engine's
//! natural outcome producer reads to label the run from the user's later
//! words. Capture is on here; it is off by default.
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::store::RetrievalTurn;
use oneiron::{EdgeKind, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, models};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// A rooted vault that captures retrieval runs, served with a chat seat on
/// `base_url`.
pub(super) async fn capturing_server(
    base_url: &str,
) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, TEST_SECRET.as_bytes());
    let issuer = vault.bootstrap_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault.provision_engine_machine_identities(&issuer).unwrap();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (server, host) = AiHost::attach(server, Some(&models(base_url, ""))).await;
    (dir, Arc::new(server), host)
}

/// One owner chat turn in `conversation`, from this device; its NDJSON
/// lines once the reply is saved.
pub(super) async fn chat_turn(
    server: &Arc<SyncServer>,
    conversation: &str,
    text: &str,
) -> Vec<Value> {
    let body = json!({"conversation_ref": conversation, "text": text, "stream": true});
    let mut request: Request<Body> =
        core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body));
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            40_000,
        ))));
    let request = slip_credentials::bind_request(server, request);
    let response = api_routes(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let lines: Vec<Value> = body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("NDJSON line"))
        .collect();
    assert_eq!(
        lines.last().map(|line| line["type"].clone()),
        Some(json!("saved")),
        "{lines:?}"
    );
    lines
}

/// The turns the vault's captured runs name, oldest run first.
fn stamped_turns(vault: &Vault) -> Vec<RetrievalTurn> {
    let mut runs = vault.retrieval_runs(64).unwrap();
    assert!(
        !runs.is_empty(),
        "capture is on, so the board's recall writes a run"
    );
    runs.sort_by_key(|run| run.started_at);
    runs.into_iter().filter_map(|run| run.turn).collect()
}

/// Whether `turn` is a TURN of `conversation` that holds a MESSAGE with
/// `text`: the TURN the user's words were witnessed in.
fn witnessed_user_turn(
    vault: &Vault,
    conversation: &EntityId,
    turn: &EntityId,
    text: &str,
) -> bool {
    let of_conversation = vault
        .sources(conversation, EdgeKind::ChildOf, None)
        .unwrap()
        .contains(turn);
    let holds_text = vault
        .sources(turn, EdgeKind::ChildOf, None)
        .unwrap()
        .iter()
        .any(|message| {
            vault
                .get(message)
                .unwrap()
                .is_some_and(|raw| String::from_utf8_lossy(&raw).contains(text))
        });
    of_conversation && holds_text
}

#[tokio::test]
async fn a_chat_turns_recall_names_the_witnessed_user_turn_and_its_conversation() {
    let fake = FakeLlm::start(
        Vec::new(),
        Some(Reply::Text {
            text: "noted".into(),
            model: "fake".into(),
        }),
    )
    .await;
    let (_dir, server, host) = capturing_server(&fake.base_url).await;
    let vault = server.vault();
    let conversation = EntityId::now();

    chat_turn(&server, &conversation.to_hex(), "my sister lives in Lisbon").await;
    let first = stamped_turns(vault);
    assert_eq!(
        first.len(),
        1,
        "the turn's board recall names its turn: {first:?}"
    );
    let first = first[0];
    assert_eq!(first.episode_id, *conversation.as_bytes());
    assert_eq!(first.turn_idx, 0, "the conversation's first TURN");
    let first_turn = EntityId::from_bytes(first.turn_id).unwrap();
    assert!(
        witnessed_user_turn(
            vault,
            &conversation,
            &first_turn,
            "my sister lives in Lisbon"
        ),
        "the run names the TURN the user's words were witnessed in"
    );

    // The next turn's run names its own TURN, after the user's and the
    // reply's TURNs of the first turn.
    chat_turn(&server, &conversation.to_hex(), "where does my sister live").await;
    let both = stamped_turns(vault);
    assert_eq!(both.len(), 2, "{both:?}");
    let second = both[1];
    assert_eq!(second.episode_id, *conversation.as_bytes());
    assert_eq!(second.turn_idx, 2);
    let second_turn = EntityId::from_bytes(second.turn_id).unwrap();
    assert_ne!(second_turn, first_turn);
    assert!(witnessed_user_turn(
        vault,
        &conversation,
        &second_turn,
        "where does my sister live"
    ));
    host.shutdown().await;
}
