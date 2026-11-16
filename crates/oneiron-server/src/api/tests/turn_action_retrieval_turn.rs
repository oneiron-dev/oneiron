//! A queued Retry's board recall names, on its retrieval run, the user TURN
//! the reply answers and that TURN's conversation (FIX
//! RETRIEVAL-TURN-STAMP-TURN-ACTIONS), as a live chat turn's recall does
//! (`chat_retrieval_turn`): the convention on `RetrievalTurn` the engine's
//! natural outcome producer reads to label the run from the user's later
//! words. Capture is on here; it is off by default.
use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::conversation::TURN_ACTION_ATTEMPT_KIND;
use oneiron::{EdgeKind, EntityId};
use serde_json::{Value, json};

use super::chat_retrieval_turn::{capturing_server, chat_turn};
use super::*;
use crate::ai_host::test_support::eventually;
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// Queues a Retry of the assistant TURN `reply_turn` through its verb's
/// facade route, from this device as the chat turn was, as the owner on a
/// slip that names him: the attempt keeps that slip, and the worker reads
/// the action's board as its requester only through it.
async fn queue_retry(server: &Arc<SyncServer>, reply_turn: &EntityId) -> Value {
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    let body = json!({"turn_id": reply_turn.to_hex()});
    let mut request = core_request_with_authz(
        "POST",
        "/v1/core/facade/vault.conversations.turn.retry",
        test_bearer(&format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human",
            owner.to_hex()
        )),
        Some(&body),
    );
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            40_000,
        ))));
    let (status, receipt) = route_json(Arc::clone(server), request).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    receipt
}

#[tokio::test]
async fn the_recall_of_a_queued_retry_names_the_user_turn_it_answers_and_its_conversation() {
    let fake = FakeLlm::start(
        Vec::new(),
        Some(Reply::Text {
            text: "noted".into(),
            model: "fake".into(),
        }),
    )
    .await;
    let (_dir, server, host) = capturing_server(&fake.base_url).await;
    // An attached host takes queued Continue and Retry up only once bound,
    // as a served one is (commands/serve/workers.rs).
    host.bind_turn_actions(&server);
    let vault = server.vault();
    let conversation = EntityId::now();

    let lines = chat_turn(&server, &conversation.to_hex(), "my sister lives in Lisbon").await;
    // The live turn's recall names the user TURN (FIX
    // RETRIEVAL-TURN-CONVENTION-HOST-STAMP, `chat_retrieval_turn`). Only a
    // chat host's recall names a turn, so a background recall's run is not
    // counted.
    let before = vault.retrieval_runs(64).unwrap();
    let live: Vec<_> = before.iter().filter_map(|run| run.turn).collect();
    assert_eq!(live.len(), 1, "the live turn's recall: {before:?}");
    let user_turn = live[0];
    assert_eq!(user_turn.episode_id, *conversation.as_bytes());
    assert_eq!(user_turn.turn_idx, 0);

    // The assistant TURN the Retry names: the conversation's TURN that holds
    // the reply's MESSAGE.
    let message = EntityId::from_hex(lines[0]["message_id"].as_str().unwrap()).unwrap();
    let conversation_turns = vault
        .sources(&conversation, EdgeKind::ChildOf, None)
        .unwrap();
    let reply_turn = vault
        .targets(&message, EdgeKind::ChildOf, None)
        .unwrap()
        .into_iter()
        .find(|turn| conversation_turns.contains(turn))
        .expect("the reply's MESSAGE sits in a TURN of the conversation");
    assert_ne!(reply_turn.as_bytes(), &user_turn.turn_id);

    let receipt = queue_retry(&server, &reply_turn).await;
    let settled = |state: AttemptState| {
        matches!(
            state,
            AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
        )
    };
    let ran = eventually(Duration::from_secs(60), || {
        AttemptQueue::new(vault)
            .list()
            .unwrap()
            .iter()
            .any(|row| row.kind == TURN_ACTION_ATTEMPT_KIND && settled(row.state))
    })
    .await;
    let attempts = AttemptQueue::new(vault).list().unwrap();
    assert!(ran, "the worker settles the Retry {receipt}: {attempts:?}");

    // The Retry's board recall wrote one more named run, which names the
    // same user TURN, in its conversation, at its place there.
    let retry_runs: Vec<_> = vault
        .retrieval_runs(64)
        .unwrap()
        .into_iter()
        .filter(|run| before.iter().all(|old| old.run_id != run.run_id))
        .collect();
    let retry_turns: Vec<_> = retry_runs.iter().filter_map(|run| run.turn).collect();
    assert_eq!(
        retry_turns,
        vec![user_turn],
        "the Retry's run names the user TURN its reply answers: {retry_runs:?}; attempts {attempts:?}"
    );
    host.shutdown().await;
}
