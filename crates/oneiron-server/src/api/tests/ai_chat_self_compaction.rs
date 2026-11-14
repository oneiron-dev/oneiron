//! L10-33 (RULING L10-33-SCOPE = B): under a self row on the retained
//! turns, a self agent's chat compacts as the agent on the cheap writer, as
//! the executor's runs do. The row says how the history is cut, never
//! whether the agent writes in its own voice (canon #own-voice-default).
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, eventually, models_toml, rooted_vault};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// The self-writer frame this test's prompt package carries: only the
/// cheap writer's call as the agent wears it.
const SELF_WRITER_FRAME: &str =
    "You write this summary as the agent itself, in the first person, about your own conversation.";
/// A phrase only the fake's summary holds, so a later request that carries
/// it read the landed summary.
const SUMMARY_PHRASE: &str = "harbour-ledger-summary";

/// Copies the prompt package tree at `from` to `to`.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The workspace's test prompt package plus a self-writer frame, which the
/// package lacks: without one, self-written summaries are off (FIX 4575).
fn prompt_package_with_frame() -> tempfile::TempDir {
    let package = tempfile::tempdir().unwrap();
    copy_tree(
        &oneiron::prompt::workspace_test_prompt_package_root().unwrap(),
        package.path(),
    );
    std::fs::write(
        package
            .path()
            .join(oneiron::prompt::COMPACTION_SELF_WRITER_PROMPT_RELATIVE_PATH),
        SELF_WRITER_FRAME,
    )
    .unwrap();
    package
}

/// The text of one request message: a string, or its text parts joined.
fn message_text(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// Whether `body` is a compaction call: its system message is the
/// compaction prompt, never a fork of a chat request.
fn is_compaction_call(body: &Value) -> bool {
    body["messages"]
        .as_array()
        .and_then(|messages| messages.first())
        .is_some_and(|system| message_text(system).contains("You compact"))
}

/// The fake model's reply: a compaction call's summary over the span it
/// names, with every pin, or else a long chat answer that fills the window.
fn reply(body: &Value) -> String {
    if is_compaction_call(body) {
        let messages = body["messages"].as_array().cloned().unwrap_or_default();
        let input: Value = messages
            .last()
            .and_then(|message| serde_json::from_str(&message_text(message)).ok())
            .unwrap_or(Value::Null);
        let mut summary = format!(
            "I went over the north pier tide readings with the owner and logged each one; {SUMMARY_PHRASE}."
        );
        for pin in input["pins"].as_array().into_iter().flatten() {
            summary.push('\n');
            summary.push_str(pin.as_str().unwrap_or_default());
        }
        return json!({"from": input["from"], "through": input["through"], "summary": summary})
            .to_string();
    }
    (0..60)
        .map(|reading| {
            format!(
                "Tide reading {reading} at the north pier stood at {} centimetres.",
                100 + reading * 7
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A served vault whose code-mode writer compaction is live on the fake
/// model at `base_url`, a 1500-token window with one hot turn, and whose
/// self row reads the retained turns with the widest locality ceiling.
async fn retained_row_server(
    base_url: &str,
) -> (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<SyncServer>,
    AiHost,
) {
    let prompts = prompt_package_with_frame();
    let models = models_toml(&format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {:?}\n\
         [code_mode.compaction]\nwindow_tokens = 1500\nhot_steps = 1\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         context_tokens = 32768\n",
        prompts.path().display().to_string(),
    ));
    let (dir, vault) = rooted_vault();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (server, host) = AiHost::attach(server, Some(&models)).await;
    let mut table = server.vault().purpose_default_table().unwrap();
    table.self_compaction.source = oneiron::llm::SelfCompactionSource::RetainedTurns;
    table.self_compaction.locality = oneiron::ModelLocality::ThirdParty;
    server.vault().set_purpose_default_table(&table).unwrap();
    (dir, prompts, Arc::new(server), host)
}

async fn send(server: &Arc<SyncServer>, mut request: Request<Body>) -> (StatusCode, Vec<u8>) {
    // The owner's app on this device, as `ai_chat` sends it.
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
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn chat_turn(server: &Arc<SyncServer>, conversation: &str, turn: usize) {
    let body = json!({
        "conversation_ref": conversation,
        "text": format!("Log the north pier tide, turn {turn}."),
    });
    let (status, answer) = send(
        server,
        core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

/// Each request's message roles and the first line of its first message,
/// for a failure's report.
fn seen_report(fake: &FakeLlm) -> Vec<String> {
    fake.seen()
        .iter()
        .map(|seen| {
            let messages = seen.body["messages"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let roles: Vec<&str> = messages
                .iter()
                .map(|message| message["role"].as_str().unwrap_or("?"))
                .collect();
            let first = messages.first().map(message_text).unwrap_or_default();
            format!("{roles:?} {}", first.lines().next().unwrap_or_default())
        })
        .collect()
}

/// The rows stored as the conversation's children, unread by any lane:
/// each one's entity type and how many rows are part of it, so a report
/// tells a turn never listed from a turn whose page was not admitted.
fn stored_children(vault: &oneiron::Vault, conversation: &oneiron::EntityId) -> String {
    let edges = match vault.edges_in(conversation) {
        Ok(edges) => edges,
        Err(error) => return format!("children unread: {error:?}"),
    };
    let children: Vec<String> = edges
        .iter()
        .filter(|edge| edge.kind == oneiron::EdgeKind::ChildOf)
        .map(|edge| {
            let entity_type = vault.get_entity_type(&edge.target).ok().flatten();
            let parts = vault.edges_in(&edge.target).map(|parts| {
                parts
                    .iter()
                    .filter(|part| part.kind == oneiron::EdgeKind::PartOf)
                    .count()
            });
            format!("type={entity_type:?} parts={parts:?}")
        })
        .collect();
    format!(
        "{} inbound edges, children [{}]",
        edges.len(),
        children.join(", ")
    )
}

/// The chat log the turns' own reader, the owner, reads now, as a self
/// turn reads it before its user turn, the transcript under it, and the
/// rows stored under the conversation, for a failure's report.
fn log_report(server: &SyncServer, owner: oneiron::EntityId, conversation: &str) -> String {
    let Ok(id) = oneiron::EntityId::from_hex(conversation) else {
        return format!("conversation ref {conversation} names no id");
    };
    let stored = stored_children(server.vault(), &id);
    let reader = server.vault().memory(owner, oneiron::EdgeActorClass::Human);
    let history_lines = server.ai.chat_settings().history_turns;
    let log = match oneiron::compaction::read_chat_log(&reader, id, 1, history_lines) {
        Ok(log) => format!(
            "log lines={} pinned={} turns pinned={} last turn session={:?} uncompacted_tokens={}",
            log.lines.len(),
            log.pinned,
            log.sources.len(),
            log.session,
            log.uncompacted_tokens,
        ),
        Err(error) => format!("log refused: {error:?}"),
    };
    let transcript = match reader.conversation_transcript(&id, None, 50) {
        Ok(page) => page
            .value
            .turns
            .iter()
            .map(|turn| {
                let messages: Vec<String> = turn
                    .messages
                    .iter()
                    .map(|message| {
                        format!(
                            "{} {} chars incomplete={} generating={}",
                            message.role,
                            message.text.len(),
                            message.incomplete,
                            message.generating,
                        )
                    })
                    .collect();
                format!("[{}]", messages.join(", "))
            })
            .collect::<Vec<_>>()
            .join(" "),
        Err(error) => format!("transcript refused: {error:?}"),
    };
    format!("{log}; transcript: {transcript}; stored: {stored}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_turns_row_admits_the_self_chat_mode() {
    let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
    let (_dir, _prompts, server, _host) = retained_row_server(&fake.base_url).await;
    let (agent, _) = server
        .vault()
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("seeded default agent");
    assert!(
        server.ai.chat_self_mode(server.vault(), agent).is_some(),
        "a self agent's chat under a row on the retained turns compacts as the agent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_turns_row_chat_compacts_on_the_cheap_writer_as_the_agent() {
    let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
    let (_dir, _prompts, server, _host) = retained_row_server(&fake.base_url).await;
    let conversation = oneiron::EntityId::now().to_hex();

    // A chat window compacts one sitting's turns, and with the Dreamer off no
    // AppOpen ever mints that sitting: open the owner's sitting on this
    // machine first, under the key each turn's witness bumps, so every turn
    // below joins it.
    let owner = server
        .vault()
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let sitting = server
        .vault()
        .local_session_key(owner)
        .expect("local session key");
    assert!(
        matches!(
            server
                .vault()
                .mint_session(sitting, server.vault().now_recorded_at()),
            Ok(oneiron::session_lifecycle::SessionMintOutcome::Minted(_))
        ),
        "the owner's sitting opens for the turns to join"
    );

    // The cold-start threshold is 750 tokens for this 1500-token window.
    // A tiny first flight can be rejected; later flights include a long answer.
    let mut turn = 0;
    let mut compacted = false;
    while turn < 6 && !compacted {
        chat_turn(&server, &conversation, turn).await;
        turn += 1;
        compacted = eventually(Duration::from_secs(10), || {
            fake.seen()
                .iter()
                .any(|seen| is_compaction_call(&seen.body))
        })
        .await;
    }
    assert!(
        compacted,
        "no compaction call after {turn} turns; requests: {:?}; owner's read: {}; sitting open: {:?}",
        seen_report(&fake),
        log_report(&server, owner, &conversation),
        server
            .vault()
            .open_session(sitting)
            .map(|open| open.is_some()),
    );
    let call = fake
        .seen()
        .into_iter()
        .find(|seen| is_compaction_call(&seen.body))
        .unwrap();
    // The retained turns, not a live fork: the call is the compaction
    // prompt over the ledger's steps, worn by the agent's own frame.
    let system = message_text(&call.body["messages"][0]);
    assert!(
        system.contains(SELF_WRITER_FRAME),
        "the cheap writer writes as the agent: {system}"
    );

    // The summary landed: a later turn's request reads it as the agent's
    // own record of the turns it covers.
    let mut carried = false;
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        chat_turn(&server, &conversation, turn).await;
        turn += 1;
        carried = fake.seen().iter().any(|seen| {
            !is_compaction_call(&seen.body) && seen.body.to_string().contains(SUMMARY_PHRASE)
        });
        if carried {
            break;
        }
    }
    assert!(
        carried,
        "no later chat request read the landed summary; requests: {:?}",
        seen_report(&fake)
    );
}
