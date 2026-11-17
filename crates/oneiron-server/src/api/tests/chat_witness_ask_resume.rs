//! A chat turn whose user witness an owner's `vault.witness` pre-hook held on
//! its ask resumes once the owner answers proceed (FIX
//! CHAT-WITNESS-ASK-RESUME-ARGS-DRIFT): the retry under the same invocation
//! rebuilds the witness from the stamps the first try saved, its time and its
//! TURN id, so the resumed chain checks the call the ask held. The user's
//! words land in one TURN, and every recall the turn's board ran names that
//! TURN. Capture is on here; it is off by default.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Request, StatusCode};
use oneiron::runtime_hooks::{HookBodyRun, HookBodyRuntime, HookRunContext};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, models};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

const PACK: &str = "example.witnessask";
const HOOK: &str = "ask-before-witness";

/// A hook sandbox whose first run asks and every later run does nothing:
/// the user's witness asks once, and anything else the turn hooks runs on.
#[derive(Default)]
struct AskOnceRuntime {
    runs: AtomicUsize,
}

impl HookBodyRuntime for AskOnceRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        let outcome = if self.runs.fetch_add(1, Ordering::SeqCst) == 0 {
            json!({"kind": "ask", "question": "May this turn be witnessed?"})
        } else {
            json!({"kind": "nothing"})
        };
        Ok(HookBodyRun {
            outcome_json: outcome.to_string(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// A rooted vault that captures retrieval runs and runs its verb hooks on
/// [`AskOnceRuntime`], served with a chat seat on `base_url`.
async fn asking_server(base_url: &str) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, TEST_SECRET.as_bytes());
    vault
        .install_hook_runtime(Arc::new(AskOnceRuntime::default()))
        .expect("the vault runs its verb hooks on the test sandbox");
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

/// The owner puts a pack whose one pre-hook asks before every
/// `vault.witness`; answers the owner and the hook's binding claim.
fn bind_witness_ask(vault: &Vault) -> (EntityId, EntityId) {
    vault
        .prepare_install_signing()
        .expect("install signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let files = vec![
        HubFile::new(
            "PACK.md",
            format!(
                "---\nname: {PACK}\ndescription: Chat witness ask fixture.\nversion: 1.0.0\nkind: capability\nhooks: [\"{HOOK}\"]\n---\nA pack whose one pre-hook asks before a witness.\n"
            ),
        ),
        HubFile::new(
            format!("hooks/{HOOK}/HOOK.md"),
            format!(
                "---\nname: {HOOK}\nversion: 1.0.0\nverbs: [\"vault.witness\"]\nphase: pre\noutcomes: [\"ask\"]\n---\n{HOOK} asks before a turn is witnessed.\n"
            ),
        ),
        HubFile::new(
            format!("hooks/{HOOK}/body.js"),
            "return { kind: \"ask\", question: \"May this turn be witnessed?\" };\n",
        ),
    ];
    match vault
        .put_pack(&proof, files)
        .expect("the owner puts the pack")
    {
        PackInstallDisposition::Installed(receipt) => assert_eq!(receipt.pack_name, PACK),
        other => panic!("the owner's put installs the pack: {other:?}"),
    }
    let (binding, row) = vault
        .pack_hook_bindings()
        .expect("list bindings")
        .into_iter()
        .find(|(_, row)| row.pack == PACK && row.hook == HOOK)
        .expect("the owner's hook binds");
    assert!(row.enabled, "the new binding runs");
    (owner, binding)
}

/// One owner chat turn in `conversation` under `invocation`, from this
/// device: its status and body bytes.
async fn chat_turn(
    server: &Arc<SyncServer>,
    conversation: &str,
    text: &str,
    invocation: &str,
) -> (StatusCode, Vec<u8>) {
    let body = json!({"conversation_ref": conversation, "text": text, "stream": true});
    let mut request: Request<Body> =
        core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body));
    request.headers_mut().insert(
        "x-oneiron-invocation",
        HeaderValue::from_str(invocation).unwrap(),
    );
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
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

/// The TURNs of `conversation` that hold a MESSAGE with `text`.
fn turns_holding(vault: &Vault, conversation: &EntityId, text: &str) -> Vec<EntityId> {
    vault
        .sources(conversation, EdgeKind::ChildOf, None)
        .unwrap()
        .into_iter()
        .filter(|turn| {
            vault
                .sources(turn, EdgeKind::ChildOf, None)
                .unwrap()
                .iter()
                .any(|message| {
                    vault
                        .get(message)
                        .unwrap()
                        .is_some_and(|raw| String::from_utf8_lossy(&raw).contains(text))
                })
        })
        .collect()
}

#[tokio::test]
async fn a_chat_turn_whose_witness_a_hook_held_resumes_on_the_turn_the_ask_saved() {
    let fake = FakeLlm::start(
        Vec::new(),
        Some(Reply::Text {
            text: "noted".into(),
            model: "fake".into(),
        }),
    )
    .await;
    let (_dir, server, host) = asking_server(&fake.base_url).await;
    let vault = server.vault();
    let (owner, binding) = bind_witness_ask(vault);
    let conversation = EntityId::now();
    let invocation = EntityId::now().to_hex();
    let text = "my sister lives in Lisbon";

    let (status, body) = chat_turn(&server, &conversation.to_hex(), text, &invocation).await;
    let held: Value = serde_json::from_slice(&body).expect("a JSON stop");
    assert_eq!(status, StatusCode::ACCEPTED, "the hook asks first: {held}");
    assert_eq!(held["error"]["code"], json!("verb_hook_pending"), "{held}");
    let ask = EntityId::from_hex(held["error"]["hook"]["ask"].as_str().expect("ask handle"))
        .expect("a 32-hex ask handle");
    assert!(
        turns_holding(vault, &conversation, text).is_empty(),
        "nothing is witnessed while the ask is open"
    );

    let mut word = TaskAskWord::new(binding);
    word.option = Some(TaskAskOptionId::new("proceed").unwrap());
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&TaskAskHandle { group_ref: ask }, &word)
        .expect("the owner answers proceed");

    // The same turn again, under the same invocation, a moment later: its
    // host stamps differ from the first try's unless it takes them back.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, body) = chat_turn(&server, &conversation.to_hex(), text, &invocation).await;
    let shown = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(status, StatusCode::OK, "the held witness resumes: {shown}");
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

    let witnessed = turns_holding(vault, &conversation, text);
    assert_eq!(
        witnessed.len(),
        1,
        "the user's words land in one TURN: {witnessed:?}"
    );
    let mut runs = vault.retrieval_runs(64).unwrap();
    runs.sort_by_key(|run| run.started_at);
    let named: Vec<EntityId> = runs
        .iter()
        .filter_map(|run| run.turn)
        .map(|turn| EntityId::from_bytes(turn.turn_id).unwrap())
        .collect();
    assert!(
        !named.is_empty(),
        "capture is on, so each board's recall writes a run"
    );
    assert!(
        named.iter().all(|turn| *turn == witnessed[0]),
        "every recall names the TURN the resumed witness wrote: {named:?} vs {:?}",
        witnessed[0]
    );
    host.shutdown().await;
}
