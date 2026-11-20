//! A compaction pass on a vault with no model manifest goes out as one
//! model (FIX-LIST SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED, and the
//! house half of [T0I-SERVED-COMPACTION-SUPPRESSED]).
//!
//! With no manifest and no model pack, the compaction role's route is its
//! seat, whose id (`seat/<role>@<rev>`) names the seat's whole ladder. A
//! pass is admitted as exactly one model, and an exact call never walks a
//! ladder: `generate_exact` refuses one as an invalid request before
//! anything is sent. So the house's own pass, and an agent's self-written
//! pass that gives way to the house route because the row's cheap model is
//! served nowhere here, must each send the seat's first served rung.
//!
//! Each case binds a rooted vault whose one provider is a local
//! OpenAI-compatible scripted model, code mode's compaction live under a
//! prompt package that holds the self-writer frame, and the shipped
//! self-compaction row (`auto`; its cheap model, deepseek's, served nowhere
//! here; bound at `third_party`). It sends one pass over a two-turn window
//! through `oneiron_server::test_doors::compaction_pass`, off the runtime
//! the pass blocks on.
//!
//! On unmodified main both passes are refused as an invalid request (the
//! seat id went out as an exact model), and the scripted model sees no
//! request.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test compaction_seat_exact_model`.

#![allow(clippy::unwrap_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::Path;
use std::sync::Arc;

use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::MachineRole;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::compaction_pass::{PassAnswer, house_pass, self_written_pass};
use serde_json::{Value, json};

/// The self-writer frame this test's prompt package carries: only a
/// self-written pass wears it.
const SELF_WRITER_FRAME: &str =
    "You write this summary as the agent itself, in the first person, about your own conversation.";

/// The scripted model's summary, which only its reply holds.
const SUMMARY: &str = "The owner logged one north pier tide reading of 104 centimetres.";

/// The window each pass compacts: two turns.
const WINDOW: [&str; 2] = [
    "Log the north pier tide: 104 centimetres.",
    "Logged the north pier tide at 104 centimetres.",
];

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

/// The scripted model's answer to any call: a summary of the span the
/// compaction input names.
fn reply(body: &Value) -> String {
    let input: Value = body["messages"]
        .as_array()
        .and_then(|messages| messages.last())
        .and_then(|message| serde_json::from_str(&message_text(message)).ok())
        .unwrap_or(Value::Null);
    json!({"from": input["from"], "through": input["through"], "summary": SUMMARY}).to_string()
}

/// One local provider and no `[roles]`: the chat role's seat is one rung,
/// and no manifest or model pack binds any role. Code mode's compaction is
/// live on that seat under `prompts`.
fn models(base_url: &str, prompts: &Path) -> ModelsConfig {
    ModelsConfig::from_toml(
        &format!(
            "default = \"local:test-model\"\n\
             [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
             [code_mode]\nprompt_package = {:?}\n\
             [code_mode.compaction]\nwindow_tokens = 1500\nhot_steps = 1\n\
             [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
             context_tokens = 32768\n",
            prompts.display().to_string(),
        ),
        None,
    )
    .unwrap()
}

/// A rooted vault served with its AI host attached under `models`, as
/// `oneiron serve` starts one: the keystore before the server, then the
/// host root and this install's live machine profile.
async fn served(dir: &Path, models: &ModelsConfig) -> (Arc<SyncServer>, AiHost) {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("compaction-seat-exact-model".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let issuer = vault.load_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let (server, host) = AiHost::attach(server, Some(models)).await;
    (Arc::new(server), host)
}

/// Every compaction call the scripted model saw: its system message is the
/// compaction prompt.
fn compaction_calls(fake: &FakeLlm) -> Vec<Value> {
    fake.seen()
        .into_iter()
        .map(|seen| seen.body)
        .filter(|body| message_text(&body["messages"][0]).contains("You compact"))
        .collect()
}

/// Every request the scripted model saw, as its model and first line, for
/// a failure's report.
fn seen_report(fake: &FakeLlm) -> Vec<String> {
    fake.seen()
        .iter()
        .map(|seen| {
            let first = seen.body["messages"][0].clone();
            format!(
                "{} {}",
                seen.body["model"],
                message_text(&first).lines().next().unwrap_or_default()
            )
        })
        .collect()
}

#[test]
fn a_house_pass_on_the_seat_sends_its_first_rung() {
    run_on_engine_stack("house-pass-seat", || async {
        let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let request =
            oneiron::test_doors::compaction_request::sealed_window(server.vault(), &WINDOW, 200)
                .unwrap();

        let pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &request))
                .await
                .unwrap()
        };
        let answer: PassAnswer = pass.unwrap_or_else(|refusal| {
            panic!(
                "the house pass was refused: {refusal}; requests: {:?}",
                seen_report(&fake)
            )
        });

        assert!(answer.summary.contains(SUMMARY), "{answer:?}");
        let calls = compaction_calls(&fake);
        assert_eq!(
            calls.len(),
            1,
            "one call went out: {:?}",
            seen_report(&fake)
        );
        let system = message_text(&calls[0]["messages"][0]);
        assert!(
            !system.contains(SELF_WRITER_FRAME),
            "the house writes as the house: {system}"
        );
    });
}

#[test]
fn a_self_written_pass_on_the_house_fallback_sends_its_first_rung_as_the_agent() {
    run_on_engine_stack("self-written-pass-seat", || async {
        let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let (agent, _) = server
            .vault()
            .get_seeded_agent_definition_by_logical_id("sys.default")
            .unwrap()
            .expect("sys.default is seeded on open");
        let row = server
            .vault()
            .purpose_default_table()
            .unwrap()
            .self_compaction()
            .clone();
        assert!(
            row.cheap_model.as_str().starts_with("deepseek/"),
            "the shipped row's cheap model is served nowhere here: {}",
            row.cheap_model
        );
        let request =
            oneiron::test_doors::compaction_request::sealed_window(server.vault(), &WINDOW, 200)
                .unwrap();

        let pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || self_written_pass(&server, agent, &request))
                .await
                .unwrap()
        };
        let answer = pass.unwrap_or_else(|refusal| {
            panic!(
                "the self-written pass was refused: {refusal}; requests: {:?}",
                seen_report(&fake)
            )
        });

        assert!(answer.summary.contains(SUMMARY), "{answer:?}");
        let admitted = answer.admitted_model.as_deref().unwrap_or_default();
        assert!(
            admitted.starts_with("local/test-model@"),
            "the receipt names the rung's own model, never the seat: {answer:?}"
        );
        assert_eq!(
            answer.filed_calls, 1,
            "the one call is filed as the agent's step: {answer:?}"
        );
        let calls = compaction_calls(&fake);
        assert_eq!(
            calls.len(),
            1,
            "one call went out: {:?}",
            seen_report(&fake)
        );
        let system = message_text(&calls[0]["messages"][0]);
        assert!(
            system.contains(SELF_WRITER_FRAME),
            "the house fallback writes as the agent: {system}"
        );
    });
}
