// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! The host words the Dreamer's extraction prompt and its consolidation
//! questions (ARCH-0026 #dreamer-seat-open, census L2-09; Engine ruling
//! L2-09-HOME = A, 13 Nov): `[models.dreamer.wording]` takes an
//! `extraction_prompt_file` and a `consolidation_wording_file`. The shipped
//! binary serves one Dreamer pass over one queued turn on a fake model, and
//! each pass logs which wording it asks in: `shipped`, or the host file's
//! digest.
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::Duration;

use oneiron::dreamer_consolidation::{
    enqueue_partition_attempts, read_watermark, scan_dirty_turns,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::{DreamerConsolidationScope, EntityId, TimeRange, Vault};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::ai_serve::{
    free_port, models_section, oneiron, stop, vault_config, wait_for, write_config,
};
use crate::fake_llm::{FakeLlm, Reply, Seen};

/// The shipped extraction prompt's first words.
const SHIPPED_START: &str = "Extract durable memory claims";
const HOST_SYSTEM: &str =
    "Host extraction wording: list each durable claim the speaker states about a person.";
const HOST_EXAMPLE_USER: &str = "[T1] user: I keep my bike in the hall.";
/// A reply that proposes no claim and no person.
const NOTHING: &str = r#"{"candidates":[],"persons":[]}"#;
const SAID: &str = "I'm Owen and I live in Lisbon.";

/// One user turn in a new conversation, queued for the Dreamer while the
/// server is stopped.
fn witness(vault_path: &Path) {
    let vault = Vault::open_owned(vault_path, vault_config()).unwrap();
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let at = vault.now_recorded_at();
    let when = TimeRange { start: at, end: at };
    let encode = |body: Value| rmp_serde::to_vec_named(&body).unwrap();
    vault
        .batch()
        .put(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            when,
            at,
            &encode(json!({"title": "wording"})),
        )
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            when,
            at,
            &encode(json!({"txt": SAID, "spkr": "user", "at": at})),
        )
        .edge_checked(&turn, &conversation, 1.0)
        .commit()
        .unwrap();
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope).unwrap();
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 16).unwrap();
    assert!(!dirty.is_empty(), "the new turn is dirty");
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "wording-1", 1).unwrap();
}

/// `oneiron serve` on `config`, its output and the Dreamer's info lines in
/// `log`.
fn serve_logged(config: &Path, log: &Path) -> Child {
    let log = std::fs::File::create(log).unwrap();
    oneiron(config, &["serve"])
        .env("RUST_LOG", "warn,oneiron::dreamer=info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap()
}

/// Stops the server off this test's runtime thread, where the fake model
/// answers: a call made after the signal is still answered.
async fn stop_serving(child: Child) {
    tokio::task::spawn_blocking(move || stop(child))
        .await
        .unwrap();
}

/// The config file for a vault at `vault_path` on `fake`, `wording` after
/// its `[models]` section.
fn config_with(dir: &Path, vault_path: &Path, fake: &FakeLlm, wording: &str) -> std::path::PathBuf {
    write_config(
        dir,
        vault_path,
        free_port(),
        &format!("{}{wording}", models_section(&fake.base_url)),
    )
}

/// One served pass over one queued turn, with `files` written beside the
/// config and `wording` after its `[models]` section. Every call is answered
/// with no claim. Returns the calls the model heard and the server's log.
async fn served_pass(wording: &str, files: &[(&str, &str)]) -> (Vec<Seen>, String) {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    for (name, text) in files {
        std::fs::write(dir.path().join(name), text).unwrap();
    }
    witness(&vault_path);
    let fake = FakeLlm::start(Vec::new(), Some(Reply::text(NOTHING))).await;
    let config = config_with(dir.path(), &vault_path, &fake, wording);
    let granted = oneiron(
        &config,
        &["dreamer", "grant", "--extraction-route", "own_server"],
    )
    .output()
    .unwrap();
    assert!(
        granted.status.success(),
        "grant: {}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let log = dir.path().join("serve.log");
    let child = serve_logged(&config, &log);
    let called = wait_for(Duration::from_secs(90), || !fake.seen().is_empty()).await;
    if called {
        // The pass is done once the model hears nothing more for a spell.
        let mut heard = fake.seen().len();
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let now = fake.seen().len();
            if now == heard {
                break;
            }
            heard = now;
        }
    }
    stop_serving(child).await;
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(called, "the server made no model call; its log:\n{log}");
    (fake.seen(), log)
}

/// Each message of `call` as (role, text).
fn messages(call: &Seen) -> Vec<(&str, &str)> {
    call.body["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .map(|message| {
                    (
                        message["role"].as_str().unwrap_or_default(),
                        message["content"].as_str().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `file:sha256:<16 hex>` a pass logs for a host file holding `text`.
fn file_source(text: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    format!("file:sha256:{}", &digest[..16])
}

/// The pass's wording line in `log`.
fn wording_line(log: &str) -> &str {
    log.lines()
        .find(|line| line.contains("dreamer pass wording"))
        .unwrap_or_else(|| panic!("no pass logged its wording:\n{log}"))
}

/// The host's extraction prompt is the Dreamer's: its system text and its
/// worked example go out first on every extraction call, the shipped prompt
/// on none, and the pass logs the file's digest.
#[tokio::test]
async fn a_host_extraction_prompt_file_words_every_extraction_call() {
    let prompt = json!({
        "system": HOST_SYSTEM,
        "examples": [{"user": HOST_EXAMPLE_USER, "assistant": NOTHING}],
    })
    .to_string();
    let (seen, log) = served_pass(
        "\n[models.dreamer.wording]\nextraction_prompt_file = \"extraction.json\"\n",
        &[("extraction.json", &prompt)],
    )
    .await;

    let firsts: Vec<_> = seen
        .iter()
        .map(|call| messages(call).first().copied())
        .collect();
    let extraction: Vec<_> = seen
        .iter()
        .map(messages)
        .filter(|messages| messages.first() == Some(&("system", HOST_SYSTEM)))
        .collect();
    assert!(
        !extraction.is_empty(),
        "no call asked in the host's prompt; first messages: {firsts:?}"
    );
    for messages in &extraction {
        assert_eq!(
            messages.get(1..3),
            Some(&[("user", HOST_EXAMPLE_USER), ("assistant", NOTHING)][..]),
            "the host's worked example follows its system text: {messages:?}"
        );
        assert!(
            messages
                .last()
                .is_some_and(|(role, text)| *role == "user" && text.contains(SAID)),
            "the turn is the last message: {messages:?}"
        );
    }
    assert!(
        !seen.iter().any(|call| messages(call)
            .iter()
            .any(|(_, text)| text.starts_with(SHIPPED_START))),
        "no call asks in the shipped prompt; first messages: {firsts:?}"
    );
    let line = wording_line(&log);
    assert!(
        line.contains(&file_source(&prompt)) && line.contains("shipped"),
        "the pass names the host prompt's digest and the shipped questions: {line}"
    );
}

/// With no host file, the pass asks in the shipped prompt (unchanged).
#[tokio::test]
async fn without_a_host_file_the_dreamer_asks_in_the_shipped_prompt() {
    let (seen, _) = served_pass("", &[]).await;
    let firsts: Vec<_> = seen
        .iter()
        .map(|call| messages(call).first().copied())
        .collect();
    assert!(
        firsts.iter().any(|first| first
            .is_some_and(|(role, text)| role == "system" && text.starts_with(SHIPPED_START))),
        "an extraction call asks in the shipped prompt: {firsts:?}"
    );
    assert!(
        !firsts
            .iter()
            .any(|first| first.is_some_and(|(_, text)| text == HOST_SYSTEM)),
        "{firsts:?}"
    );
}

/// The host's consolidation wording is in force on the pass: the pass logs
/// its file's digest, and the extraction prompt it left unset stays shipped.
#[tokio::test]
async fn a_host_consolidation_wording_file_is_in_force_on_the_pass() {
    let questions = json!({
        "resolution": "Several values were extracted for one claim; how do they resolve?",
        "correction": "Does this new candidate correct one of the listed claims?",
    })
    .to_string();
    let (seen, log) = served_pass(
        "\n[models.dreamer.wording]\nconsolidation_wording_file = \"questions.json\"\n",
        &[("questions.json", &questions)],
    )
    .await;
    let line = wording_line(&log);
    assert!(
        line.contains(&file_source(&questions)) && line.contains("shipped"),
        "the pass names the host questions' digest and the shipped prompt: {line}"
    );
    assert!(
        seen.iter().any(|call| messages(call)
            .first()
            .is_some_and(|(_, text)| text.starts_with(SHIPPED_START))),
        "the extraction prompt stays shipped"
    );
}

/// `oneiron serve` on `config` refuses to start: it exits, failing, within
/// a minute. Returns what it wrote.
async fn refused(config: &Path, log: &Path) -> String {
    let mut child = serve_logged(config, log);
    let exited = wait_for(Duration::from_secs(60), || {
        child.try_wait().unwrap().is_some()
    })
    .await;
    let output = std::fs::read_to_string(log).unwrap_or_default();
    if !exited {
        stop_serving(child).await;
        panic!("the server started on a refused config:\n{output}");
    }
    assert!(
        !child.wait().unwrap().success(),
        "the refused config exits failing:\n{output}"
    );
    output
}

/// A missing file fails the load with its path, and a wording file naming
/// a question the engine does not ask fails it with that key.
#[tokio::test]
async fn a_missing_file_or_an_unknown_question_refuses_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let fake = FakeLlm::start(Vec::new(), Some(Reply::text(NOTHING))).await;

    let config = config_with(
        dir.path(),
        &vault_path,
        &fake,
        "\n[models.dreamer.wording]\nextraction_prompt_file = \"absent.json\"\n",
    );
    let output = refused(&config, &dir.path().join("absent.log")).await;
    let absent = dir.path().join("absent.json");
    assert!(
        output.contains("extraction_prompt_file") && output.contains(&absent.display().to_string()),
        "the refusal names the key and the missing file's path: {output}"
    );

    std::fs::write(
        dir.path().join("questions.json"),
        json!({"verdict": "Which value wins?"}).to_string(),
    )
    .unwrap();
    let config = config_with(
        dir.path(),
        &vault_path,
        &fake,
        "\n[models.dreamer.wording]\nconsolidation_wording_file = \"questions.json\"\n",
    );
    let output = refused(&config, &dir.path().join("unknown.log")).await;
    assert!(
        output.contains("consolidation_wording_file") && output.contains("unknown field `verdict`"),
        "the refusal names the key and the question it does not know: {output}"
    );
    assert!(fake.seen().is_empty(), "a refused config calls no model");
}
