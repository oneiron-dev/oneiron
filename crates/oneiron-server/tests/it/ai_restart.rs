// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! The shipped binary runs the Dreamer from `[models]`; killed mid-pass and
//! started again, the interrupted pass runs again exactly once.
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use oneiron::dreamer_consolidation::{
    enqueue_partition_attempts, read_watermark, scan_dirty_turns,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::{DreamerConsolidationScope, EntityId, TimeRange, Vault, VaultConfig};

use crate::fake_llm::{FakeLlm, Reply};

const SECRET: &str = "ai-restart-test-host-secret-0001";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(dir: &Path, vault: &Path, port: u16, model_url: &str) -> std::path::PathBuf {
    let path = dir.join("oneiron.toml");
    std::fs::write(
        &path,
        format!(
            r#"vault_path = "{vault}"
host = "127.0.0.1"
port = {port}
dimensions = 8

[models]
default = "local:test-model"
extraction_egress = true

[models.providers.local]
kind = "local-openai-compat"
base_url = "{model_url}"
"#,
            vault = vault.display()
        ),
    )
    .unwrap();
    path
}

fn oneiron(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env("RUST_LOG", "warn");
    command
}

fn serve(config: &Path) -> Child {
    oneiron(config, &["serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn vault_config() -> VaultConfig {
    let mut config = VaultConfig::server();
    config.dimensions = 8;
    config
}

/// One captured user turn (the core turn door's shape: text in the TURN
/// body, a child of its conversation) and a queued consolidation round over
/// it, written while the server is stopped. Returns the TURN and the subject.
fn seed(vault_path: &Path) -> (EntityId, EntityId) {
    let vault = Vault::open_owned(vault_path, vault_config()).unwrap();
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let at = vault.now_recorded_at();
    let when = TimeRange { start: at, end: at };
    let encode = |body: serde_json::Value| rmp_serde::to_vec_named(&body).unwrap();
    vault
        .batch()
        .put(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            when,
            at,
            &encode(serde_json::json!({"title": "restart"})),
        )
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            when,
            at,
            &encode(serde_json::json!({"txt": "call me Oleksii", "spkr": "user", "at": at})),
        )
        .edge_checked(&turn, &conversation, 1.0)
        .commit()
        .unwrap();
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope).unwrap();
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 16).unwrap();
    assert!(!dirty.is_empty(), "the captured turn is dirty");
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "restart-run", 1).unwrap();
    (turn, subject)
}

fn extraction(subject: EntityId, turn: EntityId) -> String {
    serde_json::json!({"candidates": [{
        "subject": subject.to_hex(),
        "predicate": "profile.name",
        "value": "Oleksii",
        "confidence": 0.9,
        "evidence_refs": [{"source_id": turn.to_hex(), "byte_range": [0, 4]}],
    }]})
    .to_string()
}

async fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    done()
}

fn stop(mut child: Child) {
    // SIGTERM: the graceful path; a pass in flight finishes its boundary.
    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    panic!("server did not stop on SIGTERM");
}

#[tokio::test]
async fn a_dream_pass_killed_mid_call_runs_again_exactly_once_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let (turn, subject) = seed(&vault_path);
    let fake = FakeLlm::start(
        vec![
            Reply::Hold {
                text: extraction(subject, turn),
            },
            Reply::text(extraction(subject, turn)),
        ],
        None,
    )
    .await;
    let config = write_config(dir.path(), &vault_path, free_port(), &fake.base_url);

    // Without the owner's grant the Dreamer waits and spends nothing.
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

    let mut first = serve(&config);
    tokio::time::timeout(Duration::from_secs(60), fake.wait_holding())
        .await
        .expect("the first server's pass reached its model call");
    // Killed mid-call: no graceful path, the attempt's lease is left behind.
    first.kill().unwrap();
    first.wait().unwrap();

    let second = serve(&config);
    assert!(
        wait_for(Duration::from_secs(60), || fake.seen().len() >= 2).await,
        "the restarted server never re-ran the pass"
    );
    // Give the re-run time to land, then stop gracefully.
    tokio::time::sleep(Duration::from_secs(2)).await;
    stop(second);

    assert_eq!(
        fake.seen().len(),
        2,
        "one interrupted call, one re-run, no more"
    );
    let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
    let claims: Vec<_> = vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == "profile.name")
        .collect();
    assert_eq!(claims.len(), 1, "landed exactly once");
    assert_eq!(claims[0].approval, oneiron::ClaimApprovalStatus::Auto);
    let unfinished: Vec<_> = oneiron::attempt_queue::AttemptQueue::new(&vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|row| {
            matches!(
                row.state,
                oneiron::attempt_queue::AttemptState::Leased
                    | oneiron::attempt_queue::AttemptState::Queued
            )
        })
        .collect();
    assert!(unfinished.is_empty(), "{unfinished:?}");
}
