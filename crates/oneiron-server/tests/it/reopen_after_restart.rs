//! Text saved through `oneiron serve` survives a restart (prune e2e row 4):
//! witness one invented line, stop the server with SIGTERM, start it again
//! on the same vault, and recall and text search must still return that line
//! under the reference it had before the stop.
use std::fs::File;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::memory::{Effort, RecallScope, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron_remote::{OneironClient, unix_seconds_now};
use serde_json::Value;

const SECRET: &str = "restart-check-issuer-key-not-a-bearer";
const TEXT: &str = "The spare key to the Quillamere boathouse hangs behind the tide clock.";

/// A running `oneiron serve`. Dropping it kills the process, so a failed
/// assertion never leaves a server holding the vault.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL");
    command
}

fn stdout(mut command: Command) -> String {
    let output = command.output().expect("run oneiron");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

/// Starts `oneiron serve` and waits until the facade router answers: an
/// unauthenticated call must reach the auth extractor and be refused.
fn serve(config: &Path, port: u16, log: &Path) -> Server {
    let port = port.to_string();
    let mut command = oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], config);
    command
        .stdout(Stdio::null())
        .stderr(File::create(log).expect("server log file"));
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));
    let probe = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{port}/v1/core/facade/receipts");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({status}): {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        let answered = probe
            .post(&url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .map(|response| response.status().as_u16());
        if matches!(answered, Ok(401 | 403)) {
            return server;
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became ready: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn sigterm(mut server: Server) {
    let pid = libc::pid_t::try_from(server.0.id()).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory; `pid` is a
    // child this test spawned and has not yet reaped.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM could not be sent");
    let deadline = Instant::now() + Duration::from_secs(30);
    while server.0.try_wait().expect("poll oneiron serve").is_none() {
        assert!(Instant::now() < deadline, "oneiron serve ignored SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The reference recall returns for [`TEXT`]: the turn that says it.
fn recalled_ref(client: &OneironClient) -> String {
    let pack = client
        .recall(
            "Quillamere boathouse",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let refs: Vec<&str> = pack
        .items
        .iter()
        .filter(|item| item.value_text.contains(TEXT))
        .map(|item| item.short_id.as_str())
        .collect();
    assert_eq!(refs.len(), 1, "recall items: {:#?}", pack.items);
    refs[0].to_owned()
}

/// The entity id `GET /api/search/text` returns for [`TEXT`], signed with
/// the paired credential's connection key as every slip request must be.
fn searched_id(port: u16, credential: &str) -> String {
    let (slip, seed) = credential
        .strip_prefix("v2.cred.")
        .and_then(|rest| rest.rsplit_once('.'))
        .expect("a paired v2 credential");
    let bearer = format!("v2.slip.{slip}");
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).expect("hex seed"))
        .collect();
    let key = SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"));
    let slip = CapabilitySlip::from_token(&bearer).expect("v2 slip");
    let proof = holder_proof(&slip, &key, unix_seconds_now()).expect("holder proof");
    let response = reqwest::blocking::Client::new()
        .get(format!(
            "http://127.0.0.1:{port}/api/search/text?query=Quillamere&view=full"
        ))
        .bearer_auth(&bearer)
        .header("x-oneiron-binding", proof.to_string())
        .send()
        .expect("text search");
    assert!(response.status().is_success(), "{}", response.status());
    let body: Value = response.json().expect("text search JSON");
    let ids: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|item| item.to_string().contains(TEXT))
        .map(|item| item["id"].as_str().expect("hit id"))
        .collect();
    assert_eq!(ids.len(), 1, "text search body: {body:#}");
    ids[0].to_owned()
}

#[test]
fn witnessed_text_is_found_under_the_same_reference_after_sigterm_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    let link = stdout(oneiron(&["token", "bootstrap", "--url", &origin], &config));

    let first = serve(&config, port, &dir.path().join("serve-1.log"));
    let (url, credential) = OneironClient::pair(link.trim()).unwrap();
    let client = OneironClient::connect(&url, &credential).unwrap();
    client
        .witness(&WitnessTurn {
            conversation_ref: "44444444444444444444444444444444".into(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: TEXT.into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: unix_seconds_now(),
        })
        .unwrap();
    let recalled = recalled_ref(&client);
    let searched = searched_id(port, &credential);
    sigterm(first);

    let _second = serve(&config, port, &dir.path().join("serve-2.log"));
    assert_eq!(recalled_ref(&client), recalled);
    assert_eq!(searched_id(port, &credential), searched);
}
