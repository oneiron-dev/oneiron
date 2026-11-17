#![cfg(all(unix, oneiron_test_support))]
//! An owner device's signed Cancel at `POST /v1/owner/recovery-box/cancel`.
//! A fresh proof by the owner's own live key reaches the box through the
//! supervisor relay and answers what the box said; without a box it answers
//! false. A proof with a flipped signature, a stale time, or another's name
//! is refused before anything reaches the box. A box failure answers
//! unreachable. Malformed bodies are refused, as is a caller without the
//! owner's credential. Each case drives the real route in process.
//!
//! Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support,oneiron/test-hooks,
//! oneiron-broker/test-support,tokio/test-util --test recovery_box_cancel_route`.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, CapabilitySlip, CheckpointRootSigner, HostSlipIssuer,
    MachineRole, OwnerKeyEnrollment, RecoveryBoxCancelProof,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::recovery_box_hold::{hold_client, install_recovery_box_hold};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);
const ANSWER: Duration = Duration::from_secs(15);
const CANCEL_PATH: &str = "/v1/owner/recovery-box/cancel";

/// Seed of the owner device key this handle holds to sign Cancels with.
const PROVING_KEY_SEED: u8 = 61;

fn run_on_engine_stack(
    name: &str,
    case: impl std::future::Future<Output = TestResult> + Send + 'static,
) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(case)
        })
        .expect("spawn the engine-sized test thread");
    match run.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("{error}"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn token() -> String {
    "c3".repeat(32)
}

fn error_code(answer: &Value) -> Option<&str> {
    answer["error"]["code"].as_str()
}

fn error_state(answer: &Value) -> Option<&str> {
    answer["error"]["details"]["state"].as_str()
}

/// An owner device key held on the vault handle.
struct KeySigner(SigningKey);

impl CheckpointRootSigner for KeySigner {
    fn root(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.0.verifying_key().to_bytes())
    }

    fn sign_checkpoint_statement(&self, statement: &[u8]) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(statement).to_bytes().to_vec())
    }

    fn sign_owner_proof(&self, transcript: &[u8]) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }
}

fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// What the stub answers one connection with.
enum Script {
    /// `held` with `cancelled` as told.
    Cancelled(bool),
    /// The refusal line a supervisor answers a stale choice with.
    Refused,
}

fn stub(
    script: Vec<Script>,
) -> (
    tempfile::TempDir,
    PathBuf,
    mpsc::Receiver<String>,
    JoinHandle<()>,
) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    let (lines, incoming) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut served = Vec::new();
        for entry in script {
            let (stream, _) = listener.accept().expect("accept the vault");
            let lines = lines.clone();
            served.push(std::thread::spawn(move || {
                serve_connection(stream, entry, &lines)
            }));
        }
        for connection in served {
            connection.join().expect("serve one connection");
        }
    });
    (dir, socket, incoming, handle)
}

fn serve_connection(mut stream: UnixStream, entry: Script, lines: &mpsc::Sender<String>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read the request");
    drop(reader);
    lines.send(line).expect("the test reads each line");
    let answer: &[u8] = match entry {
        Script::Cancelled(true) => br#"{"held":true,"cancelled":true}"#,
        Script::Cancelled(false) => br#"{"held":true,"cancelled":false}"#,
        Script::Refused => br#"{"held":false,"error":"stale_generation"}"#,
    };
    stream.write_all(answer).ok();
    stream.write_all(b"\n").ok();
}

fn silent_supervisor() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    listener.set_nonblocking(true).expect("nonblocking");
    (dir, socket, listener)
}

fn assert_no_call(listener: &UnixListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("no call reaches the supervisor, got {other:?}"),
    }
}

fn serve(vault: &Arc<Vault>) -> Result<(Arc<SyncServer>, Router), TestError> {
    let server = Arc::new(SyncServer::new(
        Arc::clone(vault),
        SyncServerConfig {
            auth_secret: Some("recovery-box-cancel-route".into()),
            ..Default::default()
        },
    )?);
    let app = build_app(Arc::clone(&server));
    Ok((server, app))
}

/// A served vault whose owner holds an enrolled device key on this handle.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    signing_key: SigningKey,
    public_key: [u8; 32],
    vault_id: [u8; 32],
}

impl Host {
    fn new() -> Result<Self, TestError> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let (server, app) = serve(&vault)?;
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        let owner_token = owner_slip.to_token()?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let person = vault.ensure_embedded_owner_actor()?;
        bind_host_owner(&vault, &issuer, person)?;
        vault.ensure_vault_key()?;
        let machine = vault.prepare_install_signing()?;
        let vault_id = vault.authority_fold()?.vault_id.expect("a rooted vault");
        let authority = ActAuthority::Owner(owner_proof(&vault, person), ActSurface::ThisInstall);
        let issued = vault.issue_world_kit(
            &owner_proof(&vault, person),
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::TrustedPerson,
                    PieceHome::SecurityKey,
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
        )?;
        let refs: Vec<_> = issued.pieces.iter().take(2).collect();
        vault.confirm_world_kit(&owner_proof(&vault, person), &refs, None, &BTreeSet::new())?;
        let signing_key = SigningKey::from_bytes(&[PROVING_KEY_SEED; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let challenge =
            vault.owner_key_enrollment_challenge_as(&authority, machine, &public_key)?;
        vault.enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: signing_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )?;
        let device_signer = SigningKey::from_bytes(&[PROVING_KEY_SEED; 32]);
        vault.hold_checkpoint_root_signer(Arc::new(KeySigner(device_signer)));
        Ok(Self {
            _dir: dir,
            vault,
            server,
            app,
            issuer,
            owner_slip,
            owner_token,
            person,
            signing_key,
            public_key,
            vault_id,
        })
    }

    fn binding(&self) -> Result<String, TestError> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let body = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        });
        Ok(body.to_string())
    }

    async fn send(
        &self,
        request: axum::http::request::Builder,
        body: Body,
        as_owner: bool,
    ) -> Result<(StatusCode, Value), TestError> {
        let token = &self.owner_token;
        let request = if as_owner {
            request
                .header("authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", self.binding()?)
        } else {
            request
        };
        let response = self.app.clone().oneshot(request.body(body)?).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, answer))
    }

    async fn cancel(&self, body: Value, as_owner: bool) -> Result<(StatusCode, Value), TestError> {
        self.send(
            Request::post(CANCEL_PATH).header("content-type", "application/json"),
            Body::from(body.to_string()),
            as_owner,
        )
        .await
    }

    fn signed_proof(
        &self,
        person: EntityId,
        issued_at: u64,
        receipt: Option<u64>,
    ) -> RecoveryBoxCancelProof {
        let mut proof = RecoveryBoxCancelProof {
            person,
            key: self.public_key,
            issued_at,
            release_receipt: receipt,
            signature: Vec::new(),
        };
        let transcript = proof.transcript(&self.vault_id);
        proof.signature = self.signing_key.sign(&transcript).to_bytes().to_vec();
        proof
    }

    fn proof_body(&self, proof: &RecoveryBoxCancelProof) -> Value {
        json!({
            "person": proof.person.to_hex(),
            "key": hex(&proof.key),
            "issued_at": proof.issued_at,
            "release_receipt": proof.release_receipt,
            "signature": hex(&proof.signature),
        })
    }

    fn fresh_body(&self) -> Value {
        let now = self.vault.now_recorded_at();
        let proof = self.signed_proof(self.person, now, Some(7));
        self.proof_body(&proof)
    }
}

#[test]
fn a_fresh_owner_proof_cancels_the_pending_release_at_the_box() {
    run_on_engine_stack("cancel-true", async {
        let host = Host::new()?;
        let (_dir, socket, lines, supervisor) = stub(vec![Script::Cancelled(true)]);
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let (status, answer) = host.cancel(host.fresh_body(), true).await?;
        assert_eq!(status, StatusCode::OK, "a fresh proof cancels: {answer}");
        assert_eq!(
            answer["cancelled"].as_bool(),
            Some(true),
            "the box voided it: {answer}"
        );
        let line = lines.recv_timeout(ANSWER).expect("the cancel's line");
        let request: Value = serde_json::from_str(&line).expect("the line is JSON");
        assert_eq!(
            request["op"].as_str(),
            Some("recovery_box_cancel"),
            "the op: {line}"
        );
        let person = host.person.to_hex();
        assert_eq!(
            request["cancelled_by"]["person"].as_str(),
            Some(person.as_str()),
            "who cancelled: {line}"
        );
        let key = hex(&host.public_key);
        assert_eq!(
            request["cancelled_by"]["device_key"].as_str(),
            Some(key.as_str()),
            "whose key: {line}"
        );
        assert_eq!(
            request["release_receipt"].as_u64(),
            Some(7),
            "which release: {line}"
        );
        assert!(
            lines.recv_timeout(Duration::from_millis(200)).is_err(),
            "exactly one line"
        );
        supervisor.join().expect("supervisor");
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_proof_with_no_release_receipt_cancels_whichever_release_is_pending() {
    run_on_engine_stack("cancel-any-release", async {
        let host = Host::new()?;
        let (_dir, socket, lines, supervisor) = stub(vec![Script::Cancelled(true)]);
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let now = host.vault.now_recorded_at();
        let proof = host.signed_proof(host.person, now, None);
        let mut body = host.proof_body(&proof);
        body.as_object_mut()
            .expect("the body is an object")
            .remove("release_receipt");
        let (status, answer) = host.cancel(body, true).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a proof naming no release cancels: {answer}"
        );
        assert_eq!(
            answer["cancelled"].as_bool(),
            Some(true),
            "the box voided the pending release: {answer}"
        );
        let line = lines.recv_timeout(ANSWER).expect("the cancel's line");
        let request: Value = serde_json::from_str(&line).expect("the line is JSON");
        assert_eq!(
            request["op"].as_str(),
            Some("recovery_box_cancel"),
            "the op: {line}"
        );
        assert!(
            request.get("release_receipt").is_none(),
            "the line names no release: {line}"
        );
        supervisor.join().expect("supervisor");
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_cancel_when_nothing_is_pending_answers_not_cancelled() {
    run_on_engine_stack("cancel-false", async {
        let host = Host::new()?;
        let (_dir, socket, lines, supervisor) = stub(vec![Script::Cancelled(false)]);
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let (status, answer) = host.cancel(host.fresh_body(), true).await?;
        assert_eq!(status, StatusCode::OK, "no release pending: {answer}");
        assert_eq!(
            answer["cancelled"].as_bool(),
            Some(false),
            "none voided: {answer}"
        );
        let line = lines.recv_timeout(ANSWER).expect("the cancel's line");
        let request: Value = serde_json::from_str(&line).expect("the line is JSON");
        assert_eq!(
            request["op"].as_str(),
            Some("recovery_box_cancel"),
            "the op: {line}"
        );
        supervisor.join().expect("supervisor");
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_vault_with_no_box_answers_not_cancelled() {
    run_on_engine_stack("cancel-no-box", async {
        let host = Host::new()?;
        let (status, answer) = host.cancel(host.fresh_body(), true).await?;
        assert_eq!(status, StatusCode::OK, "no box, nothing pending: {answer}");
        assert_eq!(
            answer["cancelled"].as_bool(),
            Some(false),
            "self-hosted answers false: {answer}"
        );
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_proof_with_a_flipped_signature_byte_never_reaches_the_box() {
    run_on_engine_stack("cancel-bad-sig", async {
        let host = Host::new()?;
        let (_dir, socket, listener) = silent_supervisor();
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let now = host.vault.now_recorded_at();
        let mut proof = host.signed_proof(host.person, now, Some(7));
        proof.signature[0] ^= 1;
        let (status, answer) = host.cancel(host.proof_body(&proof), true).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a forged proof is refused: {answer}"
        );
        assert_eq!(
            error_code(&answer),
            Some("INVALID_STATE"),
            "the code: {answer}"
        );
        assert_eq!(error_state(&answer), Some("refused"), "the state: {answer}");
        assert_no_call(&listener);
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_stale_proof_never_reaches_the_box() {
    run_on_engine_stack("cancel-stale", async {
        let host = Host::new()?;
        let (_dir, socket, listener) = silent_supervisor();
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let now = host.vault.now_recorded_at();
        let stale = now - 600;
        let proof = host.signed_proof(host.person, stale, Some(7));
        let (status, answer) = host.cancel(host.proof_body(&proof), true).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a stale proof is refused: {answer}"
        );
        assert_eq!(error_state(&answer), Some("refused"), "the state: {answer}");
        assert_no_call(&listener);
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_proof_naming_another_person_never_reaches_the_box() {
    run_on_engine_stack("cancel-other", async {
        let host = Host::new()?;
        let (_dir, socket, listener) = silent_supervisor();
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let now = host.vault.now_recorded_at();
        let other = EntityId::now();
        assert_ne!(other, host.person, "the test names another");
        let proof = host.signed_proof(other, now, Some(7));
        let (status, answer) = host.cancel(host.proof_body(&proof), true).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "another name is refused: {answer}"
        );
        assert_eq!(error_state(&answer), Some("refused"), "the state: {answer}");
        assert_no_call(&listener);
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_box_failure_answers_unreachable() {
    run_on_engine_stack("cancel-unreachable", async {
        let host = Host::new()?;
        let (_dir, socket, lines, supervisor) = stub(vec![Script::Refused]);
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let (status, answer) = host.cancel(host.fresh_body(), true).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a failed box call is 409: {answer}"
        );
        assert_eq!(
            error_state(&answer),
            Some("recovery_box_unreachable"),
            "the state: {answer}"
        );
        let line = lines
            .recv_timeout(ANSWER)
            .expect("the cancel reached the box");
        let request: Value = serde_json::from_str(&line).expect("the line is JSON");
        assert_eq!(
            request["op"].as_str(),
            Some("recovery_box_cancel"),
            "the op: {line}"
        );
        supervisor.join().expect("supervisor");
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_malformed_body_never_reaches_the_box() {
    run_on_engine_stack("cancel-malformed", async {
        let host = Host::new()?;
        let (_dir, socket, listener) = silent_supervisor();
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let mut upper = host.fresh_body();
        let signature = upper["signature"]
            .as_str()
            .expect("a signature")
            .to_ascii_uppercase();
        upper["signature"] = Value::String(signature);
        let (status, answer) = host.cancel(upper, true).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "upper-case hex is 400: {answer}"
        );
        let mut unknown = host.fresh_body();
        unknown["extra"] = json!(1);
        let (status, answer) = host.cancel(unknown, true).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unknown field is 400: {answer}"
        );
        assert_no_call(&listener);
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_caller_without_the_owners_credential_reaches_no_box() {
    run_on_engine_stack("cancel-no-cred", async {
        let host = Host::new()?;
        let (_dir, socket, listener) = silent_supervisor();
        let client = hold_client(&socket, VAULT, &token(), BOUND);
        install_recovery_box_hold(&host.server, &client)?;
        let (status, answer) = host.cancel(host.fresh_body(), false).await?;
        assert!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "no credential is refused: {status} {answer}"
        );
        assert_no_call(&listener);
        Ok::<(), TestError>(())
    });
}
