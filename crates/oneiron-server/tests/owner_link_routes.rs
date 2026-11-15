//! L10-16 PR 2: `/v1/owner/link`, the owner's hosted peer (plan
//! `lanes/post-untangle/plans/PLAN-L10-16.md`, Design 5-6), over HTTP.
//!
//! `POST /v1/owner/link` mints nothing unless the vault's cloud registration
//! is live: the control plane takes a peer request only from the linked
//! cloud account. With none, it answers 409 `cloud_registration_required`
//! and the vault still has no linked peer. `DELETE` with no peer answers
//! 409 `not_linked`. All three routes are the owner's: a paired credential
//! that is not his is refused 403. `oneiron link`, `oneiron link status`
//! and `oneiron unlink` parse as canon spells them (cross-arch-0024 M4.25).
//! The link and unlink acts themselves run in `tests/hosted_peer_link.rs`,
//! since no test can pin an https issuer and so make a registration live.
//!
//! On unmodified main every route answers 404 and the CLI refuses `link`
//! and `unlink` as unknown subcommands.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test owner_link_routes`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use clap::Parser as _;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, pairing_binding_transcript};
use oneiron::federation::Scope;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, cli::Cli, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const LINK: &str = "/v1/owner/link";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault: rooted from its install's keystore, its install
/// profiled as a serving start leaves it, with no cloud registration pins.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owner-link-routes".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
    }
}

/// A credential and the key its binding proof is signed with.
struct Caller {
    slip: CapabilitySlip,
    token: String,
    /// The paired holder's own binding key; `None` for the host root, whose
    /// proof the host issuer signs.
    key: Option<SigningKey>,
}

impl Host {
    /// The owner: the host root's own credential.
    fn owner(&self) -> Caller {
        let slip = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        Caller {
            slip,
            token,
            key: None,
        }
    }

    /// A credential paired for a holder that is not the owner, with every
    /// verb.
    fn paired_holder(&self) -> Caller {
        let link = self
            .vault
            .issue_pairing_link(&self.issuer, Scope::top(), 3600)
            .expect("a pairing link");
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let binding_key = key.verifying_key().to_bytes();
        let holder = EntityId::now().to_hex();
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &holder)
            .expect("the binding transcript");
        let slip = self
            .vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder,
                binding_key,
                &key.sign(&transcript).to_bytes(),
            )
            .expect("the holder redeems its link");
        let token = slip.to_token().expect("paired slip token");
        Caller {
            slip,
            token,
            key: Some(key),
        }
    }

    fn binding(&self, caller: &Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match &caller.key {
            None => self
                .issuer
                .binding_proof(&caller.slip, challenge.as_bytes())
                .expect("owner holder proof")
                .to_vec(),
            Some(key) => {
                let transcript = caller
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("the request transcript");
                key.sign(&transcript).to_bytes().to_vec()
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)}).to_string()
    }

    /// `method` on `/v1/owner/link` as `caller`: its status and its answer,
    /// the answer as text when it is not JSON.
    async fn call(
        &self,
        caller: &Caller,
        method: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(LINK)
            .header("authorization", format!("Bearer {}", caller.token))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("link request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("link response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("link answer");
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, answer)
    }
}

/// The state code a 409's details name.
fn conflict_state(answer: &Value) -> Option<&str> {
    answer
        .pointer("/error/details/state")
        .and_then(Value::as_str)
}

#[test]
fn a_link_without_a_live_cloud_registration_refuses_and_keeps_nothing() {
    run_on_engine_stack("link-without-registration", || async {
        let host = host();
        let owner = host.owner();
        let (status, answer) = host
            .call(
                &owner,
                "POST",
                Some(json!({"origin": "https://laptop.example"})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(
            conflict_state(&answer),
            Some("cloud_registration_required"),
            "{answer}"
        );
        let (status, answer) = host.call(&owner, "GET", None).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["state"], "not_linked", "{answer}");
    });
}

#[test]
fn an_unlink_with_no_hosted_peer_answers_not_linked() {
    run_on_engine_stack("unlink-not-linked", || async {
        let host = host();
        let (status, answer) = host.call(&host.owner(), "DELETE", None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert_eq!(conflict_state(&answer), Some("not_linked"), "{answer}");
    });
}

#[test]
fn only_the_owner_links_reads_or_unlinks_a_hosted_peer() {
    run_on_engine_stack("link-owner-only", || async {
        let host = host();
        let holder = host.paired_holder();
        for (method, body) in [
            ("POST", Some(json!({"origin": "https://laptop.example"}))),
            ("GET", None),
            ("DELETE", None),
        ] {
            let (status, answer) = host.call(&holder, method, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {answer}");
        }
    });
}

#[test]
fn the_cli_spells_link_link_status_and_unlink() {
    for argv in [
        ["oneiron", "link", "--origin", "https://laptop.example"].as_slice(),
        ["oneiron", "link", "status"].as_slice(),
        ["oneiron", "unlink"].as_slice(),
    ] {
        if let Err(error) = Cli::try_parse_from(argv) {
            panic!("{argv:?} does not parse: {error}");
        }
    }
}
