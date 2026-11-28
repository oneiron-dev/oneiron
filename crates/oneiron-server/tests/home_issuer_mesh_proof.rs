//! PLAN-HOME-ISSUER-MESH-PROOF (R6 1.5, Engine P0 26 Nov 01:31): a home that is also the
//! vault's job issuer must be provable on the mesh by its nodes.
//!
//! A node admits a job stream only from a peer that `mesh_peer_machine` proves: a host-signed
//! binding of that MACHINE whose device key is its machine proof key, and a live grant on the
//! ALPN. A binding stands only on a live pairing slip held by the MACHINE under its machine key.
//! A link's redemption mints such a slip for the machine it enrols, but the home never redeems a
//! link of its own. So on main no replica can bind the home, and `vault.mesh.set_alpn_grant` for
//! the home's MACHINE is refused (`invalid_authority`, 401 at the door).
//!
//! `vault.mesh.pair_self` (owner only) mints that pairing and answers the bind body. These tests
//! post that body to `vault.mesh.bind_machine` and grant the job ALPNs on the same vault. The
//! bind and the grants are what the owner runs on each other replica, which is why the body
//! carries both proofs. The home's MACHINE is then Proven on `oneiron/job/1`.
//!
//! Red: the stub branch, where `pair_own_mesh_machine_as_owner` answers `invalid_authority`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test home_issuer_mesh_proof`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, PeerMachine, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::job_workload::{JOB_ALPN, JOB_STATUS_ALPN};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "home-issuer-mesh-proof-secret";

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key_of(value: &Value) -> [u8; 32] {
    let bytes: Vec<u8> = serde_json::from_value(value.clone()).expect("a byte array");
    bytes.try_into().expect("32 bytes")
}

/// A rooted home: the server's router, its own host issuer and root credential (the vault's
/// embedded owner), and this install's own machine profile, as a serving start ensures it.
struct Home {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
}

impl Home {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        vault.ensure_embedded_owner_actor().unwrap();
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let vault = Arc::new(vault);
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let issuer = vault.load_host_slip_issuer().unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        vault.ensure_serving_install_profile_at_start(Some(&issuer), "home_issuer_mesh_proof");
        Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            root,
        }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `verb` as the owner, at its facade door.
    async fn post(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        self.post_path(&format!("/v1/core/facade/{verb}"), body)
            .await
    }

    /// `body` posted to the route at `path` as the owner, through the root credential with a
    /// fresh proof.
    async fn post_path(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .unwrap();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", self.root.to_token().unwrap()),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    /// `verb` as another person, holding `read` and `write` but no owner proof.
    async fn post_as_member(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        let member = EntityId::now();
        self.vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"another person",
            )
            .unwrap();
        let key = SigningKey::from_bytes(&[0xB7; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0xB7; 32];
        claims.holder_ref = member.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .unwrap();
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = key
            .sign(&slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", slip.to_token().unwrap()),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }
}

/// The owner pairs the home's own MACHINE once he has answered it. A serving start enrols this
/// install `unanswered`, and a replica proves no unanswered MACHINE, so the pairing refuses until
/// the answer and names that step. The answered body names this install's MACHINE, its machine
/// key and its endpoint key. That body binds as it is, so the pairing stands, held by the MACHINE
/// under its machine key. Both job ALPNs are then granted, and `mesh_peer_machine` proves the
/// home on `oneiron/job/1`, as a node's gate asks.
#[test]
fn the_owner_pairs_the_homes_own_machine_and_it_is_proven_on_the_job_alpn() {
    run_on_engine_stack("home-issuer-mesh-proof", || async {
        let home = Home::open();
        let (status, identity) = home.post("vault.mesh.identity", &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{identity}");
        let machine = EntityId::from_hex(identity["machine"].as_str().unwrap()).unwrap();
        let endpoint_key = key_of(&identity["endpoint_key"]);

        let (status, refused) = home.post("vault.mesh.pair_self", &json!({})).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "an unanswered home is not paired: {refused}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "the owner's credential stands; the refusal is the home's state: {refused}"
        );
        assert!(
            refused.to_string().contains("/v1/owner/machines/answer"),
            "the refusal names the owner's step: {refused}"
        );
        let (status, answered) = home
            .post_path(
                "/v1/owner/machines/answer",
                &json!({"machine": machine.to_hex(), "answer": "yours"}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner answers the home: {answered}"
        );

        let (status, binding) = home.post("vault.mesh.pair_self", &json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner pairs the home: {binding}"
        );
        assert_eq!(
            binding["machine"], identity["machine"],
            "this install's MACHINE"
        );
        assert_eq!(
            binding["device_key"], identity["device_key"],
            "its machine key"
        );
        assert_eq!(
            binding["address"]["endpoint_key"], identity["endpoint_key"],
            "its endpoint key"
        );
        assert!(
            home.vault.mesh_machine(machine).unwrap().is_none(),
            "pair_self binds nothing"
        );

        let (status, bound) = home.post("vault.mesh.bind_machine", &binding).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the body binds on its pairing: {bound}"
        );
        for alpn in [JOB_ALPN, JOB_STATUS_ALPN] {
            let grant = json!({
                "machine": machine.to_hex(),
                "endpoint_key": endpoint_key.to_vec(),
                "alpn": alpn.to_vec(),
                "allow": true,
            });
            let (status, echoed) = home.post("vault.mesh.set_alpn_grant", &grant).await;
            assert_eq!(status, StatusCode::OK, "the job ALPN is granted: {echoed}");
        }
        let peer = home
            .vault
            .mesh_peer_machine(endpoint_key, JOB_ALPN)
            .unwrap();
        assert!(
            matches!(peer, PeerMachine::Proven { machine: proven, .. } if proven == machine),
            "the home is proven on the job ALPN: {peer:?}"
        );
    });
}

/// `vault.mesh.pair_self` is the owner's: another person's call is refused and mints nothing
/// that binds.
#[test]
fn another_person_cannot_pair_the_home() {
    run_on_engine_stack("home-issuer-mesh-proof-refusal", || async {
        let home = Home::open();
        let (status, body) = home
            .post_as_member("vault.mesh.pair_self", &json!({}))
            .await;
        assert_ne!(status, StatusCode::OK, "a non-owner is refused: {body}");
        assert!(body.get("pairing_slip_id").is_none(), "no body: {body}");
    });
}
