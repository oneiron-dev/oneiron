//! The `vault.mesh.*` rows at the public door: each test proves one canon
//! promise of paired-machine mesh membership through the server's real router.
//!
//! Five rows are host doors (`crate::task_verb::sdk::host_only(...)`
//! in-process), so these tests drive `build_app` at
//! `POST /v1/core/facade/<verb>`. The sixth, `vault.mesh.path_receipts`,
//! answers in-process too and is served over HTTP as well, so the one server
//! file reaches every row. The server roots the vault with its own host
//! issuer, from a process-memory keystore (as
//! `facade_repo_refusal_status.rs` does): the mesh doors sign with that
//! issuer (`api/pairing.rs` `with_issuer`), and its root credential acts as
//! the vault's embedded owner. Every body runs on the engine's stack, because
//! the facade dispatch overflows a test thread's. No test needs a live peer:
//! `vault.mesh.dial` appears in the refusal table only, with bodies that fail
//! at decode or auth before any dial.
//!
//! Canon: `oneiron/sync/oneiron-arch-0043-federation-membership-v1.md`.
//! - `pairing_is_the_only_enrollment` (:36, OF-452 D10 "pairing is the only
//!   enrollment"): a bind that names no live pairing is refused; the
//!   issue, redeem and bind ceremony lands, and the MACHINE row carries the
//!   bound endpoint key.
//! - `revokes_are_owner_authority_acts` (:22 "Connection confirms and subtree
//!   revokes are owner authority actions"): another person's revoke is
//!   refused and revokes nothing; the owner's lands, and the machine takes no
//!   grant after it.
//! - `a_malformed_or_unsigned_mesh_act_is_refused`: each of the 6 rows.
//!
//! An engine refusal at these doors (`invalid_authority`) leaves
//! `with_issuer` as 401 `UNAUTHORIZED`, but the door hands it on as a
//! `MemoryError`, and the facade maps a code it does not know to 500
//! (`api/facade/errors.rs` `From<MemoryError>`). The tests assert the code
//! and a refused status, not the status number (FIX
//! [MESH-DOOR-REFUSAL-STATUS-500]).
//!
//! Seeded faults (each makes its test fail and leaves the crates compiling):
//! - red1: `oneiron/src/authority/mesh_machine/doors.rs:164`, the
//!   pairing-live check made `self.mesh_pairing_live(..)? && false`, so a
//!   bind with no pairing lands (`pairing_is_the_only_enrollment`).
//! - red1: `oneiron-verb-wire/src/verbs/mesh.rs:51`, `deny_unknown_fields`
//!   deleted on `MeshMachineRevokeRequest`, so a revoke with an unknown field
//!   decodes and the engine refuses it, not the decode
//!   (`a_malformed_or_unsigned_mesh_act_is_refused`).
//! - red2: `oneiron/src/authority/mesh_machine/doors.rs:387`,
//!   `claims.revoked = true;` made `if false { .. }`, so a revoked machine
//!   takes a fresh grant (`revokes_are_owner_authority_acts`).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test vault_mesh_doors`.
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
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, holder_proof_challenge, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-mesh-doors-secret";
/// The ALPN the grant tests admit.
const ALPN: &[u8] = b"mesh/test";
/// The domain of the transcript both bind proofs sign
/// (`oneiron/src/authority/mesh_machine.rs` `BIND_DOMAIN`).
const BIND_DOMAIN: &[u8] = b"oneiron/mesh-machine-binding/v1\0";

fn seeded_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A slip a test minted and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// One rooted vault with a second person, the server's router and the
/// server's own root credential.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    member: EntityId,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), test_vault_config()).unwrap();
        let member = seeded_id(0xC1);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"another person",
            )
            .unwrap();
        vault.ensure_embedded_owner_actor().unwrap();
        // The server bootstraps its host issuer from this keystore and roots
        // the vault with it; the mesh doors sign with that issuer.
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
        Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            root,
            member,
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

    /// `POST /v1/core/facade/<verb>` with `body` as sent: signed by the root
    /// credential with a fresh proof when `signed`, else with no credential.
    async fn post_raw(&self, verb: &str, body: String, signed: bool) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json");
        if signed {
            let timestamp = self.vault.now_recorded_at();
            let nonce = EntityId::now().to_hex();
            let challenge = format!("oneiron-request:{timestamp}:{nonce}");
            let signature = self
                .issuer
                .binding_proof(&self.root, challenge.as_bytes())
                .unwrap();
            let binding =
                json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
            request = request
                .header(
                    "authorization",
                    format!("Bearer {}", self.root.to_token().unwrap()),
                )
                .header("x-oneiron-binding", binding.to_string());
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    /// `verb` as the owner, through the root credential.
    async fn post(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        self.post_raw(verb, body.to_string(), true).await
    }

    /// `verb` under `holder`'s slip, with a fresh holder proof.
    async fn post_as(&self, holder: &Holder, verb: &str, body: &Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = holder
            .key
            .sign(&holder.slip.binding_transcript(&challenge).unwrap())
            .to_bytes();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", holder.slip.to_token().unwrap()),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    /// A slip this host mints `who` as a person, holding `read` and `write`:
    /// not owner-grade and not the host's own.
    fn mint(&self, who: EntityId, seed: u8) -> Holder {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [seed; 32];
        claims.holder_ref = who.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .unwrap();
        Holder { slip, key }
    }

    /// A MACHINE row for `machine`: the live holder public pairing asks for.
    fn put_machine(&self, machine: EntityId) {
        self.vault
            .put_entity(
                &machine,
                ENTITY_TYPE_MACHINE,
                TimeRange { start: 1, end: 1 },
                1,
                b"mesh machine",
            )
            .unwrap();
    }

    /// The pairing ceremony for `machine` (as
    /// `oneiron-mesh-transport/tests/roster.rs` runs it): issue a link with
    /// the host issuer and redeem it for `device`. Answers the pairing slip.
    fn pair(&self, machine: EntityId, device: &SigningKey) -> CapabilitySlip {
        let link = self
            .vault
            .issue_pairing_link(&self.issuer, Scope::top(), 3600)
            .unwrap();
        let device_key = device.verifying_key().to_bytes();
        let proof = device
            .sign(&pairing_binding_transcript(&link.code, &device_key, &machine.to_hex()).unwrap())
            .to_bytes();
        self.vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &machine.to_hex(),
                device_key,
                &proof,
            )
            .unwrap()
    }
}

/// A `vault.mesh.bind_machine` body for `machine` at `transport`'s endpoint,
/// both proofs signed over the binding transcript the engine checks.
fn bind_body(
    machine: EntityId,
    pairing_slip_id: [u8; 32],
    device: &SigningKey,
    transport: &SigningKey,
) -> Value {
    let endpoint_key = transport.verifying_key().to_bytes();
    let mut transcript = BIND_DOMAIN.to_vec();
    transcript.extend_from_slice(machine.as_bytes());
    transcript.extend_from_slice(&endpoint_key);
    json!({
        "machine": machine.to_hex(),
        "address": {
            "endpoint_key": endpoint_key.to_vec(),
            "direct_addrs": [],
            "relay_url": null,
        },
        "device_key": device.verifying_key().to_bytes().to_vec(),
        "pairing_slip_id": pairing_slip_id.to_vec(),
        "device_proof": device.sign(&transcript).to_bytes().to_vec(),
        "transport_proof": transport.sign(&transcript).to_bytes().to_vec(),
    })
}

/// A refusal's (status, code): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value) {
    (status, body["error"]["code"].clone())
}

/// The engine refused the act: code `UNAUTHORIZED` (`api/pairing.rs`
/// `with_issuer`), and no success status (see the module doc on 500).
fn assert_engine_refused(status: StatusCode, body: &Value, what: &str) {
    assert!(
        !status.is_success(),
        "{what}: refused, not {status}: {body}"
    );
    assert_eq!(
        body["error"]["code"],
        json!("UNAUTHORIZED"),
        "{what} ({status}): {body}"
    );
}

/// arch-0043:36, OF-452 D10 "pairing is the only enrollment": a bind that
/// names no live pairing is refused; the ceremony's bind lands and the
/// MACHINE row carries its endpoint.
#[test]
fn pairing_is_the_only_enrollment() {
    run_on_engine_stack("mesh-pairing-only-enrollment", || async {
        let door = Door::open();
        let machine = seeded_id(0xE1);
        door.put_machine(machine);
        let device = SigningKey::from_bytes(&[0xD1; 32]);
        let transport = SigningKey::from_bytes(&[0xD2; 32]);
        let endpoint_key = transport.verifying_key().to_bytes();

        // No pairing: valid proofs over a slip id no host minted.
        let (status, body) = door
            .post(
                "vault.mesh.bind_machine",
                &bind_body(machine, [9; 32], &device, &transport),
            )
            .await;
        assert_engine_refused(status, &body, "a bind with no pairing");
        assert!(
            door.vault.mesh_machine(machine).unwrap().is_none(),
            "the refused bind wrote no address"
        );

        // The ceremony's bind lands, and the MACHINE row carries the endpoint.
        let pair = door.pair(machine, &device);
        let (status, bound) = door
            .post(
                "vault.mesh.bind_machine",
                &bind_body(machine, pair.claims.slip_id, &device, &transport),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{bound}");
        assert_eq!(
            bound,
            json!({"machine": machine.to_hex(), "endpoint_key": endpoint_key.to_vec()}),
            "{bound}"
        );
        let row = door
            .vault
            .mesh_machine(machine)
            .unwrap()
            .expect("the bound address");
        assert_eq!(row.endpoint_key, endpoint_key);
    });
}

/// arch-0043:22 "Connection confirms and subtree revokes are owner authority
/// actions": another person's revoke is refused and revokes nothing; the
/// owner's lands, and the revoked machine takes no grant after it.
#[test]
fn revokes_are_owner_authority_acts() {
    run_on_engine_stack("mesh-revoke-owner-act", || async {
        let door = Door::open();
        let machine = seeded_id(0xE3);
        door.put_machine(machine);
        let device = SigningKey::from_bytes(&[0xD4; 32]);
        let transport = SigningKey::from_bytes(&[0xD5; 32]);
        let endpoint_key = transport.verifying_key().to_bytes();
        let pair = door.pair(machine, &device);
        let (status, bound) = door
            .post(
                "vault.mesh.bind_machine",
                &bind_body(machine, pair.claims.slip_id, &device, &transport),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{bound}");

        // One grant: the machine is admitted on `mesh/test`.
        let grant = json!({
            "machine": machine.to_hex(),
            "endpoint_key": endpoint_key.to_vec(),
            "alpn": ALPN.to_vec(),
            "allow": true,
        });
        let (status, echoed) = door.post("vault.mesh.set_alpn_grant", &grant).await;
        assert_eq!(
            (status, &echoed),
            (StatusCode::OK, &grant),
            "the grant door answers its grant"
        );
        assert!(
            door.vault
                .mesh_grant_permits(machine, endpoint_key, ALPN)
                .unwrap(),
            "the grant admits the machine"
        );

        // Another person's revoke is refused and revokes nothing.
        let member = door.mint(door.member, 0x61);
        let revoke = json!({"machine": machine.to_hex()});
        let (status, body) = door
            .post_as(&member, "vault.mesh.revoke_machine", &revoke)
            .await;
        assert_eq!(
            refusal(status, &body),
            (StatusCode::FORBIDDEN, json!("FORBIDDEN")),
            "{body}"
        );
        assert!(
            door.vault
                .mesh_grant_permits(machine, endpoint_key, ALPN)
                .unwrap(),
            "the refused revoke revoked nothing"
        );

        // The owner's revoke lands and withdraws the grant.
        let (status, revoked) = door.post("vault.mesh.revoke_machine", &revoke).await;
        assert_eq!((status, &revoked), (StatusCode::OK, &revoke), "{revoked}");
        assert!(
            !door
                .vault
                .mesh_grant_permits(machine, endpoint_key, ALPN)
                .unwrap(),
            "no grant admits a revoked machine"
        );

        // A revoked machine stays revoked: the owner's fresh grant is refused.
        let (status, body) = door.post("vault.mesh.set_alpn_grant", &grant).await;
        assert_engine_refused(status, &body, "a grant to a revoked machine");
        assert!(
            !door
                .vault
                .mesh_grant_permits(machine, endpoint_key, ALPN)
                .unwrap(),
            "the refused grant admits nothing"
        );
    });
}

/// Each of the 6 rows refuses a body missing its fields and a body with a
/// field it does not know, and refuses any body with no credential.
/// (`vault.mesh.identity` and `vault.mesh.path_receipts` take `{}`, so they
/// skip the no-fields leg. `vault.mesh.dial` never dials here: every body
/// fails at decode or auth first.)
#[test]
fn a_malformed_or_unsigned_mesh_act_is_refused() {
    run_on_engine_stack("mesh-refusals", || async {
        let door = Door::open();
        let machine = seeded_id(0xE4).to_hex();
        // Bodies of the right shape with arbitrary bytes: decode checks the
        // shape, never the proofs.
        let address = json!({
            "endpoint_key": vec![0xD2u8; 32],
            "direct_addrs": [],
            "relay_url": null,
        });
        let bind = json!({
            "machine": machine,
            "address": address,
            "device_key": vec![0xD1u8; 32],
            "pairing_slip_id": vec![9u8; 32],
            "device_proof": vec![1u8; 64],
            "transport_proof": vec![2u8; 64],
        });
        let dial = json!({"address": address, "alpn": ALPN.to_vec()});
        let grant = json!({
            "machine": machine,
            "endpoint_key": vec![0xD2u8; 32],
            "alpn": ALPN.to_vec(),
            "allow": true,
        });
        let revoke = json!({"machine": machine});
        let bad_request = (StatusCode::BAD_REQUEST, json!("BAD_REQUEST"));
        for (verb, body) in [
            ("vault.mesh.bind_machine", &bind),
            ("vault.mesh.dial", &dial),
            ("vault.mesh.revoke_machine", &revoke),
            ("vault.mesh.set_alpn_grant", &grant),
        ] {
            let (status, refused) = door.post(verb, &json!({})).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with no fields: {refused}"
            );
            let mut extra = body.clone();
            extra["unexpected"] = json!(1);
            let (status, refused) = door.post(verb, &extra).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with an unknown field: {refused}"
            );
        }
        for verb in ["vault.mesh.identity", "vault.mesh.path_receipts"] {
            let (status, refused) = door.post(verb, &json!({"unexpected": 1})).await;
            assert_eq!(
                refusal(status, &refused),
                bad_request,
                "{verb} with an unknown field: {refused}"
            );
        }
        for (verb, body) in [
            ("vault.mesh.bind_machine", bind),
            ("vault.mesh.dial", dial),
            ("vault.mesh.identity", json!({})),
            ("vault.mesh.path_receipts", json!({})),
            ("vault.mesh.revoke_machine", revoke),
            ("vault.mesh.set_alpn_grant", grant),
        ] {
            let (status, refused) = door.post_raw(verb, body.to_string(), false).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} with no credential: {refused}"
            );
        }

        let (status, refused) = door
            .post_raw("vault.mesh.revoke_machine", "{not json".to_owned(), true)
            .await;
        assert_eq!(refusal(status, &refused), bad_request, "{refused}");
        assert_eq!(
            refused["error"]["message"], "invalid JSON request body",
            "{refused}"
        );

        // The refusals bound nothing, and the owner's receipts read empty.
        assert!(door.vault.mesh_machine(seeded_id(0xE4)).unwrap().is_none());
        let (status, receipts) = door.post("vault.mesh.path_receipts", &json!({})).await;
        assert_eq!(
            (status, &receipts),
            (StatusCode::OK, &json!([])),
            "{receipts}"
        );
    });
}
