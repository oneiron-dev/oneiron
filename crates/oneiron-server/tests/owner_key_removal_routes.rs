//! Row AUTH-5 PR b (the owner's ruling AUTH-5): a managed host holds no
//! owner key, so its server removes none.
//!
//! On a served vault in the HOSTED posture (a managed host: its server's
//! install holds only the custodial host root, never an owner key), the owner
//! enrols a device owner key over HTTP, the key lists live and not held here,
//! and its removal is refused: `POST /v1/owner/owner-signing-keys/remove`
//! answers 409 with the error envelope's state `owner_key_required` and
//! writes nothing, so the key stays live and `GET .../changes` still lists
//! only the enrolment.
//!
//! One test function: one server serves all four steps in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no models) with the
//! owner's own full human slip, on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test owner_key_removal_routes`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::{
    EntityId, HostingPrivacyPosture, Vault, VaultConfig, VaultDataKeyCustody, VaultPrivacyConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const KEYS: &str = "/v1/owner/owner-signing-keys";
const CHALLENGE: &str = "/v1/owner/owner-signing-keys/challenge";
const ENROLL: &str = "/v1/owner/owner-signing-keys/enroll";
const REMOVE: &str = "/v1/owner/owner-signing-keys/remove";
const CHANGES: &str = "/v1/owner/owner-signing-keys/changes";
/// The `confirm` value that lets a removal end the last owner key held on a
/// device (the routes file's `LAST_DEVICE_KEY`).
const LAST_DEVICE_KEY: &str = "last_device_key";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `value` as bytes: the challenge the device key signs.
fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(format!("expected even-length hex, saw {} chars", value.len()).into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("expected hex, saw {pair:?}"))
        })
        .collect::<Result<Vec<u8>, String>>()
        .map_err(Into::into)
}

/// A served vault in the HOSTED posture: a managed host whose server's
/// install holds only the custodial host root, never an owner key.
struct Host {
    app: Router,
    vault: Arc<Vault>,
    owner_slip: CapabilitySlip,
    holder_key: SigningKey,
    _dir: tempfile::TempDir,
}

impl Host {
    /// The hosted vault, served: its install rooted and profiled, its owner
    /// holding a full human slip.
    fn serve() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.privacy = VaultPrivacyConfig {
            posture: HostingPrivacyPosture::Hosted,
            data_key_custody: VaultDataKeyCustody::HostManagedKms {
                key_ref: "kms://example/owner-key-removal-routes".to_owned(),
            },
        };
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owner-key-removal-routes".to_owned()),
                ..Default::default()
            },
        )?);
        let issuer: HostSlipIssuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        // The owner's acts are carried by this install's live machine
        // profile, as a serving start enrols it.
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        assert_eq!(
            vault.privacy_posture(),
            HostingPrivacyPosture::Hosted,
            "the vault serves in the HOSTED posture"
        );
        let holder_key = SigningKey::from_bytes(&[0x5B; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0xC1; 32];
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key.verifying_key().to_bytes();
        let owner_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            app: build_app(server),
            vault,
            owner_slip,
            holder_key,
            _dir: dir,
        })
    }

    /// This server's install machine: the holder the enrolment names.
    fn machine(&self) -> TestResult<EntityId> {
        Ok(self
            .vault
            .local_machine()?
            .ok_or("the serving install has a machine")?
            .id)
    }

    /// One owner request to the served app: its status and its answer, as
    /// text when it is not JSON.
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let binding = holder_proof(
            &self.owner_slip,
            &self.holder_key,
            self.vault.now_recorded_at(),
        )?;
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header(
                "authorization",
                format!("Bearer {}", self.owner_slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string());
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?,
            None => builder.body(Body::empty())?,
        };
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, answer))
    }
}

#[test]
fn a_managed_hosts_server_removes_no_owner_key_and_lists_the_enrolment() -> TestResult {
    on_engine_stack(managed_host_removes_no_owner_key)
}

async fn managed_host_removes_no_owner_key() -> TestResult {
    let host = Host::serve()?;
    let machine = host.machine()?.to_hex();
    let device_key = SigningKey::from_bytes(&[0x2D; 32]);
    let public_key = hex(&device_key.verifying_key().to_bytes());

    // The owner enrols the device owner key over HTTP.
    let (status, answer) = host
        .send(
            "POST",
            CHALLENGE,
            Some(json!({"machine": machine.clone(), "public_key": public_key.clone()})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the challenge answers: {answer}");
    let challenge = answer["challenge"]
        .as_str()
        .ok_or("the challenge answers hex")?;
    let proof = hex(&device_key.sign(&decode_hex(challenge)?).to_bytes());
    let (status, answer) = host
        .send(
            "POST",
            ENROLL,
            Some(json!({"machine": machine.clone(), "public_key": public_key.clone(), "proof": proof})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the enrolment lands: {answer}");

    // The key lists live, a device key, not held here.
    let (status, answer) = host.send("GET", KEYS, None).await?;
    assert_eq!(status, StatusCode::OK, "the list reads: {answer}");
    let keys = answer["keys"].as_array().ok_or("the list names keys")?;
    assert_eq!(keys.len(), 1, "one enrolled key: {answer}");
    assert_eq!(
        keys[0]["public_key"], public_key,
        "the enrolled key: {answer}"
    );
    assert_eq!(keys[0]["machine"], machine, "the holding machine: {answer}");
    assert_eq!(keys[0]["live"], true, "the key is live: {answer}");
    assert_eq!(keys[0]["kind"], "device", "a device key: {answer}");
    assert_eq!(keys[0]["held_here"], false, "never held here: {answer}");

    // Its removal is refused: this install holds no owner key.
    let (status, answer) = host
        .send(
            "POST",
            REMOVE,
            Some(json!({"public_key": public_key.clone(), "confirm": LAST_DEVICE_KEY})),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the removal is refused: {answer}"
    );
    assert_eq!(
        answer["error"]["code"], "INVALID_STATE",
        "the typed envelope: {answer}"
    );
    assert_eq!(
        answer["error"]["details"]["state"], "owner_key_required",
        "the refusal names its state: {answer}"
    );
    assert!(
        answer.get("code").is_none(),
        "no bare ApiError body: {answer}"
    );

    // Nothing was written: the key stays live, and the changes list its
    // enrolment alone.
    let (status, answer) = host.send("GET", KEYS, None).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the list reads after the refusal: {answer}"
    );
    let keys = answer["keys"].as_array().ok_or("the list names keys")?;
    assert_eq!(keys.len(), 1, "the key is still the only one: {answer}");
    assert_eq!(keys[0]["live"], true, "the key stays live: {answer}");
    let (status, answer) = host.send("GET", CHANGES, None).await?;
    assert_eq!(status, StatusCode::OK, "the changes read: {answer}");
    let changes = answer["changes"].as_array().ok_or("the changes list")?;
    assert_eq!(changes.len(), 1, "the enrolment alone: {answer}");
    assert_eq!(changes[0]["change"], "enrolled", "the enrolment: {answer}");
    assert_eq!(
        changes[0]["public_key"], public_key,
        "the enrolled key: {answer}"
    );
    assert_eq!(changes[0]["kind"], "device", "a device key: {answer}");
    Ok(())
}
