//! HOSTED-RELAY-OWNER-HUMAN-BIND-CEREMONY (lead ruling B, Sat 21 Nov 04:3x):
//! the owner of a managed host's vault binds themselves to their device's
//! owner key over HTTP, and the key signs the binding.
//!
//! On a served vault in the HOSTED posture the enrolment's predecessor is
//! the custodial host root, and the vault counts no `human` binding that
//! only a key in the host's custody signs, so the enrolment over
//! `POST /v1/owner/owner-signing-keys/enroll` binds no one, and the owner's
//! owner verbs answer OWNER_BINDING_REQUIRED (`Memory::verify_owner`). The
//! device then runs `POST .../bind/prepare` with its key and
//! `POST .../bind/land` with the key's signature over the transcript the
//! prepare answered: a signature by another key is refused and binds no
//! one, the key's own lands, and the owner verb passes.
//!
//! Red on main: the routes do not exist, so the prepare answers 404 after
//! the enrolment, and the owner stays unbound. Green on the head.
//!
//! One test function: one server serves every step in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no models) with the
//! owner's own full human slip, on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test owner_key_binding_routes`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::{
    EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig, VaultDataKeyCustody,
    VaultPrivacyConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHALLENGE: &str = "/v1/owner/owner-signing-keys/challenge";
const ENROLL: &str = "/v1/owner/owner-signing-keys/enroll";
const BIND_PREPARE: &str = "/v1/owner/owner-signing-keys/bind/prepare";
const BIND_LAND: &str = "/v1/owner/owner-signing-keys/bind/land";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `value` as bytes: a challenge or a transcript the device key signs.
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
    owner: EntityId,
    owner_slip: CapabilitySlip,
    holder_key: SigningKey,
    _dir: tempfile::TempDir,
}

impl Host {
    /// The hosted vault, served: its install rooted and profiled, its owner
    /// holding a full human slip and bound by no one.
    fn serve() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.privacy = VaultPrivacyConfig {
            posture: HostingPrivacyPosture::Hosted,
            data_key_custody: VaultDataKeyCustody::HostManagedKms {
                key_ref: "kms://example/owner-key-binding-routes".to_owned(),
            },
        };
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owner-key-binding-routes".to_owned()),
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
        let holder_key = SigningKey::from_bytes(&[0x5C; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0xC2; 32];
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key.verifying_key().to_bytes();
        let owner_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            app: build_app(server),
            vault,
            owner,
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

    /// The owner enrols `device_key` as the owner key of this server's
    /// install machine over HTTP; answers the key as hex.
    async fn enrol(&self, device_key: &SigningKey) -> TestResult<String> {
        let machine = self.machine()?.to_hex();
        let public_key = hex(&device_key.verifying_key().to_bytes());
        let (status, answer) = self
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
        let (status, answer) = self
            .send(
                "POST",
                ENROLL,
                Some(json!({"machine": machine, "public_key": public_key.clone(), "proof": proof})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the enrolment lands: {answer}");
        Ok(public_key)
    }

    /// The owner verb's answer: `None` when it passes, else its code.
    fn owner_verb_refusal(&self) -> Option<String> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .verify_owner()
            .err()
            .map(|error| error.code)
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
fn a_managed_hosts_owner_binds_with_their_device_key_over_http() -> TestResult {
    on_engine_stack(managed_host_owner_binds_with_their_device_key)
}

async fn managed_host_owner_binds_with_their_device_key() -> TestResult {
    let host = Host::serve()?;
    let device_key = SigningKey::from_bytes(&[0x2E; 32]);

    // The owner enrols the device owner key over HTTP; it binds no one.
    let public_key = host.enrol(&device_key).await?;
    assert_eq!(
        host.owner_verb_refusal().as_deref(),
        Some(MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "the enrolment binds no one, so the owner verb answers OWNER_BINDING_REQUIRED"
    );

    // The device prepares its binding.
    let (status, answer) = host
        .send(
            "POST",
            BIND_PREPARE,
            Some(json!({"public_key": public_key.clone()})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the binding is prepared: {answer}");
    let entry = answer["entry"]
        .as_str()
        .ok_or("the prepare answers the entry as hex")?
        .to_owned();
    let transcript = decode_hex(
        answer["transcript"]
            .as_str()
            .ok_or("the prepare answers the transcript as hex")?,
    )?;

    // Another key's signature binds no one.
    let stranger = SigningKey::from_bytes(&[0x3F; 32]);
    let (status, answer) = host
        .send(
            "POST",
            BIND_LAND,
            Some(json!({
                "entry": entry.clone(),
                "signature": hex(&stranger.sign(&transcript).to_bytes()),
            })),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another key's signature is refused: {answer}"
    );
    assert_eq!(
        host.owner_verb_refusal().as_deref(),
        Some(MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "the refused binding wrote nothing"
    );

    // The key's own signature lands the binding.
    let (status, answer) = host
        .send(
            "POST",
            BIND_LAND,
            Some(json!({
                "entry": entry,
                "signature": hex(&device_key.sign(&transcript).to_bytes()),
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the binding lands: {answer}");
    assert_eq!(
        answer["owner"],
        host.owner.to_hex(),
        "the receipt names the owner: {answer}"
    );
    assert_eq!(
        answer["public_key"], public_key,
        "the receipt names the key: {answer}"
    );
    assert_eq!(answer["epoch"], 1, "the key's first binding: {answer}");
    assert_eq!(
        host.owner_verb_refusal(),
        None,
        "the bound owner's owner verb passes"
    );
    Ok(())
}
