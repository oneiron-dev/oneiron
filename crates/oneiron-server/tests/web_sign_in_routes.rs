//! Row AUTH-5 PR c (the owner's ruling AUTH-5): a managed host holds no
//! owner key, so its server switches no vault back to web sign-in.
//!
//! On a served vault in the HOSTED posture (a managed host: its server's
//! install holds only the custodial host root, never an owner key),
//! `GET /v1/owner/owner-signing-keys/requirement` reads `never_held` before
//! any enrolment and `required` with its 64 lower-case hex `web_sign_in_switch`
//! after the owner enrols a device owner key over HTTP, and
//! `POST /v1/owner/owner-signing-keys/web-sign-in` with that value is refused:
//! it answers 409 with the error envelope's state `owner_key_required` and
//! writes nothing, so the requirement still reads the same state. A malformed
//! `seen` answers 400.
//!
//! One test function: one server serves all five steps in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no models) with the
//! owner's own full human slip, on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test web_sign_in_routes`.

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

const CHALLENGE: &str = "/v1/owner/owner-signing-keys/challenge";
const ENROLL: &str = "/v1/owner/owner-signing-keys/enroll";
const REQUIREMENT: &str = "/v1/owner/owner-signing-keys/requirement";
const WEB_SIGN_IN: &str = "/v1/owner/owner-signing-keys/web-sign-in";

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
                key_ref: "kms://example/web-sign-in-routes".to_owned(),
            },
        };
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("web-sign-in-routes".to_owned()),
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
fn the_requirement_route_reads_the_state_and_the_switch_route_refuses_without_an_owner_key()
-> TestResult {
    on_engine_stack(requirement_reads_and_switch_refuses_without_owner_key)
}

async fn requirement_reads_and_switch_refuses_without_owner_key() -> TestResult {
    let host = Host::serve()?;

    // Before any enrolment the vault never held an owner key and asks for none.
    let (status, answer) = host.send("GET", REQUIREMENT, None).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the requirement reads before any enrolment: {answer}"
    );
    assert_eq!(
        answer["state"], "never_held",
        "a vault that never held an owner key asks for none: {answer}"
    );
    assert!(
        answer.get("web_sign_in_switch").is_none(),
        "no switch value before any enrolment: {answer}"
    );

    // The owner enrols the device owner key over HTTP.
    let machine = host.machine()?.to_hex();
    let device_key = SigningKey::from_bytes(&[0x2D; 32]);
    let public_key = hex(&device_key.verifying_key().to_bytes());
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

    // This hosted vault now asks for an owner key and names its switch value.
    let (status, answer) = host.send("GET", REQUIREMENT, None).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the requirement reads after the enrolment: {answer}"
    );
    assert_eq!(
        answer["state"], "required",
        "a hosted vault that held an owner key asks for one: {answer}"
    );
    let switch = answer["web_sign_in_switch"]
        .as_str()
        .ok_or("a hosted vault in required names its switch value")?;
    assert_eq!(switch.len(), 64, "the switch value is 64 hex: {answer}");
    assert!(
        switch
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "the switch value is lower-case hex: {answer}"
    );
    let switch = switch.to_owned();

    // The switch is refused: this install holds no owner key.
    let (status, answer) = host
        .send("POST", WEB_SIGN_IN, Some(json!({"seen": switch.clone()})))
        .await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the switch is refused without an owner key: {answer}"
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

    // Nothing was written: the requirement still reads the same state.
    let (status, answer) = host.send("GET", REQUIREMENT, None).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the requirement still reads after the refusal: {answer}"
    );
    assert_eq!(
        answer["state"], "required",
        "the refused switch writes nothing: {answer}"
    );
    assert_eq!(
        answer["web_sign_in_switch"], switch,
        "the switch value is unchanged: {answer}"
    );

    // A malformed seen is a bad request.
    let (status, answer) = host
        .send("POST", WEB_SIGN_IN, Some(json!({"seen": "zz"})))
        .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed seen is a bad request: {answer}"
    );
    assert_eq!(
        answer["error"]["code"], "BAD_REQUEST",
        "the typed envelope: {answer}"
    );
    assert!(
        answer.get("code").is_none(),
        "no bare ApiError body: {answer}"
    );
    Ok(())
}
