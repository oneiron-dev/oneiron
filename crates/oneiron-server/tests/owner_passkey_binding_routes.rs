//! PASSKEY-SELF-BIND over HTTP (row PASSKEY-SELF-BIND): the passkey-only
//! owner of a managed host's vault binds themselves with their own passkey
//! over HTTP, and the passkey signs the binding with a user-verified
//! assertion.
//!
//! On a served vault in the HOSTED posture the passkey enrolment's
//! predecessor is the custodial host root, and the vault counts no `human`
//! binding that only a key in the host's custody signs, so the enrolment
//! over `POST /v1/owner/owner-passkeys/enroll` binds no one, and the
//! owner's owner verbs answer OWNER_BINDING_REQUIRED (`Memory::verify_owner`).
//! The browser then runs `POST .../bind/prepare` with the passkey's
//! credential id and `POST .../bind/land` with the passkey's assertion over
//! the challenge the prepare answered: an assertion made without verifying
//! the user is refused and binds no one, the verified one lands, the owner
//! verb passes, the changes list names `bound_by_passkey`, and a second prepare
//! is refused.
//!
//! Red on PR C (opus-ownerkey-p1/passkey-self-bind 907a860f45e): the routes
//! do not exist, so the prepare answers 404 and the owner stays unbound.
//! Green on the head.
//!
//! One test function: one server serves every step in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no models) with the
//! owner's own full human slip, on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test owner_passkey_binding_routes`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::{
    EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig, VaultDataKeyCustody,
    VaultPrivacyConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHALLENGE: &str = "/v1/owner/owner-passkeys/challenge";
const ENROLL: &str = "/v1/owner/owner-passkeys/enroll";
const BIND_PREPARE: &str = "/v1/owner/owner-passkeys/bind/prepare";
const BIND_LAND: &str = "/v1/owner/owner-passkeys/bind/land";
const CHANGES: &str = "/v1/owner/owner-signing-keys/changes";

/// SubjectPublicKeyInfo DER prefix of an uncompressed P-256 key
/// (id-ecPublicKey, prime256v1, BIT STRING of 66 bytes): the browser's
/// `getPublicKey()` returns this prefix and the point.
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bytes as base64url with no padding, as WebAuthn's JSON forms spell them.
fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Bytes the route spelled as base64url, padded or not.
fn b64url_decode(value: &str) -> TestResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|error| format!("expected base64url, saw {value:?}: {error}").into())
}

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// The passkey's key as `getPublicKey()` hands it: its SubjectPublicKeyInfo.
fn passkey_spki() -> Vec<u8> {
    let mut spki = SPKI_P256_PREFIX.to_vec();
    spki.extend_from_slice(passkey().verifying_key().to_encoded_point(false).as_bytes());
    spki
}

/// The passkey's key as the roster names it: compressed SEC1, hex.
fn passkey_compressed_hex() -> String {
    hex(passkey().verifying_key().to_encoded_point(true).as_bytes())
}

/// What `navigator.credentials.get` returns for `challenge`: authenticator
/// data (RP id hash, `flags`, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

/// What `navigator.credentials.get` returns for `challenge` when the
/// passkey `key` answers it at `origin`.
fn assert_by(key: &P256SigningKey, challenge: &[u8], flags: u8, origin: &str) -> Assertion {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = key.sign(&signed);
    Assertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
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
                key_ref: "kms://example/owner-passkey-binding-routes".to_owned(),
            },
        };
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owner-passkey-binding-routes".to_owned()),
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

    /// The owner enrols the passkey over HTTP; answers the passkey's key as
    /// compressed SEC1 hex.
    async fn enrol_passkey(&self) -> TestResult<String> {
        let public_key = b64url_encode(&passkey_spki());
        let (status, answer) = self
            .send(
                "POST",
                CHALLENGE,
                Some(json!({"public_key": public_key.clone()})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the challenge answers: {answer}");
        let challenge = b64url_decode(
            answer["challenge"]
                .as_str()
                .ok_or("the challenge answers base64url")?,
        )?;
        let assertion = assert_by(&passkey(), &challenge, FLAGS_PRESENT_VERIFIED, ORIGIN);
        let credential_id = b64url_encode(CREDENTIAL_ID);
        let (status, answer) = self
            .send(
                "POST",
                ENROLL,
                Some(json!({
                    "credential_id": credential_id,
                    "public_key": public_key,
                    "authenticator_data": b64url_encode(&assertion.authenticator_data),
                    "client_data_json": b64url_encode(&assertion.client_data_json),
                    "signature": b64url_encode(&assertion.signature),
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the enrolment lands: {answer}");
        let enrolled = answer["public_key"]
            .as_str()
            .ok_or("the enrolment answers the key as hex")?;
        assert_eq!(
            enrolled,
            passkey_compressed_hex(),
            "the enrolment names the passkey: {answer}"
        );
        Ok(passkey_compressed_hex())
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
fn a_managed_hosts_passkey_only_owner_binds_with_their_passkey_over_http() -> TestResult {
    on_engine_stack(managed_hosts_passkey_only_owner_binds_with_their_passkey)
}

async fn managed_hosts_passkey_only_owner_binds_with_their_passkey() -> TestResult {
    let host = Host::serve()?;

    // The owner enrols the passkey over HTTP; it binds no one.
    let public_key = host.enrol_passkey().await?;
    assert_eq!(
        host.owner_verb_refusal().as_deref(),
        Some(MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "the enrolment binds no one, so the owner verb answers OWNER_BINDING_REQUIRED"
    );

    // The passkey's binding is prepared.
    let credential_id = b64url_encode(CREDENTIAL_ID);
    let (status, answer) = host
        .send(
            "POST",
            BIND_PREPARE,
            Some(json!({"credential_id": credential_id.clone()})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the binding is prepared: {answer}");
    let entry = answer["entry"]
        .as_str()
        .ok_or("the prepare answers the entry as base64url")?
        .to_owned();
    let challenge = b64url_decode(
        answer["challenge"]
            .as_str()
            .ok_or("the prepare answers the challenge as base64url")?,
    )?;

    // An assertion made without verifying the user binds no one.
    let unverified = assert_by(&passkey(), &challenge, FLAGS_PRESENT_ONLY, ORIGIN);
    let (status, answer) = host
        .send(
            "POST",
            BIND_LAND,
            Some(json!({
                "entry": entry.clone(),
                "authenticator_data": b64url_encode(&unverified.authenticator_data),
                "client_data_json": b64url_encode(&unverified.client_data_json),
                "signature": b64url_encode(&unverified.signature),
            })),
        )
        .await?;
    assert!(
        !status.is_success(),
        "an unverified assertion is refused: {answer}"
    );
    assert_eq!(
        host.owner_verb_refusal().as_deref(),
        Some(MEMORY_CODE_OWNER_BINDING_REQUIRED),
        "the refused binding wrote nothing"
    );

    // The verified assertion lands the binding.
    let verified = assert_by(&passkey(), &challenge, FLAGS_PRESENT_VERIFIED, ORIGIN);
    let (status, answer) = host
        .send(
            "POST",
            BIND_LAND,
            Some(json!({
                "entry": entry.clone(),
                "authenticator_data": b64url_encode(&verified.authenticator_data),
                "client_data_json": b64url_encode(&verified.client_data_json),
                "signature": b64url_encode(&verified.signature),
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
        "the receipt names the passkey: {answer}"
    );
    assert_eq!(answer["epoch"], 1, "a passkey's first binding: {answer}");
    let receipt_entry = answer["entry"]
        .as_str()
        .ok_or("the receipt names the entry as hex")?
        .to_owned();
    assert_eq!(
        host.owner_verb_refusal(),
        None,
        "the bound owner's owner verb passes"
    );

    // Every owner device lists the binding.
    let (status, answer) = host.send("GET", CHANGES, None).await?;
    assert_eq!(status, StatusCode::OK, "the changes list reads: {answer}");
    let changes = answer["changes"]
        .as_array()
        .ok_or("the changes list names changes")?;
    assert!(
        changes.iter().any(
            |change| change["change"] == "bound_by_passkey" && change["entry"] == receipt_entry
        ),
        "the list names the binding's entry as bound_by_passkey: {answer}"
    );

    // A second binding of a bound owner is refused.
    let (status, answer) = host
        .send(
            "POST",
            BIND_PREPARE,
            Some(json!({"credential_id": credential_id})),
        )
        .await?;
    assert!(
        !status.is_success(),
        "a bound owner binds never again: {answer}"
    );
    Ok(())
}
