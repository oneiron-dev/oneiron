//! PASSKEY-VOUCH-PREPARE-PICKS-BY-CREDENTIAL-ID-ALONE over HTTP: the
//! owner's passkey vouches for a new device key from the browser, through
//! `POST /v1/owner/owner-passkeys/vouch/prepare` and `.../vouch/land`, on a
//! shared vault whose co-owner enrolled a passkey under the same credential
//! id.
//!
//! A credential id names no key across owners: enrolment takes the id the
//! browser posts, so the co-owner's live passkey may carry the owner's id,
//! and here it sorts first in the passkey list, which is ascending by key.
//! The owner's prepare picks the owner's own passkey as the predecessor, the
//! owner's verified assertion lands the enrollment, and the new device key
//! is a live owner root.
//!
//! Red on main (83f27a59201b): the prepare picks the first live passkey
//! with the credential id, the co-owner's, so the owner's assertion never
//! signs the prepared entry and the land is refused. Green on the head.
//!
//! REVIEW-10307 P1: the co-owner enrols the owner's own passkey, under the
//! same credential id, on a sibling branch of the owner's enrolment. Both
//! enrolments count, and the passkey list keeps one row per key, the
//! smallest entry's; the test adds sibling enrolments until that row is the
//! co-owner's. The owner's prepare still finds the owner's enrolment of the
//! key, and the owner's vouch lands. Red at 45cbfc35da82 (the prepare
//! matches the owner on the list's one row, the co-owner's, and refuses);
//! green on the head.
//!
//! The served vault is `recovery_hold_passkey_cancel_routes.rs`'s fixture
//! with no kit: a self-host vault rooted under its host, its owner bound by
//! the host root and holding a full human slip, made shared with a
//! co-Owner (the fixture of `passkey_owner_key.rs`'s `SharedVault`). One
//! server serves every step in process (`build_app(..).oneshot(..)`, no TCP
//! ports, no sleeps, no models), on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test owner_passkey_vouch_routes`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey, CapabilitySlip, HostSlipIssuer,
    MachineRole, OwnerPasskeyEnrollment, ROLE_OWNER, holder_proof,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::passkey_vouch_limits::{
    enrol_owner_passkey_on, main_log_heads, sign_as_host_root,
};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const VOUCH_PREPARE: &str = "/v1/owner/owner-passkeys/vouch/prepare";
const VOUCH_LAND: &str = "/v1/owner/owner-passkeys/vouch/land";

/// The seed of the new device key the owner's passkey vouches for.
const NEW_KEY_SEED: u8 = 41;
/// The credential id (`rawId`) both passkeys enrol under.
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkeys enrol at.
const ORIGIN: &str = "https://oneiron.test";
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// The scalar of the owner's passkey.
const OWNER_PASSKEY_SCALAR: u8 = 0x5A;
/// The shared vault's id.
const SHARED: u64 = 44;
/// The most sibling enrolments the co-owner makes before the passkey list
/// names the co-owner for the owner's passkey: each names it with chance
/// one half.
const SIBLING_ATTEMPTS: usize = 24;

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

/// A passkey a platform authenticator holds, as a software key.
fn passkey_of(scalar: u8) -> P256SigningKey {
    P256SigningKey::from_slice(&[scalar; 32]).expect("a P-256 scalar")
}

/// The owner's passkey.
fn passkey() -> P256SigningKey {
    passkey_of(OWNER_PASSKEY_SCALAR)
}

/// `key`'s public key as the roster names it: compressed SEC1.
fn compressed(key: &P256SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

/// A co-owner's passkey whose key sorts before the owner's, so a lookup by
/// credential id alone meets it first in the list, which is ascending by key.
fn co_owner_passkey() -> P256SigningKey {
    let owner = compressed(&passkey());
    (1..=u8::MAX)
        .filter(|scalar| *scalar != OWNER_PASSKEY_SCALAR)
        .map(passkey_of)
        .find(|key| compressed(key) < owner)
        .expect("a P-256 key that sorts before the owner's")
}

/// What `navigator.credentials.get` returns for `challenge` when the
/// passkey `key` answers it at its own origin with `flags`: authenticator
/// data (RP id hash, flags, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

fn assert_by(key: &P256SigningKey, challenge: &[u8], flags: u8) -> Assertion {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64url_encode(challenge)
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

/// A served self-host shared vault: its owner bound by the host root and
/// holding a full human slip, and a co-Owner.
struct Home {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
    owner_slip: CapabilitySlip,
    holder_key: SigningKey,
    _dir: tempfile::TempDir,
}

impl Home {
    fn serve() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing()?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owner-passkey-vouch-routes".to_owned()),
                ..Default::default()
            },
        )?);
        let issuer: HostSlipIssuer = vault.bootstrap_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        vault.provision_engine_machine_identities(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::HostedNode)?;
        let person = vault.ensure_embedded_owner_actor()?;
        bind_host_owner(&vault, &issuer, person)?;
        vault.ensure_vault_key()?;
        let machine = vault.prepare_install_signing()?;
        let holder_key = SigningKey::from_bytes(&[0x5C; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0xC2; 32];
        claims.parent_id = None;
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key.verifying_key().to_bytes();
        let owner_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            person,
            machine,
            owner_slip,
            holder_key,
            _dir: dir,
        })
    }

    fn owner(&self) -> TestResult<AuthenticatedOwner> {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> TestResult<ActAuthority> {
        Ok(ActAuthority::Owner(self.owner()?, ActSurface::ThisInstall))
    }

    /// `person`'s authority and the enrollment of `key` as their passkey,
    /// with the credential id [`CREDENTIAL_ID`].
    fn passkey_enrollment(
        &self,
        person: EntityId,
        key: &P256SigningKey,
    ) -> TestResult<(ActAuthority, OwnerPasskeyEnrollment)> {
        let authority = ActAuthority::Owner(proof(&self.vault, person)?, ActSurface::ThisInstall);
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let challenge = self
            .vault
            .owner_passkey_enrollment_challenge_as(&authority, &public_key)?;
        let assertion = assert_by(key, &challenge, FLAGS_PRESENT_VERIFIED);
        let input = OwnerPasskeyEnrollment {
            credential_id: CREDENTIAL_ID.to_vec(),
            public_key,
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
            signature: assertion.signature,
        };
        Ok((authority, input))
    }

    /// Enrols `key` as `person`'s passkey, with the credential id
    /// [`CREDENTIAL_ID`], under the host root.
    fn enrol_passkey_as(&self, person: EntityId, key: &P256SigningKey) -> TestResult {
        let (authority, input) = self.passkey_enrollment(person, key)?;
        self.vault
            .enrol_owner_passkey_as_host(&authority, &input, &self.issuer)?;
        Ok(())
    }

    /// Enrols `key` as `person`'s passkey on `parents`, a sibling branch of
    /// every row stored since, under the host root; true when it counted.
    fn enrol_passkey_on(
        &self,
        person: EntityId,
        key: &P256SigningKey,
        parents: Vec<AuthorityEntryHash>,
    ) -> TestResult<bool> {
        let (authority, input) = self.passkey_enrollment(person, key)?;
        Ok(enrol_owner_passkey_on(
            &self.vault,
            &authority,
            &input,
            parents,
            self.issuer.public_key(),
            |transcript| sign_as_host_root(&self.issuer, transcript),
        )?)
    }

    /// The owner the passkey list's row of `key` names.
    fn listed_owner_of(&self, key: &P256SigningKey) -> TestResult<EntityId> {
        let public_key = compressed(key);
        Ok(self
            .vault
            .enrolled_owner_passkeys()?
            .into_iter()
            .find(|passkey| passkey.live && passkey.public_key == public_key)
            .ok_or("a live row of the passkey")?
            .owner)
    }

    /// Makes the vault shared and adds a live person as a co-Owner, as
    /// `add_owner` runs at once for its only owner; the co-Owner's id.
    fn add_co_owner(&self) -> TestResult<EntityId> {
        self.vault.initialize_shared_vault(
            &self.owner()?,
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: self.person,
                role: Some(FederationGrantRole::Owner),
            }],
            1,
        )?;
        let co_owner = EntityId::now();
        self.vault.put_entity(
            &co_owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
        let act = self
            .vault
            .propose_add_owner(&self.owner()?, SHARED, co_owner)?;
        self.vault
            .execute_completed_shared_act(&self.owner()?, &act.id, Some(&self.issuer))?;
        Ok(co_owner)
    }

    /// The vouch request for the device key `key` on this install's
    /// machine, its proof over the enrollment challenge, by the passkey
    /// [`CREDENTIAL_ID`].
    fn vouch_prepare_body(&self, key: &SigningKey) -> TestResult<Value> {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self.vault.owner_key_enrollment_challenge_as(
            &self.authority()?,
            self.machine,
            &public_key,
        )?;
        Ok(json!({
            "machine": self.machine.to_hex(),
            "public_key": hex(&public_key),
            "proof": hex(&key.sign(&challenge).to_bytes()),
            "credential_id": b64url_encode(CREDENTIAL_ID),
        }))
    }

    /// `key` is a live owner root on the roster.
    fn live_owner_key(&self, key: &AuthorityKey) -> TestResult<bool> {
        Ok(self
            .vault
            .authority_fold()?
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0))
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

fn proof(vault: &Vault, person: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

#[test]
fn a_co_owners_passkey_under_the_same_credential_id_never_vouches_for_the_owner() -> TestResult {
    on_engine_stack(co_owners_passkey_under_the_same_credential_id_never_vouches_for_the_owner)
}

async fn co_owners_passkey_under_the_same_credential_id_never_vouches_for_the_owner() -> TestResult
{
    let home = Home::serve()?;
    home.enrol_passkey_as(home.person, &passkey())?;
    let co_owner = home.add_co_owner()?;
    home.enrol_passkey_as(co_owner, &co_owner_passkey())?;
    let first = home
        .vault
        .enrolled_owner_passkeys()?
        .into_iter()
        .find(|passkey| passkey.live && passkey.credential_id == CREDENTIAL_ID)
        .ok_or("a live passkey with the credential id")?;
    assert_eq!(
        first.owner, co_owner,
        "the co-owner's passkey is listed first under the shared credential id"
    );
    owners_passkey_vouches_for_a_new_device_key(&home).await
}

#[test]
fn an_owners_passkey_listed_under_a_co_owners_sibling_enrolment_still_vouches() -> TestResult {
    on_engine_stack(owners_passkey_listed_under_a_co_owners_sibling_enrolment_still_vouches)
}

async fn owners_passkey_listed_under_a_co_owners_sibling_enrolment_still_vouches() -> TestResult {
    let home = Home::serve()?;
    let co_owner = home.add_co_owner()?;
    let fork = main_log_heads(&home.vault)?;
    home.enrol_passkey_as(home.person, &passkey())?;
    assert_eq!(
        home.listed_owner_of(&passkey())?,
        home.person,
        "guard: the owner's enrolment of the passkey is listed"
    );
    // The co-owner enrols the same passkey on a sibling branch until the
    // list's row of it is a co-owner's enrolment, the smallest entry.
    for _ in 0..SIBLING_ATTEMPTS {
        if home.listed_owner_of(&passkey())? == co_owner {
            break;
        }
        assert!(
            home.enrol_passkey_on(co_owner, &passkey(), fork.clone())?,
            "the co-owner's sibling enrolment of the passkey counts"
        );
    }
    assert_eq!(
        home.listed_owner_of(&passkey())?,
        co_owner,
        "the passkey list names the co-owner for the owner's passkey"
    );
    owners_passkey_vouches_for_a_new_device_key(&home).await
}

/// The owner's passkey vouches for a new device key over HTTP: the
/// prepare picks the owner's own passkey as the predecessor, the owner's
/// verified assertion lands the enrollment, and the key is a live owner
/// root.
async fn owners_passkey_vouches_for_a_new_device_key(home: &Home) -> TestResult {
    // The owner's prepare picks the owner's own passkey as the predecessor.
    let device = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let device_key = AuthorityKey::Ed25519(device.verifying_key().to_bytes());
    let (status, answer) = home
        .send(
            "POST",
            VOUCH_PREPARE,
            Some(home.vouch_prepare_body(&device)?),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner's own passkey prepares the vouch: {answer}"
    );
    let entry = answer["entry"]
        .as_str()
        .ok_or("the prepare answers the entry as base64url")?
        .to_owned();
    let challenge = b64url_decode(
        answer["challenge"]
            .as_str()
            .ok_or("the prepare answers the challenge as base64url")?,
    )?;

    // The owner's passkey signs it, and the new device key lands.
    let verified = assert_by(&passkey(), &challenge, FLAGS_PRESENT_VERIFIED);
    let (status, answer) = home
        .send(
            "POST",
            VOUCH_LAND,
            Some(json!({
                "entry": entry,
                "authenticator_data": b64url_encode(&verified.authenticator_data),
                "client_data_json": b64url_encode(&verified.client_data_json),
                "signature": b64url_encode(&verified.signature),
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the owner's vouch lands: {answer}");
    assert_eq!(
        answer["public_key"],
        hex(&device.verifying_key().to_bytes()),
        "the receipt names the new device key: {answer}"
    );
    assert_eq!(
        answer["machine"],
        home.machine.to_hex(),
        "the receipt names the device key's machine: {answer}"
    );
    assert!(
        home.live_owner_key(&device_key)?,
        "the device key the owner's passkey vouched for is a live owner root"
    );
    Ok(())
}
