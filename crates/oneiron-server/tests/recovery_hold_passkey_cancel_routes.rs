//! RECOVERY-HOLD-PASSKEY-CANCEL-ROUTE over HTTP: an owner whose passkey is
//! an owner key reads a box recovery's wait and cancels it from the
//! browser, the passkey signing the Cancel with a user-verified assertion.
//!
//! The served vault is `recovery_hold_passkey_cancel.rs`'s engine fixture
//! (a self-host vault rooted under its host, with a confirmed kit), with the
//! owner's passkey and a device key that is lost enrolled, and a box
//! recovery held through the test door. Over HTTP, `GET
//! /v1/owner/recovery-holds` lists the hold as waiting; `POST
//! .../owner-passkeys/recovery-hold-cancel/prepare` with the passkey's
//! credential id answers the unsigned Cancel and its challenge; an
//! assertion made without verifying the person cancels nothing; the
//! verified one lands through `.../recovery-hold-cancel/land`; the list then
//! names the hold cancelled by the owner, and a second prepare is refused,
//! since the hold is no longer live.
//!
//! A credential id names no key across owners (enrolment takes the id the
//! browser posts): on a shared vault whose co-owner enrolled a passkey with
//! the owner's credential id, listed first, the owner's prepare still picks
//! the owner's own passkey, and its Cancel lands (review round 1 of #10288,
//! P1).
//!
//! Red on main (beff0851b5bf): the routes do not exist, so the list and the
//! prepare answer 404. Red at the routes that picked a passkey by credential
//! id alone: the co-owner's key prepares, and the door refuses it as not the
//! acting owner's. Green on the head.
//!
//! Each test function: one server serves every step in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no models) with
//! the owner's own full human slip, on an engine-sized stack.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test recovery_hold_passkey_cancel_routes`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey, CapabilitySlip, HostSlipIssuer,
    MachineRole, OwnerKeyEnrollment, OwnerPasskeyEnrollment, RootMaterial, RootRecovery,
    RootSuccessor, holder_proof,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_doors::root_recovery::{recover_owner_root_waiting, released_authority_seed};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const HOLDS: &str = "/v1/owner/recovery-holds";
const CANCEL_PREPARE: &str = "/v1/owner/owner-passkeys/recovery-hold-cancel/prepare";
const CANCEL_LAND: &str = "/v1/owner/owner-passkeys/recovery-hold-cancel/land";

/// The wait the box recovery holds with: one hour.
const WAIT: Duration = Duration::from_secs(60 * 60);
/// The seed of the owner's device key that is lost.
const LOST_KEY_SEED: u8 = 21;
/// The seed of the successor key the box recovery would enrol.
const NEW_KEY_SEED: u8 = 41;
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;
/// The scalar of the owner's passkey.
const OWNER_PASSKEY_SCALAR: u8 = 0x5A;
/// The shared vault's id.
const SHARED: u64 = 44;

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
/// passkey answers it at its own origin with `flags`: authenticator data (RP
/// id hash, flags, a zero sign count), the client data JSON, and the DER
/// signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

fn assert_with(challenge: &[u8], flags: u8) -> Assertion {
    assert_by(&passkey(), challenge, flags)
}

/// [`assert_with`] for the passkey `key`.
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

fn land_body(entry: &str, assertion: &Assertion) -> Value {
    json!({
        "entry": entry,
        "authenticator_data": b64url_encode(&assertion.authenticator_data),
        "client_data_json": b64url_encode(&assertion.client_data_json),
        "signature": b64url_encode(&assertion.signature),
    })
}

/// A served self-host vault with a confirmed world kit, the owner's passkey
/// and a lost device key enrolled, and the owner holding a full human slip.
struct Home {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
    vault_id: [u8; 32],
    pieces: Vec<KitPiece>,
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
                auth_secret: Some("recovery-hold-passkey-cancel-routes".to_owned()),
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
        let vault_id = vault
            .authority_fold()?
            .vault_id
            .ok_or("the vault is rooted")?;
        let holder_key = SigningKey::from_bytes(&[0x5C; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0xC2; 32];
        claims.parent_id = None;
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key.verifying_key().to_bytes();
        let owner_slip = vault.mint_capability_slip(&issuer, claims)?;
        let issued = vault.issue_world_kit(
            &proof(&vault, person)?,
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
        let home = Self {
            app: build_app(server),
            vault,
            issuer,
            person,
            machine,
            vault_id,
            pieces: issued.pieces,
            owner_slip,
            holder_key,
            _dir: dir,
        };
        home.vault
            .confirm_world_kit(&home.owner()?, &home.kit_refs(), None, &BTreeSet::new())?;
        Ok(home)
    }

    fn owner(&self) -> TestResult<AuthenticatedOwner> {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> TestResult<ActAuthority> {
        Ok(ActAuthority::Owner(self.owner()?, ActSurface::ThisInstall))
    }

    fn kit_refs(&self) -> Vec<&KitPiece> {
        self.pieces.iter().take(2).collect()
    }

    /// `key`'s enrolment input for this vault and owner.
    fn enrollment(&self, key: &SigningKey) -> TestResult<OwnerKeyEnrollment> {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self.vault.owner_key_enrollment_challenge_as(
            &self.authority()?,
            self.machine,
            &public_key,
        )?;
        Ok(OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        })
    }

    /// Enrols a device key (not this install's) under the host root.
    fn enrol_device_key(&self, seed: u8) -> TestResult<AuthorityKey> {
        let key = SigningKey::from_bytes(&[seed; 32]);
        self.vault.enrol_owner_signing_key_as_host(
            &self.authority()?,
            self.enrollment(&key)?,
            &self.issuer,
        )?;
        Ok(AuthorityKey::Ed25519(key.verifying_key().to_bytes()))
    }

    /// Enrols the owner's passkey under the host root, its assertion over
    /// the enrollment challenge at its own origin.
    fn enrol_passkey(&self) -> TestResult {
        self.enrol_passkey_as(self.person, &passkey())
    }

    /// Enrols `key` as `person`'s passkey, with the credential id
    /// [`CREDENTIAL_ID`], under the host root.
    fn enrol_passkey_as(&self, person: EntityId, key: &P256SigningKey) -> TestResult {
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
        self.vault
            .enrol_owner_passkey_as_host(&authority, &input, &self.issuer)?;
        Ok(())
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

    /// Generation 0's key as the box releases it: a box recovery.
    fn released_material(&self) -> TestResult<RootMaterial> {
        let secret = restore_kit(
            self.vault_id,
            KitSecretKind::RecoveryRoot,
            &self.kit_refs(),
            None,
        )
        .expect("two pieces restore the seed");
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        let root = seed.public(&self.vault_id)?.id;
        Ok(RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&seed, &self.vault_id, 0),
                &self.vault_id,
                root,
            )?,
        ))
    }

    /// A box recovery that waits: its hold (the attempt id) and its landing
    /// second, enrolling `successor` and revoking `lost`.
    fn hold(
        &self,
        successor: &SigningKey,
        lost: &AuthorityKey,
    ) -> TestResult<(AuthorityEntryHash, u64)> {
        let answer = recover_owner_root_waiting(
            &self.vault,
            &self.owner()?,
            ActSurface::ThisInstall,
            self.released_material()?,
            RootSuccessor::Device(self.enrollment(successor)?),
            std::slice::from_ref(lost),
            WAIT,
        )?;
        let RootRecovery::Held { hold, lands_at } = answer else {
            return Err("the box recovery holds with a nonzero wait".into());
        };
        Ok((hold, lands_at))
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

    /// The one hold `GET /v1/owner/recovery-holds` lists.
    async fn listed_hold(&self) -> TestResult<Value> {
        let (status, answer) = self.send("GET", HOLDS, None).await?;
        assert_eq!(status, StatusCode::OK, "the hold list reads: {answer}");
        let holds = answer["holds"]
            .as_array()
            .ok_or("the hold list names holds")?;
        assert_eq!(holds.len(), 1, "one recovery hold: {answer}");
        Ok(holds[0].clone())
    }
}

fn proof(vault: &Vault, person: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

#[test]
fn a_passkey_owner_reads_a_box_recovery_and_cancels_it_over_http() -> TestResult {
    on_engine_stack(passkey_owner_reads_a_box_recovery_and_cancels_it)
}

async fn passkey_owner_reads_a_box_recovery_and_cancels_it() -> TestResult {
    let home = Home::serve()?;
    home.enrol_passkey()?;
    let lost = home.enrol_device_key(LOST_KEY_SEED)?;
    let successor = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, lands_at) = home.hold(&successor, &lost)?;
    let hold_hex = hex(&hold);
    let person_hex = home.person.to_hex();

    // The owner reads the recovery's wait.
    let listed = home.listed_hold().await?;
    assert_eq!(listed["hold"], hold_hex, "the attempt id: {listed}");
    assert_eq!(listed["state"], "waiting", "the hold waits: {listed}");
    assert_eq!(listed["lands_at"], lands_at, "its landing second: {listed}");
    assert_eq!(listed["owner"], person_hex, "whose recovery: {listed}");
    assert_eq!(
        listed["successor_machine"],
        home.machine.to_hex(),
        "the successor's machine: {listed}"
    );
    assert_eq!(
        listed["successor_key"],
        hex(&successor.verifying_key().to_bytes()),
        "the successor key: {listed}"
    );
    let AuthorityKey::Ed25519(lost_bytes) = &lost else {
        return Err("the lost key is a device key".into());
    };
    assert_eq!(
        listed["lost"],
        json!([hex(lost_bytes)]),
        "the lost key: {listed}"
    );
    assert_eq!(
        listed["cancelled_by"],
        json!([]),
        "nobody cancelled: {listed}"
    );

    // A credential id no live passkey has prepares nothing.
    let (status, answer) = home
        .send(
            "POST",
            CANCEL_PREPARE,
            Some(json!({"hold": hold_hex.clone(), "credential_id": b64url_encode(b"another")})),
        )
        .await?;
    assert!(
        !status.is_success(),
        "an unknown credential id is refused: {answer}"
    );

    // The passkey's Cancel is prepared.
    let credential_id = b64url_encode(CREDENTIAL_ID);
    let (status, answer) = home
        .send(
            "POST",
            CANCEL_PREPARE,
            Some(json!({"hold": hold_hex.clone(), "credential_id": credential_id.clone()})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "the Cancel is prepared: {answer}");
    let entry = answer["entry"]
        .as_str()
        .ok_or("the prepare answers the entry as base64url")?
        .to_owned();
    let challenge = b64url_decode(
        answer["challenge"]
            .as_str()
            .ok_or("the prepare answers the challenge as base64url")?,
    )?;

    // An assertion made without verifying the person cancels nothing.
    let unverified = assert_with(&challenge, FLAGS_PRESENT_ONLY);
    let (status, answer) = home
        .send("POST", CANCEL_LAND, Some(land_body(&entry, &unverified)))
        .await?;
    assert!(
        !status.is_success(),
        "an unverified assertion is refused: {answer}"
    );
    let listed = home.listed_hold().await?;
    assert_eq!(
        listed["state"], "waiting",
        "the refused Cancel wrote nothing: {listed}"
    );

    // The verified assertion lands the Cancel.
    let verified = assert_with(&challenge, FLAGS_PRESENT_VERIFIED);
    let (status, answer) = home
        .send("POST", CANCEL_LAND, Some(land_body(&entry, &verified)))
        .await?;
    assert_eq!(status, StatusCode::OK, "the Cancel lands: {answer}");
    let cancel = answer["entry"]
        .as_str()
        .ok_or("the receipt names the Cancel's entry as hex")?;
    assert_eq!(cancel.len(), 64, "a 64-hex entry hash: {answer}");
    assert_ne!(cancel, hold_hex, "the Cancel is its own entry: {answer}");

    // The hold is cancelled, by the owner, and is no longer live.
    let listed = home.listed_hold().await?;
    assert_eq!(
        listed["state"], "cancelled",
        "the hold is cancelled: {listed}"
    );
    assert_eq!(
        listed["cancelled_by"],
        json!([person_hex]),
        "the hold names the owner whose passkey cancelled it: {listed}"
    );
    let (status, answer) = home
        .send(
            "POST",
            CANCEL_PREPARE,
            Some(json!({"hold": hold_hex, "credential_id": credential_id})),
        )
        .await?;
    assert!(
        !status.is_success(),
        "a cancelled hold prepares no second Cancel: {answer}"
    );
    Ok(())
}

#[test]
fn a_co_owners_passkey_under_the_same_credential_id_never_signs_for_the_owner() -> TestResult {
    on_engine_stack(co_owners_passkey_under_the_same_credential_id_never_signs_for_the_owner)
}

async fn co_owners_passkey_under_the_same_credential_id_never_signs_for_the_owner() -> TestResult {
    let home = Home::serve()?;
    home.enrol_passkey()?;
    let lost = home.enrol_device_key(LOST_KEY_SEED)?;
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
    let successor = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, _) = home.hold(&successor, &lost)?;

    // The owner's prepare picks the owner's own passkey.
    let (status, answer) = home
        .send(
            "POST",
            CANCEL_PREPARE,
            Some(json!({"hold": hex(&hold), "credential_id": b64url_encode(CREDENTIAL_ID)})),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner's own passkey prepares the Cancel: {answer}"
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

    // The owner's passkey signs it, and it lands.
    let verified = assert_with(&challenge, FLAGS_PRESENT_VERIFIED);
    let (status, answer) = home
        .send("POST", CANCEL_LAND, Some(land_body(&entry, &verified)))
        .await?;
    assert_eq!(status, StatusCode::OK, "the owner's Cancel lands: {answer}");
    let listed = home.listed_hold().await?;
    assert_eq!(
        listed["state"], "cancelled",
        "the hold is cancelled: {listed}"
    );
    assert_eq!(
        listed["cancelled_by"],
        json!([home.person.to_hex()]),
        "the owner cancelled it: {listed}"
    );
    Ok(())
}
