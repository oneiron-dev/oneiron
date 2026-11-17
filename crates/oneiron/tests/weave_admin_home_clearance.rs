//! A weave Admin who is not the vault's owner reads its weave report under
//! the conversation home (L5-02 PR 3, FIX-LIST
//! [WEAVE-ADMIN-HOME-CLEARANCE-TEST]), public API only.
//!
//! The vault is shared: its embedded owner is Owner and a second PERSON is
//! Admin, having accepted its founding invitation. The Admin holds a
//! credential of its own, steps it up with an enrolled passkey (WebAuthn,
//! EdDSA) and reads the weave Admin report under that proof. Two claims about
//! one PERSON carry the report's predicate: one unstamped, one stamped
//! `sensitivity: private`. The Admin is neither the vault's owner nor one of
//! its own agents, so its key is homed: its report withholds the private
//! claim's entry and still shows the unstamped one. Before the fix the Admin
//! key was built un-homed and the report showed both (fix:
//! `for_weave_admin_in_txn` in `claim/scoped_read/actor_key/weave_admin.rs`
//! builds `homed_unnamed` unless the Admin is the vault's owner). The LEAK
//! assertion is red at c6e6336ac1c9 and green at 7bfff97f9a22. The owner's
//! own weave report still shows both entries (over-refusal guard).
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertion comes last. Deterministic: in-process vault, no server, no
//! models, no embedder.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! weave_admin_home_clearance`.

use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AdminStepUp, CapabilitySlip, HostSlipIssuer, PasskeyAssertion, PasskeyRegistration,
    StepUpCeremony, VerifiedSlip,
};
use oneiron::claim::{
    WeaveItemView, WeaveReportRequest, WeaveReportView, WeaveSectionInput, WeaveSectionKind,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shared vault's id.
const SHARED: u64 = 42;
/// When the seeded rows were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The report's predicate, which the shipped policy manifest names normal.
const PREDICATE: &str = "profile.note";
/// The Admin's holder-proof challenge: the seal is what is verified, not the
/// freshness of the request.
const ADMIN_CHALLENGE: &[u8] = b"weave admin home clearance read";
/// The RP id the Admin's passkey is enrolled under, and the secure origin
/// its ceremonies run at.
const RP_ID: &str = "vault.test";
const ORIGIN: &str = "https://vault.test";
/// COSE algorithm identifier for EdDSA over Ed25519.
const COSE_EDDSA: i64 = -8;
/// SubjectPublicKeyInfo DER prefix of an Ed25519 key (id-Ed25519, BIT
/// STRING of 33 bytes), as the browser's `getPublicKey()` returns it.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Authenticator data flags: user present and user verified, and attested
/// credential data following the fixed header.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
const FLAG_ATTESTED: u8 = 0x40;
/// The Admin's passkey credential id.
const CREDENTIAL_ID: [u8; 16] = [0x5a; 16];

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    admin: EntityId,
    /// The Admin's one Admin membership grant in the shared vault.
    admin_grant: EntityId,
    issuer: HostSlipIssuer,
    admin_slip: CapabilitySlip,
    admin_key: SigningKey,
    unstamped: EntityId,
    private_stamped: EntityId,
}

fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn person(vault: &Vault, id: EntityId, body: &[u8]) -> TestResult {
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
        body,
    )?;
    Ok(())
}

fn person_proof(vault: &Vault, person: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

/// One Approved, Active claim about `subject` under [`PREDICATE`], holding
/// `text`, stamped `sensitivity` when a band is named.
fn seed_claim(
    vault: &Vault,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
) -> TestResult<EntityId> {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    let id = EntityId::now();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
    )?;
    Ok(id)
}

/// The id of the one live membership grant naming `member` at Admin.
fn admin_grant_of(vault: &Vault, member: EntityId) -> TestResult<EntityId> {
    let mut grants = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)? {
        let Some(body) = vault.get(&id)? else {
            continue;
        };
        let Ok(grant) = oneiron::federation::decode_federation_grant_body(&body) else {
            continue;
        };
        if grant.member_ref == member && grant.role == FederationGrantRole::Admin {
            grants.push(id);
        }
    }
    let [grant] = grants.as_slice() else {
        return Err(format!("FIXTURE: one Admin membership grant, found {grants:?}").into());
    };
    Ok(*grant)
}

/// The report's one section: the claims under [`PREDICATE`].
fn note_report() -> WeaveReportRequest {
    WeaveReportRequest {
        sections: vec![WeaveSectionInput {
            kind: WeaveSectionKind::Conflicts,
            predicates: vec![PREDICATE.to_owned()],
            edge_kinds: Vec::new(),
        }],
    }
}

/// The claim refs `view` shows, over all its sections.
fn shown_claims(view: &WeaveReportView) -> BTreeSet<String> {
    view.sections
        .iter()
        .flat_map(|section| section.items.iter())
        .filter_map(|item| match item {
            WeaveItemView::Claim { claim } => Some(claim.claim_ref.clone()),
            _ => None,
        })
        .collect()
}

/// `CollectedClientData` for one ceremony of `kind` over `challenge`, at
/// [`ORIGIN`].
fn client_data(kind: &str, challenge: &str) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": challenge,
        "origin": ORIGIN,
        "crossOrigin": false,
    }))?)
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open_owned(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let owner_proof = person_proof(&vault, owner)?;
        let admin = EntityId::now();
        person(&vault, admin, b"the weave admin")?;
        let subject = EntityId::now();
        person(&vault, subject, b"the claims' subject")?;

        // The shared vault, its owner at Owner and the second PERSON at
        // Admin, who accepts its founding invitation.
        vault.initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(FederationGrantRole::Admin),
                },
            ],
            1,
        )?;
        let admin_proof = person_proof(&vault, admin)?;
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED)?
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Admin)
            .ok_or("FIXTURE: the Admin holds its founding invitation")?;
        vault.accept_shared_invitation(&admin_proof, SHARED, &invitation.id)?;
        let admin_grant = admin_grant_of(&vault, admin)?;

        let unstamped = seed_claim(&vault, subject, "an unstamped note", None)?;
        let private_stamped = seed_claim(&vault, subject, "a private note", Some("private"))?;

        // The host roots the vault and mints the Admin a credential of its
        // own, a live PERSON's slip with no delegation, which the Admin
        // proves with its key.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-weave-admin-home-clearance")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let admin_key = SigningKey::from_bytes(&[0x68; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0x68; 32];
        claims.parent_id = None;
        claims.holder_ref = admin.to_hex();
        claims.binding_key = admin_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        let admin_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            admin,
            admin_grant,
            issuer,
            admin_slip,
            admin_key,
            unstamped,
            private_stamped,
        })
    }

    fn verified_admin(&self) -> TestResult<VerifiedSlip> {
        let transcript = self.admin_slip.binding_transcript(ADMIN_CHALLENGE)?;
        let signature = self.admin_key.sign(&transcript).to_bytes();
        Ok(self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &self.admin_slip,
            ADMIN_CHALLENGE,
            &signature,
        )?)
    }

    /// Enrolls an Ed25519 passkey for the Admin on `request`'s slip, steps
    /// the slip up with it, and returns the step-up witness the slip holds.
    fn step_up(&self, request: &VerifiedSlip) -> TestResult<AdminStepUp> {
        let passkey = SigningKey::from_bytes(&[0x69; 32]);
        let enroll = self
            .vault
            .open_step_up_ceremony(request, StepUpCeremony::Enroll)?;
        // rpIdHash, flags, signCount 0, then the attested credential data:
        // AAGUID (16 zero bytes), the id's length and the id.
        let mut registration_data = sha256(RP_ID.as_bytes()).to_vec();
        registration_data.push(FLAGS_PRESENT_VERIFIED | FLAG_ATTESTED);
        registration_data.extend_from_slice(&0_u32.to_be_bytes());
        registration_data.extend_from_slice(&[0; 16]);
        registration_data.extend_from_slice(&u16::try_from(CREDENTIAL_ID.len())?.to_be_bytes());
        registration_data.extend_from_slice(&CREDENTIAL_ID);
        let mut spki = SPKI_ED25519_PREFIX.to_vec();
        spki.extend_from_slice(&passkey.verifying_key().to_bytes());
        self.vault.enroll_step_up_passkey(
            request,
            &PasskeyRegistration {
                challenge: enroll.challenge.clone(),
                rp_id: RP_ID.to_owned(),
                credential_id: base64url(&CREDENTIAL_ID),
                client_data_json: base64url(&client_data("webauthn.create", &enroll.challenge)?),
                authenticator_data: base64url(&registration_data),
                public_key: base64url(&spki),
                algorithm: COSE_EDDSA,
                label: None,
            },
        )?;

        let assert = self
            .vault
            .open_step_up_ceremony(request, StepUpCeremony::Assert)?;
        let client_data_json = client_data("webauthn.get", &assert.challenge)?;
        let mut assertion_data = sha256(RP_ID.as_bytes()).to_vec();
        assertion_data.push(FLAGS_PRESENT_VERIFIED);
        assertion_data.extend_from_slice(&1_u32.to_be_bytes());
        let mut signed = assertion_data.clone();
        signed.extend_from_slice(&sha256(&client_data_json));
        let signature = passkey.sign(&signed).to_bytes();
        self.vault.step_up_with_passkey(
            request,
            &PasskeyAssertion {
                challenge: assert.challenge.clone(),
                credential_id: base64url(&CREDENTIAL_ID),
                client_data_json: base64url(&client_data_json),
                authenticator_data: base64url(&assertion_data),
                signature: base64url(&signature),
            },
        )?;
        Ok(self
            .vault
            .admin_step_up(request)?
            .ok_or("FIXTURE: the Admin's step-up stands on its slip")?)
    }

    /// The claim refs the Admin's own weave Admin report shows.
    fn admin_report(&self) -> TestResult<BTreeSet<String>> {
        let request = self.verified_admin()?;
        let step_up = self.step_up(&request)?;
        let proof = self
            .vault
            .authenticate_weave_admin(&request, self.admin_grant, &step_up)?;
        let view = self
            .vault
            .memory(self.admin, EdgeActorClass::Human)
            .weave_admin_report(&proof, &note_report())?;
        Ok(shown_claims(&view))
    }
}

#[test]
fn a_non_owner_admins_weave_report_withholds_a_private_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let shown = fixture.admin_report()?;
    assert!(
        shown.contains(&fixture.unstamped.to_hex()),
        "FIXTURE: the Admin's weave report shows the unstamped claim: {shown:?}"
    );
    assert!(
        !shown.contains(&fixture.private_stamped.to_hex()),
        "LEAK: the weave Admin report of an Admin who is not the vault's owner shows a \
         private-stamped claim's entry"
    );
    Ok(())
}

#[test]
fn the_owners_weave_report_shows_the_private_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let view = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .weave_report(Some(&fixture.owner_proof), &note_report())?;
    let shown = shown_claims(&view);
    let withheld: Vec<&str> = [
        (fixture.unstamped, "unstamped"),
        (fixture.private_stamped, "private"),
    ]
    .into_iter()
    .filter(|(id, _)| !shown.contains(&id.to_hex()))
    .map(|(_, band)| band)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the owner's weave report withholds the {withheld:?} claims"
    );
    Ok(())
}
