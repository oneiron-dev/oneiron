//! A member credential's saved lane reads while its membership grant still
//! confers what the lane reads (round 2 review P1 of #9583, frozen.rs:120),
//! public API only.
//!
//! The vault is shared: its embedded owner is Owner and a second PERSON is
//! Admin, having accepted its founding invitation. The Admin holds a
//! credential that names its Admin grant and holds a verb the grant does
//! not confer, `derive`, as a slip minted before a role move that narrowed
//! its grant's verbs does: the grant keeps its id and the slip stays
//! unrevoked. Each fresh verification meets the proof to the grant's
//! current verbs, so the Admin's live lane reads. The Admin is neither the
//! vault's owner nor one of its own agents, so its key is homed in no
//! conversation of this vault, and since #9583 such a lane saves. Each
//! rebuild then judged the credential by its mint, whose `derive` is no
//! narrowing of the grant, and read nothing. A saved lane only reads: it
//! now judges the mint's read Scope, its verbs met to `read`, against the
//! grant, and every expiry, revocation and reference check stands. Guard:
//! once the credential is revoked, the rebuild and a key rebuilt before the
//! revocation read nothing.
//!
//! Red at #9583's 6c4a4f1ec78: the rebuild over the Admin's own credential
//! key reads nothing. Each `FIXTURE:` assertion checks the setup.
//! Deterministic: in-process vault, no server, no models, no embedder.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! saved_member_lane_read_scope`.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, VerifiedSlip};
use oneiron::claim::{FrozenReadLane, PointRead, ScopedRead, ScopedReadActorKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shared vault's id.
const SHARED: u64 = 44;
/// When the seeded rows were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The seeded claims' predicate, which the shipped policy manifest names
/// normal.
const PREDICATE: &str = "profile.note";
/// The Admin's holder-proof challenge: the seal is what is verified, not the
/// freshness of the request.
const ADMIN_CHALLENGE: &[u8] = b"saved member lane read scope";
/// The Admin's credential id and binding key seed.
const ADMIN_SLIP_ID: [u8; 32] = [0x6c; 32];
const ADMIN_BINDING_SEED: u8 = 0x6d;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    admin_slip: CapabilitySlip,
    admin_key: SigningKey,
    unstamped: EntityId,
    private_stamped: EntityId,
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

/// The id of the one live membership grant naming `member` at Admin, and
/// its verbs.
fn admin_grant_of(vault: &Vault, member: EntityId) -> TestResult<(EntityId, ScopeAxis<String>)> {
    let mut grants = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)? {
        let Some(body) = vault.get(&id)? else {
            continue;
        };
        let Ok(grant) = oneiron::federation::decode_federation_grant_body(&body) else {
            continue;
        };
        if grant.member_ref == member && grant.role == FederationGrantRole::Admin {
            grants.push((id, grant.authority_scope.verbs));
        }
    }
    let [grant] = grants.as_slice() else {
        return Err(format!("FIXTURE: one Admin membership grant, found {grants:?}").into());
    };
    Ok(grant.clone())
}

/// Whether `lane` serves `id` by point read: a withheld row reads as `None`,
/// exactly like a missing one.
fn lane_reads(lane: &ScopedRead<'_>, id: &EntityId) -> TestResult<bool> {
    let read = lane.read(&[PointRead::id(*id)], None)?;
    Ok(read.value.into_iter().next().flatten().is_some())
}

/// Whether `lane` reads nothing of `id` once its credential is revoked: the
/// point read is refused because the credential is no longer live (each
/// read rechecks its holder), or it returns no row. Any other error is the
/// test's error.
fn lane_reads_nothing_after_revocation(lane: &ScopedRead<'_>, id: &EntityId) -> TestResult<bool> {
    match lane.read(&[PointRead::id(*id)], None) {
        Err(oneiron::Error::InvalidClaimBody("scoped read credential no longer live")) => Ok(true),
        Ok(read) => Ok(read.value.into_iter().next().flatten().is_none()),
        Err(error) => Err(error.into()),
    }
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
        person(&vault, admin, b"the shared vault's admin")?;
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
        let (admin_grant, grant_verbs) = admin_grant_of(&vault, admin)?;
        let derive = "derive".to_owned();
        assert!(
            matches!(&grant_verbs, ScopeAxis::Some(verbs) if verbs.contains("read") && !verbs.contains(&derive)),
            "FIXTURE: the Admin grant confers read and not derive; seen {grant_verbs:?}"
        );

        let unstamped = seed_claim(&vault, subject, "an unstamped note", None)?;
        let private_stamped = seed_claim(&vault, subject, "a private note", Some("private"))?;

        // The host roots the vault and mints the Admin a credential naming
        // its Admin grant, with read, write and derive: derive is a verb the
        // grant does not confer, as after a role move that narrowed it.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-saved-member-lane-read-scope")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let admin_key = SigningKey::from_bytes(&[ADMIN_BINDING_SEED; 32]);
        let mut claims = root.claims;
        claims.slip_id = ADMIN_SLIP_ID;
        claims.parent_id = None;
        claims.holder_ref = admin.to_hex();
        claims.binding_key = admin_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.grant_ref = Some(admin_grant.to_hex());
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "read".to_owned(),
            "write".to_owned(),
            derive,
        ]));
        let admin_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            _dir: dir,
            vault,
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

    /// The Admin's own credential key, from a fresh verification.
    fn admin_read_key(&self) -> TestResult<ScopedReadActorKey> {
        Ok(self
            .vault
            .credential_read_key(&self.verified_admin()?)?
            .ok_or("FIXTURE: the Admin's credential grants a read")?)
    }

    /// The Admin's live lane, once it is shown to read the unstamped claim
    /// and to withhold the private one, frozen as saved work keeps it, read
    /// back from its stored MessagePack form.
    fn saved_admin_lane(&self) -> TestResult<FrozenReadLane> {
        assert!(
            !self
                .vault
                .capability_slip_id_is_live(&self.admin_slip.claims.slip_id)?,
            "FIXTURE: the Admin credential's mint holds a verb its grant does not confer"
        );
        let lane = self.vault.scoped_read(self.admin_read_key()?);
        assert!(
            lane_reads(&lane, &self.unstamped)?,
            "FIXTURE: the Admin's live lane, its proof met to the grant's verbs, reads the unstamped claim"
        );
        assert!(
            !lane_reads(&lane, &self.private_stamped)?,
            "FIXTURE: the Admin's key is homed in no conversation of this vault and withholds the private claim"
        );
        let frozen = lane.freeze()?;
        let stored = rmp_serde::to_vec_named(&frozen)?;
        let frozen: FrozenReadLane = rmp_serde::from_slice(&stored)?;
        assert!(
            !frozen.reads_as_principal(),
            "FIXTURE: the Admin's homed lane is saved narrowed, held to its credential"
        );
        Ok(frozen)
    }
}

/// The Admin's saved lane, rebuilt over its own credential key, reads what
/// its live lane read: the grant still confers read, so the verb the mint
/// holds beyond it ends no saved read.
#[test]
fn a_member_saved_lane_reads_while_its_grant_confers_read() -> TestResult {
    let fixture = Fixture::new()?;
    let frozen = fixture.saved_admin_lane()?;
    let rebuilt = frozen.narrow(&fixture.vault, fixture.admin_read_key()?)?;
    let lane = fixture.vault.scoped_read(rebuilt);
    assert!(
        lane_reads(&lane, &fixture.unstamped)?,
        "actor=a shared vault's Admin under a credential holding derive beside its grant's read; expected its saved lane, rebuilt over its own credential key, to read the unstamped claim its live lane read, not to read nothing for a verb the lane never reads with"
    );
    assert!(
        !lane_reads(&lane, &fixture.private_stamped)?,
        "actor=a shared vault's Admin; expected its rebuilt saved lane to keep the home and withhold the private claim"
    );
    Ok(())
}

/// Guard: the revocation check stands. Once the Admin's credential is
/// revoked, a rebuild reads nothing, and so does a key rebuilt before it:
/// each point read is refused as no longer live, or returns no row.
#[test]
fn a_member_saved_lane_reads_nothing_once_its_credential_is_revoked() -> TestResult {
    let fixture = Fixture::new()?;
    let frozen = fixture.saved_admin_lane()?;
    let key = fixture.admin_read_key()?;
    let held = frozen.narrow(&fixture.vault, key.clone())?;
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, fixture.admin_slip.claims.slip_id)?;
    let rebuilt = frozen.narrow(&fixture.vault, key)?;
    assert!(
        lane_reads_nothing_after_revocation(
            &fixture.vault.scoped_read(rebuilt),
            &fixture.unstamped
        )?,
        "actor=a shared vault's Admin whose credential was revoked; expected its saved lane, rebuilt after the revocation, to read nothing"
    );
    assert!(
        lane_reads_nothing_after_revocation(&fixture.vault.scoped_read(held), &fixture.unstamped)?,
        "actor=a shared vault's Admin whose credential was revoked; expected a key rebuilt from its saved lane before the revocation to read nothing after it"
    );
    Ok(())
}
