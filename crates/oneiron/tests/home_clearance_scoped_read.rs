//! Home clearance on the engine's scoped read lane (L5-02 PR 3, RULING
//! SECREAD-HOME-READ-DOORS = B), public API only.
//!
//! A reader that is neither the vault's owner nor one of its own agents
//! reading on its own reads no claim stamped `sensitivity` private or
//! sensitive through its credential lane, unless it reads inside a room of
//! this vault it stands in. Unstamped and `public` claims still read. The
//! outside lane's stamped-claim assertions are red on the base (the
//! precleared contact's delegated read slip read them there) and green on the
//! head. A saved lane keeps the home: rebuilt onto an un-homed key, it still
//! withholds the stamped claims.
//!
//! Naming a room lifts the home only for a reader that stands in it (Astra on
//! L5-02 PR 3, finding 3): the outside reader, which is not in the room,
//! reads no stamped claim inside it, and a member of the room, on its own
//! delegated read slip, reads them inside the room and not outside it.
//!
//! The same four claims about one PERSON as the read-doors test (unstamped,
//! public, private, sensitive). Deterministic: in-process vault, no server,
//! no models, no embedder.
//!
//! Run with: RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test home_clearance_scoped_read

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::claim::{FrozenReadLane, PointRead, ScopedRead};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The word every seeded claim holds, which no other row holds.
const SHARED_WORD: &str = "lanternwick";
/// The one word each seeded claim alone holds.
const UNSTAMPED_WORD: &str = "juniper";
const PUBLIC_WORD: &str = "sorrel";
const PRIVATE_WORD: &str = "wren";
const SENSITIVE_WORD: &str = "lark";
/// The seeded claims' predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";
/// Holder-proof challenges are fixed bytes: the seal is what is verified, not
/// the freshness of the request.
const OUTSIDE_CHALLENGE: &[u8] = b"home clearance outside read";
const OWNER_CHALLENGE: &[u8] = b"home clearance owner read";
const MEMBER_CHALLENGE: &[u8] = b"home clearance member read";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    outside_slip: CapabilitySlip,
    outside_key: SigningKey,
    member_slip: CapabilitySlip,
    member_key: SigningKey,
    unstamped: EntityId,
    public: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
    room: EntityId,
}

/// One seeded claim about `subject`, holding `text`, stamped `sensitivity`
/// when named, and indexed for text retrieval.
fn seed_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
) -> TestResult {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    vault.put_claim(
        id,
        &body,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
    )?;
    vault.batch().text(id, &[("body", text)]).commit()?;
    Ok(())
}

/// Whether `lane` serves `id` by point read: a withheld row reads as `None`,
/// exactly like a missing one.
fn lane_reads(lane: &ScopedRead, id: &EntityId) -> TestResult<bool> {
    let read = lane.read(&[PointRead::id(*id)], None)?;
    Ok(read.value.into_iter().next().flatten().is_some())
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Vault::open_owned(dir.path(), config)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        // One PERSON the four claims hang off, one more PERSON seating the
        // room, and one PERSON the outside contact's identity links to.
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"home clearance subject",
        )?;
        let other = EntityId::now();
        vault.put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"room member",
        )?;
        let outside_person = EntityId::now();
        vault.put_entity(
            &outside_person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"outside person",
        )?;
        // Four claims about one PERSON, each findable by the shared word and
        // its own word, written as the empty-beside-L2 fixture writes its
        // base claim.
        let unstamped = EntityId::from_bytes([0x51; 16])?;
        seed_claim(
            &vault,
            &unstamped,
            subject,
            &format!("{SHARED_WORD} {UNSTAMPED_WORD}"),
            None,
        )?;
        let public = EntityId::from_bytes([0x52; 16])?;
        seed_claim(
            &vault,
            &public,
            subject,
            &format!("{SHARED_WORD} {PUBLIC_WORD}"),
            Some("public"),
        )?;
        let private_stamped = EntityId::from_bytes([0x53; 16])?;
        seed_claim(
            &vault,
            &private_stamped,
            subject,
            &format!("{SHARED_WORD} {PRIVATE_WORD}"),
            Some("private"),
        )?;
        let sensitive_stamped = EntityId::from_bytes([0x54; 16])?;
        seed_claim(
            &vault,
            &sensitive_stamped,
            subject,
            &format!("{SHARED_WORD} {SENSITIVE_WORD}"),
            Some("sensitive"),
        )?;
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        // A room of this vault seating the owner and one more member. It
        // carries no signed facets, so reading inside it lifts only the home.
        let room = EntityId::now();
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owner, other],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // The outside reader's contact, cleared for the vault's full scope,
        // so the audience clamp admits the sensitive claim on main.
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                outside_person,
                "outside@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        let _ = vault.preclear_contact_disclosure(
            &proof,
            "outside-reader",
            &[contact],
            Scope::top(),
        )?;
        // The outside reader's delegated credential: read-only, so not
        // owner-grade, and not one of the vault's own agents.
        let outside_key = SigningKey::from_bytes(&[0x66; 32]);
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let mut claims = owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = contact.to_hex();
        claims.binding_key = outside_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = scope;
        claims.slip_id = [0x66; 32];
        let outside_slip = vault.mint_capability_slip(&issuer, claims.clone())?;
        // The room member's own delegated credential, read-only as well: a
        // PERSON of the room's roster, neither the owner nor an agent.
        let member_key = SigningKey::from_bytes(&[0x67; 32]);
        claims.holder_ref = other.to_hex();
        claims.binding_key = member_key.verifying_key().to_bytes();
        claims.slip_id = [0x67; 32];
        let member_slip = vault.mint_capability_slip(&issuer, claims)?;
        Ok(Self {
            _dir: dir,
            vault,
            issuer,
            owner_slip,
            outside_slip,
            outside_key,
            member_slip,
            member_key,
            unstamped,
            public,
            private_stamped,
            sensitive_stamped,
            room,
        })
    }

    fn verified_outside(&self) -> TestResult<VerifiedSlip> {
        let transcript = self.outside_slip.binding_transcript(OUTSIDE_CHALLENGE)?;
        let signature = self.outside_key.sign(&transcript).to_bytes();
        Ok(self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &self.outside_slip,
            OUTSIDE_CHALLENGE,
            &signature,
        )?)
    }

    fn verified_member(&self) -> TestResult<VerifiedSlip> {
        let transcript = self.member_slip.binding_transcript(MEMBER_CHALLENGE)?;
        let signature = self.member_key.sign(&transcript).to_bytes();
        Ok(self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &self.member_slip,
            MEMBER_CHALLENGE,
            &signature,
        )?)
    }

    fn verified_owner(&self) -> TestResult<VerifiedSlip> {
        let proof = self
            .issuer
            .binding_proof(&self.owner_slip, OWNER_CHALLENGE)?;
        Ok(self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &self.owner_slip,
            OWNER_CHALLENGE,
            &proof,
        )?)
    }

    /// The outside reader's credential lane.
    fn outside_lane(&self) -> TestResult<ScopedRead<'_>> {
        let verified = self.verified_outside()?;
        let Some(key) = self.vault.credential_read_key(&verified)? else {
            panic!("the outside credential grants a read");
        };
        Ok(self.vault.scoped_read(key))
    }

    /// The room member's credential lane.
    fn member_lane(&self) -> TestResult<ScopedRead<'_>> {
        let verified = self.verified_member()?;
        let Some(key) = self.vault.credential_read_key(&verified)? else {
            panic!("the member credential grants a read");
        };
        Ok(self.vault.scoped_read(key))
    }

    /// The owner's credential lane: un-homed, reading every claim on its own.
    fn owner_lane(&self) -> TestResult<ScopedRead<'_>> {
        let verified = self.verified_owner()?;
        let Some(key) = self.vault.credential_read_key(&verified)? else {
            panic!("the owner credential grants a read");
        };
        Ok(self.vault.scoped_read(key))
    }
}

#[test]
fn outside_lane_reads_unstamped_and_public_claims_by_id_only() -> TestResult {
    let fixture = Fixture::new()?;
    let lane = fixture.outside_lane()?;
    assert!(
        lane_reads(&lane, &fixture.unstamped)?,
        "the point read serves the outside lane the unstamped claim"
    );
    assert!(
        lane_reads(&lane, &fixture.public)?,
        "the point read serves the outside lane the public claim"
    );
    assert!(
        !lane_reads(&lane, &fixture.private_stamped)?,
        "the point read withholds the private stamped claim from the outside lane"
    );
    assert!(
        !lane_reads(&lane, &fixture.sensitive_stamped)?,
        "the point read withholds the sensitive stamped claim from the outside lane"
    );
    Ok(())
}

#[test]
fn outside_lane_naming_a_room_it_is_not_in_reads_no_stamped_claim() -> TestResult {
    let fixture = Fixture::new()?;
    let lane = fixture.outside_lane()?.within_room_facets(fixture.room);
    assert!(
        lane_reads(&lane, &fixture.unstamped)?,
        "the point read inside a room serves the outside lane the unstamped claim"
    );
    assert!(
        !lane_reads(&lane, &fixture.sensitive_stamped)?,
        "the point read inside a room the outside reader is not in withholds the sensitive stamped claim"
    );
    assert!(
        !lane_reads(&lane, &fixture.private_stamped)?,
        "the point read inside a room the outside reader is not in withholds the private stamped claim"
    );
    Ok(())
}

#[test]
fn a_member_reads_stamped_claims_inside_its_room_only() -> TestResult {
    let fixture = Fixture::new()?;
    let inside = fixture.member_lane()?.within_room_facets(fixture.room);
    assert!(
        lane_reads(&inside, &fixture.unstamped)?,
        "control: the point read inside its room serves the member lane the unstamped claim"
    );
    assert!(
        lane_reads(&inside, &fixture.sensitive_stamped)?,
        "the point read inside its room serves the member lane the sensitive stamped claim"
    );
    assert!(
        lane_reads(&inside, &fixture.private_stamped)?,
        "the point read inside its room serves the member lane the private stamped claim"
    );
    let outside = fixture.member_lane()?;
    assert!(
        !lane_reads(&outside, &fixture.sensitive_stamped)?,
        "the point read outside any room withholds the sensitive stamped claim from the member lane"
    );
    Ok(())
}

#[test]
fn a_saved_lane_keeps_the_home_across_narrow() -> TestResult {
    let fixture = Fixture::new()?;
    let lane = fixture.outside_lane()?;
    let frozen = FrozenReadLane::freeze(&lane)?;
    // Control: the un-narrowed owner key reads the sensitive claim on its
    // own. (A raw contact key reads nothing on its own: no grant names it
    // and it carries no proof Scope, so the owner key is the un-homed key
    // this rebuild narrows onto.)
    let owner = fixture.owner_lane()?;
    assert!(
        lane_reads(&owner, &fixture.sensitive_stamped)?,
        "control: the point read serves the un-narrowed owner key the sensitive stamped claim"
    );
    let verified = fixture.verified_owner()?;
    let Some(owner_key) = fixture.vault.credential_read_key(&verified)? else {
        panic!("the owner credential grants a read");
    };
    let rebuilt = frozen.narrow(&fixture.vault, owner_key)?;
    let lane = fixture.vault.scoped_read(rebuilt);
    assert!(
        lane_reads(&lane, &fixture.unstamped)?,
        "the narrowed lane still reads the unstamped claim by id"
    );
    assert!(
        !lane_reads(&lane, &fixture.sensitive_stamped)?,
        "the narrowed lane does not read the sensitive stamped claim by id"
    );
    assert!(
        !lane_reads(&lane, &fixture.private_stamped)?,
        "the narrowed lane does not read the private stamped claim by id"
    );
    Ok(())
}
