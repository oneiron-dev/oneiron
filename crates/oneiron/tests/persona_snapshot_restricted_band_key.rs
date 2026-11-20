//! The owner's opt-out for the persona snapshot's restricted-band clamp
//! (`persona_snapshot.compile.include_restricted_band`; owner principle 16 Nov 00:44: a
//! restriction that is not a correctness fix ships as a good default plus an owner opt-out).
//!
//! With no row a restricted-band claim (sensitivity band 3) never enters a compile, as before.
//! The owner's true lets their own restricted-band claims into a card about themself. A card
//! about a contact keeps the clamp, and a claim whose band does not read stays out whatever the
//! key says.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test persona_snapshot_restricted_band_key`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::persona_snapshot::{PersonaSnapshotCompile, PersonaSnapshotCompileOptions};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;
use serde_json::json;

const KEY: &str = "persona_snapshot.compile.include_restricted_band";
/// The restricted band: the lowest band the clamp holds back.
const RESTRICTED_BAND: u64 = 3;
const OWNER_RESTRICTED: &str = "the owner's restricted medical detail";
const OWNER_PLAIN: &str = "the owner prefers tea over coffee";
const CONTACT_RESTRICTED: &str = "the contact's restricted medical detail";
const OWNER_UNREADABLE: &str = "the owner's detail with an out-of-range band";
/// A band past `u8`: it does not read, so the claim is Tier A (unreadable band).
const OUT_OF_RANGE_BAND: u64 = 300;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open fixture vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner_proof = vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
        }
    }

    /// A PERSON who is not an owner of the vault.
    fn contact(&self) -> EntityId {
        let contact = EntityId::from_bytes([0x6C; 16]).expect("contact id");
        self.vault
            .put_entity(
                &contact,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"contact",
            )
            .expect("store the contact");
        contact
    }

    /// Stores an approved, active, owner-stated claim about `subject` whose scope map holds
    /// `band`.
    fn claim(&self, subject: EntityId, predicate: &str, text: &str, band: u64) {
        self.try_claim(subject, predicate, text, band)
            .expect("store the claim");
    }

    fn try_claim(
        &self,
        subject: EntityId,
        predicate: &str,
        text: &str,
        band: u64,
    ) -> oneiron::Result<()> {
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from(text),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.salience = Some(0.9);
        body.source = Some(ClaimSource::UserStated);
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from(band),
        )]));
        self.vault.put_claim(
            &EntityId::now(),
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
    }

    /// The owner turns the key on.
    fn include_restricted_band(&self) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(KEY, json!(true)),
            )
            .expect("the owner sets the key");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applies at once: {outcome:?}"
        );
    }

    fn compile(&self, subject: EntityId) -> PersonaSnapshotCompile {
        self.vault
            .compile_persona_snapshot(&subject, &PersonaSnapshotCompileOptions::default())
            .expect("compile the card")
    }
}

fn holds(compile: &PersonaSnapshotCompile, text: &str) -> bool {
    compile.rows.iter().any(|row| row.text.contains(text))
}

#[test]
fn with_no_row_a_restricted_band_claim_about_the_owner_stays_out() {
    let fixture = Fixture::open();
    fixture.claim(fixture.owner, "profile.preference", OWNER_PLAIN, 0);
    fixture.claim(
        fixture.owner,
        "profile.health",
        OWNER_RESTRICTED,
        RESTRICTED_BAND,
    );
    let compile = fixture.compile(fixture.owner);
    assert!(holds(&compile, OWNER_PLAIN), "a band-0 claim enters");
    assert!(
        !holds(&compile, OWNER_RESTRICTED),
        "the default keeps today's clamp"
    );
}

#[test]
fn the_owners_true_lets_their_own_restricted_band_claim_into_their_card() {
    let fixture = Fixture::open();
    fixture.claim(
        fixture.owner,
        "profile.health",
        OWNER_RESTRICTED,
        RESTRICTED_BAND,
    );
    fixture.include_restricted_band();
    assert!(
        holds(&fixture.compile(fixture.owner), OWNER_RESTRICTED),
        "the owner's restricted-band claim enters the owner's own card"
    );
}

#[test]
fn the_owners_true_leaves_a_card_about_a_contact_clamped() {
    let fixture = Fixture::open();
    let contact = fixture.contact();
    fixture.claim(
        contact,
        "profile.health",
        CONTACT_RESTRICTED,
        RESTRICTED_BAND,
    );
    fixture.include_restricted_band();
    assert!(
        !holds(&fixture.compile(contact), CONTACT_RESTRICTED),
        "a contact's restricted-band claim never takes the owner's opt-out"
    );
}

/// A vault that refuses such a claim at the write holds the line as well: the claim then
/// never exists to enter.
#[test]
fn the_owners_true_leaves_an_unreadable_band_out() {
    let fixture = Fixture::open();
    let _stored = fixture.try_claim(
        fixture.owner,
        "profile.preference",
        OWNER_UNREADABLE,
        OUT_OF_RANGE_BAND,
    );
    fixture.include_restricted_band();
    assert!(
        !holds(&fixture.compile(fixture.owner), OWNER_UNREADABLE),
        "a band that does not read fails closed whatever the key says"
    );
}
