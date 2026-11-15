//! Stamped content stays in conversations homed in its own vault, unless its
//! owner granted clearance (DEC-0006 `#home-clearance`; L5-02 PR 1; RULINGs
//! L5-02-STAMPED = A, L5-02-HOME-GRANT = A).
//!
//! One vault holds four claims about one PERSON: one unstamped, one stamped
//! public, one stamped private and one stamped sensitive. The same context
//! pack is read homed in this vault and homed in another vault (`OTHER`, the
//! member's or the company's). Homed elsewhere, the two stamped claims stay
//! out unless the owner set a home clearance for `OTHER` at or above their
//! band; the unstamped and the public claim stay in; the audience's own
//! clearance still applies on top, and this vault's own id is this vault.
//! A pinned revision meets that clearance by its own stamp, which is its
//! live row's: a rewrite that moves a claim's stamp is refused (the Sol
//! review of PR 1).
//!
//! On main the file does not compile: `ConversationHome`, `homed_in` and the
//! home-clearance doors do not exist.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test home_clearance_stamped_content`.

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use oneiron::disclosure::{DisclosureBand, DisclosureScope};
use oneiron::federation::{Scope, Sensitivity, SensitivityCeiling};
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::memory::ReadMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ConversationHome,
    DisclosureContext, EdgeActorClass, EntityId, HomeClearanceRequest, HomeClearanceSet, TimeRange,
    Vault, VaultConfig,
};
use rmpv::Value;
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When every row of the fixture was written and learned.
const NOW: u64 = 1_780_000_000;
/// Another vault's authority id: the vault that holds the conversation.
const OTHER: [u8; 32] = [0x42; 32];
/// The one word every claim's text holds, so one search reads all four.
const WORD: &str = "lighthouse";
/// The contact present in the conversation.
const CONTACT_LABEL: &str = "kenji@example.com";

/// The four claims about one PERSON, one per stamp.
struct Claims {
    unstamped: EntityId,
    public: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
}

/// One vault, its owner's proof, one contact and the four claims.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    proof: AuthenticatedOwner,
    contact: EntityId,
    claims: Claims,
}

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn at_now() -> TimeRange {
    TimeRange {
        start: NOW,
        end: NOW,
    }
}

fn put_person(vault: &Vault, label: &[u8]) -> TestResult<EntityId> {
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at_now(), NOW, label)?;
    Ok(person)
}

/// A claim about `subject` whose text holds [`WORD`], stamped `stamp` (no
/// scope map at all when `None`), indexed for text search.
fn put_claim(
    vault: &Vault,
    subject: EntityId,
    text: &str,
    stamp: Option<&str>,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    write_claim(vault, id, subject, text, stamp)?;
    Ok(id)
}

/// [`put_claim`] at `id`, which may already hold a claim: the write replaces
/// its body and its indexed text.
fn write_claim(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    text: &str,
    stamp: Option<&str>,
) -> TestResult {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    if let Some(stamp) = stamp {
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from(stamp),
        )]));
    }
    vault.put_claim(&id, &body, at_now(), NOW)?;
    vault.batch().text(&id, &[("body", text)]).commit()?;
    Ok(())
}

/// A clearance of every axis, up to `sensitivity`.
fn clearance(sensitivity: Sensitivity) -> Scope {
    let mut scope = Scope::top();
    scope.sensitivity = SensitivityCeiling::AtMost(sensitivity);
    scope
}

fn clear_contact(vault: &Vault, contact: EntityId, sensitivity: Sensitivity) -> TestResult {
    let scope = DisclosureScope::new(clearance(sensitivity), "home clearance test", NOW)?;
    vault.set_counterparty_disclosure_scope(&contact, &scope)?;
    Ok(())
}

/// The fixture: the contact cleared for sensitive content.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.disclosure.home.set")?;
    let subject = put_person(&vault, b"owen")?;
    let claims = Claims {
        unstamped: put_claim(&vault, subject, "lighthouse unstamped note", None)?,
        public: put_claim(&vault, subject, "lighthouse public note", Some("public"))?,
        private_stamped: put_claim(&vault, subject, "lighthouse private note", Some("private"))?,
        sensitive_stamped: put_claim(
            &vault,
            subject,
            "lighthouse sensitive note",
            Some("sensitive"),
        )?,
    };
    let contact_person = put_person(&vault, b"kenji")?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(contact_person, CONTACT_LABEL, NOW)?,
    )?;
    clear_contact(&vault, contact, Sensitivity::Sensitive)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        proof,
        contact,
        claims,
    })
}

impl Fixture {
    /// The owner and the contact present: the contact's clearance applies.
    fn with_contact(&self) -> TestResult<DisclosureContext> {
        Ok(DisclosureContext::resolve(
            &self.vault,
            InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
                self.contact,
                CONTACT_LABEL,
                CounterpartyFirstTouch::Public,
            )]),
        )?)
    }

    /// The ids one pack read under `ctx` returns, results and neighbours.
    fn pack_ids(&self, ctx: DisclosureContext) -> TestResult<Vec<EntityId>> {
        let pack = self
            .vault
            .context_pack()
            .search_text(WORD, 20)
            .disclosure_context(ctx)
            .run()?;
        Ok(pack
            .results
            .iter()
            .chain(pack.neighbors.iter())
            .map(|entity| entity.id)
            .collect())
    }

    /// Whether each claim is in `ids`, in the order unstamped, public,
    /// private_stamped, sensitive_stamped.
    fn seen(&self, ids: &[EntityId]) -> [bool; 4] {
        [
            ids.contains(&self.claims.unstamped),
            ids.contains(&self.claims.public),
            ids.contains(&self.claims.private_stamped),
            ids.contains(&self.claims.sensitive_stamped),
        ]
    }

    fn set_home_band(&self, band: DisclosureBand) -> TestResult {
        let view = self.vault.set_home_disclosure_clearance(
            &self.proof,
            HomeClearanceSet {
                home_vault_id: hex(&OTHER),
                band,
            },
        )?;
        assert_eq!(view.band, Some(band), "the set returns the stored band");
        Ok(())
    }
}

const ALL_FOUR: [bool; 4] = [true, true, true, true];
/// Unstamped and public in, both stamped claims out.
const STAMPED_OUT: [bool; 4] = [true, true, false, false];

#[test]
fn stamped_claims_stay_out_of_a_pack_homed_in_another_vault() -> TestResult {
    let fixture = fixture()?;

    let here = fixture.with_contact()?;
    let here_stamp = here.receipt_stamp();
    assert_eq!(here.home(), ConversationHome::ThisVault);
    assert_eq!(
        fixture.seen(&fixture.pack_ids(here.clone())?),
        ALL_FOUR,
        "homed here, the contact cleared for sensitive content reads all four claims",
    );
    assert!(
        !here_stamp.contains(";home="),
        "a pack homed here stamps as before: {here_stamp}"
    );
    assert_eq!(
        here.assembly(0).home,
        None,
        "homed here, the block names no home"
    );

    let elsewhere = here.homed_in(&fixture.vault, ConversationHome::Vault(OTHER))?;
    assert_eq!(elsewhere.home(), ConversationHome::Vault(OTHER));
    assert_eq!(
        fixture.seen(&fixture.pack_ids(elsewhere.clone())?),
        STAMPED_OUT,
        "homed in another vault, the private and the sensitive claim stay out; \
         the unstamped and the public claim stay in",
    );
    assert_eq!(
        elsewhere.receipt_stamp(),
        format!("{here_stamp};home={}", hex(&OTHER)),
        "the stamp of a pack homed elsewhere names the home after the old stamp",
    );
    assert_eq!(
        elsewhere.assembly(0).home,
        Some(hex(&OTHER)),
        "the agent-visible block names the home, so the agent can tell why claims are missing",
    );
    Ok(())
}

#[test]
fn the_owner_alone_shortcut_does_not_cross_homes() -> TestResult {
    let fixture = fixture()?;
    let alone = DisclosureContext::resolve(&fixture.vault, InterlocutorSet::owner_alone())?;
    assert_eq!(
        fixture.seen(&fixture.pack_ids(alone.clone())?),
        ALL_FOUR,
        "the owner alone in a conversation of this vault reads all four claims",
    );
    let elsewhere = alone.homed_in(&fixture.vault, ConversationHome::Vault(OTHER))?;
    assert_eq!(
        fixture.seen(&fixture.pack_ids(elsewhere)?),
        STAMPED_OUT,
        "the owner alone in a conversation another vault holds reads no stamped claim",
    );
    Ok(())
}

#[test]
fn an_owner_home_clearance_lets_stamped_claims_in() -> TestResult {
    let fixture = fixture()?;
    let request = || HomeClearanceRequest {
        home_vault_id: hex(&OTHER),
    };
    assert_eq!(
        fixture
            .vault
            .home_disclosure_clearance(&fixture.proof, request())?
            .band,
        None,
        "no home clearance before the owner sets one",
    );
    let homed = || -> TestResult<DisclosureContext> {
        Ok(fixture
            .with_contact()?
            .homed_in(&fixture.vault, ConversationHome::Vault(OTHER))?)
    };

    fixture.set_home_band(DisclosureBand::Sensitive)?;
    assert_eq!(
        fixture
            .vault
            .home_disclosure_clearance(&fixture.proof, request())?
            .band,
        Some(DisclosureBand::Sensitive),
        "the owner's home clearance reads back",
    );
    assert_eq!(
        fixture.seen(&fixture.pack_ids(homed()?)?),
        ALL_FOUR,
        "a home cleared for sensitive content reads both stamped claims",
    );

    fixture.set_home_band(DisclosureBand::Private)?;
    assert_eq!(
        fixture.seen(&fixture.pack_ids(homed()?)?),
        [true, true, true, false],
        "a home cleared for private content reads the private claim, not the sensitive one",
    );

    let cleared = fixture
        .vault
        .clear_home_disclosure_clearance(&fixture.proof, request())?;
    assert_eq!(cleared.band, None, "the clear returns no band");
    assert_eq!(
        fixture
            .vault
            .home_disclosure_clearance(&fixture.proof, request())?
            .band,
        None,
        "the revoked clearance is gone",
    );
    assert_eq!(
        fixture.seen(&fixture.pack_ids(homed()?)?),
        STAMPED_OUT,
        "after the owner revokes the clearance, both stamped claims stay out again",
    );
    Ok(())
}

#[test]
fn a_home_clearance_never_widens_the_audience() -> TestResult {
    let fixture = fixture()?;
    clear_contact(&fixture.vault, fixture.contact, Sensitivity::Private)?;
    fixture.set_home_band(DisclosureBand::Sensitive)?;
    let elsewhere = fixture
        .with_contact()?
        .homed_in(&fixture.vault, ConversationHome::Vault(OTHER))?;
    let [unstamped, public, private_stamped, sensitive_stamped] =
        fixture.seen(&fixture.pack_ids(elsewhere)?);
    assert!(public, "the public claim reaches anyone");
    assert!(
        private_stamped,
        "the private claim sits under both the contact's and the home's clearance",
    );
    assert!(
        !sensitive_stamped,
        "the home's sensitive clearance does not lift the contact's private one",
    );
    assert!(
        !unstamped,
        "an unstamped claim reads at the sensitive floor, above the contact's clearance",
    );
    Ok(())
}

#[test]
fn the_vaults_own_id_is_homed_here() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[7; HOST_ISSUER_SEED_BYTES])?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let own = vault
        .authority_vault_id()?
        .ok_or("a rooted vault has an authority id")?;

    let here = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    let named = here
        .clone()
        .homed_in(&vault, ConversationHome::Vault(own))?;
    assert_eq!(
        named.home(),
        ConversationHome::ThisVault,
        "a home named by this vault's own id is this vault",
    );
    assert_eq!(named.receipt_stamp(), here.receipt_stamp());
    assert_eq!(named.assembly(0).home, None);

    let set = |home_vault_id: String| {
        vault.set_home_disclosure_clearance(
            &proof,
            HomeClearanceSet {
                home_vault_id,
                band: DisclosureBand::Sensitive,
            },
        )
    };
    assert!(
        set(hex(&own)).is_err(),
        "this vault's own conversations take no home clearance",
    );
    assert!(
        set("00".repeat(32)).is_err(),
        "the all-zero id stands for an unnamed home, which no clearance opens",
    );
    assert!(set("zz".repeat(32)).is_err(), "a home id is 64 hex digits");
    let other = set(hex(&OTHER))?;
    assert_eq!(
        other,
        oneiron::HomeClearanceView {
            home_vault_id: hex(&OTHER),
            band: Some(DisclosureBand::Sensitive),
        },
        "the same proof sets another vault's clearance",
    );
    Ok(())
}

/// The Sol review of PR 1 asked for a pinned sensitive revision under a live
/// public rewrite. That pair cannot be written: a CLAIM's stamp is fixed at its
/// birth, and a rewrite that moves it is refused (a changed sensitivity is a
/// fork with a new id, `record_scope/stamping.rs`). So a pinned revision
/// carries the stamp of its live row, and the audience's own clearance still
/// withholds it, homed here and homed elsewhere.
#[test]
fn a_pinned_revision_meets_the_audience_by_its_own_stamp() -> TestResult {
    let fixture = fixture()?;
    clear_contact(&fixture.vault, fixture.contact, Sensitivity::Private)?;
    fixture.set_home_band(DisclosureBand::Sensitive)?;
    let subject = put_person(&fixture.vault, b"yuki")?;
    let rewritten = EntityId::now();
    write_claim(
        &fixture.vault,
        rewritten,
        subject,
        "lighthouse pinned sensitive note",
        Some("sensitive"),
    )?;
    let revision = fixture.vault.pin_entity_revision(&rewritten)?;
    let restamp = write_claim(
        &fixture.vault,
        rewritten,
        subject,
        "lighthouse pinned public note",
        Some("public"),
    )
    .expect_err("a rewrite that moves the claim's stamp is refused");
    assert!(
        matches!(
            restamp.downcast_ref::<oneiron::Error>(),
            Some(oneiron::Error::InvalidClaimBody(
                "record scope restamp refused"
            ))
        ),
        "the public rewrite is refused as a restamp, got {restamp}",
    );
    write_claim(
        &fixture.vault,
        rewritten,
        subject,
        "lighthouse pinned sensitive rewrite",
        Some("sensitive"),
    )?;
    let pinned_ids = |ctx: DisclosureContext| -> TestResult<Vec<EntityId>> {
        let pack = fixture
            .vault
            .context_pack()
            .search_text(WORD, 20)
            .read_mode(ReadMode::Pinned(revision))
            .disclosure_context(ctx)
            .run()?;
        Ok(pack
            .results
            .iter()
            .chain(pack.neighbors.iter())
            .map(|entity| entity.id)
            .collect())
    };
    assert!(
        pinned_ids(DisclosureContext::resolve(
            &fixture.vault,
            InterlocutorSet::owner_alone(),
        )?)?
        .contains(&rewritten),
        "the owner alone is served the pinned sensitive revision",
    );
    assert!(
        !pinned_ids(fixture.with_contact()?)?.contains(&rewritten),
        "homed here, the pinned sensitive revision is not served under the contact's private clearance",
    );
    let elsewhere = fixture
        .with_contact()?
        .homed_in(&fixture.vault, ConversationHome::Vault(OTHER))?;
    assert!(
        !pinned_ids(elsewhere)?.contains(&rewritten),
        "homed elsewhere, the home's sensitive clearance does not lift the contact's private one for a pinned revision",
    );
    Ok(())
}
