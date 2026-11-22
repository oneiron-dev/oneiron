// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX [RESTRICTION-CLOSE-BY-SYSTEM-GRANT]: lifting a restriction is a live
//! owner's act alone, whoever wrote the row (the Engine's RULING
//! RESTRICTION-FIX-SCOPE = A), and a System actor was the one exception.
//! `vault.claims.retract` lets a System actor through on an owner-issued exact
//! standing Grant for the target, then asked the live-owner check, which
//! answered "no restriction lifted" for every System actor. So the Dreamer,
//! holding the owner's exact `memory.claim.retract` Grant on a delivery window
//! or a suppressed `campaign.member`, retracted it with no person. A standing
//! Grant is no live owner's stamp on a widening (ARCH-0003: "widening writes
//! are human-gated").
//!
//! Each red is the Dreamer's retract under the owner's exact Grant; the
//! controls are the same Grant on a row that restricts no one, and the owner
//! retracting the restriction itself. The vault is rooted under a host (an
//! owner's delegation needs a rooted vault).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test restriction_lift_system_grant`.
#![cfg(oneiron_test_support)]

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{CommitReceipt, MEMORY_CODE_FORBIDDEN, MemoryAuthoringAction, MemoryResult};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::cohort_claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

const LEARNED_AT: u64 = 1_780_000_000;

/// A row that restricts no one: the shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// The refusal of a retract that lifts a restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

/// A vault rooted under a host with the shipped default manifest, its owner
/// and the owner's proof, and the Dreamer, the engine's System actor.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    dreamer: WriteActor,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer = HostSlipIssuer::from_secret(b"restriction-lift-system-grant")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let dreamer = vault.dreamer_authority().expect("the Dreamer");
        assert_eq!(
            dreamer.actor_class(),
            EdgeActorClass::System,
            "the Dreamer is a System actor"
        );
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            dreamer,
            facet,
            _directory: directory,
        }
    }

    /// A live PERSON.
    fn person(&self) -> EntityId {
        let person = EntityId::now();
        self.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                at(LEARNED_AT),
                LEARNED_AT,
                b"human",
            )
            .expect("a live person");
        person
    }

    /// `body` on the owner's raw door in the default facet, an Auto row with
    /// no source and no declared scope. Returns its id.
    fn owner_puts(&self, mut body: ClaimBody) -> EntityId {
        body.source = None;
        body.scope = None;
        body.scope_facet = self.facet;
        let predicate = body.predicate.clone();
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(LEARNED_AT), LEARNED_AT)
            .unwrap_or_else(|error| panic!("the owner's {predicate} claim lands: {error:?}"));
        id
    }

    /// A delivery window about a new PERSON, as the owner's row.
    fn delivery_window(&self) -> EntityId {
        let person = self.person();
        self.owner_puts(claim_about(
            DELIVERY_WINDOW_CONTEXT,
            person,
            Value::Map(vec![
                (Value::from("schema_version"), Value::from(1_u64)),
                (Value::from("applies_to"), Value::from("interrupt")),
                (Value::from("when"), Value::from("asleep")),
            ]),
        ))
    }

    /// A suppressed `campaign.member` of a new PERSON, as the owner's row.
    fn suppressed_member(&self) -> EntityId {
        let person = self.person();
        self.owner_puts(claim_about(
            PREDICATE_CAMPAIGN_MEMBER,
            person,
            encode_campaign_member_value(&CampaignMemberValue {
                campaign: EntityId::now(),
                state: CampaignMemberState::Suppressed,
                channels: vec![CampaignMemberChannel {
                    channel: "email".to_owned(),
                    basis_evidence: EntityId::now(),
                    sender_ref: EntityId::now(),
                }],
                derivation: None,
            }),
        ))
    }

    /// A note about a new PERSON, as the owner's row: it restricts no one.
    fn note(&self) -> EntityId {
        let person = self.person();
        self.owner_puts(claim_about(NOTE, person, Value::from("a note")))
    }

    /// The owner delegates to the Dreamer exactly `memory.claim.retract` of
    /// `id`, a standing Grant under the owner's proof.
    fn owner_grants_the_dreamer_retract_of(&self, id: EntityId) {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .delegate_memory_authoring(
                &self.owner_proof,
                self.dreamer,
                MemoryAuthoringAction::RetractClaim,
                id,
            )
            .expect("the owner delegates this one retract to the Dreamer");
    }

    /// `actor`'s `vault.claims.retract` of `id` on its own handle.
    fn retracts(&self, actor: WriteActor, id: EntityId) -> MemoryResult<CommitReceipt> {
        self.vault
            .memory(actor.entity_ref(), actor.actor_class())
            .claim_retract(&id.to_hex())
    }

    /// The lifecycle of the row stored at `id`.
    fn lifecycle(&self, id: EntityId) -> ClaimLifecycleStatus {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
            .lifecycle
    }
}

/// An Auto, Active claim of `predicate` about `subject` holding `value`.
fn claim_about(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap_or_else(|error| panic!("a {predicate} body: {error:?}"))
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// The Dreamer, holding the owner's exact retract Grant on `held`, a row that
/// restricts someone, retracts it: refused, and `held` still holds. `what`
/// names the row.
fn the_dreamers_granted_retract_never_lifts(f: &Fixture, held: EntityId, what: &str) {
    f.owner_grants_the_dreamer_retract_of(held);

    let retracted = f.retracts(f.dreamer, held);

    assert_eq!(
        f.lifecycle(held),
        ClaimLifecycleStatus::Active,
        "{what} still holds (retract: {retracted:?})"
    );
    let refused = retracted.expect_err("a System actor's Grant never lifts a restriction");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Red: the owner's delivery window, which holds interrupts.
#[test]
fn a_system_actors_retract_grant_never_lifts_a_delivery_window() {
    let f = Fixture::new();
    let window = f.delivery_window();

    the_dreamers_granted_retract_never_lifts(&f, window, "the delivery window");
}

/// Red: the owner's suppressed `campaign.member`, which stops the campaign's
/// sends to that person.
#[test]
fn a_system_actors_retract_grant_never_lifts_a_suppressed_member() {
    let f = Fixture::new();
    let member = f.suppressed_member();

    the_dreamers_granted_retract_never_lifts(&f, member, "the suppressed member");
}

/// Control: the same Grant on a row that restricts no one is not refused.
/// (Whether the gate lands the System actor's retract at once or holds it is
/// the gate's answer, not this fix's.)
#[test]
fn a_system_actors_retract_grant_still_retracts_a_note() {
    let f = Fixture::new();
    let note = f.note();
    f.owner_grants_the_dreamer_retract_of(note);

    f.retracts(f.dreamer, note)
        .expect("the Dreamer retracts the note under the owner's Grant");
}

/// Control: the owner still lifts the delivery window the Dreamer may not.
#[test]
fn the_owner_still_retracts_a_delivery_window() {
    let f = Fixture::new();
    let window = f.delivery_window();
    f.owner_grants_the_dreamer_retract_of(window);

    f.retracts(WriteActor::new(f.owner, EdgeActorClass::Human), window)
        .expect("the owner lifts the delivery window");

    assert_eq!(f.lifecycle(window), ClaimLifecycleStatus::Retracted);
}
