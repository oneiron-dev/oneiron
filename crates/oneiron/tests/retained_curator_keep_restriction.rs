// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [RESTRICTION-CLOSE-BY-RETAINED-CURATOR-KEEP] (Astra F2 on #8238): a
//! conflict's retained alternative keeps its predicate and value, so it can
//! be the Dreamer's curator finding (`dreamer.curator.proposal`) whose rung
//! retracts a row outside the conflict's members. A Keep the Gate holds is
//! retried once with the responder's approval (FIX 5753), and that approval
//! applies the finding's rung as it lands (FIX 5423). RULING
//! RESTRICTION-CLOSE-BY-CURATOR-APPROVAL = A (15 Nov 18:33): an approval of
//! a curator finding that retracts a restricting row by no person is
//! refused and stays for a person; RULING RESTRICTION-CLOSE-BY-CONFLICT-
//! SETTLE = A: a settlement by no person never lifts a restriction.
//!
//! The responder that is no person here is the vault owner presenting his
//! slip handed on to another key (`attenuate_to`): the conflict door reads
//! it as the owner, so his proof answers the finding's critical approval
//! and it is never parked, yet the hand-on makes it no person's act
//! (`Memory::acts_as_own_person`; Astra review on #8189, F1). An agent
//! holder of `memory.conflict_review` is the other such responder; its own
//! approval of the critical finding is parked on the criticality floor, so
//! its Keep lands nothing either way (a guard, not a red).
//!
//! The red: the handed-on Keep of a finding that retracts a do-not-contact
//! bar on another PERSON is refused, the bar stands and the conflict stays
//! open. The guard: the owner's own Keep of the same finding applies it.
//! The control: the handed-on Keep of a finding that retracts a row that
//! restricts no one still lands and applies.
//!
//! The conflict is opened over an Observed `profile.note` about a PERSON
//! (`test_doors::curator_finding::open_conflict_with_retract_finding`; a
//! retained alternative's evidence must be no generated claim), and its
//! retained alternative is the finding, graded on the target's body now.
//! The vault is rooted under a host, as `tests/conflict_settle_restriction.rs`
//! roots it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test retained_curator_keep_restriction`.

#![cfg(oneiron_test_support)]

use ed25519_dalek::Signer;
use oneiron::agent_def::AgentCeiling;
use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::campaign::claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    ConflictReviewScope, ConflictSettleOutcome, ConflictSettlement,
};
use oneiron::memory::MemoryResult;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::comm_claim_rows::put_comm_claim_row;
use oneiron::test_doors::curator_finding::open_conflict_with_retract_finding;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

const LEARNED_AT: u64 = 1_780_000_000;

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The host's slip issuer, which minted the vault's root slip.
    issuer: HostSlipIssuer,
    /// An agent with an Auto ceiling; holds a Grant only where a test mints one.
    agent_holder: EntityId,
    /// The PERSON the conflict is about.
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
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
        let issuer = HostSlipIssuer::from_secret(b"retained-curator-keep-restriction")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        // The Dreamer signs its marker, alternatives and findings as a
        // MACHINE; an unsigned MACHINE write is refused.
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let agent_holder = vault
            .ensure_agent_principal("retained-curator-keep-agent")
            .expect("agent holder");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent_holder.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent holder read and an Auto ceiling");
        Self {
            subject: person(&vault),
            vault,
            owner,
            issuer,
            agent_holder,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    /// An Observed note about the subject, a member a retained alternative
    /// may cite: a generated claim never corroborates.
    fn observed_note(&self) -> EntityId {
        let mut body = body(NOTE, self.subject, Value::from("the observed note"));
        body.source = Some(ClaimSource::Observed);
        body.scope_facet = self.facet;
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(), LEARNED_AT)
            .expect("the observed note lands");
        id
    }

    /// A Generated do-not-contact bar on a new PERSON, outside the conflict.
    fn do_not_contact_bar(&self) -> EntityId {
        let mut body = body(
            PREDICATE_COMM_DO_NOT_CONTACT,
            person(&self.vault),
            encode_do_not_contact_value(&CommDoNotContactValue {
                channel: None,
                scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
            }),
        );
        body.scope_facet = self.facet;
        let bar = EntityId::now();
        put_comm_claim_row(&self.vault, &bar, &body, at(), LEARNED_AT)
            .expect("the do-not-contact bar lands");
        bar
    }

    /// A Generated note on a new PERSON, outside the conflict: it restricts
    /// no one.
    fn note_elsewhere(&self) -> EntityId {
        let mut body = body(NOTE, person(&self.vault), Value::from("a note elsewhere"));
        body.scope_facet = self.facet;
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(), LEARNED_AT)
            .expect("the note lands");
        id
    }

    /// A conflict over an Observed note about the subject whose retained
    /// alternative is the Dreamer's curator finding that retracts `target`.
    /// Returns the marker and the alternative's selector.
    fn conflict_keeping_a_retract_of(&self, target: EntityId) -> (EntityId, EntityId) {
        let member = self.observed_note();
        open_conflict_with_retract_finding(&self.vault, member, target)
            .expect("an open conflict whose retained alternative is the finding")
    }

    /// The owner's Keep of `selector`, authenticated, presenting `slip`.
    fn owner_keeps_with(
        &self,
        slip: &VerifiedSlip,
        marker: EntityId,
        selector: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_read_proof(slip)
            .settle_conflict(
                Some(&self.owner_proof),
                marker,
                ConflictSettlement::Keep(selector),
                self.vault.now_recorded_ms(),
            )
    }

    /// The owner's own authenticated Keep of `selector`.
    fn owner_keeps(
        &self,
        marker: EntityId,
        selector: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .settle_conflict(
                Some(&self.owner_proof),
                marker,
                ConflictSettlement::Keep(selector),
                self.vault.now_recorded_ms(),
            )
    }

    /// The agent holder's Keep of `selector`, under the owner's Grant of the
    /// subject's conflict review.
    fn agent_keeps(
        &self,
        marker: EntityId,
        selector: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .grant_conflict_review(
                &self.owner_proof,
                WriteActor::new(self.agent_holder, EdgeActorClass::Agent),
                ConflictReviewScope::Subject(self.subject),
            )
            .expect("the owner grants the agent the subject's conflict review");
        self.vault
            .memory(self.agent_holder, EdgeActorClass::Agent)
            .settle_conflict(
                None,
                marker,
                ConflictSettlement::Keep(selector),
                self.vault.now_recorded_ms(),
            )
    }

    /// The owner's Human slip from the host root, handed on to another key
    /// (as `tests/conflict_settle_restriction.rs` hands the person holder's
    /// slip on).
    fn owner_slip_handed_on(&self) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        let mut handed = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        let next = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(b"retained curator keep handed holder").as_bytes(),
        );
        self.issuer
            .attenuate_to(
                &mut handed,
                SlipCaveat::default(),
                next.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        let challenge = b"retained curator keep handed slip";
        let binding = next
            .sign(
                &handed
                    .binding_transcript(challenge)
                    .expect("the transcript"),
            )
            .to_bytes();
        let handed = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &handed, challenge, &binding)
            .expect("the handed slip verifies");
        assert!(handed.is_transferred(), "control: the slip was handed on");
        handed
    }

    /// Whether the owner still sees `marker` open on the subject.
    fn still_open(&self, marker: EntityId) -> bool {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .open_conflicts(Some(&self.owner_proof), Some(self.subject), usize::MAX)
            .expect("the owner reads the open conflicts")
            .iter()
            .any(|conflict| conflict.marker == marker)
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

fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// A live PERSON.
fn person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(), LEARNED_AT, b"human")
        .expect("a live person");
    person
}

/// `predicate` about `subject` holding `value`: Generated, Auto, Active, with
/// no declared scope.
fn body(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Generated);
    body.scope = None;
    body
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

/// The conflict settled on its retained alternative.
fn assert_settled(settled: MemoryResult<ConflictSettleOutcome>) {
    let settled = settled.expect("the Keep lands");
    assert!(
        matches!(settled, ConflictSettleOutcome::Settled(_)),
        "the conflict settles: {settled:?}"
    );
}

/// Red: the owner's slip handed on to another key keeps a retained curator
/// finding that retracts a do-not-contact bar outside the conflict. No
/// person approves it, so the Keep is refused before the finding lands: the
/// bar stands and the conflict stays open.
#[test]
fn a_handed_on_owner_slip_never_keeps_a_finding_that_retracts_a_do_not_contact() {
    let f = Fixture::new();
    let bar = f.do_not_contact_bar();
    let (marker, selector) = f.conflict_keeping_a_retract_of(bar);
    let handed = f.owner_slip_handed_on();

    let settled = f.owner_keeps_with(&handed, marker, selector);

    assert!(
        settled.is_err(),
        "a Keep by no person never applies a finding that lifts a restriction: {settled:?}"
    );
    assert_eq!(
        f.lifecycle(bar),
        ClaimLifecycleStatus::Active,
        "the do-not-contact bar stands"
    );
    assert!(f.still_open(marker), "the conflict stays for a person");
}

/// Guard: the agent holder's Keep of the same finding lands nothing that
/// lifts the bar: the bar stands and the conflict stays open.
#[test]
fn an_agent_holders_keep_never_retracts_a_do_not_contact() {
    let f = Fixture::new();
    let bar = f.do_not_contact_bar();
    let (marker, selector) = f.conflict_keeping_a_retract_of(bar);

    let settled = f.agent_keeps(marker, selector);

    assert!(
        settled.is_err(),
        "the agent's Keep lands nothing: {settled:?}"
    );
    assert_eq!(
        f.lifecycle(bar),
        ClaimLifecycleStatus::Active,
        "the do-not-contact bar stands"
    );
    assert!(f.still_open(marker), "the conflict stays for a person");
}

/// Guard: the owner's own Keep of the same finding settles the conflict and
/// applies the finding: the bar is retracted.
#[test]
fn the_owners_own_keep_applies_a_finding_that_retracts_a_do_not_contact() {
    let f = Fixture::new();
    let bar = f.do_not_contact_bar();
    let (marker, selector) = f.conflict_keeping_a_retract_of(bar);

    assert_settled(f.owner_keeps(marker, selector));
    assert_eq!(
        f.lifecycle(bar),
        ClaimLifecycleStatus::Retracted,
        "the owner's approval applies the finding's rung"
    );
    assert!(!f.still_open(marker), "the conflict is settled");
}

/// Control: the handed-on Keep of a finding that retracts a row restricting
/// no one still lands and applies: the cut is narrow.
#[test]
fn a_handed_on_owner_slip_still_keeps_a_finding_that_retracts_a_note() {
    let f = Fixture::new();
    let note = f.note_elsewhere();
    let (marker, selector) = f.conflict_keeping_a_retract_of(note);
    let handed = f.owner_slip_handed_on();

    assert_settled(f.owner_keeps_with(&handed, marker, selector));
    assert_eq!(
        f.lifecycle(note),
        ClaimLifecycleStatus::Retracted,
        "the finding's rung applies"
    );
    assert!(!f.still_open(marker), "the conflict is settled");
}
