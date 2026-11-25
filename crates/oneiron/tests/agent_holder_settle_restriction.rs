// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [RESTRICTION-HOLDER-SETTLE] and the Engine's RULING
//! RESTRICTION-HOLDER-SETTLE = A (15 Nov), its cut for agent holders: an
//! agent holding the owner's review Grant never settles a proposal whose
//! settlement closes a claim that restricts someone's access (canon
//! #widen-world-floor: "An agent's widen always asks the person affected ...
//! No standing grant and no bypass grant covers it"; the lead's RULING
//! WORLD-ACCESS-GRANT-DELETE = A: "deleting a restriction IS a widening").
//! Three settlements close one (Astra review on #8153, F3):
//! 1. a reject of a Proposed `comm.do_not_contact`, which bars contact at any
//!    approval: the reject retracts it;
//! 2. an approval of a replacement that supersedes a restricting head, here a
//!    delivery window;
//! 3. an approval of a retract parked on a restricting claim. The retract
//!    door now refuses an agent's retract of one before it parks, but a vault
//!    may hold one parked before that check: the cfg door
//!    `test_doors::parked_own_retract` parks it as the door did.
//!
//! Each red is the agent holder's settle: it is refused, and the proposal
//! stays open for a person holder or the owner. A person who holds the same
//! Grant settles it as the owner's delegated act (DEC-0006 row 10: "offered
//! to every holder whose power covers them"), and so does the owner: one
//! guard each per case. The controls show the cut is narrow: the agent holder
//! still declines a parked retract (it closes nothing), approves a
//! replacement over a row that restricts no one, and rejects a proposal that
//! restricts no one.
//!
//! The vault is rooted under a host (an owner's native Grant needs a rooted
//! vault), with the shipped default manifest. The proposer reads and
//! proposes (`grant_foreign_principal`), so its own retract waits for a
//! holder. The agent holder has an Auto ceiling. The person holder is a
//! PERSON acting as class Human under the owner's read Grant.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test agent_holder_settle_restriction`.
#![cfg(oneiron_test_support)]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::{AuthenticatedOwner, consent_receipt_grant_ref};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementReason, ClaimSettlementVerdict, MEMORY_CODE_FORBIDDEN,
    MemoryAuthoringAction, MemoryResult, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::parked_own_retract::park_own_retract;
use oneiron::write_envelope::cohort_claims::{
    DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor,
};
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// The refusal of an agent holder's settle that lifts a restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// Opens every proposal: read and propose, so its own retract parks.
    proposer: EntityId,
    /// An agent holding the owner's review Grant, with an Auto ceiling.
    agent_holder: EntityId,
    /// A PERSON who is not the owner, holding the owner's review Grant.
    person_holder: EntityId,
    /// What the delivery windows are about.
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
        let issuer =
            HostSlipIssuer::from_secret(b"agent-holder-settle").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let proposer = vault
            .ensure_agent_principal("holder-settle-proposer")
            .expect("proposer");
        let agent_holder = vault
            .ensure_agent_principal("holder-settle-agent")
            .expect("agent holder");
        let person_holder = vault
            .ensure_agent_principal("holder-settle-person")
            .expect("person holder");
        let subject = vault
            .ensure_agent_principal("holder-settle-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        for reader in [proposer, person_holder] {
            vault
                .grant_foreign_principal(&owner_proof, &reader.to_hex())
                .expect("the owner grants read and propose");
        }
        vault
            .grant_agent_principal(&owner_proof, &agent_holder.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent holder read and an Auto ceiling");
        Self {
            vault,
            owner,
            proposer,
            agent_holder,
            person_holder,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    fn agent_holder(&self) -> WriteActor {
        WriteActor::new(self.agent_holder, EdgeActorClass::Agent)
    }

    fn person_holder(&self) -> WriteActor {
        WriteActor::new(self.person_holder, EdgeActorClass::Human)
    }

    /// A live PERSON.
    fn person(&self) -> EntityId {
        let person = EntityId::now();
        self.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: LEARNED_AT,
                    end: LEARNED_AT,
                },
                LEARNED_AT,
                b"human",
            )
            .expect("a live person");
        person
    }

    /// The proposer's `vault.claims.propose` of `predicate` about `subject`
    /// holding `value`, in the default facet. Returns the proposal's id.
    fn proposes(&self, predicate: &str, subject: EntityId, value: serde_json::Value) -> EntityId {
        let receipt = self
            .vault
            .memory(self.proposer, EdgeActorClass::Agent)
            .claim_propose(&ClaimInput {
                id: None,
                predicate: predicate.to_owned(),
                subject_ref: subject.to_hex(),
                value,
                confidence: 1.0,
                confidence_details: None,
                source: "inferred".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: Some(json!({ "facet": self.facet.to_hex() })),
                valid_from: Some(100),
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
            })
            .unwrap_or_else(|error| panic!("the proposer's {predicate} proposal: {error:?}"));
        assert_eq!(receipt.approval, "proposed", "the {predicate} proposal");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("the proposal's id")
    }

    /// The owner's `vault.claims.review` then `vault.claims.settle` of `id`.
    fn owner_settles(&self, id: EntityId, decision: ClaimSettleDecision) -> ClaimSettlement {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = memory
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("the owner reviews the proposal");
        memory
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision,
                    grant_ref: None,
                },
            )
            .expect("the owner settles the proposal")
    }

    /// The owner's native Grant: `holder` may review and settle `id`.
    /// Returns its 64-hex grant_ref.
    fn grant_review(&self, holder: WriteActor, id: EntityId) -> String {
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .delegate_memory_authoring(
                &self.owner_proof,
                holder,
                MemoryAuthoringAction::ReviewClaim,
                id,
            )
            .expect("the owner grants the holder this proposal's review");
        consent_receipt_grant_ref(&receipt).expect("a standing grant names its grant_ref")
    }

    /// `holder`'s `vault.claims.review` then `vault.claims.settle` of `id`,
    /// both under the owner's Grant.
    fn holder_settles(
        &self,
        holder: WriteActor,
        id: EntityId,
        decision: ClaimSettleDecision,
    ) -> MemoryResult<ClaimSettlement> {
        let grant_ref = self.grant_review(holder, id);
        let memory = self.vault.memory(holder.entity_ref(), holder.actor_class());
        let review = memory
            .claim_review(&ClaimProposalReviewRequest {
                claim_ref: id.to_hex(),
                grant_ref: Some(grant_ref.clone()),
            })
            .expect("the holder reviews under its Grant");
        memory.claim_settle(&ClaimSettleRequest {
            claim_ref: id.to_hex(),
            review_id: review.review_id,
            decision,
            grant_ref: Some(grant_ref),
        })
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }

    /// Case 1: the proposer's Proposed do-not-contact bar on a new PERSON.
    fn proposed_do_not_contact(&self) -> EntityId {
        let person = self.person();
        self.proposes(
            PREDICATE_COMM_DO_NOT_CONTACT,
            person,
            json!({ "scope": DO_NOT_CONTACT_SCOPE_ALL }),
        )
    }

    /// The proposer's claim of `predicate` about the subject holding
    /// `value`, approved by the owner. Returns its id.
    fn approved(&self, predicate: &str, value: serde_json::Value) -> EntityId {
        let id = self.proposes(predicate, self.subject, value);
        let settled = self.owner_settles(id, ClaimSettleDecision::Approve);
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
        assert_eq!(self.stored(id).approval, ClaimApprovalStatus::Approved);
        id
    }

    /// Case 2: an approved delivery window, then the proposer's replacement
    /// of it (the same conflict set, another condition). Returns both.
    fn replacement_over_a_delivery_window(&self) -> (EntityId, EntityId) {
        let window = self.approved(DELIVERY_WINDOW_CONTEXT, delivery_window("asleep"));
        let replacement = self.proposes(
            DELIVERY_WINDOW_CONTEXT,
            self.subject,
            delivery_window("driving"),
        );
        (window, replacement)
    }

    /// Case 3: an approved delivery window whose proposer's own retract waits
    /// for the holder. The manifest declares the window normal, so the
    /// parked retract keeps no critical confirm; on the shipped fallback
    /// every holder's approval of it waits for the owner's critical confirm.
    fn parked_retract_of_a_delivery_window(&self) -> EntityId {
        self.declare_delivery_window_normal();
        let window = self.approved(DELIVERY_WINDOW_CONTEXT, delivery_window("asleep"));
        let refused = self
            .vault
            .memory(self.proposer, EdgeActorClass::Agent)
            .claim_retract(&window.to_hex());
        assert!(
            refused.is_err(),
            "the retract door refuses the proposer's retract of its window: {refused:?}"
        );
        let parked = park_own_retract(
            &self.vault,
            WriteActor::new(self.proposer, EdgeActorClass::Agent),
            window,
        )
        .expect("the proposer's retract parks");
        assert!(parked, "the proposer's retract waits for the holder");
        assert_eq!(self.stored(window).lifecycle, ClaimLifecycleStatus::Active);
        window
    }

    /// Installs the shipped manifest plus one rule: `delivery_window.context`
    /// is normal, as `tests/claim_settle_supersession.rs` declares a
    /// predicate normal.
    fn declare_delivery_window_normal(&self) {
        use rmpv::Value;

        let id = oneiron_store::policy_record::default_policy_manifest_id()
            .expect("default policy manifest id");
        let body = self
            .vault
            .get(&id)
            .expect("read default policy manifest")
            .expect("default policy manifest exists");
        let Value::Map(mut fields) =
            rmpv::decode::read_value(&mut body.as_slice()).expect("decode default policy manifest")
        else {
            panic!("default policy manifest is a map");
        };
        let (_, Value::Array(rules)) = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("rules"))
            .expect("default policy rules")
        else {
            panic!("default policy rules are an array");
        };
        rules.push(Value::Map(vec![
            (Value::from("prefix"), Value::from(DELIVERY_WINDOW_CONTEXT)),
            (Value::from("exact"), Value::Boolean(true)),
            (
                Value::from("axes"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
        ]));
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(fields))
            .expect("encode delivery window policy");
        self.vault
            .install_owner_policy_manifest(
                &self.owner_proof,
                id,
                bytes,
                self.vault.now_recorded_at(),
            )
            .expect("declare the delivery window normal");
    }
}

/// A delivery window value that holds interrupts `when`.
fn delivery_window(when: &str) -> serde_json::Value {
    json!({ "schema_version": 1, "applies_to": "interrupt", "when": when })
}

/// The agent holder's refusal names the restriction rule.
fn assert_refused_as_a_restriction_close(settled: MemoryResult<ClaimSettlement>, why: &str) {
    let refused = settled.expect_err(why);
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Case 1, red: the agent holder's reject retracted the Proposed bar.
#[test]
fn an_agent_holder_never_rejects_a_proposed_do_not_contact() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();

    let settled = f.holder_settles(f.agent_holder(), bar, ClaimSettleDecision::Reject);

    let body = f.stored(bar);
    assert_eq!(
        (body.lifecycle, body.approval),
        (ClaimLifecycleStatus::Active, ClaimApprovalStatus::Proposed),
        "the do-not-contact bar still holds and waits (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "an agent holder never lifts a bar");
    let person = f
        .holder_settles(f.person_holder(), bar, ClaimSettleDecision::Reject)
        .expect("the proposal stays open for a person holder");
    assert_eq!(person.verdict, ClaimSettlementVerdict::Rejected);
}

/// Case 1, guard: a person holder's reject lands.
#[test]
fn a_person_holder_rejects_a_proposed_do_not_contact() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();

    let settled = f
        .holder_settles(f.person_holder(), bar, ClaimSettleDecision::Reject)
        .expect("a person holder rejects the bar under the owner's Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(settled.reason, ClaimSettlementReason::HolderDeclined);
    assert_eq!(f.stored(bar).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// Case 1, guard: the owner's reject lands.
#[test]
fn the_owner_rejects_a_proposed_do_not_contact() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();

    let settled = f.owner_settles(bar, ClaimSettleDecision::Reject);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(f.stored(bar).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// Case 2, red: the agent holder's approval superseded the window.
#[test]
fn an_agent_holder_never_approves_a_replacement_over_a_delivery_window() {
    let f = Fixture::new();
    let (window, replacement) = f.replacement_over_a_delivery_window();

    let settled = f.holder_settles(f.agent_holder(), replacement, ClaimSettleDecision::Approve);

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the delivery window still holds (settle: {settled:?})"
    );
    assert_eq!(
        f.stored(replacement).approval,
        ClaimApprovalStatus::Proposed,
        "the replacement still waits"
    );
    assert_refused_as_a_restriction_close(settled, "an agent holder never lifts a window");
    let owner = f.owner_settles(replacement, ClaimSettleDecision::Approve);
    assert_eq!(owner.verdict, ClaimSettlementVerdict::Landed);
}

/// Case 2, guard: a person holder's approval lands and supersedes the window.
#[test]
fn a_person_holder_approves_a_replacement_over_a_delivery_window() {
    let f = Fixture::new();
    let (window, replacement) = f.replacement_over_a_delivery_window();

    let settled = f
        .holder_settles(f.person_holder(), replacement, ClaimSettleDecision::Approve)
        .expect("a person holder approves the replacement under the owner's Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(settled.reason, ClaimSettlementReason::HolderApproved);
    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(
        f.stored(replacement).approval,
        ClaimApprovalStatus::Approved
    );
}

/// Case 2, guard: the owner's approval lands and supersedes the window.
#[test]
fn the_owner_approves_a_replacement_over_a_delivery_window() {
    let f = Fixture::new();
    let (window, replacement) = f.replacement_over_a_delivery_window();

    let settled = f.owner_settles(replacement, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Superseded);
}

/// Case 3, red: the agent holder's approval completed the parked retract.
#[test]
fn an_agent_holder_never_completes_a_parked_retract_of_a_delivery_window() {
    let f = Fixture::new();
    let window = f.parked_retract_of_a_delivery_window();

    let settled = f.holder_settles(f.agent_holder(), window, ClaimSettleDecision::Approve);

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the delivery window still holds (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "an agent holder never lifts a window");
    let person = f
        .holder_settles(f.person_holder(), window, ClaimSettleDecision::Approve)
        .expect("the parked retract stays open for a person holder");
    assert_eq!(person.verdict, ClaimSettlementVerdict::Landed);
}

/// Case 3, guard: a person holder's approval retracts the window.
#[test]
fn a_person_holder_completes_a_parked_retract_of_a_delivery_window() {
    let f = Fixture::new();
    let window = f.parked_retract_of_a_delivery_window();

    let settled = f
        .holder_settles(f.person_holder(), window, ClaimSettleDecision::Approve)
        .expect("a person holder approves the parked retract under the owner's Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// Case 3, guard: the owner's approval retracts the window.
#[test]
fn the_owner_completes_a_parked_retract_of_a_delivery_window() {
    let f = Fixture::new();
    let window = f.parked_retract_of_a_delivery_window();

    let settled = f.owner_settles(window, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// Control: declining a parked retract closes nothing, so the agent holder
/// still declines it, and the window stands as it was.
#[test]
fn an_agent_holder_still_declines_a_parked_retract_of_a_delivery_window() {
    let f = Fixture::new();
    let window = f.parked_retract_of_a_delivery_window();

    let settled = f
        .holder_settles(f.agent_holder(), window, ClaimSettleDecision::Reject)
        .expect("the agent holder declines the parked retract");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    let body = f.stored(window);
    assert_eq!(
        (body.lifecycle, body.approval),
        (ClaimLifecycleStatus::Active, ClaimApprovalStatus::Approved)
    );
}

/// Control: a replacement over a row that restricts no one still lands on
/// the agent holder's approval.
#[test]
fn an_agent_holder_still_approves_a_replacement_over_a_note() {
    let f = Fixture::new();
    let note = f.approved(NOTE, json!("the first note"));
    let replacement = f.proposes(NOTE, f.subject, json!("the second note"));

    let settled = f
        .holder_settles(f.agent_holder(), replacement, ClaimSettleDecision::Approve)
        .expect("the agent holder approves the replacement");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(note).lifecycle, ClaimLifecycleStatus::Superseded);
}

/// Control: a proposal that restricts no one still declines on the agent
/// holder's reject.
#[test]
fn an_agent_holder_still_rejects_a_proposed_note() {
    let f = Fixture::new();
    let note = f.proposes(NOTE, f.subject, json!("a note"));

    let settled = f
        .holder_settles(f.agent_holder(), note, ClaimSettleDecision::Reject)
        .expect("the agent holder rejects the note");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(f.stored(note).lifecycle, ClaimLifecycleStatus::Retracted);
}
