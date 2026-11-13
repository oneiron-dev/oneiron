//! The owner's approval lands past the criticality floor
//! ([CRITICALITY-FLOOR-PENDS-OWNER-WRITES]). A predicate no manifest rule
//! names resolves critical by fallback, and the shipped manifest declares
//! `health.` critical; on either, the gate's floor pended every Approved
//! write the owner made, because the owner's proof never reached the gate.
//! ARCH-0057 §2: "A manifest never overrules the person on their own vault";
//! ARCH-0003 §Criticality: the critical default "does not stop the write".
//! Each public door below carries the owner's proof to the gate now. Without
//! that proof an Approved stamp keeps its floor.
//!
//! Run with `cargo test --locked -p oneiron --all-features --test owner_approval_criticality_floor`.

use oneiron::agent_dispatch::{ResidentAgentSpec, ResidentGoalRecord, ResidentWakeMode};
use oneiron::authority::HostSlipIssuer;
use oneiron::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT;
use oneiron::campaign::send_hygiene::{SuppressionCause, SuppressionInput, apply_suppression};
use oneiron::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::run_review::{
    RunChangeVerdict, RunReviewChange, RunReviewRequest, RunSettleDecision, RunSettleRequest,
};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
    resolve_entity_ref,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use serde_json::json;

/// No rule of the shipped manifest names this predicate: it resolves
/// critical by fallback.
const UNDECLARED_PREDICATE: &str = "loop.alpha";
/// The shipped manifest declares the `health.` class critical.
const DECLARED_CRITICAL_PREDICATE: &str = "health.allergy";
/// The gate's reason for a write parked on the criticality floor.
const CRITICALITY_FLOOR: &str = "gate.pending.criticality_floor";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault opened with the shipped default manifest, its owner's proof,
    /// and an agent the owner granted read and propose.
    fn new() -> Self {
        Self::open(false)
    }

    /// [`Fixture::new`] on a vault rooted under a host, which binds its
    /// owner under the root (H149). The run review doors act only for the
    /// root owner (`verify_owner`), as a served vault always has one.
    fn rooted() -> Self {
        Self::open(true)
    }

    fn open(rooted: bool) -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        if rooted {
            let issuer = HostSlipIssuer::from_secret(b"owner-approval-criticality-floor")
                .expect("fixture host issuer");
            vault
                .ensure_host_root_slip(&issuer)
                .expect("the host root binds the owner");
        }
        let agent = vault
            .ensure_agent_principal("criticality-floor-proposer")
            .expect("agent");
        let subject = vault
            .ensure_agent_principal("criticality-floor-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_foreign_principal(&owner_proof, &agent.to_hex())
            .expect("the owner grants the proposer read and propose");
        Self {
            vault,
            owner,
            agent,
            subject,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    fn input(&self, predicate: &str, value: &str) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(value),
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
        }
    }

    /// The agent's proposal, parked for the owner.
    fn propose(&self, predicate: &str, value: &str) -> EntityId {
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&self.input(predicate, value))
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id")
    }

    /// The owner's `vault.claims.review` then `vault.claims.settle` (approve).
    fn owner_settles(&self, id: EntityId) -> ClaimSettlementVerdict {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = memory
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("owner review");
        assert_eq!(review.opener_ref, Some(self.agent.to_hex()));
        memory
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("the owner's approval lands")
            .verdict
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    /// The claim reads back Approved and live, as the owner's approval left it.
    fn assert_approved(&self, id: EntityId, predicate: &str) {
        let body = self.body(id);
        assert_eq!(body.predicate, predicate);
        assert_eq!(body.approval, ClaimApprovalStatus::Approved);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    }

    fn stored_row(&self, entity_type: u8, body: &[u8]) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(&id, entity_type, TimeRange { start: 5, end: 5 }, 5, body)
            .expect("fixture row");
        id
    }
}

/// `vault.claims.settle`: the owner approves an agent's proposal on a
/// predicate no rule names. On main the approval answered 403
/// `gate.pending.criticality_floor` (MUSE-LOOP-01, SECRETS-06).
#[test]
fn owner_settle_lands_an_agent_proposal_on_an_undeclared_predicate() {
    let f = Fixture::new();
    let id = f.propose(UNDECLARED_PREDICATE, "the first loop note");

    assert_eq!(f.owner_settles(id), ClaimSettlementVerdict::Landed);

    f.assert_approved(id, UNDECLARED_PREDICATE);
}

/// `vault.claims.settle` on a DECLARED critical class: the owner's approval
/// of an agent's `health.` proposal lands too (Engine ruling Q1 = A).
#[test]
fn owner_settle_lands_an_agent_proposal_on_a_declared_critical_predicate() {
    let f = Fixture::new();
    let id = f.propose(DECLARED_CRITICAL_PREDICATE, "peanuts");

    assert_eq!(f.owner_settles(id), ClaimSettlementVerdict::Landed);

    f.assert_approved(id, DECLARED_CRITICAL_PREDICATE);
}

/// `vault.runs.settle`: the owner approves a run's waiting claim on a
/// predicate no rule names (MUSE-LOOP-08).
#[test]
fn owner_run_settle_lands_an_agent_proposal_on_an_undeclared_predicate() {
    let f = Fixture::rooted();
    let id = f.propose(UNDECLARED_PREDICATE, "the run's loop note");
    let memory = f.vault.memory(f.owner, EdgeActorClass::Human);
    let request = RunReviewRequest {
        run_id: "run:criticality-floor".to_owned(),
        changes: vec![RunReviewChange::Claim {
            claim_ref: id.to_hex(),
        }],
    };
    let review = memory
        .review_run_as_owner(&f.owner_proof, &request)
        .expect("owner run review");
    assert_eq!(review.changes.len(), 1);
    assert_eq!(review.changes[0].verdict, RunChangeVerdict::Waiting);

    let settled = memory
        .settle_run_as_owner(
            &f.owner_proof,
            &RunSettleRequest {
                review: request,
                review_id: review.review_id,
                decision: RunSettleDecision::Approve,
            },
        )
        .expect("the owner's run approval lands");

    assert_eq!(settled.changes.len(), 1);
    assert_eq!(settled.changes[0].verdict, RunChangeVerdict::Landed);
    f.assert_approved(id, UNDECLARED_PREDICATE);
}

/// `Vault::bind_resident_agent`: the owner's binding writes an Approved
/// `agent.resident` claim, a predicate no rule names (FIX 23440).
#[test]
fn owner_resident_binding_lands_on_its_undeclared_predicate() {
    let f = Fixture::new();
    let (lead, _) = f
        .vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded definitions read")
        .expect("the seeded team lead");
    let inbox = EntityId::now();
    f.vault
        .create_own_app_channel_identity(&inbox, lead, 1)
        .expect("the lead's home channel");
    let goal = f.stored_row(ENTITY_TYPE_TURN, &[0x80]);
    let (room, node) = (EntityId::now(), EntityId::now());
    f.vault
        .memory(f.owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(node.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "room".to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 2,
            assertions: WitnessAssertions::default(),
        })
        .expect("the resident's home room");
    let spec = ResidentAgentSpec {
        agent_def_ref: lead,
        inbox_identity_ref: inbox,
        home_conversation_ref: room,
        home_message_ref: node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::HumanMessages,
        wake_hold_secs: 0,
        digest_delay_secs: oneiron::agent_dispatch::RESIDENT_DIGEST_DELAY_DEFAULT_SECS,
    };

    let binding = f
        .vault
        .bind_resident_agent(&f.owner_proof, &spec, 3)
        .expect("the owner's resident binding lands");

    f.assert_approved(binding, "agent.resident");
    assert_eq!(
        f.vault.resident_agent(lead).expect("resident read"),
        Some(spec)
    );
}

/// `federation::bind_member_person`: the owner binds a member to a person
/// with an Approved `core.relationship.person_ref`, a predicate no rule names
/// (Engine ruling Q2 = A: the binding is the owner's act and takes the
/// owner's proof).
#[test]
fn owner_member_binding_lands_on_its_undeclared_predicate() {
    let f = Fixture::new();
    let member = f.stored_row(ENTITY_TYPE_PERSON, b"member");
    let person = f.stored_row(ENTITY_TYPE_PERSON, b"person");

    let binding = oneiron::federation::bind_member_person(
        &f.vault,
        &f.owner_proof,
        member,
        person,
        TimeRange { start: 13, end: 13 },
        13,
    )
    .expect("the owner's member binding lands");

    f.assert_approved(binding, PREDICATE_RELATIONSHIP_PERSON_REF);
    assert_eq!(
        f.body(binding).value.as_str(),
        Some(person.to_hex().as_str())
    );
    assert_eq!(f.body(binding).subject, ClaimSubject::Entity(member));
}

/// The suppression writer behind `vault.campaign.unsubscribe` and the
/// hard-bounce webhook: a person's unsubscribe writes `comm.do_not_contact`,
/// a restriction no rule names. It rides the engine-owned door, as a STOP's
/// projected opt-out does (F06 H160): the ladder never refuses a restriction.
#[test]
fn unsubscribe_restriction_lands_on_an_undeclared_comm_predicate() {
    let f = Fixture::new();
    let person = f.stored_row(ENTITY_TYPE_PERSON, b"unsubscribing person");
    let evidence = f.stored_row(ENTITY_TYPE_TURN, b"unsubscribe");

    let receipt = apply_suppression(
        &f.vault,
        SuppressionCause::Unsubscribe,
        &SuppressionInput {
            person_ref: person,
            campaign_ref: None,
            channel: "email".to_owned(),
            sender_ref: None,
            evidence_ref: evidence,
            occurred_at: 50,
        },
    )
    .expect("the unsubscribe's restriction lands");

    f.assert_approved(
        receipt.do_not_contact_claim_ref,
        PREDICATE_COMM_DO_NOT_CONTACT,
    );
    assert_eq!(
        f.body(receipt.do_not_contact_claim_ref).subject,
        ClaimSubject::Entity(person)
    );
}

/// Refusal: an Approved stamp with no owner proof keeps the floor. The local
/// writer's raw put of an Approved body on a predicate no rule names pends,
/// on main and on this head alike, and nothing is written.
#[test]
fn an_approved_stamp_without_the_owners_proof_still_pends() {
    let f = Fixture::new();
    let id = EntityId::now();
    let body = ClaimBody::new(
        UNDECLARED_PREDICATE,
        ClaimSubject::Entity(f.subject),
        rmpv::Value::from("a self-stamped approval"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");

    let refused = f
        .vault
        .put_claim(&id, &body, TimeRange { start: 7, end: 7 }, 7)
        .expect_err("an unattested Approved stamp is parked, not landed");

    assert!(
        refused.to_string().contains(CRITICALITY_FLOOR),
        "the floor parks it: {refused}"
    );
    assert_eq!(f.vault.get_claim(&id).expect("read claim"), None);
}
