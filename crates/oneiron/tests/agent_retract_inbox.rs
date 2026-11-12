//! The owner inbox and an agent's parked retract (FIX 23599). The retract
//! parks behind a tray row with no run id, and the inbox groups hold only
//! Dreamer-run rows, so no group lists it and no bulk verb reaches it. The
//! one inbox door keyed by claim id, the approve-with-edit door, refuses it
//! whole, edited or not: an unchanged body is re-put as the agent author's
//! write, which the gate holds at the agent's ceiling. The holder settles it
//! with `vault.claims.review` and `vault.claims.settle`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::error::GateError;
use oneiron::inbox::{InboxBulkVerb, UnifiedInboxGroup};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementVerdict, MemoryResult, resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, Error, Vault,
    VaultConfig,
};
use serde_json::json;

const RETRACT_PENDING: &str = "gate.pending.retract_closure";

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
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        // A host loads this install's signing keys from its keystore after
        // each open.
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let agent = vault
            .ensure_agent_principal("retract-author")
            .expect("agent");
        let subject = vault
            .ensure_agent_principal("retract-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        // The local host attests its own owner.
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        // The agent reads and proposes, as a paired agent session does.
        vault
            .grant_foreign_principal(&owner_proof, &agent.to_hex())
            .expect("the owner grants the agent read and propose");
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

    /// The agent's claim, proposed and then approved by the owner.
    fn approved_agent_claim(&self) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!("Yuki"),
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
        };
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&input)
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
        let settled = self.settle(id, ClaimSettleDecision::Approve);
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
        self.assert_standing(id, "the owner approved the agent's claim");
        id
    }

    /// The agent's retract of its own approved claim, which must park.
    fn park(&self, id: EntityId) {
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_retract(&id.to_hex())
            .unwrap_or_else(|error| panic!("the author's retract is refused: {error:?}"));
        assert_eq!(
            receipt.approval, "pending",
            "the retract waits for the holder"
        );
    }

    fn review(&self, id: EntityId) -> MemoryResult<String> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .map(|review| review.review_id)
    }

    fn settle(&self, id: EntityId, decision: ClaimSettleDecision) -> ClaimSettlement {
        let review_id = self.review(id).expect("review");
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id,
                    decision,
                    grant_ref: None,
                },
            )
            .expect("settle")
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    /// The claim still stands as the owner approved it.
    fn assert_standing(&self, id: EntityId, why: &str) {
        let body = self.body(id);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active, "{why}");
        assert_eq!(body.approval, ClaimApprovalStatus::Approved, "{why}");
        assert_eq!(body.valid_to, None, "{why}");
    }

    /// The claim stands and its retract still waits for the holder.
    fn assert_still_parked(&self, id: EntityId, why: &str) {
        self.assert_standing(id, why);
        assert!(self.review(id).is_ok(), "the retract still waits: {why}");
    }

    /// Every claim id an inbox group of either kind shows, as a member or
    /// as a member's collapsed duplicate.
    fn inbox_claim_ids(&self) -> Vec<String> {
        let page = self
            .vault
            .inbox_groups_unified(1_000_000, 64, None)
            .expect("project the owner's inbox");
        page.groups
            .into_iter()
            .filter_map(|group| match group {
                UnifiedInboxGroup::Dreamer { group } => Some(group),
                UnifiedInboxGroup::Shape { .. } => None,
            })
            .flat_map(|group| group.members)
            .flat_map(|member| std::iter::once(member.claim_id).chain(member.duplicate_claim_ids))
            .collect()
    }
}

#[test]
fn a_parked_retract_shows_in_no_inbox_group() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();

    f.park(id);

    let rows = f.vault.pending_gate_consents(64).expect("read the tray");
    let row = rows
        .iter()
        .find(|row| row.claim_id == *id.as_bytes())
        .expect("the parked retract has a tray row");
    assert_eq!(row.reason_codes, [RETRACT_PENDING]);
    assert_eq!(
        row.dreamer_run_id, None,
        "the parked retract's tray row names no run"
    );
    assert!(
        f.vault
            .pending_dreamer_run_ids()
            .expect("read the tray's runs")
            .is_empty(),
        "no run waits in the tray"
    );
    assert!(
        !f.inbox_claim_ids().contains(&id.to_hex()),
        "no inbox group lists the parked retract"
    );
    f.assert_still_parked(id, "reading the inbox changes nothing");
}

#[test]
fn no_inbox_bulk_verb_reaches_a_parked_retract() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);
    let decision_hex = f
        .vault
        .pending_gate_consents(64)
        .expect("read the tray")
        .into_iter()
        .find(|row| row.claim_id == *id.as_bytes())
        .expect("the parked retract has a tray row")
        .decision_id
        .to_hex();

    for verb in [InboxBulkVerb::RejectAll, InboxBulkVerb::AcceptAll] {
        for group_ref in [id.to_hex(), decision_hex.clone()] {
            let answer = f.vault.resolve_inbox_group(&group_ref, verb);
            assert!(
                matches!(answer, Err(Error::EntityNotFound)),
                "{verb:?} on {group_ref} finds no group: {answer:?}"
            );
        }
    }

    f.assert_still_parked(id, "no bulk verb closed the tray row");
    let declined = f.settle(id, ClaimSettleDecision::Reject);
    assert_eq!(declined.verdict, ClaimSettlementVerdict::Rejected);
    f.assert_standing(id, "the holder's decline leaves the claim standing");
    assert!(f.review(id).is_err(), "nothing is left to settle");
    f.park(id);
    f.assert_still_parked(id, "a later retract parks afresh");
}

#[test]
fn an_inbox_approval_with_an_edit_of_a_parked_retract_is_refused_whole() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);
    let mut edited = f.body(id);
    edited.value = rmpv::Value::from("Owen");
    let edited = encode_claim_body(&edited).expect("encode the edit");

    let answer = f.vault.approve_inbox_member_with_edit(&id, &edited);

    assert!(answer.is_err(), "an edit is no consent to the retract");
    assert_eq!(
        f.body(id).value,
        rmpv::Value::from("Yuki"),
        "the refused edit lands nothing: {answer:?}"
    );
    f.assert_still_parked(id, "the refused edit closes nothing");
}

#[test]
fn an_inbox_approval_without_an_edit_of_a_parked_retract_is_refused_whole() {
    let f = Fixture::new();
    let id = f.approved_agent_claim();
    f.park(id);
    let unchanged = encode_claim_body(&f.body(id)).expect("encode the body as reviewed");

    let answer = f.vault.approve_inbox_member_with_edit(&id, &unchanged);

    match answer.expect_err("an unchanged body is no consent to the retract") {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "pending");
            assert_eq!(reason_codes.as_slice(), ["gate.pending.actor_ceiling"]);
        }
        other => panic!("expected the agent's ceiling to hold the re-put, got {other:?}"),
    }
    f.assert_still_parked(id, "the refused approval closes nothing");
    let settled = f.settle(id, ClaimSettleDecision::Approve);
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    let body = f.body(id);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(
        body.valid_to.is_some(),
        "the retracted claim's validity ends"
    );
    assert!(f.review(id).is_err(), "nothing is left to settle");
}
