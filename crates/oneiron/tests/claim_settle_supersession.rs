//! Settling a proposal closes the supersession it proposed (e2e MEMORY-01;
//! ARCH-0040 `mcp:5`: a destructive supersede defers its closure until the
//! approval; ARCH-0003: the conflict set keys the question, `topicKey` for a
//! set-cardinality predicate). An agent's independent proposal on the
//! owner's standing claim, once the owner approves it, supersedes that
//! claim: one current head, not two. The agent stays its author.

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementVerdict, resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EdgeKind, EntityId,
    Vault, VaultConfig,
};
use serde_json::json;

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
            .ensure_agent_principal("settlement-proposer")
            .expect("agent");
        let subject = vault
            .ensure_agent_principal("settlement-subject")
            .expect("subject");
        let facet = vault.default_facet().expect("default facet");
        // The local host attests its own owner.
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        // A named agent reads nothing by its identity alone. The owner grants
        // the proposer read and propose, as a paired agent session holds: the
        // proposal names the subject, a row the proposer must read.
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

    fn declare_food_preference_normal(&self) {
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
        // A separate pack would still meet the default pack's critical fallback.
        rules.push(Value::Map(vec![
            (Value::from("prefix"), Value::from("preference.food")),
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
            .expect("encode preference policy");
        self.vault
            .install_owner_policy_manifest(
                &self.owner_proof,
                id,
                bytes,
                self.vault.now_recorded_at(),
            )
            .expect("declare food preference normal");
    }

    fn input(&self, predicate: &str, value: &str, topic: Option<&str>) -> ClaimInput {
        let mut scope = json!({ "facet": self.facet.to_hex() });
        if let Some(topic) = topic {
            scope["topic_key"] = json!(topic);
        }
        ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(scope),
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        }
    }

    /// The owner's own standing claim.
    fn head(&self, input: &ClaimInput) -> EntityId {
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(input)
            .expect("owner upsert");
        assert_eq!(receipt.approval, "auto", "the owner's claim lands");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("head id")
    }

    /// The agent's independent proposal: no deferred action names a target.
    fn propose(&self, input: &ClaimInput) -> EntityId {
        let mut proposed = input.clone();
        proposed.source = "inferred".to_owned();
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&proposed)
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
        assert_eq!(
            self.vault.pending_claim_supersession(&id).expect("pending"),
            None
        );
        id
    }

    fn review(&self, id: EntityId) -> String {
        let review = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("review");
        assert_eq!(review.opener_ref, Some(self.agent.to_hex()));
        review.review_id
    }

    fn settle_reviewed(
        &self,
        id: EntityId,
        review_id: String,
        decision: ClaimSettleDecision,
    ) -> oneiron::memory::MemoryResult<ClaimSettlement> {
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
    }

    fn settle(&self, id: EntityId, decision: ClaimSettleDecision) -> ClaimSettlement {
        let review_id = self.review(id);
        self.settle_reviewed(id, review_id, decision)
            .expect("settle")
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    fn supersedes(&self, id: EntityId) -> Vec<EntityId> {
        self.vault
            .targets(&id, EdgeKind::Supersedes, None)
            .expect("supersedes edges")
    }

    /// `old` closed and `new` standing in its place.
    fn assert_superseded(&self, old: EntityId, new: EntityId, settled: &ClaimSettlement) {
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
        assert_eq!(settled.proposal_ref, new.to_hex());
        let old_body = self.body(old);
        let new_body = self.body(new);
        assert_eq!(
            old_body.lifecycle,
            ClaimLifecycleStatus::Superseded,
            "the approval closes the head it replaces"
        );
        assert!(
            old_body.valid_to.is_some(),
            "the closed head's validity ends"
        );
        assert_eq!(new_body.approval, ClaimApprovalStatus::Approved);
        assert_eq!(new_body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(self.supersedes(new), vec![old]);
    }
}

#[test]
fn approving_a_proposal_supersedes_the_head_it_replaces() {
    let f = Fixture::new();
    let old = f.head(&f.input("profile.name", "Ada", None));
    let new = f.propose(&f.input("profile.name", "Ada Lovelace", None));
    assert_eq!(f.body(old).lifecycle, ClaimLifecycleStatus::Active);

    let settled = f.settle(new, ClaimSettleDecision::Approve);

    f.assert_superseded(old, new, &settled);
}

#[test]
fn a_set_predicate_approval_supersedes_only_the_head_on_its_topic() {
    let f = Fixture::new();
    f.declare_food_preference_normal();
    let old = f.head(&f.input("preference.food", "I like ramen", Some("ramen")));
    let other = f.head(&f.input("preference.food", "I like sushi", Some("sushi")));
    let new = f.propose(&f.input("preference.food", "I avoid ramen", Some("ramen")));

    let settled = f.settle(new, ClaimSettleDecision::Approve);

    f.assert_superseded(old, new, &settled);
    let other_body = f.body(other);
    assert_eq!(other_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(other_body.valid_to, None);
    assert!(
        f.vault
            .sources(&other, EdgeKind::Supersedes, None)
            .expect("supersedes edges")
            .is_empty(),
        "another question's answer stands"
    );
}

#[test]
fn a_set_predicate_proposal_with_no_topic_supersedes_nothing() {
    let f = Fixture::new();
    f.declare_food_preference_normal();
    let old = f.head(&f.input("preference.food", "I like ramen", None));
    let new = f.propose(&f.input("preference.food", "I like udon", None));

    let settled = f.settle(new, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.body(old).lifecycle, ClaimLifecycleStatus::Active);
    assert!(f.supersedes(new).is_empty(), "no question, no conflict set");
}

#[test]
fn a_rejection_leaves_the_head_standing() {
    let f = Fixture::new();
    let old = f.head(&f.input("profile.name", "Ada", None));
    let before = f.body(old);
    let new = f.propose(&f.input("profile.name", "Ada Lovelace", None));

    let settled = f.settle(new, ClaimSettleDecision::Reject);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(f.body(old), before);
    assert_eq!(f.body(new).approval, ClaimApprovalStatus::Rejected);
    assert!(f.supersedes(new).is_empty());
}

#[test]
fn a_head_that_lands_after_the_review_makes_it_stale() {
    let f = Fixture::new();
    let new = f.propose(&f.input("profile.name", "Ada Lovelace", None));
    let review_id = f.review(new);
    // The review read no head; the owner's claim lands after it.
    let head = f.head(&f.input("profile.name", "Ada", None));

    let refused = f.settle_reviewed(new, review_id, ClaimSettleDecision::Approve);

    assert!(
        refused.is_err(),
        "the approval would close a head its review never read"
    );
    assert_eq!(f.body(new).approval, ClaimApprovalStatus::Proposed);
    assert_eq!(f.body(head).lifecycle, ClaimLifecycleStatus::Active);
    // A fresh review reads the head, and its approval closes it.
    let settled = f.settle(new, ClaimSettleDecision::Approve);
    f.assert_superseded(head, new, &settled);
}

#[test]
fn an_approval_with_no_head_supersedes_nothing() {
    let f = Fixture::new();
    let new = f.propose(&f.input("profile.name", "Ada", None));

    let settled = f.settle(new, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.body(new).approval, ClaimApprovalStatus::Approved);
    assert!(f.supersedes(new).is_empty());
}

/// A head in another facet is another audience's (review P1 of #6930): the
/// approval closes only a head born in its proposal's facet and project. The
/// owner's head lands while a second facet is the default; the agent's
/// proposal on the same key, with no opaque scope on either, lands in the
/// first.
#[test]
fn an_approval_supersedes_no_head_in_another_facet() {
    let f = Fixture::new();
    let owner = oneiron::WriteActor::new(f.owner, EdgeActorClass::Human);
    let other = f
        .vault
        .create_facet(
            &f.owner_proof,
            f.owner,
            "settlement-second-facet",
            f.vault.now_recorded_at(),
        )
        .expect("a second facet");
    let mut input = f.input("profile.name", "Ada", None);
    input.scope = None;
    f.vault
        .set_default_facet(other, owner)
        .expect("the second facet is the default");
    let old = f.head(&input);
    f.vault
        .set_default_facet(f.facet, owner)
        .expect("the first facet is the default again");
    input.value = json!("Ada Lovelace");
    let new = f.propose(&input);
    assert_eq!(f.body(old).scope_facet, other);
    assert_eq!(f.body(new).scope_facet, f.facet);

    let settled = f.settle(new, ClaimSettleDecision::Approve);

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    let old_body = f.body(old);
    assert_eq!(
        old_body.lifecycle,
        ClaimLifecycleStatus::Active,
        "the head in the other facet stands"
    );
    assert_eq!(old_body.valid_to, None);
    assert_eq!(f.body(new).approval, ClaimApprovalStatus::Approved);
    assert!(f.supersedes(new).is_empty());
}
