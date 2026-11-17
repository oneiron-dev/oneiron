//! A generated claim that disagrees with a user-stated one lands beside it,
//! Proposed, with a disagreement card ([GENERATED-DISAGREEMENT-BESIDE-USER-CLAIM];
//! the owner, 2026-09-22: "Generated never supersedes UserStated, unchanged. A
//! user_stated claim can be stale. A generated claim that disagrees lands beside
//! it, Proposed, with a disagreement card. The person's word decides, and that
//! word is a new user_stated claim. The gate blocks a silent replacement, never
//! a correction.").
//!
//! e2e MUSE-GATE-08 found an agent's `vault.commit` of a generated
//! `profile.preferred_display_name` over the owner's user-stated one refused 403
//! "self-Grant never replaces another author's claim; ask for conflict review":
//! the commit named the user's claim as the head it replaced. It now lands as
//! its own Proposed claim with no supersession, the user's claim stands
//! unchanged, and one `core.conflict.open` marker names the pair. The agent
//! cannot settle its own proposal; the owner's approval closes nothing; the
//! owner's new user-stated word supersedes the owner's own claim at once and
//! leaves the generated one standing beside it. A generated claim over the same
//! agent's own generated head still proposes that supersession.
//!
//! The agent is paired as MUSE-GATE-08 pairs it: an ordinary PERSON that redeems
//! a pairing link the owner issued for it as class `agent`, granted the owner's
//! read and propose. Its claim is committed through `Memory::commit`, the door
//! `vault.commit` calls.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test generated_disagreement_beside_user_claim`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, MachineRole, PairingPrincipal};
use oneiron::claim::{ClaimSource, ClaimSubject};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, CommitOutcome, CommitReceipt, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use rmpv::Value;
use serde_json::json;

/// Single-valued (no declared cardinality), and the shipped manifest's
/// `profile.` rule declares it normal, so no criticality floor or critical
/// confirmation holds a write on it.
const PREDICATE: &str = "profile.preferred_display_name";
const CONFLICT_OPEN: &str = "core.conflict.open";
const USER_VALUE: &str = "Maren x";
const GENERATED_VALUE: &str = "Marenne x";

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// An ordinary PERSON paired as an agent on the owner's pairing link.
    agent: EntityId,
    /// The PERSON every claim is about.
    subject: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault rooted under a host with its owner bound under the root, on an
    /// install with a live machine profile, as a served vault is.
    fn rooted() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        let agent = person(&vault, b"generated disagreement agent");
        let subject = person(&vault, b"generated disagreement subject");
        let facet = vault.default_facet().expect("default facet");
        let fixture = Self {
            vault,
            issuer,
            owner,
            owner_proof,
            agent,
            subject,
            facet,
            _directory: directory,
        };
        fixture.pair_as_agent(agent, 9);
        fixture
    }

    /// `holder` redeems a pairing link the owner issued for it as class
    /// `agent`, as MUSE-GATE-08's `engine.pairActor` does, and the owner grants
    /// it read and propose.
    fn pair_as_agent(&self, holder: EntityId, binding_seed: u8) {
        let holder_ref = holder.to_hex();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let link = self
            .vault
            .issue_owner_pairing_link(
                &self.issuer,
                &self.owner_proof,
                scope,
                3_600,
                PairingPrincipal {
                    holder_ref: Some(holder_ref.clone()),
                    actor_class: Some("agent".to_owned()),
                    ..PairingPrincipal::default()
                },
            )
            .expect("the owner issues the agent's pairing link");
        let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
        let binding_key = signing_key.verifying_key().to_bytes();
        let transcript = oneiron::authority::pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )
        .expect("agent pairing transcript");
        self.vault
            .redeem_pairing_link(
                &self.issuer,
                &link.code,
                &holder_ref,
                binding_key,
                &signing_key.sign(&transcript).to_bytes(),
            )
            .expect("the agent redeems its pairing link");
        self.vault
            .grant_foreign_principal(&self.owner_proof, &holder_ref)
            .expect("the owner grants the agent read and propose");
    }

    fn input(&self, source: &str, value: &str) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: PREDICATE.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: source.to_owned(),
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

    /// The owner's own word on the slot, as `vault.claims.upsert` writes it.
    fn owner_states(&self, value: &str) -> CommitReceipt {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&self.input("user_stated", value))
            .expect("the owner's user-stated claim is written")
    }

    /// The owner's user-stated claim, landed Auto and standing.
    fn users_claim(&self) -> EntityId {
        let receipt = self.owner_states(USER_VALUE);
        assert_eq!(
            receipt.approval, "auto",
            "the owner's own word lands at once"
        );
        let id = self.claim_id(&receipt.claim_short_id);
        self.assert_standing(id, ClaimApprovalStatus::Auto, USER_VALUE);
        id
    }

    /// The agent's generated claim on the slot, committed through
    /// `Memory::commit` (the `vault.commit` door), as one landed element.
    fn agent_commits(&self, value: &str) -> CommitReceipt {
        let outcomes = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .commit(&[self.input("generated", value)])
            .expect("the agent's commit answers");
        assert_eq!(outcomes.len(), 1);
        match outcomes.into_iter().next().expect("one outcome") {
            CommitOutcome::Landed(receipt) => receipt,
            CommitOutcome::Refused { refusal, .. } => panic!(
                "the agent's generated claim is refused {}: {}",
                refusal.code, refusal.message,
            ),
        }
    }

    /// The owner reviews and approves `id`; the approval lands.
    fn owner_approves(&self, id: EntityId) {
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = owner
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("owner review");
        let settled = owner
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("the owner's approval lands");
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    }

    fn claim_id(&self, short: &str) -> EntityId {
        resolve_entity_ref(&self.vault, short).expect("claim id")
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    /// The claim stands: live, at `approval`, with `value`, never closed.
    fn assert_standing(&self, id: EntityId, approval: ClaimApprovalStatus, value: &str) {
        let body = self.body(id);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(body.approval, approval);
        assert_eq!(body.value.as_str(), Some(value));
        assert_eq!(body.valid_to, None);
    }

    /// The `core.conflict.open` markers about the subject.
    fn conflict_markers(&self) -> Vec<ClaimBody> {
        self.vault
            .claims_for_subject(&self.subject)
            .expect("the subject's claims")
            .into_iter()
            .map(|id| self.body(id))
            .filter(|body| body.predicate == CONFLICT_OPEN)
            .collect()
    }

    /// The user's claim and a generated disagreement the agent committed
    /// beside it, Proposed, with no supersession of the user's claim parked
    /// or closed.
    fn disagreement(&self) -> (EntityId, EntityId) {
        let users = self.users_claim();
        let receipt = self.agent_commits(GENERATED_VALUE);
        assert_eq!(receipt.approval, "proposed");
        assert_eq!(receipt.superseded_short_id, None);
        assert_eq!(receipt.superseded, None);
        let generated = self.claim_id(&receipt.claim_short_id);
        assert_ne!(generated, users);
        assert_eq!(
            self.vault
                .pending_claim_supersession(&generated)
                .expect("read the parked supersession"),
            None,
            "the generated claim proposes no replacement of the user's claim",
        );
        (users, generated)
    }
}

/// A plain PERSON row: a person of the vault who is not its owner.
fn person(vault: &Vault, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 5, end: 5 },
            5,
            body,
        )
        .expect("fixture person");
    id
}

/// (1) The agent's generated disagreement lands as its own Proposed claim, and
/// the user's claim stands unchanged: Active, Auto, its value, never closed.
/// On main the commit is refused 403 "self-Grant never replaces another
/// author's claim; ask for conflict review".
#[test]
fn an_agents_generated_disagreement_lands_proposed_beside_the_users_claim() {
    let f = Fixture::rooted();
    let (users, generated) = f.disagreement();

    let body = f.body(generated);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert_eq!(body.value.as_str(), Some(GENERATED_VALUE));
    assert_eq!(body.subject, ClaimSubject::Entity(f.subject));
    f.assert_standing(users, ClaimApprovalStatus::Auto, USER_VALUE);
    let users_body = f.body(users);
    assert_eq!(users_body.source, Some(ClaimSource::UserStated));
    assert_eq!(body.predicate, users_body.predicate);
    assert_eq!(body.scope_facet, users_body.scope_facet);
    assert_eq!(body.scope_project, users_body.scope_project);
}

/// (2) The disagreement card: one Proposed `core.conflict.open` marker about the
/// subject names the predicate and the pair `[generated, user's]`. On main the
/// commit is refused and no marker is written.
#[test]
fn the_disagreement_opens_one_conflict_naming_the_pair() {
    let f = Fixture::rooted();
    let (users, generated) = f.disagreement();

    let markers = f.conflict_markers();
    assert_eq!(markers.len(), 1, "one conflict names the differing pair");
    let marker = &markers[0];
    assert_eq!(marker.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(marker.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(marker.subject, ClaimSubject::Entity(f.subject));
    assert_eq!(marker.value.as_str(), Some(PREDICATE));
    let Some(Value::Map(evidence)) = &marker.evidence else {
        panic!("the marker has envelope evidence");
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("the marker's candidate evidence");
    assert_eq!(
        candidate_evidence,
        &Value::Map(vec![(
            Value::from("refs"),
            Value::Array(vec![
                Value::Binary(generated.as_bytes().to_vec()),
                Value::Binary(users.as_bytes().to_vec()),
            ]),
        )])
    );
}

/// (3) The agent that opened the proposal cannot settle it, and the owner's
/// approval of it closes nothing: both claims stand. On main there is no
/// proposal to settle.
#[test]
fn the_agent_cannot_settle_its_disagreement_and_the_owners_approval_closes_nothing() {
    let f = Fixture::rooted();
    let (users, generated) = f.disagreement();

    let owner = f.vault.memory(f.owner, EdgeActorClass::Human);
    let review = owner
        .claim_review_as_owner(
            &f.owner_proof,
            &ClaimProposalReviewRequest {
                claim_ref: generated.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the disagreement");
    assert_eq!(review.opener_ref, Some(f.agent.to_hex()));
    let agents_settle =
        f.vault
            .memory(f.agent, EdgeActorClass::Agent)
            .claim_settle(&ClaimSettleRequest {
                claim_ref: generated.to_hex(),
                review_id: review.review_id.clone(),
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            });
    assert!(
        agents_settle.is_err(),
        "the agent that opened the proposal never settles it: {agents_settle:?}",
    );
    f.assert_standing(generated, ClaimApprovalStatus::Proposed, GENERATED_VALUE);

    f.owner_approves(generated);
    f.assert_standing(generated, ClaimApprovalStatus::Approved, GENERATED_VALUE);
    f.assert_standing(users, ClaimApprovalStatus::Auto, USER_VALUE);
}

/// (4) The person's word decides: the owner's new user-stated claim supersedes
/// the owner's own claim at once, and the generated disagreement stays
/// standing, Proposed, beside it. On main the agent's commit is refused first.
#[test]
fn the_owners_new_word_supersedes_their_own_claim_and_leaves_the_disagreement() {
    let f = Fixture::rooted();
    let (users, generated) = f.disagreement();

    let corrected = "Marenne x, as the owner says it";
    let receipt = f.owner_states(corrected);
    assert_eq!(
        receipt.approval, "auto",
        "the owner's correction lands at once"
    );
    let superseded = receipt
        .superseded_short_id
        .as_deref()
        .expect("the correction names the claim it superseded");
    assert_eq!(f.claim_id(superseded), users);
    assert_eq!(f.body(users).lifecycle, ClaimLifecycleStatus::Superseded);
    let correction = f.claim_id(&receipt.claim_short_id);
    f.assert_standing(correction, ClaimApprovalStatus::Auto, corrected);
    f.assert_standing(generated, ClaimApprovalStatus::Proposed, GENERATED_VALUE);
}

/// (5) Control, unchanged from main: a generated claim with no standing head
/// opens no conflict, and the agent's generated claim over its own approved
/// generated head still proposes that supersession, parked until a grant.
#[test]
fn a_generated_claim_over_the_agents_own_generated_head_still_proposes_its_supersession() {
    let f = Fixture::rooted();
    let first = f.agent_commits("Marenne");
    assert_eq!(first.approval, "proposed");
    let first = f.claim_id(&first.claim_short_id);
    assert!(
        f.conflict_markers().is_empty(),
        "no stated peer, so no conflict"
    );
    f.owner_approves(first);
    f.assert_standing(first, ClaimApprovalStatus::Approved, "Marenne");

    let second = f.agent_commits(GENERATED_VALUE);
    assert_eq!(second.approval, "proposed");
    let second = f.claim_id(&second.claim_short_id);
    assert_eq!(
        f.vault
            .pending_claim_supersession(&second)
            .expect("read the parked supersession"),
        Some(first),
        "the agent's own generated head is still the head it replaces",
    );
    f.assert_standing(first, ClaimApprovalStatus::Approved, "Marenne");
    assert!(f.conflict_markers().is_empty());
}
