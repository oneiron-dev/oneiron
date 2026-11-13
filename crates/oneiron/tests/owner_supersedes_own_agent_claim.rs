//! The owner's upsert supersedes a claim of the owner's own agent in one act
//! ([OWNER-SUPERSEDES-OWN-AGENT-CLAIM]; the lead's ruling B, Fri 13 Nov 12:19:
//! never gate the owner on their own vault). MUSE-LOOP-08 found the owner's
//! `vault.claims.upsert` over their agent's approved claim refused 403 "self-Grant
//! never replaces another author's claim; ask for conflict review".
//!
//! The owner's write now lands at once and closes the agent's claim in the same
//! write, and its receipt records the owner's ruling and names the superseded
//! claim and its author. Claims by members, members' agents and agents the
//! owner never paired keep the review path (ARCH-0040, ARCH-0043: no admin
//! override by default), and a member gains nothing over the owner's agent.
//!
//! The owner's agent is paired as MUSE-LOOP-08 pairs it: an ordinary PERSON that
//! redeems a pairing link the owner issued for it as class `agent`, so its slip
//! names the owner as the member who approved it. Each case: an author holding
//! the owner's read and propose Grant proposes `profile.name` (a predicate the
//! shipped manifest declares normal) about one PERSON, the owner approves it,
//! and a second writer upserts the same slot.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_supersedes_own_agent_claim`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, MachineRole, PairingPrincipal};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, CommitReceipt, MemoryError, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor,
};
use serde_json::json;

/// The shipped manifest's `profile.` rule declares this predicate normal, so no
/// criticality floor or critical confirmation holds the owner's write.
const PREDICATE: &str = "profile.name";
/// The reason code of the owner's ruling over their own agent's claim.
const OWNER_RULING: &str = "gate.supersede.owner_ruling";
/// The refusal every other replacement of another author's claim keeps.
const CONFLICT_REVIEW: &str = "ask for conflict review";
const AGENT_VALUE: &str = "Owen, as the agent heard it";
const OWNER_VALUE: &str = "Owen, as the owner says it";

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The owner's own agent: an ordinary PERSON paired as an agent on the
    /// owner's pairing link, as MUSE-LOOP-08's proposer is.
    agent: EntityId,
    /// A second person in the vault, writing as a human.
    member: EntityId,
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
        let agent = person(&vault, b"owner supersede agent");
        let member = person(&vault, b"owner supersede member");
        let subject = person(&vault, b"owner supersede subject");
        let facet = vault.default_facet().expect("default facet");
        let fixture = Self {
            vault,
            issuer,
            owner,
            owner_proof,
            agent,
            member,
            subject,
            facet,
            _directory: directory,
        };
        fixture.pair_as_agent(agent, 7);
        fixture
    }

    /// `holder` redeems a pairing link the owner issued for it as class
    /// `agent`, as MUSE-LOOP-08's `engine.pairActor` does, and the owner grants
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

    /// An enabled agent definition the owner creates, anchored to `person` as
    /// that person's pen.
    fn pen_agent_of(&self, person: EntityId) -> EntityId {
        let agent = EntityId::now();
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "owner-supersede-member-pen",
                    "desc": "A member's pen agent",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("typed agent definition"),
            },
        )
        .expect("the owner creates the member's agent definition");
        oneiron::subject_model::anchor_actor_subject(
            &self.vault,
            agent,
            person,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            self.vault.now_recorded_at(),
        )
        .expect("the agent is anchored to its person");
        agent
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

    /// `author`'s proposal on the slot, approved by the owner: a landed claim
    /// `author` wrote, as MUSE-LOOP-08's beta is after the owner's settle.
    fn landed_claim_of(&self, author: EntityId, class: EdgeActorClass, value: &str) -> EntityId {
        // A writer names only records it can read (OF-063): with no read
        // Grant its proposal is denied gate.deny.unresolved_record_reference
        // on the subject. The owner grants the author read and propose, as
        // MUSE-LOOP-08's pairing does; a repeated grant changes nothing.
        self.vault
            .grant_foreign_principal(&self.owner_proof, &author.to_hex())
            .expect("the owner grants the author read and propose");
        let receipt = self
            .vault
            .memory(author, class)
            .claim_propose(&self.input("inferred", value))
            .expect("the proposal is written");
        assert_eq!(receipt.approval, "proposed");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
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
        assert_eq!(review.opener_ref, Some(author.to_hex()));
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
        self.assert_standing(id, ClaimApprovalStatus::Approved, value);
        id
    }

    /// `writer`'s upsert of the slot with `value`, as `vault.claims.upsert`
    /// writes it.
    fn upsert_as(
        &self,
        writer: EntityId,
        class: EdgeActorClass,
        value: &str,
    ) -> Result<CommitReceipt, MemoryError> {
        self.vault
            .memory(writer, class)
            .claim_upsert(&self.input("user_stated", value))
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    /// The claim stands: live, at `approval`, with `value`.
    fn assert_standing(&self, id: EntityId, approval: ClaimApprovalStatus, value: &str) {
        let body = self.body(id);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(body.approval, approval);
        assert_eq!(body.value.as_str(), Some(value));
    }

    /// The write was refused as a replacement of another author's claim, and
    /// `prior` still stands Approved with `value`.
    fn assert_refused_for_review(
        &self,
        result: Result<CommitReceipt, MemoryError>,
        prior: EntityId,
        value: &str,
    ) {
        let error = result.expect_err("the replacement of another author's claim is refused");
        assert_eq!(error.code, "FORBIDDEN", "{}", error.message);
        assert!(
            error.message.contains(CONFLICT_REVIEW),
            "the refusal points to conflict review: {}",
            error.message,
        );
        self.assert_standing(prior, ClaimApprovalStatus::Approved, value);
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

/// (1) The owner's upsert supersedes their own agent's approved claim in one
/// act: the replacement lands Auto, the agent's claim is closed in the same
/// write, and the receipt the upsert answers records the owner's ruling and
/// names the superseded claim and its author. On main the upsert is refused 403
/// "self-Grant never replaces another author's claim; ask for conflict review".
#[test]
fn the_owners_upsert_supersedes_their_own_agents_claim_as_the_owners_ruling() {
    let f = Fixture::rooted();
    let prior = f.landed_claim_of(f.agent, EdgeActorClass::Agent, AGENT_VALUE);

    let receipt = f
        .upsert_as(f.owner, EdgeActorClass::Human, OWNER_VALUE)
        .unwrap_or_else(|error| {
            panic!(
                "the owner's upsert over their own agent's claim is admitted, got {}: {}",
                error.code, error.message,
            )
        });

    assert_eq!(receipt.approval, "auto", "the owner's write lands at once");
    let replacement =
        resolve_entity_ref(&f.vault, &receipt.claim_short_id).expect("replacement id");
    f.assert_standing(replacement, ClaimApprovalStatus::Auto, OWNER_VALUE);
    let superseded = receipt
        .superseded_short_id
        .as_deref()
        .expect("the receipt names the claim it superseded");
    assert_eq!(
        resolve_entity_ref(&f.vault, superseded).expect("superseded id"),
        prior,
    );
    let closed = f.body(prior);
    assert_eq!(
        closed.lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the agent's claim is closed in the owner's write, with no proposal left open",
    );
    assert_eq!(closed.value.as_str(), Some(AGENT_VALUE));

    let decision = f
        .vault
        .memory(f.owner, EdgeActorClass::Human)
        .receipts(64)
        .expect("the owner reads the receipts")
        .into_iter()
        .find(|row| row.receipt_ref == receipt.receipt_ref)
        .expect("the upsert's receipt is in the decision ledger");
    assert!(
        decision
            .reason_codes
            .iter()
            .any(|code| code == OWNER_RULING),
        "the receipt records the owner's ruling: {:?}",
        decision.reason_codes,
    );
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.actor_ref, Some(f.owner.to_hex()));
    assert_eq!(decision.claim_ref, Some(replacement.to_hex()));
    assert_eq!(decision.fields.get("superseded"), Some(&prior.to_hex()));
    assert_eq!(
        decision.fields.get("superseded_author"),
        Some(&f.agent.to_hex())
    );
    assert_eq!(
        decision
            .fields
            .get("superseded_author_class")
            .map(String::as_str),
        Some("agent"),
    );
}

/// (2) The owner's upsert over a member's claim is still refused: a person's
/// claim keeps the conflict review path (ARCH-0040, ARCH-0043).
#[test]
fn the_owners_upsert_over_a_members_claim_is_still_refused() {
    let f = Fixture::rooted();
    let value = "Owen, as the member knows it";
    let prior = f.landed_claim_of(f.member, EdgeActorClass::Human, value);

    let result = f.upsert_as(f.owner, EdgeActorClass::Human, OWNER_VALUE);

    f.assert_refused_for_review(result, prior, value);
}

/// (3) A member's upsert over the owner's agent's claim is still refused: the
/// owner's ruling is the owner's alone.
#[test]
fn a_members_upsert_over_the_owners_agents_claim_is_still_refused() {
    let f = Fixture::rooted();
    let prior = f.landed_claim_of(f.agent, EdgeActorClass::Agent, AGENT_VALUE);

    let result = f.upsert_as(
        f.member,
        EdgeActorClass::Human,
        "Owen, as the member says it",
    );

    f.assert_refused_for_review(result, prior, AGENT_VALUE);
}

/// (4) The owner's upsert over a member's agent's claim is still refused: an
/// agent anchored to the member is the member's pen, not the owner's agent.
#[test]
fn the_owners_upsert_over_a_members_agents_claim_is_still_refused() {
    let f = Fixture::rooted();
    let pen = f.pen_agent_of(f.member);
    let value = "Owen, as the member's agent heard it";
    let prior = f.landed_claim_of(pen, EdgeActorClass::Agent, value);

    let result = f.upsert_as(f.owner, EdgeActorClass::Human, OWNER_VALUE);

    f.assert_refused_for_review(result, prior, value);
}

/// (5) The owner's upsert over the claim of an agent the owner never paired
/// is still refused: an author the vault cannot place as the owner's agent
/// keeps the review path.
#[test]
fn the_owners_upsert_over_an_unpaired_agents_claim_is_still_refused() {
    let f = Fixture::rooted();
    let stranger = person(&f.vault, b"owner supersede unpaired agent");
    let value = "Owen, as an unpaired agent heard it";
    let prior = f.landed_claim_of(stranger, EdgeActorClass::Agent, value);

    let result = f.upsert_as(f.owner, EdgeActorClass::Human, OWNER_VALUE);

    f.assert_refused_for_review(result, prior, value);
}
