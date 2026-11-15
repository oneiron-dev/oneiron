// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [RESTRICTION-CLOSE-BY-CONFLICT-SETTLE] and the Engine's RULING
//! RESTRICTION-CLOSE-BY-CONFLICT-SETTLE = A (15 Nov 18:21): a settlement by
//! no person, either an agent holding `memory.conflict_review` or the
//! vault's Dreamer, never supersedes a conflict member that restricts
//! someone's access, whatever the member's source (canon #widen-world-floor:
//! "An agent's widen always asks the person affected ... No standing grant
//! and no bypass grant covers it"; the lead's RULING WORLD-ACCESS-GRANT-DELETE
//! = A: "deleting a restriction IS a widening"). The conflict stays open for
//! a person holder or the owner. The owner confirmed it (15 Nov 18:3x): "If
//! the owner overrides it, it's fine; Dreamer having to ask the owner is ok":
//! the open conflict is the Dreamer's ask, and the owner's authenticated Keep
//! supersedes the member.
//!
//! RULING RESTRICTION-CLOSE-BY-CURATOR-APPROVAL = A (18:33) is folded in: an
//! agent holder's approval of a curator finding that retracts a restricting
//! target (here a Generated `comm.do_not_contact`) is refused and stays for a
//! person holder or the owner. The curator's own pass holds the same rung on
//! a restricting target for a person, whatever its predicate's criticality
//! (reviews of #8238: Muse §3, Astra F5); the owner's approval applies it.
//!
//! Two closes of the same kind, from the Astra review on #8189, are folded
//! in too:
//! - F4: the Dreamer's Auto grant of a parked replacement
//!   (`Vault::grant_deferred_claim_auto`, which its corrections call) that
//!   would supersede a restricting head waits for the owner, as a critical
//!   one does; the owner's approval of the replacement completes it;
//! - F1: a person's slip handed on to another key (`attenuate_to`) is no
//!   person's: a settle under it that lifts a restriction is refused, while
//!   the person's own slip still settles.
//!
//! Each red is a settle by no person: it is refused, and the restricting
//! member stands. The guards show a person holder and the owner still
//! settle. The controls show the cut is narrow: the agent holder and the
//! Dreamer still settle a conflict whose members restrict no one (the
//! Dreamer keeps autoapply + revert there).
//!
//! The conflicts are two Generated `delivery_window.context` rows about one
//! PERSON, landed on the raw door and opened by the Dreamer's marker
//! (`test_doors::derive::open_conflict`). The manifest declares the window
//! normal, so a kept member carries no critical confirm; whether a member
//! restricts reads its predicate, not its criticality. The curator finding
//! lands through the cfg door `test_doors::curator_finding`, as the curator
//! lands a finding over a critical target. The vault is rooted under a host
//! (an owner's native Grant needs a rooted vault), with the shipped default
//! manifest plus that one rule.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test conflict_settle_restriction`.
#![cfg(oneiron_test_support)]

use ed25519_dalek::Signer;
use oneiron::agent_def::AgentCeiling;
use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::campaign::claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use oneiron::consent::{AuthenticatedOwner, consent_receipt_grant_ref};
use oneiron::dreamer_consolidation::{
    ConflictReviewScope, ConflictSettleOutcome, ConflictSettlement,
};
use oneiron::error::{GateDenialReason, GateError};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementReason, ClaimSettlementVerdict, MemoryAuthoringAction,
    MemoryResult, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::comm_claim_rows::put_comm_claim_row;
use oneiron::test_doors::curator_finding::{
    emit_retract_finding, land_stale_consolidation, run_curator_once,
};
use oneiron::test_doors::derive::open_conflict;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// The refusal of a settle by no person that lifts a restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The host's slip issuer, which minted the vault's root slip.
    issuer: HostSlipIssuer,
    /// Opens every proposal: read and propose, so its own writes wait.
    proposer: EntityId,
    /// An agent with an Auto ceiling; holds a Grant only where a test mints one.
    agent_holder: EntityId,
    /// A PERSON who is not the owner; holds a Grant only where a test mints one.
    person_holder: EntityId,
    /// The PERSON the delivery windows are about.
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
        let issuer = HostSlipIssuer::from_secret(b"conflict-settle-restriction")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        // The Dreamer signs its marker, findings and settlements as a
        // MACHINE; an unsigned MACHINE write is refused.
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let proposer = vault
            .ensure_agent_principal("conflict-settle-proposer")
            .expect("proposer");
        let agent_holder = vault
            .ensure_agent_principal("conflict-settle-agent")
            .expect("agent holder");
        let person_holder = vault
            .ensure_agent_principal("conflict-settle-person")
            .expect("person holder");
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
        let fixture = Self {
            subject: person(&vault),
            vault,
            owner,
            issuer,
            proposer,
            agent_holder,
            person_holder,
            facet,
            owner_proof,
            _directory: directory,
        };
        fixture.declare_delivery_window_normal();
        fixture
    }

    fn agent_holder(&self) -> WriteActor {
        WriteActor::new(self.agent_holder, EdgeActorClass::Agent)
    }

    fn person_holder(&self) -> WriteActor {
        WriteActor::new(self.person_holder, EdgeActorClass::Human)
    }

    /// `predicate` about `subject` holding `value`, a Generated Auto row on
    /// the raw door in the default facet. Returns its id.
    fn generated(&self, predicate: &str, subject: EntityId, value: Value) -> EntityId {
        let mut body = generated_body(predicate, subject, value);
        body.scope_facet = self.facet;
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(), LEARNED_AT)
            .unwrap_or_else(|error| panic!("the {predicate} row lands: {error:?}"));
        id
    }

    /// `predicate` about the subject holding `value`, as the Dreamer's own
    /// consolidation on its last curator rung, learned long before now: the
    /// curator's next pass grades it for a retract. Returns its id.
    fn stale_consolidation(&self, predicate: &str, value: Value) -> EntityId {
        land_stale_consolidation(&self.vault, self.subject, predicate, value, LEARNED_AT)
            .unwrap_or_else(|error| panic!("the Dreamer's {predicate} consolidation: {error:?}"))
    }

    /// Two delivery windows about the subject, the second opening a
    /// conflict with the first. Returns the marker, the window a settle
    /// keeps and the restricting window it would supersede.
    fn conflict_over_a_delivery_window(&self) -> (EntityId, EntityId, EntityId) {
        let loser = self.generated(DELIVERY_WINDOW_CONTEXT, self.subject, window("asleep"));
        let winner = self.generated(DELIVERY_WINDOW_CONTEXT, self.subject, window("driving"));
        let marker = open_conflict(&self.vault, winner, loser).expect("an open conflict");
        (marker, winner, loser)
    }

    /// The control: two notes about the subject in conflict, as above.
    fn conflict_over_a_note(&self) -> (EntityId, EntityId, EntityId) {
        let loser = self.generated(NOTE, self.subject, Value::from("the first note"));
        let winner = self.generated(NOTE, self.subject, Value::from("the second note"));
        let marker = open_conflict(&self.vault, winner, loser).expect("an open conflict");
        (marker, winner, loser)
    }

    /// The owner's Grant: `holder` reviews the conflicts on the subject.
    fn grant_conflict_review(&self, holder: WriteActor) {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .grant_conflict_review(
                &self.owner_proof,
                holder,
                ConflictReviewScope::Subject(self.subject),
            )
            .expect("the owner grants the holder the subject's conflict review");
    }

    /// The agent holder's Keep of `winner`, under its Grant.
    fn agent_keeps(
        &self,
        marker: EntityId,
        winner: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.grant_conflict_review(self.agent_holder());
        self.vault
            .memory(self.agent_holder, EdgeActorClass::Agent)
            .settle_conflict(
                None,
                marker,
                ConflictSettlement::Keep(winner),
                self.vault.now_recorded_ms(),
            )
    }

    /// The Dreamer's Keep of `winner`: its review stands from birth.
    fn dreamer_keeps(
        &self,
        marker: EntityId,
        winner: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        let dreamer = self.vault.dreamer_authority().expect("the Dreamer");
        self.vault
            .memory(dreamer.entity_ref(), dreamer.actor_class())
            .settle_conflict(
                None,
                marker,
                ConflictSettlement::Keep(winner),
                self.vault.now_recorded_ms(),
            )
    }

    /// The person holder's authenticated Keep of `winner`, under its Grant.
    fn person_keeps(
        &self,
        marker: EntityId,
        winner: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.grant_conflict_review(self.person_holder());
        let proof = self
            .vault
            .authenticate_owner(
                self.person_holder,
                &self.person_holder.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the person holder authenticates");
        self.vault
            .memory(self.person_holder, EdgeActorClass::Human)
            .settle_conflict(
                Some(&proof),
                marker,
                ConflictSettlement::Keep(winner),
                self.vault.now_recorded_ms(),
            )
    }

    /// The owner's authenticated Keep of `winner`.
    fn owner_keeps(
        &self,
        marker: EntityId,
        winner: EntityId,
    ) -> MemoryResult<ConflictSettleOutcome> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .settle_conflict(
                Some(&self.owner_proof),
                marker,
                ConflictSettlement::Keep(winner),
                self.vault.now_recorded_ms(),
            )
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

    /// A Generated do-not-contact bar on a new PERSON, and the Dreamer's
    /// curator finding that retracts it. Returns the finding and the bar.
    fn curator_retract_of_a_do_not_contact(&self) -> (EntityId, EntityId) {
        let mut body = generated_body(
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
        let finding = emit_retract_finding(&self.vault, bar).expect("the curator's finding");
        let stored = self.stored(finding);
        assert_eq!(
            (stored.lifecycle, stored.approval),
            (ClaimLifecycleStatus::Active, ClaimApprovalStatus::Proposed),
            "the finding waits for an approval"
        );
        (finding, bar)
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

    /// `holder`'s `vault.claims.review` then `vault.claims.settle` Approve of
    /// `id`, both under the owner's Grant.
    fn holder_approves(&self, holder: WriteActor, id: EntityId) -> MemoryResult<ClaimSettlement> {
        let memory = self.vault.memory(holder.entity_ref(), holder.actor_class());
        self.settles_under_grant(&memory, holder, id, ClaimSettleDecision::Approve)
    }

    /// `memory`'s `vault.claims.review` then `vault.claims.settle` of `id`,
    /// both under the owner's Grant to `holder`, the handle's actor.
    fn settles_under_grant(
        &self,
        memory: &oneiron::memory::Memory<'_>,
        holder: WriteActor,
        id: EntityId,
        decision: ClaimSettleDecision,
    ) -> MemoryResult<ClaimSettlement> {
        let grant_ref = self.grant_review(holder, id);
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

    /// `writer`'s claim of `predicate` about the subject holding `value`
    /// from `source`, in the default facet, through `vault.claims.propose`
    /// (`replaces` false) or `vault.claims.upsert` (true). Returns the
    /// receipt's approval and the claim's id.
    fn writes(
        &self,
        writer: WriteActor,
        replaces: bool,
        source: &str,
        predicate: &str,
        value: serde_json::Value,
    ) -> (String, EntityId) {
        let input = ClaimInput {
            id: None,
            predicate: predicate.to_owned(),
            subject_ref: self.subject.to_hex(),
            value,
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
        };
        let memory = self.vault.memory(writer.entity_ref(), writer.actor_class());
        let receipt = if replaces {
            memory.claim_upsert(&input)
        } else {
            memory.claim_propose(&input)
        }
        .unwrap_or_else(|error| panic!("the {predicate} write: {error:?}"));
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("the claim's id");
        (receipt.approval, id)
    }

    /// The proposer's Proposed claim of `predicate` about the subject.
    fn proposes(&self, predicate: &str, value: serde_json::Value) -> EntityId {
        let (approval, id) = self.writes(
            WriteActor::new(self.proposer, EdgeActorClass::Agent),
            false,
            "inferred",
            predicate,
            value,
        );
        assert_eq!(approval, "proposed", "the {predicate} proposal");
        id
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

    /// F4: the agent holder's observed Auto head of `predicate` holding
    /// `prior`, then its own upsert of `next` over it, which parks as a
    /// replacement whose supersession waits for a grant. One author writes
    /// both: another agent's upsert never replaces a head it did not write
    /// (`require_claim_supersede_in_txn`). Observed, because only a
    /// user-stated or observed write asks Auto, and a Proposed head is no
    /// prior an upsert replaces. Returns both.
    fn parked_replacement(
        &self,
        predicate: &str,
        prior: serde_json::Value,
        next: serde_json::Value,
    ) -> (EntityId, EntityId) {
        let (approval, head) =
            self.writes(self.agent_holder(), true, "observed", predicate, prior);
        assert_eq!(approval, "auto", "the {predicate} head lands");
        let (approval, replacement) =
            self.writes(self.agent_holder(), true, "observed", predicate, next);
        assert_eq!(approval, "proposed", "the replacement parks");
        assert_eq!(
            self.vault
                .pending_claim_supersession(&replacement)
                .expect("the parked supersession"),
            Some(head),
            "the replacement waits to supersede the head"
        );
        (head, replacement)
    }

    /// F1: the proposer's Proposed do-not-contact bar on the subject.
    fn proposed_do_not_contact(&self) -> EntityId {
        self.proposes(
            PREDICATE_COMM_DO_NOT_CONTACT,
            json!({ "scope": DO_NOT_CONTACT_SCOPE_ALL }),
        )
    }

    /// F1: a Human slip for the person holder from the host root, verified
    /// as presented by the person's own key, or handed on to another key
    /// first (as `tests/esign_qr_capability.rs` hands an owner's slip on).
    fn person_holder_slip(&self, handed_on: bool) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.person_holder.to_hex();
        claims.actor_class = Some("human".to_owned());
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the person holder's slip");
        if !handed_on {
            let challenge = b"conflict settle own slip";
            let binding = self
                .issuer
                .binding_proof(&slip, challenge)
                .expect("the own binding proof");
            let own = self
                .vault
                .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
                .expect("the own slip verifies");
            assert!(!own.is_transferred(), "control: the person holds this one");
            return own;
        }
        let next = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(b"conflict settle handed holder").as_bytes(),
        );
        let mut handed = slip;
        self.issuer
            .attenuate_to(
                &mut handed,
                SlipCaveat::default(),
                next.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        let challenge = b"conflict settle handed slip";
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

    /// F1: the person holder's Reject of `id` under the owner's Grant,
    /// presenting `slip`.
    fn person_rejects_with(
        &self,
        slip: &VerifiedSlip,
        id: EntityId,
    ) -> MemoryResult<ClaimSettlement> {
        let memory = self
            .vault
            .memory(self.person_holder, EdgeActorClass::Human)
            .with_read_proof(slip);
        self.settles_under_grant(
            &memory,
            self.person_holder(),
            id,
            ClaimSettleDecision::Reject,
        )
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }

    /// Installs the shipped manifest plus one rule: `delivery_window.context`
    /// is normal, as `tests/agent_holder_settle_restriction.rs` declares it.
    fn declare_delivery_window_normal(&self) {
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
fn generated_body(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
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

/// A delivery window value, as JSON, that holds interrupts `when`.
fn window_json(when: &str) -> serde_json::Value {
    json!({ "schema_version": 1, "applies_to": "interrupt", "when": when })
}

/// A delivery window value that holds interrupts `when`.
fn window(when: &str) -> Value {
    Value::Map(vec![
        (Value::from("schema_version"), Value::from(1_u64)),
        (Value::from("applies_to"), Value::from("interrupt")),
        (Value::from("when"), Value::from(when)),
    ])
}

/// The refusal names the restriction rule.
fn assert_refused_as_a_restriction_close<T: std::fmt::Debug>(settled: MemoryResult<T>, why: &str) {
    let refused = settled.expect_err(why);
    assert!(
        format!("{refused:?}").contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// The conflict settled, keeping `winner` and superseding `loser`.
fn assert_kept(
    f: &Fixture,
    settled: MemoryResult<ConflictSettleOutcome>,
    winner: EntityId,
    loser: EntityId,
) {
    let settled = settled.expect("the settlement lands");
    assert!(
        matches!(settled, ConflictSettleOutcome::Settled(_)),
        "the conflict settles: {settled:?}"
    );
    assert_eq!(f.stored(winner).lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        f.stored(loser).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the other member is superseded by the kept one"
    );
}

/// Red: the agent holder's Keep superseded the restricting window.
#[test]
fn an_agent_holder_never_supersedes_a_delivery_window_in_a_conflict() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_delivery_window();

    let settled = f.agent_keeps(marker, winner);

    assert_eq!(
        f.stored(loser).lifecycle,
        ClaimLifecycleStatus::Active,
        "the restricting window still holds (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "an agent holder never lifts a window");
    assert!(f.still_open(marker), "the conflict stays open");
    assert_kept(&f, f.person_keeps(marker, winner), winner, loser);
}

/// Red: the Dreamer's Keep superseded the restricting window.
#[test]
fn the_dreamer_never_supersedes_a_delivery_window_in_a_conflict() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_delivery_window();

    let settled = f.dreamer_keeps(marker, winner);

    assert_eq!(
        f.stored(loser).lifecycle,
        ClaimLifecycleStatus::Active,
        "the restricting window still holds (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "the Dreamer never lifts a window");
    assert!(
        f.still_open(marker),
        "the conflict stays open: it is the Dreamer's ask to the owner"
    );
}

/// Red, then the owner's answer (the owner, 15 Nov 18:3x): the Dreamer is
/// refused, and the owner's authenticated Keep on the conflict it left open
/// supersedes the window.
#[test]
fn the_owner_keeps_what_the_dreamer_was_refused() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_delivery_window();

    let refused = f.dreamer_keeps(marker, winner);
    assert_refused_as_a_restriction_close(refused, "the Dreamer asks the owner");

    assert_kept(&f, f.owner_keeps(marker, winner), winner, loser);
    assert!(
        !f.still_open(marker),
        "the owner's Keep answers the conflict"
    );
}

/// Guard: a person holder's Keep supersedes the window.
#[test]
fn a_person_holder_supersedes_a_delivery_window_in_a_conflict() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_delivery_window();

    assert_kept(&f, f.person_keeps(marker, winner), winner, loser);
}

/// Guard: the owner's Keep supersedes the window.
#[test]
fn the_owner_supersedes_a_delivery_window_in_a_conflict() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_delivery_window();

    assert_kept(&f, f.owner_keeps(marker, winner), winner, loser);
}

/// Control: the agent holder still settles a conflict over a note.
#[test]
fn an_agent_holder_still_settles_a_conflict_over_a_note() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_note();

    assert_kept(&f, f.agent_keeps(marker, winner), winner, loser);
}

/// Control: the Dreamer still settles a conflict over a note.
#[test]
fn the_dreamer_still_settles_a_conflict_over_a_note() {
    let f = Fixture::new();
    let (marker, winner, loser) = f.conflict_over_a_note();

    assert_kept(&f, f.dreamer_keeps(marker, winner), winner, loser);
}

/// Red: the agent holder's approval of the curator's finding retracted the
/// Generated do-not-contact bar.
#[test]
fn an_agent_holder_never_approves_a_curator_retract_of_a_do_not_contact() {
    let f = Fixture::new();
    let (finding, bar) = f.curator_retract_of_a_do_not_contact();

    let settled = f.holder_approves(f.agent_holder(), finding);

    assert_eq!(
        f.stored(bar).lifecycle,
        ClaimLifecycleStatus::Active,
        "the do-not-contact bar still holds (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "an agent holder never lifts a bar");
    let person = f
        .holder_approves(f.person_holder(), finding)
        .expect("the finding stays open for a person holder");
    assert_eq!(person.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(bar).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// Guard: a person holder's approval of the finding retracts the bar.
#[test]
fn a_person_holder_approves_a_curator_retract_of_a_do_not_contact() {
    let f = Fixture::new();
    let (finding, bar) = f.curator_retract_of_a_do_not_contact();

    let settled = f
        .holder_approves(f.person_holder(), finding)
        .expect("a person holder approves the finding under the owner's Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(f.stored(bar).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// The curator's own pass, red: it retracted a delivery window the Dreamer
/// consolidated, its predicate declared normal, with no one's approval. The
/// retract now waits as a held finding, and the owner's approval of the
/// finding applies it.
#[test]
fn the_curators_own_pass_never_retracts_a_delivery_window() {
    let f = Fixture::new();
    let window = f.stale_consolidation(DELIVERY_WINDOW_CONTEXT, window("asleep"));

    let findings = run_curator_once(&f.vault, f.vault.now_recorded_at()).expect("one curator pass");

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the restricting window still holds (findings: {findings:?})"
    );
    let [finding] = findings.as_slice() else {
        panic!("one finding over the window: {findings:?}");
    };
    assert_eq!(
        f.stored(*finding).approval,
        ClaimApprovalStatus::Proposed,
        "the retract waits for a person"
    );
    let settled = f.owner_settles(*finding, ClaimSettleDecision::Approve);
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the owner's approval retracts the window"
    );
}

/// The curator's own pass, control: a note the Dreamer consolidated is
/// still retracted at once (the Dreamer keeps autoapply + revert there).
#[test]
fn the_curators_own_pass_still_retracts_a_note() {
    let f = Fixture::new();
    let note = f.stale_consolidation(NOTE, Value::from("the first"));

    let findings = run_curator_once(&f.vault, f.vault.now_recorded_at()).expect("one curator pass");

    assert_eq!(
        f.stored(note).lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the note's retract applied (findings: {findings:?})"
    );
    assert_eq!(findings.len(), 1, "the applied finding");
}

/// F4, red: the Auto grant superseded the restricting window. It now waits
/// for the owner, whose approval of the replacement completes it.
#[test]
fn an_auto_grant_over_a_delivery_window_asks_the_owner() {
    let f = Fixture::new();
    let (window, replacement) = f.parked_replacement(
        DELIVERY_WINDOW_CONTEXT,
        window_json("asleep"),
        window_json("driving"),
    );

    let granted = f
        .vault
        .grant_deferred_claim_auto(&replacement, f.vault.now_recorded_at());

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the restricting window still holds (grant: {granted:?})"
    );
    match granted {
        Err(Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        })) => {
            assert_eq!(outcome, "pending");
            assert_eq!(
                reason_codes,
                vec![GateDenialReason::PendingCriticalityFloor.as_str()]
            );
        }
        other => panic!("the grant waits for the owner: {other:?}"),
    }
    assert_eq!(
        f.stored(replacement).approval,
        ClaimApprovalStatus::Proposed
    );
    let settled = f.owner_settles(replacement, ClaimSettleDecision::Approve);
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the owner's approval supersedes the window"
    );
}

/// F4, control: the Auto grant over a note still supersedes it.
#[test]
fn an_auto_grant_over_a_note_still_lands() {
    let f = Fixture::new();
    let (note, replacement) = f.parked_replacement(NOTE, json!("the first"), json!("the second"));

    f.vault
        .grant_deferred_claim_auto(&replacement, f.vault.now_recorded_at())
        .expect("the Auto grant lands");

    assert_eq!(f.stored(replacement).approval, ClaimApprovalStatus::Auto);
    assert_eq!(f.stored(note).lifecycle, ClaimLifecycleStatus::Superseded);
}

/// F1, red: the person holder's slip, handed on to another key, rejected
/// the Proposed bar.
#[test]
fn a_handed_on_person_slip_never_rejects_a_proposed_do_not_contact() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();
    let handed = f.person_holder_slip(true);

    let settled = f.person_rejects_with(&handed, bar);

    let body = f.stored(bar);
    assert_eq!(
        (body.lifecycle, body.approval),
        (ClaimLifecycleStatus::Active, ClaimApprovalStatus::Proposed),
        "the do-not-contact bar still holds and waits (settle: {settled:?})"
    );
    assert_refused_as_a_restriction_close(settled, "a handed-on slip is no person's");
}

/// F1, guard: the person holder's own slip still rejects the bar.
#[test]
fn a_persons_own_slip_still_rejects_a_proposed_do_not_contact() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();
    let own = f.person_holder_slip(false);

    let settled = f
        .person_rejects_with(&own, bar)
        .expect("the person's own slip rejects the bar under the owner's Grant");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(settled.reason, ClaimSettlementReason::HolderDeclined);
    assert_eq!(f.stored(bar).lifecycle, ClaimLifecycleStatus::Retracted);
}
