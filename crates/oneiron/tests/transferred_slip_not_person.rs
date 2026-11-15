// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A Human credential handed on to another key acts as its key holder, never
//! as the person it names (HANDED-ON-SLIP-PERSON, 15 Nov: Q1 = A, its writes
//! are Generated or Observed, never UserStated; Q2 = A, a hand-on to the
//! person's own other device key is no person either; canon
//! `#credential-read-key-built`: a narrower credential "never takes the
//! owner's floor").
//!
//! Each red fails at the base (the handed-on handle acts as the owner) and
//! passes with the change; each guard (the owner's own slip, same act)
//! passes on both.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test transferred_slip_not_person`.
#![cfg(oneiron_test_support)]

use ed25519_dalek::Signer;
use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::code_run::GatedActorWrite;
use oneiron::memory::{
    CanAnswer, CanVerbGate, ClaimDemoteActionInput, ClaimDemoteRequest, ClaimInput,
    ExpressionPreferenceInput, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, SafeDeleteReason,
    resolve_entity_ref,
};
use oneiron::note::TakeTarget;
use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::test_doors::code_run_claim_put::put_claim_as_code_run;
use oneiron::verbs::{CanRequest, CanVerb, CanVerbRequest};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, ExpressionPreferenceOrigin, ExpressionPreferenceValue, RawEntityPut,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// The handed-on delete refusal.
const HANDED_ON_DELETE: &str = "handed on to another key";
/// A delivery window: it holds interrupts while its condition holds, so it
/// restricts someone (`federation::claim_removal_widens_in`).
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";
/// The refusal of a write over a restricting claim by no live owner in
/// person (`memory::authorship::guard_existing_claim_in_txn`).
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";
/// A `can` verb whose row takes a person's proof.
const PERSON_VERB: &str = "vault.members.remove";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    agent: EntityId,
    subject: EntityId,
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
        let issuer = HostSlipIssuer::from_secret(b"transferred-slip-not-person")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the engine's machine signers");
        let agent = vault
            .ensure_agent_principal("transferred-slip-agent")
            .expect("agent");
        let subject = person(&vault);
        let facet = vault.default_facet().expect("default facet");
        Self {
            vault,
            owner,
            issuer,
            agent,
            subject,
            facet,
            _directory: directory,
        }
    }

    /// A Human slip for the owner from the host root, held by the owner or
    /// handed on to another key first.
    fn owner_slip(&self, handed_on: bool) -> VerifiedSlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root")
            .claims;
        claims.slip_id = slip_id();
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        if !handed_on {
            let challenge = b"transferred slip own slip";
            let binding = self
                .issuer
                .binding_proof(&slip, challenge)
                .expect("the own binding proof");
            let own = self
                .vault
                .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
                .expect("the own slip verifies");
            assert!(!own.is_transferred(), "control: the owner holds this one");
            return own;
        }
        let next = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(b"transferred slip handed holder").as_bytes(),
        );
        let mut handed = slip;
        self.issuer
            .attenuate_to(
                &mut handed,
                SlipCaveat::default(),
                next.verifying_key().to_bytes(),
            )
            .expect("the slip is handed on");
        let challenge = b"transferred slip handed slip";
        let binding = next
            .sign(
                &handed
                    .binding_transcript(challenge)
                    .expect("the binding transcript"),
            )
            .to_bytes();
        let handed = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &handed, challenge, &binding)
            .expect("the handed slip verifies");
        assert!(handed.is_transferred(), "control: the slip was handed on");
        handed
    }

    /// The owner's handle presenting `slip`.
    fn owner_memory(&self, slip: &VerifiedSlip) -> oneiron::memory::Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_read_proof(slip)
    }

    /// An Observed Auto `profile.note` about the subject on the raw door: no
    /// envelope author, so never the owner's own row. Observed, because a
    /// Generated Auto row needs an actor-bound permit no unattributed write
    /// holds (Astra review on #8434, F4: the demotion pair failed in setup).
    fn raw_note(&self) -> EntityId {
        let mut body = observed_body(NOTE, self.subject, Value::from("a note"));
        body.scope_facet = self.facet;
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(), LEARNED_AT)
            .expect("the note lands");
        id
    }

    /// The owner's own landed Auto note on the subject's upsert slot.
    fn owner_auto_note(&self, value: &str) -> EntityId {
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&self.claim_input(self.subject, value, "user_stated"))
            .expect("the owner's note lands");
        assert_eq!(receipt.approval, "auto", "the owner's note lands at once");
        self.claim_id(&receipt.claim_short_id)
    }

    /// One write of `source` on `subject`'s upsert slot holding `value`.
    fn claim_input(&self, subject: EntityId, value: &str, source: &str) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: NOTE.to_owned(),
            subject_ref: subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: source.to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        }
    }

    /// The agent's Inferred language row about the subject.
    fn agent_preference(&self) -> EntityId {
        let now = self.vault.now_recorded_at();
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .set_expression_preference(
                &ExpressionPreferenceInput {
                    subject_ref: self.subject.to_hex(),
                    value: ExpressionPreferenceValue::Language("en-US".to_owned()),
                    origin: ExpressionPreferenceOrigin::Inferred,
                    valid_from: now,
                },
                now,
            )
            .expect("the agent's preference lands");
        self.claim_id(&receipt.claim_short_id)
    }

    /// The owner's ExplicitUser replacement of the subject's language row:
    /// the short ids it closed, or the refusal's code and message.
    fn owner_replaces_language(&self, slip: &VerifiedSlip) -> Result<String, String> {
        let now = self.vault.now_recorded_at();
        self.owner_memory(slip)
            .set_expression_preference(
                &ExpressionPreferenceInput {
                    subject_ref: self.subject.to_hex(),
                    value: ExpressionPreferenceValue::Language("en-GB".to_owned()),
                    origin: ExpressionPreferenceOrigin::ExplicitUser,
                    valid_from: now,
                },
                now,
            )
            .map(|receipt| receipt.superseded_short_ids.join(","))
            .map_err(|error| format!("{}: {}", error.code, error.message))
    }

    /// The owner's NOTE about the subject, by its full hex ref.
    fn owner_take(&self) -> String {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the owner authors a NOTE")
            .id_hex
    }

    /// The gate `can` answers on the person's verb for the owner's handle.
    fn person_verb_gate(&self, slip: &VerifiedSlip) -> CanVerbGate {
        let answer = self
            .owner_memory(slip)
            .can(&CanRequest::Verb(Box::new(CanVerbRequest {
                verb: CanVerb {
                    name: PERSON_VERB.to_owned(),
                    params: json!({}),
                    actor: None,
                },
            })))
            .expect("can answers");
        let CanAnswer::Verb(answer) = answer else {
            panic!("can({PERSON_VERB}) answers a verb gate");
        };
        answer.gate
    }

    /// The owner's NOTE and its head frontier, for a history erase.
    fn owner_note_frontier(&self) -> (EntityId, Vec<u8>) {
        let note = EntityId::from_hex(&self.owner_take()).expect("note id");
        let frontier = self
            .vault
            .note_document(note)
            .expect("the NOTE's document")
            .frontier;
        (note, frontier)
    }

    /// An off-record room named `session_ref` and a PERSON the owner staged
    /// in it, which base never held.
    fn room_staged_person(&self, session_ref: &str) -> (OffRecordSession<'_>, EntityId) {
        let room = self
            .vault
            .off_record_session_vault()
            .enter(session_ref, OffRecordBackendClass::Local)
            .expect("an off-record room");
        let body = rmp_serde::to_vec_named(&json!({ "name": "a room person" })).expect("body");
        let now = self.vault.now_recorded_at();
        let id = EntityId::now();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .in_off_record_session(room.session_ref())
            .raw_put_entity(RawEntityPut {
                id,
                entity_type: ENTITY_TYPE_PERSON,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: &body,
            })
            .expect("the owner stages a PERSON in the room");
        (room, id)
    }

    /// The owner's own landed delivery window about the subject, by its
    /// authenticated envelope: the owner's row to lift.
    fn owner_delivery_window(&self) -> EntityId {
        let input = ClaimInput {
            predicate: DELIVERY_WINDOW_CONTEXT.to_owned(),
            value: json!({ "schema_version": 1, "applies_to": "interrupt", "when": "asleep" }),
            ..self.claim_input(self.subject, "", "user_stated")
        };
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&input)
            .expect("the owner's delivery window lands");
        assert_eq!(receipt.approval, "auto", "the owner's window lands at once");
        self.claim_id(&receipt.claim_short_id)
    }

    /// A code run the host opened for the owner under `slip`, as the MCP
    /// code door binds its opener (`with_opener_credential`), puts a NOTE at
    /// `id` through the candidate writer its `vault.claims.put` lands by.
    /// Returns the id that landed.
    fn code_run_puts_a_note_at(
        &self,
        slip: &VerifiedSlip,
        id: EntityId,
    ) -> Result<EntityId, oneiron::Error> {
        let actor = GatedActorWrite::new(
            &self.vault,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            "transferred-slip-run",
        )
        .expect("the run binds")
        .with_opener_credential(slip)
        .actor();
        put_claim_as_code_run(
            &self.vault,
            actor,
            id,
            NOTE,
            self.subject,
            Value::from("a code run's note"),
            LEARNED_AT,
        )
    }

    fn claim_id(&self, short_id: &str) -> EntityId {
        resolve_entity_ref(&self.vault, short_id).expect("the claim's id")
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
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

fn observed_body(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
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

fn skill_record() -> SkillRecord {
    SkillRecord::new(
        "handed.skill",
        "candidate instructions",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("origin"), Value::from("test"))]),
    )
}

/// Red: the handed-on owner handle demotes no claim it did not write.
#[test]
fn a_handed_on_owner_slip_never_demotes_a_claim_stale() {
    let f = Fixture::new();
    let id = f.raw_note();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: id.to_hex(),
            action: ClaimDemoteActionInput::Stale,
        })
        .expect_err("a handed-on owner slip demotes no foreign claim");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains("may not demote"),
        "the refusal names its reason: {}",
        refused.message
    );
    assert!(!f.stored(id).stale, "the row keeps no stale mark");
}

/// Guard: the owner's own slip still demotes.
#[test]
fn the_owners_own_slip_still_demotes_a_claim_stale() {
    let f = Fixture::new();
    let id = f.raw_note();
    let slip = f.owner_slip(false);

    let view = f
        .owner_memory(&slip)
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: id.to_hex(),
            action: ClaimDemoteActionInput::Stale,
        })
        .expect("the owner's own slip demotes");

    assert_eq!(view.rung, "stale");
    assert!(view.stale);
    assert!(f.stored(id).stale, "the row reads stale");
}

/// Red: the handed-on correction parks as a proposal and closes nothing. An
/// `observed` write asks Auto as a `user_stated` one does, so only the owner
/// correction decides it.
#[test]
fn a_handed_on_owner_slip_never_corrects_at_once() {
    let f = Fixture::new();
    let prior = f.owner_auto_note("the standing note");
    let slip = f.owner_slip(true);

    let receipt = f
        .owner_memory(&slip)
        .claim_upsert(&f.claim_input(f.subject, "the corrected note", "observed"))
        .expect("the replacement is written");

    assert_eq!(
        receipt.approval, "proposed",
        "the correction parks for review"
    );
    assert!(
        receipt.superseded_short_id.is_none(),
        "it closes nothing at once: {receipt:?}"
    );
    let replacement = f.claim_id(&receipt.claim_short_id);
    assert_eq!(
        f.stored(prior).lifecycle,
        ClaimLifecycleStatus::Active,
        "the prior still stands"
    );
    assert_eq!(
        f.vault
            .pending_claim_supersession(&replacement)
            .expect("supersession read"),
        Some(prior),
        "the replacement waits to supersede the prior"
    );
}

/// Red: the handed-on handle overrides no row it did not write.
#[test]
fn a_handed_on_owner_slip_never_overrides_anothers_preference_at_once() {
    let f = Fixture::new();
    let agents = f.agent_preference();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_replaces_language(&slip)
        .expect_err("no override at once");

    assert!(
        refused.contains(MEMORY_CODE_BAD_REQUEST),
        "bad request: {refused}"
    );
    assert!(
        refused.contains("requires a human actor"),
        "it fails at the person gate: {refused}"
    );
    assert_eq!(
        f.stored(agents).lifecycle,
        ClaimLifecycleStatus::Active,
        "the agent's row stands"
    );
}

/// Guard: the owner's own slip still corrects and overrides at once.
#[test]
fn the_owners_own_slip_still_corrects_and_overrides_at_once() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);
    let prior = f.owner_auto_note("the standing note");

    let receipt = f
        .owner_memory(&slip)
        .claim_upsert(&f.claim_input(f.subject, "the corrected note", "observed"))
        .expect("the owner's correction lands");
    assert_eq!(receipt.approval, "auto", "the correction lands at once");
    assert!(
        receipt.superseded_short_id.is_some(),
        "it names the closed prior: {receipt:?}"
    );
    assert_eq!(
        f.stored(prior).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the prior is closed"
    );

    let agents = f.agent_preference();
    let superseded = f
        .owner_replaces_language(&slip)
        .expect("the owner's override lands");
    assert!(!superseded.is_empty(), "the override names what it closed");
    assert_eq!(
        f.stored(agents).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the agent's row is closed"
    );
}

/// Red: a claim the handed-on handle declares `user_stated` is Generated.
#[test]
fn a_handed_on_slip_declares_no_user_stated_claim() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);
    let subject = person(&f.vault);

    let receipt = f
        .owner_memory(&slip)
        .claim_upsert(&f.claim_input(subject, "a stated note", "user_stated"))
        .expect("the claim is written");

    let stored = f.stored(f.claim_id(&receipt.claim_short_id));
    assert_eq!(stored.source, Some(ClaimSource::Generated));
}

/// Guard: the owner's own slip still declares `user_stated`.
#[test]
fn the_owners_own_slip_still_declares_a_user_stated_claim() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);
    let subject = person(&f.vault);

    let receipt = f
        .owner_memory(&slip)
        .claim_upsert(&f.claim_input(subject, "a stated note", "user_stated"))
        .expect("the claim is written");

    assert_eq!(
        receipt.approval, "auto",
        "the owner's statement lands at once"
    );
    let stored = f.stored(f.claim_id(&receipt.claim_short_id));
    assert_eq!(stored.source, Some(ClaimSource::UserStated));
}

/// Red: the handed-on skill save stamps no person's provenance.
#[test]
fn a_handed_on_slip_stamps_no_user_stated_skill() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);
    let id = EntityId::now();

    let saved = f
        .owner_memory(&slip)
        .skill_save(id, &skill_record(), None, f.vault.now_recorded_at())
        .expect("the skill saves");

    assert_eq!(saved.skill_id, id);
    let record = f
        .vault
        .get_skill_record(&id)
        .expect("skill read")
        .expect("the skill stands");
    assert_eq!(record.source, ClaimSource::Generated);
    assert!(record.generated);
    assert!(!record.human_authored);
}

/// Guard: the owner's own slip still stamps UserStated.
#[test]
fn the_owners_own_slip_still_stamps_a_user_stated_skill() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);
    let id = EntityId::now();

    f.owner_memory(&slip)
        .skill_save(id, &skill_record(), None, f.vault.now_recorded_at())
        .expect("the skill saves");

    let record = f
        .vault
        .get_skill_record(&id)
        .expect("skill read")
        .expect("the skill stands");
    assert_eq!(record.source, ClaimSource::UserStated);
    assert!(!record.generated);
    assert!(record.human_authored);
}

/// Red: the handed-on handle deletes nothing as the owner.
#[test]
fn a_handed_on_owner_slip_never_deletes_as_the_owner() {
    let f = Fixture::new();
    let note = f.owner_take();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .safe_delete(&note, SafeDeleteReason::UserDelete)
        .expect_err("a handed-on owner slip deletes nothing as the owner");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains(HANDED_ON_DELETE),
        "the refusal names the handover: {}",
        refused.message
    );
    assert!(!f.deleted(&note), "the NOTE stands");
}

/// Guard: the owner's own slip still deletes.
#[test]
fn the_owners_own_slip_still_deletes() {
    let f = Fixture::new();
    let note = f.owner_take();
    let slip = f.owner_slip(false);

    let receipt = f
        .owner_memory(&slip)
        .safe_delete(&note, SafeDeleteReason::UserDelete)
        .expect("the owner's own slip deletes");

    assert!(receipt.existed);
    assert!(f.deleted(&note), "the NOTE is a deleted shell");
}

/// Red: `can` asks a person's proof of the handed-on handle on a person's verb.
#[test]
fn a_handed_on_owner_slip_answers_person_for_a_persons_verb() {
    let f = Fixture::new();
    let slip = f.owner_slip(true);

    assert_eq!(f.person_verb_gate(&slip), CanVerbGate::Person);
}

/// Guard: `can` answers Unchecked for the owner's own slip.
#[test]
fn the_owners_own_slip_answers_unchecked_for_a_persons_verb() {
    let f = Fixture::new();
    let slip = f.owner_slip(false);

    assert_eq!(f.person_verb_gate(&slip), CanVerbGate::Unchecked);
}

/// Red: a code run opened under a handed-on owner slip lifts no restriction
/// the owner wrote (Astra review on #8434, F1: the dispatcher kept only the
/// slip's lineage, so its write actor passed the owner-only restriction gate
/// as the person).
#[test]
fn a_code_run_on_a_handed_on_owner_slip_never_lifts_the_owners_window() {
    let f = Fixture::new();
    let window = f.owner_delivery_window();
    let slip = f.owner_slip(true);

    let put = f.code_run_puts_a_note_at(&slip, window);

    let stored = f.stored(window);
    assert_eq!(
        (stored.predicate.as_str(), stored.lifecycle),
        (DELIVERY_WINDOW_CONTEXT, ClaimLifecycleStatus::Active),
        "the delivery window still holds (put: {put:?})"
    );
    let refused = put.expect_err("a run under a handed-on slip lifts no restriction");
    assert!(
        refused.to_string().contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Guard: a code run opened under the owner's own slip still writes over
/// the owner's own window.
#[test]
fn a_code_run_on_the_owners_own_slip_still_writes_over_the_owners_window() {
    let f = Fixture::new();
    let window = f.owner_delivery_window();
    let slip = f.owner_slip(false);

    f.code_run_puts_a_note_at(&slip, window)
        .expect("the owner's own run writes over the owner's window");
}

/// Red: the handed-on handle erases no NOTE's history as the owner (Astra
/// review on #8434, F3 B: `purge_note_history` asked the class alone).
#[test]
fn a_handed_on_owner_slip_never_purges_a_notes_history() {
    let f = Fixture::new();
    let (note, frontier) = f.owner_note_frontier();
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .purge_note_history(note, &frontier)
        .expect_err("a handed-on owner slip erases no note history");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains(HANDED_ON_DELETE),
        "the refusal names the handover: {}",
        refused.message
    );
}

/// Guard: the owner's own slip still erases its NOTE's history.
#[test]
fn the_owners_own_slip_still_purges_a_notes_history() {
    let f = Fixture::new();
    let (note, frontier) = f.owner_note_frontier();
    let slip = f.owner_slip(false);

    f.owner_memory(&slip)
        .purge_note_history(note, &frontier)
        .expect("the owner's own slip erases the NOTE's history");
}

/// Red: the handed-on handle deletes no row an off-record room staged (Astra
/// review on #8434, F3 A: the room's delete asked the class alone).
#[test]
fn a_handed_on_owner_slip_never_deletes_a_rooms_staged_row() {
    let f = Fixture::new();
    let (room, id) = f.room_staged_person("transferred-slip-room-delete");
    let slip = f.owner_slip(true);

    let refused = f
        .owner_memory(&slip)
        .in_off_record_session(room.session_ref())
        .raw_delete_entity(&id)
        .expect_err("a handed-on owner slip deletes nothing the room staged");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        refused.message.contains(HANDED_ON_DELETE),
        "the refusal names the handover: {}",
        refused.message
    );
}

/// Guard: the owner's own slip still deletes a row the room staged.
#[test]
fn the_owners_own_slip_still_deletes_a_rooms_staged_row() {
    let f = Fixture::new();
    let (room, id) = f.room_staged_person("transferred-slip-room-own-delete");
    let slip = f.owner_slip(false);

    let deleted = f
        .owner_memory(&slip)
        .in_off_record_session(room.session_ref())
        .raw_delete_entity(&id)
        .expect("the owner's own slip deletes the room's row");

    assert!(deleted, "the room's own delete ran");
}
