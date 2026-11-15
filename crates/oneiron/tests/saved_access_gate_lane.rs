//! A saved lane keeps the access gate its live key read under (FIX
//! SAVED-PRINCIPAL-LANE-DROPS-ACCESS-GATE, Sol F3 on #8061; Engine RULING
//! 15 Nov 11:46).
//!
//! A key that carries no proof and holds no owner standing reads under the
//! access gate (`Memory::read_key`): it refuses every MESSAGE and SUMMARY
//! that names no relationship and no private scope, unless an access grant
//! on the MESSAGE's conversation admits it. Saved work froze that lane as
//! its principal's own, and the saved question's reader rebuilt the
//! principal's key under the relationship gate, which admits those rows: the
//! saved question read the owner's unscoped MESSAGE its live lane refused.
//! The lane now keeps its live key's grant basis, so the rebuilt reader
//! refuses those rows again, and so does a lane frozen again from that
//! reader, a lane rebuilt over a key no grant gate binds, the owner's floor
//! under the access gate, and a gate bound to no principal, which reads on
//! no grant (Sol F3/F4/F5 on #8065).
//!
//! The lane keeps no Scope its live key lacked (Sol F1/F2 on #8065): a top
//! Scope stood as explicit read authority, so the rebuilt house read the
//! owner's CLAIM past its MESSAGE-only policy row and lost the read
//! alternative of its own agent Grant.
//!
//! The asker is the house mind a fresh vault seeds (`sys.team_lead`). Its
//! shipped policy row lets it read the owner's MESSAGEs, so the grant gate
//! alone decides. Red on #8061 (a0e7a94c82a): the saved reader reads the
//! unscoped MESSAGE, the lane freezes as its principal's own and the rebuilt
//! reader reads under the relationship gate, a lane frozen again or rebuilt
//! over an ungated key reads the MESSAGE too, and so do the owner's gated
//! floor and the unbound gate. Red on 4bd84532dcb (the top Scope): the CLAIM
//! reads, the own Grant's MESSAGE does not, the owner's gated floor freezes
//! as its principal's own, and the unbound gate rebuilds bound to the house.
//! Guards: a MESSAGE that the house's access grant on its conversation
//! admits, or its own read Grant, still reads through the saved lane.
//!
//! A lane with no basis says nothing of the gate its key read under (FIX
//! SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS; Engine RULING 15 Nov 13:13 =
//! A): questions saved before the basis was kept, and those an engine path
//! stores with no live lane (`create_question`, a review's dissent through
//! `create_question_in_txn`), keep their principal's own lane. Its reader
//! now rebuilds under the access gate for an asker that is no live owner,
//! and the lane of every such actor freezes with its basis, the
//! relationship gate included, so a lane frozen from a relationship-gated
//! key still reads the unscoped MESSAGE its live lane read. Red on #8065
//! (074276b10c7): the house's question stored with no lane, its dissent
//! question and its own lane rebuilt and frozen again read the owner's
//! unscoped MESSAGE, and the relationship-gated lane freezes as its
//! principal's own. Guards: the owner's own question stored with no lane,
//! the owner's source reader of a lane with no basis, and a MESSAGE the
//! house's conversation grant or own read Grant admits, still read.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_access_gate_lane`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::decision::questions::{
    QuestionActivation, QuestionDefinitionInput, QuestionRecord, RefreshPolicy, create_question,
    read_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionBand, DecisionClass, DecisionDial, DecisionQuestionInput, DecisionRung,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::question_saved_lane::{
    create_question_in_writer, question_read, reads_under_relationship_gate, saved_question_reader,
    under_relationship_gate,
};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{ClaimInput, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

/// A fresh vault whose owner witnessed a MESSAGE that names no relationship
/// and no private scope, and the house mind it seeds.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    house: EntityId,
    conversation: EntityId,
    message: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner");
    let house = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded agent definition read")
        .expect("the fresh vault seeds sys.team_lead")
        .0;
    let conversation = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: "The spring garden needs a watering rota.".to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the owner's turn lands");
    Fixture {
        vault,
        _dir: dir,
        owner,
        house,
        conversation,
        message,
    }
}

/// The house holds a live access grant to read the conversation's MESSAGEs.
fn grant_conversation_messages(fixture: &Fixture) {
    grant_conversation_messages_to(fixture, fixture.house);
}

/// `principal` holds a live access grant to read the conversation's
/// MESSAGEs.
fn grant_conversation_messages_to(fixture: &Fixture, principal: EntityId) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    fixture
        .vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope,
                principal_ref: principal,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: fixture.conversation,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after the epoch")
                    .as_secs(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )
        .expect("the access grant on the conversation");
}

/// The owner's unscoped base-world CLAIM, outside the house's MESSAGE-only
/// policy row.
fn owner_claim(fixture: &Fixture) -> EntityId {
    let id = EntityId::now();
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: "preference.travel.seat".to_owned(),
            subject_ref: fixture.owner.to_hex(),
            value: json!({ "seat": "window" }),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .expect("the owner's CLAIM write");
    assert_eq!(
        receipt.claim.as_ref().map(|claim| claim.id.clone()),
        Some(id.to_hex()),
        "precondition: the owner's unscoped base-world CLAIM lands with the requested id"
    );
    id
}

/// The owner mints the house a live agent Grant to read every row. The
/// owner's act needs a carrier: this install rooted, then profiled in the
/// vault's roster under its own keys, as `oneiron init` leaves it.
fn grant_house_read(fixture: &Fixture) {
    let issuer = HostSlipIssuer::from_secret(b"saved-access-gate-house-grant")
        .expect("the install's host slip issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("the install's host root slip");
    fixture
        .vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the install's roster profile");
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            "principal:owner",
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: fixture.house,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the house a read Grant");
    assert!(
        minted.grant.confers,
        "precondition: the owner-minted read Grant is live"
    );
}

/// The house's own live key: no proof, no owner standing, the access gate.
fn live_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = fixture
        .vault
        .memory(fixture.house, EdgeActorClass::Agent)
        .read_key()
        .expect("the house's own read key");
    assert!(
        !key.reads_as_vault_owner() && !reads_under_relationship_gate(&key),
        "precondition: the house's own key reads below the owner's floor, not under the relationship gate"
    );
    key
}

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

/// `key`'s lane frozen as saved work keeps it, read back from its stored
/// MessagePack form, as a saved question's lane is.
fn saved_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(key)
        .freeze()
        .expect("the house's read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// The owner's own key under the access gate: the owner's floor passes the
/// policy check, not the grant gate.
fn gated_owner_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's own read key")
        .require_access_grants(Some(fixture.owner));
    assert!(
        key.reads_as_vault_owner() && !reads_under_relationship_gate(&key),
        "precondition: the owner's key under the access gate keeps the owner's floor and the access gate"
    );
    key
}

/// What `asker`'s saved question, saved under `frozen`, reads of `row`
/// through the reader the question's own reads build.
fn saved_reads(
    fixture: &Fixture,
    asker: EntityId,
    frozen: &FrozenReadLane,
    row: EntityId,
) -> (bool, String) {
    match saved_question_reader(&fixture.vault, asker, frozen) {
        Ok(key) => reads(&question_read(&fixture.vault, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// A standing graph question over the owner's MESSAGE.
fn message_question(fixture: &Fixture) -> QuestionDefinitionInput {
    QuestionDefinitionInput {
        question: DecisionQuestionInput {
            text: "Does the garden need a watering rota?".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        adapter: "graph".into(),
        units: vec![fixture.message],
        recipe: "unit".into(),
        profile: "fixture".into(),
        dial: DecisionDial {
            first: DecisionRung::Local,
            ceiling: DecisionRung::Local,
            band: DecisionBand::default(),
        },
        activation: QuestionActivation::Standing,
        refresh: RefreshPolicy {
            on_arrival: false,
            every_seconds: None,
        },
        delivery: "none".into(),
        learning: false,
        binding: None,
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    }
}

/// The lane `record` keeps, read back as the question's own reads find it:
/// a question stored with no live lane keeps its principal's own.
fn stored_lane(fixture: &Fixture, asker: EntityId, record: &QuestionRecord) -> FrozenReadLane {
    let stored = read_question(&fixture.vault, asker, record.definition.question.id, None)
        .expect("the stored question reads back")
        .expect("the stored question is found");
    assert!(
        stored.read_lane.is_principal(),
        "precondition: a question stored with no live lane keeps its principal's own lane"
    );
    stored.read_lane
}

#[test]
fn an_access_gated_saved_question_reads_no_unscoped_message_its_live_lane_refused() {
    let fixture = fixture();
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        !live,
        "precondition: the house's live lane refuses the owner's unscoped MESSAGE under the access gate; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, fixture.message);
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected its saved question's reader to refuse the unscoped MESSAGE its live lane refused; seen {seen}"
    );
}

#[test]
fn an_access_gated_saved_lane_keeps_its_grant_basis_and_rebuilds_under_the_access_gate() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture, live_key(&fixture));
    assert!(
        !frozen.reads_as_principal(),
        "actor=the house under the access gate, no proof; expected its saved lane to keep its grant basis, not to read as its principal's own"
    );
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &frozen)
        .expect("the saved question's reader rebuilds");
    assert!(
        !reads_under_relationship_gate(&rebuilt),
        "actor=the house under the access gate, no proof; expected its saved question's rebuilt reader to keep the access gate, not the relationship gate that admits unscoped rows"
    );
}

#[test]
fn an_access_gated_saved_lane_frozen_again_from_its_rebuilt_reader_reads_no_unscoped_message() {
    let fixture = fixture();
    let frozen = saved_lane(&fixture, live_key(&fixture));
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &frozen)
        .expect("the saved question's reader rebuilds");
    let refrozen = saved_lane(&fixture, rebuilt);
    let (read, seen) = saved_reads(&fixture, fixture.house, &refrozen, fixture.message);
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected a lane frozen again from its saved question's rebuilt reader to refuse the unscoped MESSAGE; seen {seen}"
    );
}

/// Guard: the rebuilt reader keeps the access gate, not a narrower one, so
/// an access grant on the MESSAGE's conversation still admits it.
#[test]
fn an_access_gated_saved_question_reads_a_message_its_conversation_grant_admits() {
    let fixture = fixture();
    grant_conversation_messages(&fixture);
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        live,
        "precondition: the house's access grant on the conversation admits the unscoped MESSAGE to its live lane; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, fixture.message);
    assert!(
        read,
        "actor=the house under the access gate, no proof; expected its saved question's reader to read the MESSAGE its access grant on the conversation admits; seen {seen}"
    );
}

/// A rebuild over a key no grant gate binds keeps the saved access gate
/// (Sol F4 on #8065).
#[test]
fn an_access_gated_saved_lane_rebuilt_over_an_ungated_key_reads_no_unscoped_message() {
    let fixture = fixture();
    let ungated = ScopedReadActorKey::with_actor_class(fixture.house.to_hex(), "agent")
        .expect("the house's bare agent key");
    let (bare, seen) = reads(&fixture.vault.scoped_read(ungated.clone()), fixture.message);
    assert!(
        bare,
        "control: the house's bare key, which no grant gate binds, reads the unscoped MESSAGE under its policy row; seen {seen}"
    );
    let frozen = saved_lane(&fixture, live_key(&fixture));
    let (read, seen) = match frozen.narrow(&fixture.vault, ungated) {
        Ok(key) => reads(&fixture.vault.scoped_read(key), fixture.message),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected its saved lane rebuilt over a key no grant gate binds to refuse the unscoped MESSAGE; seen {seen}"
    );
}

/// The owner's floor under the access gate refused the unscoped MESSAGE
/// too, so its lane keeps the basis (Sol F3 on #8065).
#[test]
fn an_owner_key_under_the_access_gate_saves_a_question_that_reads_no_unscoped_message() {
    let fixture = fixture();
    let key = gated_owner_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        !live,
        "precondition: the owner's live lane under the access gate refuses the owner's unscoped MESSAGE; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.owner, &frozen, fixture.message);
    assert!(
        !read,
        "actor=the owner's floor under the access gate, no proof; expected its saved question's reader to refuse the unscoped MESSAGE its live lane refused; seen {seen}"
    );
}

/// A gate bound to no principal read on no grant, so its rebuild does not
/// take the asker's own grants (Sol F5 on #8065).
#[test]
fn an_unbound_access_gated_saved_question_reads_no_message_its_askers_grant_admits() {
    let fixture = fixture();
    grant_conversation_messages(&fixture);
    let key = live_key(&fixture).require_access_grants(None);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        !live,
        "precondition: the house's live lane under an access gate bound to no principal refuses the MESSAGE the house's own access grant admits; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, fixture.message);
    assert!(
        !read,
        "actor=the house under an access gate bound to no principal; expected its saved question's reader to read on no grant and refuse the MESSAGE its live lane refused; seen {seen}"
    );
}

/// The saved lane keeps no top Scope: one stood as explicit read authority
/// past the house's MESSAGE-only policy row (Sol F1 on #8065).
#[test]
fn an_access_gated_saved_question_reads_no_claim_its_live_policy_row_refused() {
    let fixture = fixture();
    let claim = owner_claim(&fixture);
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), claim);
    assert!(
        !live,
        "precondition: the house's live lane refuses the owner's CLAIM outside its MESSAGE-only policy row; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, claim);
    assert!(
        !read,
        "actor=the house under the access gate, no proof; expected its saved question's reader to refuse the CLAIM its live policy row refused, not to read it under a Scope its live key lacked; seen {seen}"
    );
}

/// Guard: the saved lane keeps the read alternative of the house's own
/// agent Grant, which a top Scope turned off (Sol F2 on #8065).
#[test]
fn an_access_gated_saved_question_reads_a_message_its_own_agent_grant_admits() {
    let fixture = fixture();
    grant_house_read(&fixture);
    let key = live_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        live,
        "precondition: the house's owner-minted read Grant admits the unscoped MESSAGE to its live lane; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, fixture.message);
    assert!(
        read,
        "actor=the house under the access gate with an owner-minted read Grant; expected its saved question's reader to read the MESSAGE its own Grant admits; seen {seen}"
    );
}

/// A rebuild over a key a gate already binds to no principal reads on no
/// grant: the meet never lends it the owner as principal (Astra F1 on
/// #8061).
#[test]
fn a_gated_owner_saved_lane_rebuilt_over_an_unbound_gated_owner_key_reads_on_no_grant() {
    let fixture = fixture();
    grant_conversation_messages_to(&fixture, fixture.owner);
    let saving = gated_owner_key(&fixture);
    let (live, seen) = reads(&fixture.vault.scoped_read(saving.clone()), fixture.message);
    assert!(
        live,
        "precondition: the owner's access grant on the conversation admits the MESSAGE to the owner's gated live lane; seen {seen}"
    );
    let unbound = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("the owner's own read key")
        .require_access_grants(None);
    let (current, seen) = reads(&fixture.vault.scoped_read(unbound.clone()), fixture.message);
    assert!(
        !current,
        "precondition: the owner's key under an access gate bound to no principal refuses the MESSAGE; seen {seen}"
    );
    let frozen = saved_lane(&fixture, saving);
    let (read, seen) = match frozen.narrow(&fixture.vault, unbound) {
        Ok(key) => reads(&fixture.vault.scoped_read(key), fixture.message),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        !read,
        "actor=the owner's floor under an access gate bound to no principal; expected the saved lane rebuilt over it to read on no grant and refuse the MESSAGE; seen {seen}"
    );
}

/// The engine's lane-free save (`create_question`): the house's question
/// keeps its principal's own lane, which says nothing of the gate the house
/// read under, so its reader rebuilds under the access gate (FIX
/// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
#[test]
fn a_house_question_stored_with_no_lane_reads_no_unscoped_owner_message() {
    let fixture = fixture();
    let record = create_question(
        &fixture.vault,
        WriteActor::new(fixture.house, EdgeActorClass::Agent),
        message_question(&fixture),
        2,
    )
    .expect("the house's question is stored");
    let lane = stored_lane(&fixture, fixture.house, &record);
    let (read, seen) = saved_reads(&fixture, fixture.house, &lane, fixture.message);
    assert!(
        !read,
        "actor=the house, question stored with no lane; expected its saved question's reader to refuse the owner's unscoped MESSAGE under the access gate, as for every asker that is no live owner; seen {seen}"
    );
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &lane)
        .expect("the saved question's reader rebuilds");
    assert!(
        !reads_under_relationship_gate(&rebuilt),
        "actor=the house, question stored with no lane; expected its rebuilt reader to read under the access gate, not the relationship gate that admits unscoped rows"
    );
}

/// The dissent path: a review whose principal is an agent stores its
/// overruled prediction's standing question in a writer of its own with no
/// lane (`critic::review::dissent`, `create_question_in_txn`), and that
/// question's reader rebuilds under the access gate too.
#[test]
fn an_agent_dissent_question_stored_in_its_own_writer_reads_no_unscoped_owner_message() {
    let fixture = fixture();
    let record = create_question_in_writer(
        &fixture.vault,
        WriteActor::new(fixture.house, EdgeActorClass::Agent),
        message_question(&fixture),
        2,
    )
    .expect("the house's dissent question is stored");
    let lane = stored_lane(&fixture, fixture.house, &record);
    let (read, seen) = saved_reads(&fixture, fixture.house, &lane, fixture.message);
    assert!(
        !read,
        "actor=the house as a review's agent principal, dissent question stored in its own writer; expected its saved question's reader to refuse the owner's unscoped MESSAGE; seen {seen}"
    );
}

/// Guard: the owner is a live owner, so the owner's own question stored
/// with no lane still reads as the owner's own.
#[test]
fn the_owners_question_stored_with_no_lane_still_reads_the_owners_unscoped_message() {
    let fixture = fixture();
    let record = create_question(
        &fixture.vault,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        message_question(&fixture),
        2,
    )
    .expect("the owner's question is stored");
    let lane = stored_lane(&fixture, fixture.owner, &record);
    let (read, seen) = saved_reads(&fixture, fixture.owner, &lane, fixture.message);
    assert!(
        read,
        "actor=the owner, question stored with no lane; expected its saved question's reader to read the owner's own unscoped MESSAGE; seen {seen}"
    );
}

/// The relationship gate is a basis too: the lane of an actor that is no
/// live owner keeps it, so its rebuild reads the unscoped MESSAGE its live
/// lane read and is not taken for a lane with no basis.
#[test]
fn a_relationship_gated_house_lane_freezes_with_its_basis_and_reads_the_unscoped_message() {
    let fixture = fixture();
    let key = under_relationship_gate(
        ScopedReadActorKey::with_actor_class(fixture.house.to_hex(), "agent")
            .expect("the house's bare agent key"),
        fixture.house,
    );
    let (live, seen) = reads(&fixture.vault.scoped_read(key.clone()), fixture.message);
    assert!(
        reads_under_relationship_gate(&key) && live,
        "precondition: the house's key under the relationship gate reads the owner's unscoped MESSAGE under its policy row; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    assert!(
        !frozen.reads_as_principal(),
        "actor=the house under the relationship gate, no proof; expected its saved lane to keep its grant basis, not to read as its principal's own"
    );
    let (read, seen) = saved_reads(&fixture, fixture.house, &frozen, fixture.message);
    assert!(
        read,
        "actor=the house under the relationship gate, no proof; expected its saved question's reader to read the unscoped MESSAGE its live lane read; seen {seen}"
    );
    let rebuilt = saved_question_reader(&fixture.vault, fixture.house, &frozen)
        .expect("the saved question's reader rebuilds");
    assert!(
        reads_under_relationship_gate(&rebuilt),
        "actor=the house under the relationship gate, no proof; expected its rebuilt reader to keep the relationship gate"
    );
}

/// A reader rebuilt from a lane with no basis, frozen again, keeps the
/// access gate it was rebuilt under.
#[test]
fn a_house_lane_with_no_basis_rebuilt_and_frozen_again_reads_no_unscoped_message() {
    let fixture = fixture();
    let rebuilt =
        saved_question_reader(&fixture.vault, fixture.house, &FrozenReadLane::principal())
            .expect("the house's saved question reader rebuilds");
    let refrozen = saved_lane(&fixture, rebuilt);
    let (read, seen) = saved_reads(&fixture, fixture.house, &refrozen, fixture.message);
    assert!(
        !read,
        "actor=the house, lane with no basis; expected a lane frozen again from its rebuilt reader to refuse the owner's unscoped MESSAGE; seen {seen}"
    );
}

/// Guard: the access gate a lane with no basis rebuilds under still admits
/// the MESSAGE an access grant on its conversation admits the house.
#[test]
fn a_house_lane_with_no_basis_reads_a_message_its_conversation_grant_admits() {
    let fixture = fixture();
    grant_conversation_messages(&fixture);
    let (read, seen) = saved_reads(
        &fixture,
        fixture.house,
        &FrozenReadLane::principal(),
        fixture.message,
    );
    assert!(
        read,
        "actor=the house, lane with no basis; expected its saved question's reader to read the MESSAGE its access grant on the conversation admits; seen {seen}"
    );
}

/// Guard: the access gate a lane with no basis rebuilds under keeps the
/// read alternative of the house's own agent Grant.
#[test]
fn a_house_lane_with_no_basis_reads_a_message_its_own_agent_grant_admits() {
    let fixture = fixture();
    grant_house_read(&fixture);
    let (read, seen) = saved_reads(
        &fixture,
        fixture.house,
        &FrozenReadLane::principal(),
        fixture.message,
    );
    assert!(
        read,
        "actor=the house with an owner-minted read Grant, lane with no basis; expected its saved question's reader to read the MESSAGE its own Grant admits; seen {seen}"
    );
}

/// Guard: a question's source reader (its refresh, artifact and wake reads)
/// builds the owner's bare key under the access gate, with no owner
/// standing of its own. The owner is a live owner by the vault's census, so
/// a lane with no basis leaves that key, and the owner's own live authority
/// beside it, as it is.
#[test]
fn the_owners_source_reader_of_a_lane_with_no_basis_still_reads_the_owners_unscoped_message() {
    let fixture = fixture();
    let key = ScopedReadActorKey::with_actor_class(fixture.owner.to_hex(), "human")
        .expect("the owner's bare principal key")
        .require_access_grants(Some(fixture.owner));
    let (read, seen) = match FrozenReadLane::principal().narrow(&fixture.vault, key) {
        Ok(key) => reads(&question_read(&fixture.vault, key), fixture.message),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        read,
        "actor=the owner's bare key under the access gate, lane with no basis; expected its question read to keep the owner's own live authority and read the owner's unscoped MESSAGE; seen {seen}"
    );
}
