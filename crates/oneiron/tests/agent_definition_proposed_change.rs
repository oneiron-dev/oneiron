//! The owner answers an agent's proposed change to a stored agent definition.
//!
//! Canon ARCH-0053:20 (owner, 22 Sep 2026): "An agent may author an
//! AGENT_DEF for later use under the same rule as a skill: a definition that
//! widens nothing lands Active at the author's ceiling; anything beyond the
//! author's slice is a proposal." ARCH-0053 r6: "a skill update that widens
//! the capability surface requires human re-consent".
//!
//! An agent's generic put that grants a stored definition more than its
//! slice holds is stored beside it as a proposal: a Proposed row whose
//! provenance names the stored row under `replaces`. The owner lists the
//! proposals (`vault.agents.proposed_changes.list`), approves one
//! (`vault.agents.proposed_changes.approve`: the stored row takes it as its
//! next version) or rejects it (`vault.agents.proposed_changes.reject`: the
//! stored row stays). Either answer deletes the proposal row and records one
//! gate decision. These tests call the verbs by name on the embedded owner's
//! handle, as the facade does.

use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence, encode_agent_definition,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;

/// The author agent's fixture id, `[seed; 16]`, off the pinned bytes a fresh
/// vault holds.
const AUTHOR: u8 = 0x70;

const LIST: &str = "vault.agents.proposed_changes.list";
const APPROVE: &str = "vault.agents.proposed_changes.approve";
const REJECT: &str = "vault.agents.proposed_changes.reject";

/// The key the engine derives the id of a proposed change under
/// (`agent_def/doors.rs`, `PROPOSED_CHANGE_ID_CONTEXT`).
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

/// The id the engine stores version `version` of the definition at `stored`
/// under, as a proposal.
fn proposed_change_id(stored: &EntityId, version: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(stored.as_bytes());
    hasher.update(version.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).expect("derived proposal id")
}

/// The author's definition as the owner creates it: scope Base, ceiling
/// Proposed, version "1", a companion's wake cadence (the one role the
/// default wake policy wakes on a surprise alone).
fn author_definition() -> AgentDefinition {
    AgentDefinition::new(
        "proposed_change.author",
        "proposed change fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
    .with_wake_cadence(AgentWakeCadence::Companion {
        every_turns: Some(1),
    })
}

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => Value::Bool(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("an integer fits i64 or u64"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => Value::String(text.as_str().expect("UTF-8").to_owned()),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

/// Puts `def` at the author's own id through `vault.batch` on the author's
/// Agent-class handle, as a code-mode run does.
fn author_batch_put(
    vault: &Vault,
    author: EntityId,
    def: &AgentDefinition,
    at: u64,
) -> Result<Value, String> {
    let bytes = encode_agent_definition(def).expect("valid definition");
    let body = json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack"));
    oneiron::task_verb::sdk::invoke(
        &vault.memory(author, EdgeActorClass::Agent),
        "vault.batch",
        json!({"entities": [{
            "id": author.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": at,
            "occurred_end": at,
            "learned_at": at,
            "body": body,
        }]}),
    )
    .map_err(|error| format!("{error:?}"))
}

/// One dispatch of the definition at `id`, as a label.
fn dispatch_of(vault: &Vault, id: EntityId) -> String {
    match AgentDispatcher::new(vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: NOW + 9,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

/// A personal vault, held by this process, whose owner created one agent
/// and whose agent proposed a wider version of its own definition.
struct Fixture {
    vault: Vault,
    owner_person: EntityId,
    author: EntityId,
    /// The author's stored definition before the proposal.
    before: AgentDefinition,
    /// The author's definition at scope All, version "2", as it proposed it.
    wider: AgentDefinition,
    /// The proposal row holding `wider`.
    proposal: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    // The owner verbs answer the embedded owner on the handle of the process
    // that holds the vault's writer lease.
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &author_definition(),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    // A put over a stored row is admitted only on a lane that reads the row.
    vault
        .install_read_permits_for_test(&[oneiron::WriteActor::new(author, EdgeActorClass::Agent)])
        .expect("the author reads its own row");
    let before = vault
        .get_agent_definition(&author)
        .expect("read the author")
        .expect("the author row");
    let mut wider = before.clone();
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    author_batch_put(&vault, author, &wider, NOW + 5).expect("the author's widening batch lands");
    let proposal = proposed_change_id(&author, "2");
    let stored = vault
        .get_agent_definition(&proposal)
        .expect("read the proposal id")
        .expect("ARCH-0053 r6: the widening put is stored as a proposal");
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(
        vault
            .get_agent_definition(&author)
            .expect("read the author"),
        Some(before.clone()),
        "the proposal leaves the stored row as it was"
    );
    Fixture {
        vault,
        owner_person,
        author,
        before,
        wider,
        proposal,
        _dir: dir,
    }
}

/// Calls owner verb `verb` by name on the embedded owner's handle.
fn as_owner(fixture: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(
        &fixture
            .vault
            .memory(fixture.owner_person, EdgeActorClass::Human),
        verb,
        input,
    )
    .map_err(|error| format!("{error:?}"))
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is text in {value}"))
}

/// The gate decision `receipt_ref` (`gate:<hex>`) names.
fn gate_record(fixture: &Fixture, receipt_ref: &str) -> oneiron::store::GateDecisionRecord {
    let hex = receipt_ref
        .strip_prefix("gate:")
        .unwrap_or_else(|| panic!("{receipt_ref} names a gate decision"));
    fixture
        .vault
        .gate_decisions(256)
        .expect("read the gate decisions")
        .into_iter()
        .find(|record| record.decision_id.to_hex() == hex)
        .unwrap_or_else(|| panic!("no gate decision {hex}"))
}

/// Holds the gate decision of an answer: the owner as actor, `reason`, the
/// stored row as grant ref, the proposal's body hash as diff handle, and the
/// ids, versions and proposer as audit details.
fn assert_answer_recorded(
    fixture: &Fixture,
    receipt_ref: &str,
    outcome: &str,
    reason: &str,
    proposal_body: &[u8],
    details: &[String],
) {
    let record = gate_record(fixture, receipt_ref);
    assert_eq!(record.outcome, outcome);
    assert_eq!(record.reason_codes, vec![reason.to_owned()]);
    assert_eq!(
        record.actor_ref.as_deref(),
        Some(fixture.owner_person.to_hex().as_str()),
        "the owner answered"
    );
    assert_eq!(
        record.grant_ref.as_deref(),
        Some(format!("agent_def:{}", fixture.author.to_hex()).as_str())
    );
    assert_eq!(
        record.diff_handle,
        blake3::hash(proposal_body).as_bytes().to_vec(),
        "the receipt binds the proposal's body"
    );
    let bodies: Vec<&str> = record
        .system_notices
        .iter()
        .map(|notice| notice.body.as_str())
        .collect();
    for detail in details {
        assert!(
            bodies.contains(&detail.as_str()),
            "the receipt names {detail}: {bodies:?}"
        );
    }
}

fn proposal_body(fixture: &Fixture) -> Vec<u8> {
    let proposal = fixture
        .vault
        .get_agent_definition(&fixture.proposal)
        .expect("read the proposal")
        .expect("the proposal row");
    encode_agent_definition(&proposal).expect("encode the proposal")
}

fn waiting_changes(fixture: &Fixture) -> Vec<Value> {
    let listed = as_owner(fixture, LIST, json!({})).expect("the owner lists proposed changes");
    listed
        .get("changes")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("changes is a list in {listed}"))
        .clone()
}

#[test]
fn owner_lists_a_proposed_change_beside_the_definition_it_would_replace() {
    let fixture = fixture();
    let changes = waiting_changes(&fixture);
    assert_eq!(changes.len(), 1, "one change waits: {changes:?}");
    let change = &changes[0];
    assert_eq!(
        text(change, "/proposal/agent_def_ref"),
        fixture.proposal.to_hex()
    );
    assert_eq!(text(change, "/proposal/definition/version"), "2");
    assert_eq!(text(change, "/proposal/approval_status"), "proposed");
    assert_eq!(text(change, "/target_ref"), fixture.author.to_hex());
    assert_eq!(text(change, "/target/definition/version"), "1");
    assert_eq!(text(change, "/proposed_by"), fixture.author.to_hex());
    assert_eq!(text(change, "/proposed_through"), "vault.batch");
    let other = EntityId::from_bytes([0x7E; 16]).expect("other id");
    let none = as_owner(&fixture, LIST, json!({"target_ref": other.to_hex()}))
        .expect("the owner lists one definition's changes");
    assert_eq!(none["changes"], json!([]), "no change names another row");
}

#[test]
fn owner_approving_a_proposed_change_makes_it_the_stored_definitions_next_version() {
    let fixture = fixture();
    let body = proposal_body(&fixture);
    let settled = as_owner(
        &fixture,
        APPROVE,
        json!({"proposal_ref": fixture.proposal.to_hex(), "expected_target_version": "1"}),
    )
    .expect("the owner approves the proposed change");
    assert_eq!(text(&settled, "/decision"), "approved");
    assert_eq!(text(&settled, "/proposal_ref"), fixture.proposal.to_hex());
    assert_eq!(text(&settled, "/target_ref"), fixture.author.to_hex());
    assert_eq!(text(&settled, "/target_version_before"), "1");
    assert_eq!(text(&settled, "/target/definition/version"), "2");
    assert_eq!(text(&settled, "/proposed_by"), fixture.author.to_hex());
    let stored = fixture
        .vault
        .get_agent_definition(&fixture.author)
        .expect("read the author")
        .expect("the author row");
    assert_eq!(stored.version, "2", "the proposal is the next version");
    assert_eq!(stored.scope, AgentScope::All, "the approved grant holds");
    assert_eq!(stored.approval_status, fixture.before.approval_status);
    assert_eq!(stored.lifecycle_status, fixture.before.lifecycle_status);
    assert_eq!(stored.source, fixture.before.source);
    assert_eq!(stored.human_authored, fixture.before.human_authored);
    assert_eq!(
        stored.provenance, fixture.before.provenance,
        "the stored row keeps its own provenance"
    );
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.proposal)
            .expect("read the proposal id"),
        None,
        "the approved proposal row is deleted: the stored row holds its body"
    );
    assert_ne!(
        dispatch_of(&fixture.vault, fixture.proposal),
        "dispatched",
        "an approved proposal's own id is never dispatched"
    );
    assert_answer_recorded(
        &fixture,
        text(&settled, "/receipt_ref"),
        "allow",
        "gate.allow.owner_agent_definition_change",
        &body,
        &[
            format!("target:{}", fixture.author.to_hex()),
            format!("proposal:{}", fixture.proposal.to_hex()),
            "proposal_version:2".to_owned(),
            "target_version_before:1".to_owned(),
            "target_version_after:2".to_owned(),
            format!("proposed_by:{}", fixture.author.to_hex()),
            "proposed_through:vault.batch".to_owned(),
        ],
    );
    assert!(
        waiting_changes(&fixture).is_empty(),
        "no change waits after the answer"
    );
}

#[test]
fn owner_rejecting_a_proposed_change_leaves_the_stored_definition_as_it_was() {
    let fixture = fixture();
    let body = proposal_body(&fixture);
    let settled = as_owner(
        &fixture,
        REJECT,
        json!({"proposal_ref": fixture.proposal.to_hex()}),
    )
    .expect("the owner rejects the proposed change");
    assert_eq!(text(&settled, "/decision"), "rejected");
    assert_eq!(text(&settled, "/target_version_before"), "1");
    assert_eq!(text(&settled, "/target/definition/version"), "1");
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.author)
            .expect("read the author"),
        Some(fixture.before.clone()),
        "a rejection leaves the stored row as it was"
    );
    let rejected = fixture
        .vault
        .get_agent_definition(&fixture.proposal)
        .expect("read the proposal id")
        .expect("a rejected proposal stays at its ref");
    let rejected_version = format!("rejected-{}", blake3::hash(b"2").to_hex());
    assert_eq!(rejected.approval_status, ClaimApprovalStatus::Rejected);
    assert_eq!(rejected.lifecycle_status, ClaimLifecycleStatus::Retracted);
    assert_eq!(rejected.version, rejected_version);
    assert_eq!(
        rejected.scope,
        AgentScope::All,
        "the rejected row holds what the agent proposed"
    );
    let read = as_owner(
        &fixture,
        "vault.agents.get",
        json!({"agent_def_ref": fixture.proposal.to_hex()}),
    )
    .expect("the owner reads the rejected proposal by its ref");
    assert_eq!(text(&read, "/approval_status"), "rejected");
    assert_eq!(text(&read, "/lifecycle_status"), "retracted");
    assert_eq!(text(&read, "/definition/version"), rejected_version);
    assert_eq!(
        read.pointer("/definition/scope/kind"),
        Some(&json!("all")),
        "the owner reads the proposed scope"
    );
    assert_ne!(
        dispatch_of(&fixture.vault, fixture.proposal),
        "dispatched",
        "a rejected proposal is never dispatched"
    );
    assert_answer_recorded(
        &fixture,
        text(&settled, "/receipt_ref"),
        "deny",
        "gate.deny.owner_agent_definition_change",
        &body,
        &[
            format!("target:{}", fixture.author.to_hex()),
            format!("proposal:{}", fixture.proposal.to_hex()),
            "proposal_version:2".to_owned(),
            "target_version_before:1".to_owned(),
            "target_version_after:1".to_owned(),
            format!("proposed_by:{}", fixture.author.to_hex()),
        ],
    );
    assert!(
        waiting_changes(&fixture).is_empty(),
        "no change waits after the answer"
    );
}

#[test]
fn an_agent_cannot_bring_back_a_proposal_the_owner_rejected() {
    let fixture = fixture();
    as_owner(
        &fixture,
        REJECT,
        json!({"proposal_ref": fixture.proposal.to_hex()}),
    )
    .expect("the owner rejects the proposed change");
    let again = author_batch_put(&fixture.vault, fixture.author, &fixture.wider, NOW + 7);
    println!("CONFORMANCE case=refile-after-reject write={again:?}");
    assert!(
        again.is_err(),
        "the widening rule keeps a rejected proposal rejected: {again:?}"
    );
    let rejected = fixture
        .vault
        .get_agent_definition(&fixture.proposal)
        .expect("read the proposal id")
        .expect("the rejected proposal row");
    assert_eq!(rejected.approval_status, ClaimApprovalStatus::Rejected);
    assert_eq!(rejected.lifecycle_status, ClaimLifecycleStatus::Retracted);
    assert!(
        waiting_changes(&fixture).is_empty(),
        "no change waits after the refused re-file"
    );
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.author)
            .expect("read the author"),
        Some(fixture.before.clone())
    );
}

#[test]
fn approving_a_proposed_change_after_the_stored_definition_moved_is_refused() {
    let fixture = fixture();
    let owner = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut edited = fixture.before.clone();
    edited.desc = "edited by the owner".to_owned();
    edited.version = "1b".to_owned();
    fixture
        .vault
        .update_agent_definition_at_version_as(
            &owner,
            &fixture.author,
            "1",
            &edited,
            TimeRange {
                start: NOW + 6,
                end: NOW + 6,
            },
            NOW + 6,
        )
        .expect("the owner edits the stored row");
    let stale = as_owner(
        &fixture,
        APPROVE,
        json!({"proposal_ref": fixture.proposal.to_hex(), "expected_target_version": "1"}),
    );
    assert!(
        stale.is_err(),
        "an approval of a version the stored row has left is refused: {stale:?}"
    );
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.author)
            .expect("read the author"),
        Some(edited),
        "the refused approval wrote nothing"
    );
    assert!(
        fixture
            .vault
            .get_agent_definition(&fixture.proposal)
            .expect("read the proposal id")
            .is_some(),
        "the proposal still waits"
    );
    let settled = as_owner(
        &fixture,
        APPROVE,
        json!({"proposal_ref": fixture.proposal.to_hex(), "expected_target_version": "1b"}),
    )
    .expect("the owner approves against the version they read");
    assert_eq!(text(&settled, "/target_version_before"), "1b");
    assert_eq!(text(&settled, "/target/definition/version"), "2");
}

#[test]
fn a_definition_that_is_no_proposed_change_is_neither_approved_nor_rejected() {
    let fixture = fixture();
    let approve = as_owner(
        &fixture,
        APPROVE,
        json!({"proposal_ref": fixture.author.to_hex(), "expected_target_version": "1"}),
    );
    let reject = as_owner(
        &fixture,
        REJECT,
        json!({"proposal_ref": fixture.author.to_hex()}),
    );
    let absent = EntityId::from_bytes([0x7D; 16]).expect("absent id");
    let unknown = as_owner(&fixture, REJECT, json!({"proposal_ref": absent.to_hex()}));
    println!(
        "CONFORMANCE case=no-proposal approve={approve:?} reject={reject:?} unknown={unknown:?}"
    );
    assert!(
        approve.is_err() && reject.is_err() && unknown.is_err(),
        "only a proposed change waiting for the owner is answered"
    );
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.author)
            .expect("read the author"),
        Some(fixture.before.clone()),
        "the refused answers wrote nothing"
    );
    assert_eq!(
        waiting_changes(&fixture).len(),
        1,
        "the proposal still waits"
    );
}

#[test]
fn an_agent_cannot_answer_a_proposed_change() {
    let fixture = fixture();
    let memory = fixture.vault.memory(fixture.author, EdgeActorClass::Agent);
    for (verb, input) in [
        (
            APPROVE,
            json!({"proposal_ref": fixture.proposal.to_hex(), "expected_target_version": "1"}),
        ),
        (REJECT, json!({"proposal_ref": fixture.proposal.to_hex()})),
    ] {
        let answer = oneiron::task_verb::sdk::invoke(&memory, verb, input);
        assert!(
            answer.is_err(),
            "{verb} is the owner's, never its proposer's: {answer:?}"
        );
    }
    assert_eq!(
        fixture
            .vault
            .get_agent_definition(&fixture.author)
            .expect("read the author"),
        Some(fixture.before.clone())
    );
}

/// The agents a surprise wakes and the vault's companions, in that order.
fn cadence_scans(fixture: &Fixture) -> (Vec<EntityId>, Vec<EntityId>) {
    let woken =
        oneiron::test_doors::agent_definition_scans::surprise_wakeable_agents(&fixture.vault, 1.0)
            .expect("the surprise wake scan");
    let companions = oneiron::test_doors::agent_definition_scans::companion_agents(&fixture.vault)
        .expect("the companion scan");
    (woken, companions)
}

#[test]
fn a_proposed_change_waiting_or_answered_is_in_no_cadence_scan() {
    let fixture = fixture();
    let (woken, companions) = cadence_scans(&fixture);
    println!("CONFORMANCE case=scans-waiting woken={woken:?} companions={companions:?}");
    assert!(
        woken.contains(&fixture.author) && companions.contains(&fixture.author),
        "control: a surprise wakes the companion author, which is a companion"
    );
    assert!(
        !woken.contains(&fixture.proposal),
        "a waiting proposal is woken by no surprise"
    );
    assert!(
        !companions.contains(&fixture.proposal),
        "a waiting proposal is no companion"
    );
    as_owner(
        &fixture,
        REJECT,
        json!({"proposal_ref": fixture.proposal.to_hex()}),
    )
    .expect("the owner rejects the proposed change");
    let (woken, companions) = cadence_scans(&fixture);
    println!("CONFORMANCE case=scans-rejected woken={woken:?} companions={companions:?}");
    assert!(
        woken.contains(&fixture.author) && companions.contains(&fixture.author),
        "control: the stored definition still wakes and is still a companion"
    );
    assert!(
        !woken.contains(&fixture.proposal) && !companions.contains(&fixture.proposal),
        "a rejected proposal is in no cadence scan"
    );
}
