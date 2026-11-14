//! ROLES-CHECKIN P2.5, row 2k8e (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): two Owner-proof approvals take
//! the 2j apply shape, `vault.agents.proposed_changes.approve` and
//! `vault.widen_proposals.approve`.
//!
//! - The Owner's approval is never gated: it goes on their own proof, and
//!   the answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   approval: the approval's writer spends it, and the answer names it and
//!   its asker. An approval asked for another proposal changes nothing and
//!   stays unspent.
//! - A rejection, a decline and a repeat of a settled approval apply no
//!   check-in and answer no decision; a decline refuses a `check_in_ref`.
//!
//! On its base, 2k8d2's head, this file does not build: neither approval
//! has a `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_owner_approval_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition,
    proposed_agent_definition_change_approve_effect_digest,
};
use oneiron::agent_dispatch::widen_doors::{
    WidenProposalAnswer, WidenProposalState, WidenProposalsRequest,
    approve_widen_proposal_as_owner, decline_widen_proposal_as_owner,
    widen_proposal_approve_effect_digest, widen_proposals_as_owner,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use oneiron::check_in::ActClass;
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_projection::{ChatProjection, ContextSpec};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::verbs::{
    ProposedAgentDefinitionChangeApproveRequest, ProposedAgentDefinitionChangeRejectRequest,
    approve_proposed_agent_definition_change_as, reject_proposed_agent_definition_change_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;

/// The key the engine derives the id of a proposed change under
/// (`agent_def/doors.rs`, `PROPOSED_CHANGE_ID_CONTEXT`).
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A definition the Owner creates: `scope` and `ceiling`, version "1".
fn definition(agent_id: &str, scope: AgentScope, ceiling: AgentCeiling) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "check-in approval fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
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

/// Agent `author`'s own Base definition `agent_id`, created by the Owner,
/// and the proposal its put of a wider version "2" (scope All) is stored as.
fn proposed_change(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    author: EntityId,
    agent_id: &str,
) -> EntityId {
    let before = definition(agent_id, AgentScope::Base, AgentCeiling::Proposed);
    vault
        .create_agent_definition_as(owner_proof, &author, &before, at(NOW), NOW)
        .expect("the Owner creates the agent");
    let mut wider = before;
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    let bytes = encode_agent_definition(&wider).expect("a valid definition");
    let body = json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack"));
    oneiron::task_verb::sdk::invoke(
        &vault.memory(author, EdgeActorClass::Agent),
        "vault.batch",
        json!({"entities": [{
            "id": author.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": NOW + 5,
            "occurred_end": NOW + 5,
            "learned_at": NOW + 5,
            "body": body,
        }]}),
    )
    .expect("the agent's widening put lands");
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(author.as_bytes());
    hasher.update(b"2");
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(id).expect("the proposal id")
}

fn approval(
    proposal: EntityId,
    check_in: Option<EntityId>,
) -> ProposedAgentDefinitionChangeApproveRequest {
    ProposedAgentDefinitionChangeApproveRequest {
        proposal_ref: proposal,
        expected_target_version: "1".to_owned(),
        check_in_ref: check_in.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_agent_definition_change_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    vault.prepare_install_signing().expect("install signing");
    let authors =
        [0x70_u8, 0x71, 0x72].map(|seed| EntityId::from_bytes([seed; 16]).expect("an id"));
    let [own, asked, other] = authors;
    // A put over a stored row is admitted only on a lane that reads the row.
    vault
        .install_read_permits_for_test(
            &authors.map(|author| WriteActor::new(author, EdgeActorClass::Agent)),
        )
        .expect("each author reads its own row");
    let own_change = proposed_change(&vault, &owner_proof, own, "check_in.approval.own");
    let asked_change = proposed_change(&vault, &owner_proof, asked, "check_in.approval.asked");
    let other_change = proposed_change(&vault, &owner_proof, other, "check_in.approval.other");

    let approved_own = approve_proposed_agent_definition_change_as(
        &vault,
        &owner_proof,
        approval(own_change, None),
    )
    .expect("the Owner approves a change");
    assert_eq!(
        approved_own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own approval records their own proof"
    );
    assert_eq!(approved_own.target_ref, own);

    let asked_body = vault
        .get_agent_definition(&asked_change)
        .expect("read the proposal")
        .expect("the proposal row");
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.agents.proposed_changes.approve",
        ActClass::GrantWiden,
        &proposed_agent_definition_change_approve_effect_digest(&asked_change, "1", &asked_body)
            .expect("the approval's digest"),
    );
    let refused = approve_proposed_agent_definition_change_as(
        &vault,
        &owner_proof,
        approval(other_change, Some(check_in)),
    );
    assert!(
        refused.is_err(),
        "the approval covers the change it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert_eq!(
        vault
            .get_agent_definition(&other)
            .expect("read the agent")
            .expect("the agent row")
            .version,
        "1",
        "the refused call changed nothing"
    );

    let applied = approve_proposed_agent_definition_change_as(
        &vault,
        &owner_proof,
        approval(asked_change, Some(check_in)),
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(applied.target_ref, asked);
    assert!(spent(&vault, &check_in), "the approval spent the check-in");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );

    let rejected = reject_proposed_agent_definition_change_as(
        &vault,
        &owner_proof,
        ProposedAgentDefinitionChangeRejectRequest {
            proposal_ref: other_change,
        },
    )
    .expect("the Owner rejects a change");
    assert_eq!(rejected.check_in, None, "a rejection widens nothing");
}

/// A row for a board dispatch: All, ceiling Auto.
const WIDEN_ROW: u8 = 0xB3;
/// The first-party PERSON that files the board's TASK.
const CREATOR: u8 = 0xE1;

/// A board TASK the Owner owns, run by an Auto agent; a parent dispatched
/// under it with no context; and one child per key, each asking for the
/// parent's last chat turn, so each is held as a widen proposal: their ids.
fn widen_proposals(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    keys: &[&str],
) -> Vec<String> {
    let row = EntityId::from_bytes([WIDEN_ROW; 16]).expect("the row id");
    vault
        .create_agent_definition_as(
            owner_proof,
            &row,
            &definition("check_in.widen", AgentScope::All, AgentCeiling::Auto),
            at(1),
            1,
        )
        .expect("the Owner creates the board's agent");
    let creator = EntityId::from_bytes([CREATOR; 16]).expect("the creator id");
    vault
        .put_entity(&creator, ENTITY_TYPE_PERSON, at(1), 1, b"creator")
        .expect("the creator");
    let board = vault
        .memory(creator, EdgeActorClass::Agent)
        .tasks_create(
            &TaskCreateSpec::new(RmpValue::from("board work"), None, Some(owner), Some(1))
                .with_assignee(TaskAssignee::AgentDef { agent_def_ref: row }),
        )
        .expect("the board TASK")
        .route
        .expect("its route")
        .local_attempt()
        .expect("the board dispatch");
    let dispatcher = AgentDispatcher::new(vault);
    let child = |parent, key: &str| DispatchAgent {
        target: AgentDispatchTarget::Custom(row),
        parent_attempt: Some(parent),
        dedupe_key: Some(key.to_owned()),
        run_id: None,
        now: 3,
    };
    let parent = match dispatcher
        .dispatch_with_context(
            child(board, "parent"),
            AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
        )
        .expect("the parent dispatch")
    {
        AgentDispatchOutcome::Dispatched(status) => status.attempt.id,
        other => panic!("the parent dispatches; seen {other:?}"),
    };
    keys.iter()
        .map(|&key| {
            let asked = AgentSpawnContext::default().with_context_spec(ContextSpec {
                chat: ChatProjection::Recent { last_n: 1 },
                ..ContextSpec::excluded()
            });
            match dispatcher
                .dispatch_with_context(child(parent, key), asked)
                .expect("the child dispatch")
            {
                AgentDispatchOutcome::ProposedWiden(proposal) => proposal.proposal_id,
                other => panic!("a wider child is held as a proposal; seen {other:?}"),
            }
        })
        .collect()
}

fn answer(proposal: &str, check_in: Option<EntityId>) -> WidenProposalAnswer {
    WidenProposalAnswer {
        proposal_id: proposal.to_owned(),
        check_in_ref: check_in.map(|id| id.to_hex()),
    }
}

fn state(vault: &Vault, owner_proof: &AuthenticatedOwner, proposal: &str) -> WidenProposalState {
    widen_proposals_as_owner(vault, owner_proof, &WidenProposalsRequest::default())
        .expect("list the proposals")
        .proposals
        .into_iter()
        .find(|row| row.proposal_id == proposal)
        .expect("the proposal is listed")
        .state
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_widen_proposal_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    vault.prepare_install_signing().expect("install signing");
    let proposals = widen_proposals(&vault, owner, &owner_proof, &["own", "asked", "other"]);
    let [own, asked, other] = [&proposals[0], &proposals[1], &proposals[2]];
    assert!(
        own != asked && asked != other && own != other,
        "three children, three proposals"
    );

    let approved_own = approve_widen_proposal_as_owner(&vault, &owner_proof, &answer(own, None))
        .expect("the Owner approves a widening");
    assert_eq!(approved_own.state, WidenProposalState::Approved);
    assert_eq!(
        approved_own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own approval records their own proof"
    );

    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.widen_proposals.approve",
        ActClass::GrantWiden,
        &widen_proposal_approve_effect_digest(&answer(asked, None)).expect("the approval's digest"),
    );
    let declined =
        decline_widen_proposal_as_owner(&vault, &owner_proof, &answer(other, Some(check_in)));
    assert!(
        declined.is_err(),
        "a decline widens nothing and applies no check-in; seen {declined:?}"
    );
    let refused =
        approve_widen_proposal_as_owner(&vault, &owner_proof, &answer(other, Some(check_in)));
    assert!(
        refused.is_err(),
        "the approval covers the proposal it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert_eq!(
        state(&vault, &owner_proof, other),
        WidenProposalState::Pending,
        "the refused calls settled nothing"
    );

    let applied =
        approve_widen_proposal_as_owner(&vault, &owner_proof, &answer(asked, Some(check_in)))
            .expect("the Owner applies the approved ask");
    assert_eq!(applied.state, WidenProposalState::Approved);
    assert!(spent(&vault, &check_in), "the approval spent the check-in");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );

    let repeat =
        approve_widen_proposal_as_owner(&vault, &owner_proof, &answer(asked, Some(check_in)))
            .expect("a settled proposal answers as it settled");
    assert_eq!(repeat.state, WidenProposalState::Approved);
    assert_eq!(
        repeat.check_in, None,
        "a repeat changes nothing and records none"
    );
}
