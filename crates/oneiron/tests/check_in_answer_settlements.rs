//! ROLES-CHECKIN P2.3c, piece 2l (ARCH-0082 #ladder and "When nobody
//! answers"; Engine ruling P23-SHAPE Q7, Q8 and Q9 = A):
//! `vault.check_in.answer` through the generated verb dispatch, JSON in and
//! JSON out, on the answering person's own `Memory`.
//!
//! - A person pinned on the current rung settles the ask over its exact
//!   effect: the settlement names them, the rung and `human_confirm`. An
//!   approval makes the act eligible once; a denial makes nothing eligible.
//! - The same person's same answer again returns the settlement and writes
//!   nothing. Any other answer to a settled ask is refused, naming who
//!   answered to a person the ask pinned, and naming nobody to anyone else.
//! - A person the ask does not pin now, an answer over another effect or
//!   after the rung's wait, an agent, and a standing approval are refused,
//!   and write nothing.
//! - An inquiry's check-in is answered only through its own verb.
//! - End to end: the owner answers the ask its agent opened with
//!   `vault.check_in.open`, and the agent reads the answer back.
//!
//! On the base (P2.3b) this file builds and every case fails at its first
//! answer: no verb row is named `vault.check_in.answer`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_answer_settlements`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;
#[path = "check_in/ladder.rs"]
mod ladder;

use std::collections::BTreeSet;
use std::sync::Arc;

use fixture::{DIGEST, T0};
use ladder::Ladder;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::check_in::{
    ActClass, EligibleBasis, HolderAnswer, OpenPendingCheckIn, PendingState, Rung,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::check_in::consume;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const ANSWER: &str = "vault.check_in.answer";
/// A `member_add` act: an Admin's delegate grant asks its grantor first.
const ADD_MEMBER: &str = "org:add-member";

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `word` over `digest` on the ask `id`.
fn reply(id: &EntityId, word: &str, digest: &[u8; 32]) -> Value {
    json!({ "handle": id.to_hex(), "answer": word, "effect_digest": hex(digest) })
}

fn answered(memory: &Memory<'_>, input: Value) -> Value {
    invoke(memory, ANSWER, input).unwrap_or_else(|error| panic!("{ANSWER} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, input: Value) -> MemoryError {
    invoke(memory, ANSWER, input).expect_err("the answer is refused")
}

fn as_person(l: &Ladder, person: EntityId) -> Memory<'_> {
    l.fx.vault.memory(person, EdgeActorClass::Human)
}

/// The agent's `member_add` ask under its delegate grant, on the first
/// Admin's rung.
fn member_add_ask(l: &Ladder) -> EntityId {
    let row = l.open(l.ask(l.delegate, ActClass::MemberAdd, ADD_MEMBER));
    assert_eq!(
        row.current_rung().expect("a rung").rung,
        Rung::Grantor,
        "the Admin who minted the delegate grant is asked first"
    );
    row.id
}

#[test]
fn a_pinned_holder_approves_once_and_the_settlement_names_them() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    let settled = answered(
        &as_person(&l, l.first_admin.0),
        reply(&id, "approve", &DIGEST),
    );
    assert_eq!(
        settled,
        json!({
            "handle": id.to_hex(), "answer": "approve", "answered_by": l.first_admin.0.to_hex(),
            "rung": "grantor", "answered_at": T0, "proof_kind": "human_confirm",
            "eligible": "approved", "repeat": false,
        })
    );
    assert_eq!(
        l.fx.row(&id).state,
        PendingState::Answered {
            answer: HolderAnswer::Approve,
            by: Some(l.first_admin.0),
            rung: Rung::Grantor,
            at: T0,
        }
    );
    assert_eq!(l.fx.outcomes(&id), ["opened", "climbed", "answered"]);
    assert_eq!(
        consume(&l.fx.vault, &id, &DIGEST).expect("the act runs once"),
        EligibleBasis::Approved
    );
    assert!(
        consume(&l.fx.vault, &id, &DIGEST).is_err(),
        "an approval is spent once"
    );
}

#[test]
fn the_same_answer_again_echoes_the_settlement_and_writes_nothing() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    let admin = as_person(&l, l.first_admin.0);
    let first = answered(&admin, reply(&id, "approve", &DIGEST));
    let receipts = l.fx.outcomes(&id);
    let again = answered(&admin, reply(&id, "approve", &DIGEST));
    let mut echoed = first;
    echoed["repeat"] = json!(true);
    assert_eq!(again, echoed, "one settlement");
    assert_eq!(l.fx.outcomes(&id), receipts, "an echo writes nothing");

    let changed = refused(&admin, reply(&id, "deny", &DIGEST));
    assert_eq!(changed.code, MEMORY_CODE_INVALID_STATE, "{changed:?}");
    assert!(
        changed
            .message
            .contains(&format!("{} answered approve", l.first_admin.0.to_hex())),
        "{changed:?}"
    );
    let elsewhere = refused(&admin, reply(&id, "approve", &[0x6f; 32]));
    assert_eq!(
        elsewhere.code, MEMORY_CODE_INVALID_STATE,
        "the same word over another effect is no echo: {elsewhere:?}"
    );
    assert_eq!(l.fx.outcomes(&id), receipts, "a refusal writes nothing");
}

#[test]
fn another_holder_is_told_who_answered_and_a_stranger_is_told_nobody() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    l.climb(&id);
    let second = as_person(&l, l.second_admin.0);
    let settled = answered(&second, reply(&id, "approve", &DIGEST));
    assert_eq!(
        (settled["rung"].as_str(), settled["answered_by"].as_str()),
        (
            Some("chain_holders"),
            Some(l.second_admin.0.to_hex().as_str())
        ),
        "{settled}"
    );
    let receipts = l.fx.outcomes(&id);
    assert_eq!(receipts, ["opened", "climbed", "climbed", "answered"]);

    let late = refused(
        &as_person(&l, l.first_admin.0),
        reply(&id, "approve", &DIGEST),
    );
    assert_eq!(late.code, MEMORY_CODE_INVALID_STATE, "{late:?}");
    assert!(
        late.message.contains(&format!(
            "the check-in is settled: {} answered approve",
            l.second_admin.0.to_hex()
        )),
        "the grantor the ask asked first reads who answered: {late:?}"
    );
    let stranger = refused(&as_person(&l, l.member.0), reply(&id, "deny", &DIGEST));
    assert_eq!(stranger.code, MEMORY_CODE_FORBIDDEN, "{stranger:?}");
    assert!(
        !stranger.message.contains(&l.second_admin.0.to_hex()),
        "a person the ask never pinned learns nothing: {stranger:?}"
    );
    assert_eq!(l.fx.outcomes(&id), receipts, "refusals write nothing");
}

#[test]
fn a_denial_settles_the_ask_and_makes_nothing_eligible() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    let settled = answered(&as_person(&l, l.first_admin.0), reply(&id, "deny", &DIGEST));
    assert_eq!(
        (
            settled["answer"].as_str(),
            settled["eligible"].clone(),
            settled["proof_kind"].as_str()
        ),
        (Some("deny"), Value::Null, Some("human_confirm")),
        "{settled}"
    );
    assert!(
        consume(&l.fx.vault, &id, &DIGEST).is_err(),
        "a denied act never runs"
    );
    assert_eq!(l.fx.outcomes(&id), ["opened", "climbed", "answered"]);
}

#[test]
fn a_person_not_pinned_now_another_effect_and_an_ended_wait_cannot_answer() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    for person in [l.member.0, l.deputy.0, l.second_admin.0, l.owner.0] {
        let error = refused(&as_person(&l, person), reply(&id, "approve", &DIGEST));
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
        assert!(
            error
                .message
                .contains("only a person pinned on the current rung answers"),
            "{error:?}"
        );
    }
    let admin = as_person(&l, l.first_admin.0);
    let other = refused(&admin, reply(&id, "approve", &[0x6f; 32]));
    assert_eq!(other.code, MEMORY_CODE_FORBIDDEN, "{other:?}");
    assert!(
        other.message.contains("the answer is over another effect"),
        "{other:?}"
    );
    let due = l.fx.row(&id).current_rung().expect("a rung").due_at();
    l.fx.at(due);
    let ended = refused(&admin, reply(&id, "approve", &DIGEST));
    assert_eq!(ended.code, MEMORY_CODE_FORBIDDEN, "{ended:?}");
    assert!(
        ended.message.contains("the rung's wait has ended"),
        "{ended:?}"
    );
    assert_eq!(l.fx.row(&id).state, PendingState::Open);
    assert_eq!(
        l.fx.outcomes(&id),
        ["opened", "climbed"],
        "refusals write nothing"
    );
}

#[test]
fn a_holder_whose_own_check_in_would_wait_is_not_asked_and_cannot_answer() {
    // An Admin's own outbound send always asks, so the ask skips both Admins
    // and pins the Owner.
    let l = Ladder::new();
    let row = l.open(l.ask(l.delegate, ActClass::OutboundSend, "write"));
    let error = refused(
        &as_person(&l, l.first_admin.0),
        reply(&row.id, "approve", &DIGEST),
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    let settled = answered(
        &as_person(&l, l.owner.0),
        reply(&row.id, "approve", &DIGEST),
    );
    assert_eq!(
        (settled["rung"].as_str(), settled["answered_by"].as_str()),
        (Some("owner"), Some(l.owner.0.to_hex().as_str())),
        "{settled}"
    );
}

#[test]
fn an_agent_a_standing_approval_and_a_bad_handle_are_no_answer() {
    let l = Ladder::new();
    let id = member_add_ask(&l);
    for memory in [
        l.fx.vault.memory(l.agent, EdgeActorClass::Agent),
        l.fx.vault.memory(l.agent, EdgeActorClass::Human),
    ] {
        let error = refused(&memory, reply(&id, "approve", &DIGEST));
        assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
        assert!(
            error.message.contains("is a live person's own act"),
            "{error:?}"
        );
    }
    let admin = as_person(&l, l.first_admin.0);
    let standing = refused(&admin, reply(&id, "approve_standing", &DIGEST));
    assert_eq!(standing.code, MEMORY_CODE_BAD_REQUEST, "{standing:?}");
    let short = refused(
        &admin,
        json!({ "handle": "5e5e", "answer": "approve", "effect_digest": hex(&DIGEST) }),
    );
    assert_eq!(short.code, MEMORY_CODE_BAD_REQUEST, "{short:?}");
    assert!(short.message.contains("handle"), "{short:?}");
    let unknown = refused(&admin, reply(&EntityId::now(), "approve", &DIGEST));
    assert_eq!(unknown.code, MEMORY_CODE_NOT_FOUND, "{unknown:?}");
    assert_eq!(l.fx.row(&id).state, PendingState::Open);
    assert_eq!(
        l.fx.outcomes(&id),
        ["opened", "climbed"],
        "nothing was answered"
    );
}

#[test]
fn an_inquirys_check_in_is_answered_only_through_its_own_verb() {
    let l = Ladder::new();
    let row = l.open(OpenPendingCheckIn {
        verb: oneiron::inquiry::INQUIRY_ANSWER_VERB.to_owned(),
        ..l.ask(l.delegate, ActClass::OutboundSend, ADD_MEMBER)
    });
    let pinned = row.current_rung().expect("a rung").holders[0].principal;
    let error = refused(&as_person(&l, pinned), reply(&row.id, "approve", &DIGEST));
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(error.message.contains("vault.inquiry.answer"), "{error:?}");
    assert_eq!(l.fx.row(&row.id).state, PendingState::Open);
}

/// A rooted vault with its install enrolled, so the owner's Grant acts on
/// `ThisInstall` land; its owner, the owner's proof and the folder.
fn rooted() -> (
    Vault,
    EntityId,
    oneiron::consent::AuthenticatedOwner,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(T0).bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (vault, owner, proof, dir)
}

#[test]
fn the_owner_answers_the_ask_its_agent_opened_and_the_agent_reads_it() {
    const SEND: &str = "connector.call";
    let (vault, owner, proof, _dir) = rooted();
    let agent = vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": format!("check-in-answer-{}", agent.to_hex()),
                "desc": "check-in answer fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("the owner creates the agent");
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(
        ["read", SEND]
            .map(str::to_owned)
            .into_iter()
            .collect::<BTreeSet<_>>(),
    );
    mint_agent_grant_as(
        &vault,
        &proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the Grant");
    let me = vault.memory(agent, EdgeActorClass::Agent);
    let ask = json!({ "verb": SEND, "effect_digest": hex(&DIGEST) });
    let opened = invoke(&me, "vault.check_in.open", ask.clone()).expect("open");
    let handle = opened["handle"]["handle"].as_str().expect("a handle");
    assert_eq!(opened["handle"]["rung"].as_str(), Some("grantor"));

    let settled = answered(
        &vault.memory(owner, EdgeActorClass::Human),
        json!({ "handle": handle, "answer": "approve", "effect_digest": hex(&DIGEST) }),
    );
    assert_eq!(
        (
            settled["answered_by"].as_str(),
            settled["rung"].as_str(),
            settled["eligible"].as_str()
        ),
        (
            Some(owner.to_hex().as_str()),
            Some("grantor"),
            Some("approved")
        ),
        "{settled}"
    );
    let seen = invoke(&me, "vault.check_in.preflight", ask.clone()).expect("preflight");
    assert_eq!(
        (
            seen["handle"]["handle"].as_str(),
            seen["handle"]["state"].as_str(),
            seen["handle"]["answer"].as_str(),
            seen["handle"]["eligible"].as_str()
        ),
        (
            Some(handle),
            Some("answered"),
            Some("approve"),
            Some("approved")
        ),
        "the agent reads the answer on its ask: {seen}"
    );
    let again = invoke(&me, "vault.check_in.open", ask).expect("open again");
    assert_eq!(
        (
            again["handle"]["handle"].as_str(),
            again["handle"]["repeat"].as_bool()
        ),
        (Some(handle), Some(true)),
        "the same saved call finds the answered ask: {again}"
    );
}
