//! `vault.projects.goal.propose` (LEARNING-01, row GOAL-REVISION-PROPOSAL; rulings LEARN-GOAL
//! Q1-Q3 = A, LEARN-GOAL-RATE = A) through the verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out. The vault owner,
//! or an agent seated in the project whose live owner Grant lists the verb, proposes a whole goal
//! record against the goal claim and generation in force. The engine stores it with its diff (the
//! relaxed floor named), and `vault.projects.goal.revisions` and `vault.projects.goal.intake` show
//! it; the goal in force never moves. An agent without the Grant, or outside the project, is
//! refused FORBIDDEN; a stale base is refused; the owner dismisses with a reason and the row stays
//! as history. An agent holds one open proposal per base and four a week; the owner passes the
//! seat check and the rate.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_projects_goal_propose`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryResult};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{invoke, project_goal_get_as_owner};
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::steward::{STEWARD_READ_VERB, stand_steward_grant};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const VERB: &str = "vault.projects.goal.propose";

/// The vault clock's fixed time: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

/// The agent rate each agent row records (LEARN-GOAL-RATE = A).
const AGENT_RATE: &str = r#"{"open_per_base":1,"per_window":4,"window_secs":604800}"#;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The root project, with its goal in force.
    project: EntityId,
    /// Seated, reads the goal, holds the owner's Grant listing the verb.
    member: EntityId,
    member_grant: EntityId,
    /// Seated and reads the goal, with no Grant listing the verb.
    ungranted: EntityId,
    /// Holds the Grant and reads the goal, but sits in no seat of the project.
    outsider: EntityId,
}

/// A rooted vault with its install enrolled, its embedded owner and proof, three agents (see
/// [`Fixture`]) and the root project's goal written by the owner's intake. The agents are seated
/// before the goal is written.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
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
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let member = agent(&vault, &owner_proof, "goal-proposal-member");
    let ungranted = agent(&vault, &owner_proof, "goal-proposal-ungranted");
    let outsider = agent(&vault, &owner_proof, "goal-proposal-outsider");
    let member_grant = grant_propose(&vault, &owner_proof, member);
    grant_propose(&vault, &owner_proof, outsider);
    for reader in [member, ungranted, outsider] {
        stand_steward_grant(&vault, reader, &[STEWARD_READ_VERB]).expect("a goal read grant");
    }
    let project = vault.root_project().expect("root project");
    let mut record = vault
        .project(project)
        .expect("project read")
        .expect("root project record");
    record.roster.push(member.to_hex());
    record.roster.push(ungranted.to_hex());
    vault
        .put_project(project, &record, 3)
        .expect("seat the member and the ungranted agent");
    assert_eq!(
        write_root_goal(&vault, &owner_proof).expect("the owner's intake writes the goal"),
        project
    );
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
        project,
        member,
        member_grant,
        ungranted,
        outsider,
    }
}

/// An enabled, active agent definition the owner creates.
fn agent(vault: &Vault, owner_proof: &AuthenticatedOwner, name: &str) -> EntityId {
    let id = vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "goal proposal fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the agent");
    id
}

/// The owner's live Grant listing this verb for `agent`; the grant's row.
/// A Grant confers only with `read` among its verbs (`AgentGrantMintRequest`).
fn grant_propose(vault: &Vault, owner_proof: &AuthenticatedOwner, agent: EntityId) -> EntityId {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the propose Grant");
    assert!(minted.grant.confers, "the propose Grant confers");
    minted.grant.grant_ref
}

/// The goal in force as the owner reads it, under its proof: claim and record.
fn goal_in_force(f: &Fixture) -> Value {
    let view = project_goal_get_as_owner(&f.vault, &f.owner_proof, f.project)
        .expect("the owner reads the goal");
    serde_json::to_value(&view).expect("goal view")
}

/// The base a proposal names now: the goal claim in force and the goal generation.
fn base(f: &Fixture) -> Value {
    json!({
        "goal_claim": goal_in_force(f)["goal_claim"].clone(),
        "generation": f.vault.project_goal_generation(f.project).expect("generation"),
    })
}

/// A proposal on `base` that relaxes the unsafe-answers floor and gives `why`.
fn request(f: &Fixture, base: &Value, why: &str) -> Value {
    let mut proposed = goal_in_force(f)["record"].clone();
    proposed["why"] = json!(why);
    proposed["floor_axes"][0]["bound"] = json!("<= 1");
    json!({
        "project_ref": f.project.to_hex(),
        "base": base,
        "proposed": proposed,
        "reasons": {
            "reason": "Refusing every borderline request costs more than one unsafe answer a week.",
            "merits": ["fewer refused requests"],
            "demerits": ["a held-out unsafe answer may pass"],
            "sacrifice": "the zero floor on unsafe answers",
        },
        "evidence": {
            "attractor_case": f.project.to_hex(),
            "improvement": { "k": 4, "cycles": 3, "receipts": ["receipt:fixture-cycle-1"] },
            "cost_spent": ["fixture-root-launch"],
        },
    })
}

fn call(
    f: &Fixture,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&f.vault.memory(actor, class), verb, input)
}

fn propose(
    f: &Fixture,
    actor: EntityId,
    class: EdgeActorClass,
    input: Value,
) -> MemoryResult<Value> {
    call(f, actor, class, VERB, input)
}

/// `vault.projects.goal.revisions` as the seated member, which reads the goal.
fn revisions(f: &Fixture) -> Value {
    call(
        f,
        f.member,
        EdgeActorClass::Agent,
        "vault.projects.goal.revisions",
        json!({ "project_ref": f.project.to_hex() }),
    )
    .expect("the member reads the goal revisions")
}

/// `vault.projects.goal.intake` as the seated member, a member of the home room.
fn intake(f: &Fixture) -> Value {
    call(
        f,
        f.member,
        EdgeActorClass::Agent,
        "vault.projects.goal.intake",
        json!({ "project_ref": f.project.to_hex() }),
    )
    .expect("the member reads the intake context")
}

fn dismiss(
    f: &Fixture,
    actor: EntityId,
    class: EdgeActorClass,
    proposal: &Value,
    reason: &str,
) -> MemoryResult<Value> {
    call(
        f,
        actor,
        class,
        "vault.projects.goal.dismiss",
        json!({
            "project_ref": f.project.to_hex(),
            "target": { "kind": "proposal", "proposal_ref": proposal["proposal"]["id"].clone(), "reason": reason },
        }),
    )
}

fn assert_code(answer: MemoryResult<Value>, code: &str, what: &str) {
    let error = answer.expect_err(what);
    assert_eq!(error.code, code, "{what}: {error:?}");
}

#[test]
fn owner_proposal_is_stored_with_its_diff_and_the_goal_stays() {
    let f = fixture();
    let before = goal_in_force(&f);
    let base = base(&f);
    let input = request(&f, &base, "Fewer refused requests");

    // The owner sits in no seat of the root project and proposes anyway.
    let answer = propose(&f, f.owner, EdgeActorClass::Human, input.clone())
        .expect("the owner proposes on its own vault");
    assert_eq!(answer["status"], "open");
    let proposal = &answer["proposal"];
    assert_eq!(
        proposal["proposer"],
        json!({ "kind": "owner", "person": f.owner.to_hex() })
    );
    assert_eq!(proposal["base"], base);
    assert_eq!(proposal["proposed"], input["proposed"]);
    assert_eq!(proposal["reasons"], input["reasons"]);
    assert_eq!(proposal["evidence"], input["evidence"]);
    assert_eq!(
        proposal["rate"],
        Value::Null,
        "the owner's proposals carry no rate"
    );
    assert_eq!(proposal["dismissal"], Value::Null);
    let diff = &proposal["diff"];
    assert_eq!(diff["floor_axes"]["changed"][0]["name"], "unsafe_answers");
    assert_eq!(diff["floor_axes"]["changed"][0]["before"]["bound"], "= 0");
    assert_eq!(diff["floor_axes"]["changed"][0]["after"]["bound"], "<= 1");
    assert_eq!(diff["floor_axes"]["removed"], json!([]));
    assert_eq!(
        diff["why"],
        json!({ "before": "Reduce repeat support tickets", "after": "Fewer refused requests" })
    );
    assert_eq!(diff["goal"], Value::Null);
    assert_eq!(
        diff["primary_axes"],
        json!({ "added": [], "removed": [], "changed": [] })
    );

    // An identical repeat returns the first row.
    let again = propose(&f, f.owner, EdgeActorClass::Human, input).expect("an identical repeat");
    assert_eq!(again, answer);

    // The goal in force and its generation did not move.
    assert_eq!(goal_in_force(&f), before);
    assert_eq!(self::base(&f), base);

    // The revisions read and the interview's seed show it, open, on the goal in force.
    let revisions = revisions(&f);
    assert_eq!(revisions["base"], base);
    assert_eq!(revisions["proposals"], json!([answer]));
    assert_eq!(intake(&f)["goal_proposals"], json!([answer]));
}

#[test]
fn member_agent_proposal_names_the_agent_and_its_grant() {
    let f = fixture();
    let before = goal_in_force(&f);
    let base = base(&f);
    let answer = propose(
        &f,
        f.member,
        EdgeActorClass::Agent,
        request(&f, &base, "Fewer refused requests"),
    )
    .expect("a seated agent on its own live Grant proposes");
    assert_eq!(answer["status"], "open");
    assert_eq!(
        answer["proposal"]["proposer"],
        json!({ "kind": "agent", "agent": f.member.to_hex(), "grant": f.member_grant.to_hex() })
    );
    let rate: Value = serde_json::from_str(AGENT_RATE).expect("rate");
    assert_eq!(answer["proposal"]["rate"], rate);
    assert_eq!(goal_in_force(&f), before, "the goal in force did not move");
    assert_eq!(revisions(&f)["proposals"], json!([answer]));
}

#[test]
fn seated_agent_without_the_grant_is_refused() {
    let f = fixture();
    let base = base(&f);
    assert_code(
        propose(
            &f,
            f.ungranted,
            EdgeActorClass::Agent,
            request(&f, &base, "Fewer refused requests"),
        ),
        MEMORY_CODE_FORBIDDEN,
        "a seated agent with no Grant listing the verb is refused",
    );
    assert_eq!(revisions(&f)["proposals"], json!([]), "nothing was stored");
}

#[test]
fn granted_agent_outside_the_project_is_refused() {
    let f = fixture();
    let base = base(&f);
    assert_code(
        propose(
            &f,
            f.outsider,
            EdgeActorClass::Agent,
            request(&f, &base, "Fewer refused requests"),
        ),
        MEMORY_CODE_FORBIDDEN,
        "an agent on its Grant that sits in no seat of the project is refused",
    );
    assert_eq!(revisions(&f)["proposals"], json!([]), "nothing was stored");
}

#[test]
fn stale_base_is_refused() {
    let f = fixture();
    let old = base(&f);
    // A second intake writes a new goal claim and moves the generation.
    write_root_goal(&f.vault, &f.owner_proof).expect("a second intake");
    let now = base(&f);
    assert_ne!(old["goal_claim"], now["goal_claim"]);
    assert_ne!(old["generation"], now["generation"]);
    assert_code(
        propose(
            &f,
            f.owner,
            EdgeActorClass::Human,
            request(&f, &old, "Fewer refused requests"),
        ),
        MEMORY_CODE_INVALID_STATE,
        "a proposal on the goal before the second intake is refused",
    );
    // The claim in force with an earlier generation is stale too.
    let earlier = json!({
        "goal_claim": now["goal_claim"].clone(),
        "generation": now["generation"].as_u64().expect("generation") - 1,
    });
    assert_code(
        propose(
            &f,
            f.member,
            EdgeActorClass::Agent,
            request(&f, &earlier, "Fewer refused requests"),
        ),
        MEMORY_CODE_INVALID_STATE,
        "a proposal on an earlier generation of the claim in force is refused",
    );
    assert_eq!(revisions(&f)["proposals"], json!([]), "nothing was stored");
    assert_eq!(base(&f), now, "the goal in force did not move");
}

#[test]
fn dismissal_keeps_the_proposal_as_history() {
    let f = fixture();
    let before = goal_in_force(&f);
    let base = base(&f);
    let input = request(&f, &base, "Fewer refused requests");
    let answer = propose(&f, f.member, EdgeActorClass::Agent, input.clone()).expect("a proposal");

    assert_code(
        dismiss(
            &f,
            f.member,
            EdgeActorClass::Agent,
            &answer,
            "not mine to dismiss",
        ),
        MEMORY_CODE_FORBIDDEN,
        "an agent does not dismiss a proposal",
    );
    let reason = "The zero floor on unsafe answers stays.";
    assert_eq!(
        dismiss(&f, f.owner, EdgeActorClass::Human, &answer, reason).expect("the owner dismisses"),
        json!({ "dismissed": true })
    );
    assert_eq!(
        dismiss(
            &f,
            f.owner,
            EdgeActorClass::Human,
            &answer,
            "a second reason"
        )
        .expect("a repeat dismissal"),
        json!({ "dismissed": false }),
        "the first outcome stands"
    );

    let listed = revisions(&f)["proposals"].clone();
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(1),
        "the row stays as history"
    );
    let kept = &listed[0];
    assert_eq!(kept["status"], "dismissed");
    assert_eq!(kept["proposal"]["dismissal"]["reason"], reason);
    assert_eq!(kept["proposal"]["dismissal"]["person"], f.owner.to_hex());
    for field in [
        "id",
        "base",
        "proposed",
        "proposer",
        "reasons",
        "evidence",
        "diff",
        "created_at",
    ] {
        assert_eq!(
            kept["proposal"][field], answer["proposal"][field],
            "{field} is kept"
        );
    }
    assert_eq!(
        intake(&f)["goal_proposals"],
        json!([]),
        "the interview no longer shows it"
    );

    // The same proposal again returns the dismissed row; it never reopens.
    let again = propose(&f, f.member, EdgeActorClass::Agent, input).expect("an identical repeat");
    assert_eq!(again, *kept);
    assert_eq!(goal_in_force(&f), before, "the goal in force did not move");
}

#[test]
fn agent_holds_one_open_proposal_per_base_and_four_a_week() {
    let f = fixture();
    let base = base(&f);
    let first = propose(&f, f.member, EdgeActorClass::Agent, request(&f, &base, "A"))
        .expect("the agent's first proposal");
    assert_code(
        propose(&f, f.member, EdgeActorClass::Agent, request(&f, &base, "B")),
        MEMORY_CODE_INVALID_STATE,
        "a second open proposal on the same base is refused",
    );
    assert_eq!(
        propose(&f, f.member, EdgeActorClass::Agent, request(&f, &base, "A"))
            .expect("an identical repeat counts nothing"),
        first
    );

    // The owner passes the rate: two open proposals on one base.
    propose(
        &f,
        f.owner,
        EdgeActorClass::Human,
        request(&f, &base, "Owner one"),
    )
    .expect("the owner's first");
    propose(
        &f,
        f.owner,
        EdgeActorClass::Human,
        request(&f, &base, "Owner two"),
    )
    .expect("the owner's second");

    // Each dismissal frees the open place; dismissed rows still count in the week.
    dismiss(&f, f.owner, EdgeActorClass::Human, &first, "no").expect("dismiss the first");
    for why in ["B1", "B2", "B3"] {
        let next = propose(&f, f.member, EdgeActorClass::Agent, request(&f, &base, why))
            .expect("a proposal while the week has room");
        dismiss(&f, f.owner, EdgeActorClass::Human, &next, "no").expect("dismiss it");
    }
    assert_code(
        propose(&f, f.member, EdgeActorClass::Agent, request(&f, &base, "E")),
        MEMORY_CODE_INVALID_STATE,
        "a fifth proposal in seven days is refused",
    );
    assert_eq!(
        revisions(&f)["proposals"].as_array().map(Vec::len),
        Some(6),
        "four of the agent's and two of the owner's"
    );
}
