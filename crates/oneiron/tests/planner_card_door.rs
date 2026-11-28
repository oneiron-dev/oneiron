//! `vault.planner.card` (design pass 32 section 5, row 12; tests T24, T25):
//! the planner card of one project and task type as a read door.
//!
//! - T24: the door reads and writes nothing. No write transaction commits
//!   across the owner's reads or a granted agent's read through the engine
//!   door (LMDB's last committed transaction id is unchanged, which holds
//!   every table's rows as they were), and two reads of one card answer one
//!   digest, the agent's verb call the same.
//! - T25: an agent without a Grant that lists the verb is refused FORBIDDEN;
//!   once the owner's Grant lists it, the same call answers the owner's card.
//! - T26 (review-10395 P1): the card lists the rows it was read from, so a
//!   host can withhold it from a destination one of them is kept from: a
//!   project team receipt's fact and outcome sources reach the handle's
//!   producer listing.
//!
//! The owner reads through the engine door under its own proof; the agent
//! calls the verb by name through the SDK, as a code-mode or SDK caller does.
//! On the base the verb is unknown, so both tests fail there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test planner_card_door`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::learning_evidence::Anchor;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult, ProducerRows};
use oneiron::task_verb::sdk::invoke;
use oneiron::team::pattern::{TeamAxis, TeamPattern};
use oneiron::team::planner_card_door::{
    PLANNER_CARD_VERB, PlannerCardRequest, PlannerCardView, planner_card_as, planner_card_as_owner,
};
use oneiron::team::receipt::{
    DecidedBy, TeamOutcome, TeamReceipt, TeamShape, record_team_receipt_sourced,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::store_writes::last_committed_write;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::Value;

/// The host's clock at every read: no line is set, so no read depends on it.
const NOW_MS: u64 = 1_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (_, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    Fixture {
        vault,
        _dir: dir,
        owner_proof,
    }
}

/// The card of a family project at the root of its tree in force, for one
/// runner model.
fn card_request(vault: &Vault, project: EntityId) -> PlannerCardRequest {
    let tree = oneiron::task_type::type_tree(vault, Some(project)).expect("the tree in force");
    PlannerCardRequest {
        project_ref: project.to_hex(),
        type_ref: tree.root(),
        models: vec!["muse-spark-1.3".to_owned()],
        cursor: None,
    }
}

fn owner_card(fixture: &Fixture, input: &PlannerCardRequest) -> PlannerCardView {
    planner_card_as_owner(&fixture.vault, &fixture.owner_proof, input, NOW_MS)
        .unwrap_or_else(|error| panic!("the owner reads the card of {input:?}: {error:?}"))
}

fn agent_card(
    fixture: &Fixture,
    agent: EntityId,
    input: &PlannerCardRequest,
) -> MemoryResult<Value> {
    invoke(
        &fixture.vault.memory(agent, EdgeActorClass::Agent),
        PLANNER_CARD_VERB,
        serde_json::to_value(input).expect("the card request encodes"),
    )
}

/// The owner's Grant naming `agent` and listing `verbs`. A Grant confers
/// only with `read` among its verbs (`AgentGrantMintRequest`).
fn mint(fixture: &Fixture, agent: EntityId, verbs: &[&str]) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(
        std::iter::once("read")
            .chain(verbs.iter().copied())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
    );
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the agent a Grant");
    assert!(
        minted.grant.confers,
        "agent={agent:?} verbs={verbs:?}; expected the owner's Grant to confer; seen {minted:?}"
    );
}

fn assert_forbidden(seen: MemoryResult<Value>, why: &str) {
    match seen {
        Err(error) => assert_eq!(
            error.code, MEMORY_CODE_FORBIDDEN,
            "{why}; expected FORBIDDEN; seen {error:?}"
        ),
        Ok(view) => panic!("{why}; expected FORBIDDEN; seen admitted {view}"),
    }
}

/// T24: the door reads and writes nothing, and one card answers one digest.
#[test]
fn the_planner_card_door_reads_and_writes_nothing() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("planner-card-reader")
        .expect("named agent principal");
    mint(&fixture, agent, &[PLANNER_CARD_VERB]);
    let input = card_request(&fixture.vault, EntityId::now());

    let before = last_committed_write(&fixture.vault);
    let first = owner_card(&fixture, &input);
    let second = owner_card(&fixture, &input);
    let by_agent_door = planner_card_as(
        &fixture.vault.memory(agent, EdgeActorClass::Agent),
        None,
        &input,
        NOW_MS,
    )
    .unwrap_or_else(|error| panic!("the granted agent reads the card: {error:?}"));
    let after = last_committed_write(&fixture.vault);
    assert_eq!(
        before, after,
        "expected no write transaction to commit across two owner reads and one agent read; last committed id went {before} -> {after}"
    );

    let by_agent = agent_card(&fixture, agent, &input)
        .unwrap_or_else(|error| panic!("the granted agent calls the verb: {error:?}"));
    assert_eq!(
        by_agent_door, first,
        "expected the agent's read to answer the owner's card"
    );
    assert_eq!(
        first.digest.len(),
        64,
        "expected a 64-digit lower-hex content hash; seen {first:?}"
    );
    assert_eq!(
        first, second,
        "expected two reads of one card to answer the same card and digest"
    );
    assert_eq!(
        by_agent["digest"].as_str(),
        Some(first.digest.as_str()),
        "expected the agent's call to answer the owner's card digest; seen {by_agent}"
    );
    assert_eq!(
        (first.project_ref.as_str(), &first.type_ref),
        (input.project_ref.as_str(), &input.type_ref),
        "expected the card to name the project and type asked; seen {first:?}"
    );
}

/// T25: an agent without the Grant is refused the card; with it, the same
/// call answers.
#[test]
fn an_agent_without_the_grant_is_refused_the_card() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("planner-card-asker")
        .expect("named agent principal");
    let input = card_request(&fixture.vault, EntityId::now());

    assert_forbidden(
        agent_card(&fixture, agent, &input),
        &format!("actor=agent {agent:?} with no Grant"),
    );

    // A Grant that lists other verbs gives no standing for this one.
    mint(&fixture, agent, &["vault.gpu.jobs.list"]);
    assert_forbidden(
        agent_card(&fixture, agent, &input),
        &format!("actor=agent {agent:?} whose Grant lists another verb"),
    );

    let other = fixture
        .vault
        .ensure_agent_principal("planner-card-reader")
        .expect("named agent principal");
    mint(&fixture, other, &[PLANNER_CARD_VERB]);
    let answer = agent_card(&fixture, other, &input).unwrap_or_else(|error| {
        panic!("actor=agent {other:?} whose Grant lists {PLANNER_CARD_VERB}: expected the card; seen {error:?}")
    });
    let owner = owner_card(&fixture, &input);
    assert_eq!(
        answer["digest"].as_str(),
        Some(owner.digest.as_str()),
        "expected the granted agent to read the owner's card; seen {answer}"
    );
}

/// T26: the card lists the rows it was read from. A settled team receipt of
/// the card's project names the rows its facts and its outcome were read
/// from; the agent's read hands both to the handle's producer listing.
#[test]
fn the_card_lists_the_rows_it_was_read_from() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("planner-card-reader")
        .expect("named agent principal");
    mint(&fixture, agent, &[PLANNER_CARD_VERB]);
    let project = EntityId::now();
    let input = card_request(&fixture.vault, project);
    let (fact_source, deliverable) = (EntityId::now(), EntityId::now());
    let receipt = TeamReceipt {
        team_ref: "planner-card-sourced-team".to_owned(),
        project: Some(project),
        type_ref: input.type_ref.clone(),
        pattern: TeamPattern::Solo,
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models: input.models.clone(),
        shape: TeamShape {
            width: 1,
            roles: BTreeMap::from([("solo".to_owned(), 1)]),
        },
        decided_by: DecidedBy::Leader { actor: agent },
        coverage: None,
        confessions: None,
        spend: None,
        spend_cap: None,
        elapsed_secs: 60,
        calls: None,
        outcome: Some(TeamOutcome {
            receipt: "planner-card-sourced-outcome".to_owned(),
            anchor: Anchor::OwnerVerdict,
            success: true,
            at: 1,
            critics: None,
        }),
        at: 1,
    };
    record_team_receipt_sourced(
        &fixture.vault,
        &receipt,
        Some(vec![fact_source]),
        Some(vec![deliverable]),
    )
    .expect("the sourced team receipt is recorded");

    let producers = ProducerRows::default();
    let card = planner_card_as(
        &fixture
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .listing_producers(&producers),
        None,
        &input,
        NOW_MS,
    )
    .unwrap_or_else(|error| panic!("the granted agent reads the card: {error:?}"));
    assert_eq!(
        card.payoff_rows.iter().map(|row| row.wins).sum::<u64>(),
        1,
        "expected the card to fold the project's one settled run; seen {card:?}"
    );
    let listed = producers.take();
    for (row, what) in [(fact_source, "fact"), (deliverable, "outcome")] {
        assert!(
            listed.contains(&row),
            "expected the card's producer listing to name the receipt's {what} source {row:?}; seen {listed:?}"
        );
    }
}
