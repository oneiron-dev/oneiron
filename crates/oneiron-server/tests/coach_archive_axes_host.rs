//! The host's Coach answers an output-archive axes request (ARM05 P2): the
//! owner queues it with `vault.research.archive.propose_axes`, one Coach host
//! round, as the nightly worker runs it, leases the `coach.archive_axes` job
//! and runs the recipe on the Coach's model seat (here the fake model, the
//! chat seat the Coach falls back to), and `vault.research.archive.proposal`
//! reads back the proposal the engine recorded under the Coach's authority,
//! which install accepts.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! coach_archive_axes_host`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/eval_authoring_fixture.rs"]
mod eval_authoring_fixture;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;

use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use eval_authoring_fixture::Fixture;
use fake_llm::Reply;
use oneiron::autoreason_campaign::archive::{
    ArchiveAxesMethod, ArchiveDescriptor, ArchiveOutputRef, ArchiveQualityMetric,
    CampaignArchiveInstall, CampaignArchiveProposalRequest, CampaignArchiveProposalState,
    CampaignArchiveProposeAxes,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{
    research_archive_install, research_archive_proposal, research_archive_propose_axes,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Words only the axes recipe's System message holds.
const RECIPE_MARK: &str = "axes of one task's output archive";

/// The fake model: the axes recipe's call gets two axes; any other call of
/// the round gets an empty object.
fn recipe_reply() -> Reply {
    Reply::Computed(Arc::new(|request: &Value| {
        if request["messages"][0].to_string().contains(RECIPE_MARK) {
            json!({ "axes": [
                { "name": "tone", "bins": ["formal", "casual"] },
                { "name": "length", "bins": ["short", "long"] },
            ]})
            .to_string()
        } else {
            "{}".to_owned()
        }
    }))
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault.memory(owner, EdgeActorClass::Human)
}

/// The owner's root-project goal: the project and its goal claim.
fn goal(vault: &Vault) -> (EntityId, EntityId) {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof: AuthenticatedOwner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let project = write_root_goal(vault, &proof).expect("the owner's goal");
    let goal_ref = EntityId::from_hex(
        vault
            .project(project)
            .expect("project read")
            .expect("root project")
            .goal
            .as_deref()
            .expect("goal claim pointer"),
    )
    .expect("goal claim id");
    (project, goal_ref)
}

/// The seeded judge skill at its stored package's canonical tree hash.
fn judge_ruler(vault: &Vault) -> ArchiveQualityMetric {
    let rubric = oneiron::skill_optimize::judge_rubric(vault)
        .expect("judge rubric read")
        .expect("a fresh vault seeds the judge");
    let record = vault
        .get_skill_record(&rubric.skill)
        .expect("judge record read")
        .expect("judge record");
    ArchiveQualityMetric {
        metric_id: rubric.skill.to_hex(),
        revision: record
            .content_hash
            .expect("the seeded judge names its package")
            .to_hex(),
    }
}

/// A config campaign over a fresh root, as `verb_vault_research_create_root`
/// binds one.
fn bound_root(vault: &Vault, agent: EntityId) -> EntityId {
    let owner = owner_memory(vault);
    let created = invoke(
        &owner,
        "vault.research.create_root",
        json!({
            "agent": agent.to_hex(),
            "intent_key": "archive-axes-host",
            "briefing": "Search the parameter axis for a better quality score.",
        }),
    )
    .expect("the owner creates a root");
    let root_hex = created["root"].as_str().expect("root").to_owned();
    let incumbent: &[u8] = br#"{"parameter":"baseline"}"#;
    let digest: String = Sha256::digest(incumbent)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    invoke(
        &owner,
        "vault.research.bind",
        json!({
            "root": root_hex,
            "config": {
                "campaign_id": "archive-axes-host",
                "search_axes": [{ "name": "parameter", "values": ["baseline", "alternative"] }],
                "metric_set": {
                    "set_id": "fixture-quality",
                    "revision": "r1",
                    "axes": [{ "name": "quality", "direction": "higher", "role": "primary" }],
                },
                "splits": {
                    "search": { "dataset_id": "fixture-search", "revision": "r1" },
                    "held_out": { "dataset_id": "fixture-held-out", "revision": "r1" },
                    "sealed": { "dataset_id": "fixture-sealed", "revision": "r1" },
                },
                "budget": { "budget_id": "fixture-lease", "max_units": 100, "exploration_units": 10 },
                "decide": { "kind": "dominance" },
            },
            "target": { "config": { "subject": "archive-axes-host" } },
            "holder": null,
            "confirmation": null,
            "share": null,
            "incumbent": { "config_ref": "fixture-config:baseline", "config_sha256": digest },
            "prior_ladder": [],
            "execution": null,
        }),
    )
    .expect("the owner binds the root");
    EntityId::from_hex(&root_hex).expect("root id")
}

fn task(vault: &Vault, agent: EntityId) -> EntityId {
    let receipt = invoke(
        &owner_memory(vault),
        "tasks.create",
        json!({
            "spec": { "summary": "answer the customer's request" },
            "assignee": { "child": { "actor_ref": agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    serde_json::from_value(receipt["task_ref"].clone()).expect("task id")
}

/// An owner-uploaded ARTIFACT at its first retained version's content hash.
fn artifact(vault: &Vault, name: &str, body: &str) -> ArchiveOutputRef {
    let view: Value = invoke(
        &owner_memory(vault),
        "vault.artifacts.create",
        json!({
            "name": name,
            "media_type": "text/plain",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        }),
    )
    .expect("the owner uploads an artifact");
    ArchiveOutputRef {
        entity: serde_json::from_value(view["artifact_id"].clone()).expect("artifact id"),
        revision: view["versions"][0]["content_hash"]
            .as_str()
            .expect("version hash")
            .to_owned(),
    }
}

/// One Coach host round, as the nightly worker runs it.
async fn coach_round(fixture: &Fixture) {
    let server = Arc::clone(&fixture.server);
    tokio::task::spawn_blocking(move || {
        oneiron_server::test_doors::coach_round::coach_host_round(&server)
    })
    .await
    .expect("the round thread")
    .expect("the Coach round");
}

#[test]
fn the_host_coach_answers_an_axes_request_on_its_seat() {
    run_on_engine_stack("archive-axes-host", || async {
        let fixture = Fixture::new(None, vec![], Some(recipe_reply())).await;
        let vault = &fixture.vault;
        let (project, goal_ref) = goal(vault);
        let agent = define_agent(vault, "archive-axes-host-target").expect("the root's agent");
        let root = bound_root(vault, agent);
        let task = task(vault, agent);
        let samples = vec![
            artifact(vault, "a.txt", "a formal, short answer"),
            artifact(vault, "b.txt", "a casual, long answer"),
        ];
        let ruler = judge_ruler(vault);
        let request = research_archive_propose_axes(
            &owner_memory(vault),
            CampaignArchiveProposeAxes::First {
                root,
                task,
                project,
                goal_ref,
                quality_metric: ruler.clone(),
                sample_outputs: samples.clone(),
            },
        )
        .expect("the owner queues the request")
        .request;

        // A round runs up to four jobs; the axes job may follow other work
        // the round queues itself.
        let mut state = CampaignArchiveProposalState::Pending;
        for _ in 0..3 {
            coach_round(&fixture).await;
            state = research_archive_proposal(
                &owner_memory(vault),
                CampaignArchiveProposalRequest { request },
            )
            .expect("the owner reads the request's state");
            if state != CampaignArchiveProposalState::Pending {
                break;
            }
        }
        let recipe_calls = fixture
            .model
            .seen()
            .iter()
            .filter(|call| call.body["messages"][0].to_string().contains(RECIPE_MARK))
            .count();
        assert_eq!(recipe_calls, 1, "the recipe ran once on the Coach's seat");
        let CampaignArchiveProposalState::Proposed { proposal, method } = state else {
            panic!("the Coach proposed: {state:?}");
        };
        let ArchiveAxesMethod::CoachRecipe {
            recipe_revision,
            model,
        } = &method
        else {
            panic!("the recipe answered, not {method:?}");
        };
        assert_eq!(recipe_revision.len(), 64, "the recipe wording's BLAKE3 hex");
        assert!(!model.is_empty(), "the answering model is named");
        assert!(
            matches!(&proposal.descriptor, ArchiveDescriptor::Axes { axes } if axes.len() == 2),
            "{:?}",
            proposal.descriptor
        );
        research_archive_install(
            &owner_memory(vault),
            CampaignArchiveInstall {
                root,
                task,
                project,
                goal_ref,
                quality_metric: ruler,
                sample_outputs: samples,
                proposal,
            },
        )
        .expect("install accepts the Coach's proposal");
        fixture.finish().await;
    });
}
