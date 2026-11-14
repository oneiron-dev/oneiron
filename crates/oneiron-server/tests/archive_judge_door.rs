//! The output archive's judge door (ARM05 P3): the owner calls
//! `vault.research.archive.judge` over the real facade route, and the host's
//! decision ladder, its Big rung bound to the fake model, answers one typed
//! choice per pinned axis and the quality score on the owner's line. The
//! engine records the placement and score, and `vault.research.archive.record`
//! accepts them. A score the rung cannot read abstains: the door refuses with
//! the reason and records nothing.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! archive_judge_door`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/eval_authoring_fixture.rs"]
mod eval_authoring_fixture;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use eval_authoring_fixture::Fixture;
use fake_llm::Reply;
use oneiron::autoreason_campaign::archive::{
    ArchiveAxesMethod, ArchiveAxesMint, ArchiveAxis, ArchiveDescriptor, ArchiveOutputRef,
    ArchiveQualityMetric, CampaignArchiveInstall, mint_archive_axes,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::archive_producers::archive_producer_records;
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::research_archive_install;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VERB: &str = "vault.research.archive.judge";
const RECORD_VERB: &str = "vault.research.archive.record";

/// The Big rung on the checker seat, the fake model's.
const BIG_RUNG: &str = "[roles.checker]\nmodel = \"local:test-checker\"\n\
[decisions.big]\nrole = \"checker\"\nversion = \"archive-judge-test\"\n\
wording = \"You answer one typed question about the state you are given.\"\nreply = \"json\"\n";

/// What the Big rung's call says for each question (`big_rung.rs`
/// `contract_line`).
const TONE: &str = "Answer with exactly one of: formal, casual.";
const LENGTH: &str = "Answer with exactly one of: short, long.";
const SCORE: &str = "Answer with one number from 0 to 1.";

/// The fake model as the Big rung: each placement gets its bin and the score
/// 0.8, all sure; while `unreadable` holds, the score gets words the rung
/// cannot read, so it abstains.
fn ladder_reply(unreadable: Arc<AtomicBool>) -> Reply {
    Reply::Computed(Arc::new(move |request: &Value| {
        let text = request.to_string();
        if text.contains(TONE) {
            json!({ "answer": "formal", "probability": 0.99 }).to_string()
        } else if text.contains(LENGTH) {
            json!({ "answer": "short", "probability": 0.99 }).to_string()
        } else if text.contains(SCORE) {
            if unreadable.load(Ordering::SeqCst) {
                "I would rather not say.".to_owned()
            } else {
                json!({ "answer": 0.8, "probability": 0.99 }).to_string()
            }
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
            "intent_key": "archive-judge-door",
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
                "campaign_id": "archive-judge-door",
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
            "target": { "config": { "subject": "archive-judge-door" } },
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

/// An archive over the tone and length axes, installed from the engine's
/// own axes record: its root and descriptor revision.
fn installed(vault: &Vault) -> (EntityId, String) {
    let (project, goal_ref) = goal(vault);
    let agent = define_agent(vault, "archive-judge-door-target").expect("the root's agent");
    let root = bound_root(vault, agent);
    let task = task(vault, agent);
    let samples = vec![
        artifact(vault, "a.txt", "a formal, short answer"),
        artifact(vault, "b.txt", "a casual, long answer"),
    ];
    let ruler = judge_ruler(vault);
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proposal = mint_archive_axes(
        vault,
        ArchiveAxesMint {
            root,
            from: None,
            task,
            project,
            goal_ref,
            quality_metric: ruler.clone(),
            sample_outputs: samples.clone(),
            descriptor: ArchiveDescriptor::Axes {
                axes: vec![
                    ArchiveAxis {
                        name: "tone".into(),
                        bins: vec!["formal".into(), "casual".into()],
                    },
                    ArchiveAxis {
                        name: "length".into(),
                        bins: vec!["short".into(), "long".into()],
                    },
                ],
            },
            producer: owner,
            method: ArchiveAxesMethod::CoachRecipe {
                recipe_revision: "fixture-recipe".into(),
                model: "fixture-model".into(),
            },
        },
    )
    .expect("the engine's axes record");
    let view = research_archive_install(
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
    .expect("install");
    (root, view.descriptor_revision)
}

/// The fake model's calls that carried `line`.
fn calls_with(fixture: &Fixture, line: &str) -> usize {
    fixture
        .model
        .seen()
        .iter()
        .filter(|call| call.body.to_string().contains(line))
        .count()
}

#[test]
fn the_owner_judges_an_output_on_the_hosts_ladder() {
    run_on_engine_stack("archive-judge-door", || async {
        let unreadable = Arc::new(AtomicBool::new(true));
        let fixture = Fixture::with_models(
            None,
            vec![],
            Some(ladder_reply(Arc::clone(&unreadable))),
            BIG_RUNG,
        )
        .await;
        let vault = &fixture.vault;
        let (root, revision) = installed(vault);
        let output = artifact(vault, "output.txt", "a formal, short reply to the customer");
        let request = json!({
            "root": root.to_hex(),
            "descriptor_revision": revision,
            "output": output,
        });
        let before = archive_producer_records(vault).expect("producer records");

        // The score's reply is unreadable: the rung abstains and nothing is kept.
        let (status, refused) = fixture.as_owner(VERB, request.clone()).await;
        assert_ne!(status, StatusCode::OK, "an unanswered score: {refused}");
        let refused = refused.to_string();
        assert!(
            refused.contains("recorded nothing") && refused.contains("the quality score"),
            "refused with its reason: {refused}"
        );
        assert_eq!(
            archive_producer_records(vault).expect("producer records"),
            before,
            "a refused judgment records nothing"
        );

        // Every answer sure: the placement and score records, which record takes.
        unreadable.store(false, Ordering::SeqCst);
        let (status, judged) = fixture.as_owner(VERB, request).await;
        assert_eq!(status, StatusCode::OK, "the owner's judgment: {judged}");
        assert_eq!(calls_with(&fixture, TONE), 2, "one tone question per call");
        assert_eq!(
            calls_with(&fixture, LENGTH),
            2,
            "one length question per call"
        );
        assert_eq!(
            calls_with(&fixture, SCORE),
            2,
            "one score question per call"
        );
        assert_eq!(
            archive_producer_records(vault).expect("producer records"),
            before + 2,
            "one placement and one score record"
        );
        assert_eq!(judged["placement"]["kind"], "judgment", "{judged}");
        assert_eq!(
            judged["placement"]["judgment"]["cell"],
            json!({ "kind": "axes", "bins": ["formal", "short"] }),
            "{judged}"
        );
        assert_eq!(judged["score"]["quality"], 0.8, "{judged}");
        let (status, view) = fixture
            .as_owner(
                RECORD_VERB,
                json!({
                    "root": root.to_hex(),
                    "descriptor_revision": revision,
                    "placement": judged["placement"],
                    "score": judged["score"],
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "record takes the judge's receipts: {view}"
        );
        assert_eq!(view["best"][0]["output"], json!(output), "{view}");
        assert_eq!(
            view["best"][0]["placement_receipt"], judged["placement"]["judgment"]["receipt"],
            "{view}"
        );
        fixture.finish().await;
    });
}
