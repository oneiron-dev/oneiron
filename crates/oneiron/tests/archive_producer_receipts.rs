//! The output archive's receipts resolve to engine-minted producer records
//! (FIX ARCHIVE-RECEIPT-UNVERIFIED; RULINGS ARM05-PRODUCERS 13 Nov 21:30 and
//! ARCHIVE-QUALITY-RULER 13 Nov 22:47). `vault.research.archive.install`,
//! `.repropose` and `.record` refuse a receipt the engine never recorded, one of
//! another kind, and one bound to another task, sample set, descriptor, output,
//! cell, quality or campaign. The quality metric names a judge SKILL at its
//! stored package's tree hash, and an output ref names a revision its entity
//! holds. Each refusal is followed by the engine's own receipt being accepted
//! on the same campaign, so a refusal is never a broken fixture.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_producer_receipts`.
#![cfg(oneiron_test_support)]

use std::fmt::Debug;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::authority::MachineRole;
use oneiron::autoreason_campaign::archive::{
    ArchiveAxesMethod, ArchiveAxesMint, ArchiveAxesProposal, ArchiveAxis, ArchiveCell,
    ArchiveCellJudgment, ArchiveDescriptor, ArchiveOutputRef, ArchiveOutputScore,
    ArchivePlacementBasis, ArchiveQualityMetric, CampaignArchiveInstall, CampaignArchiveOutput,
    CampaignArchivePlacement, CampaignArchiveReproposal, CampaignArchiveView, mint_archive_axes,
    mint_archive_placement, mint_archive_score,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
};
use oneiron::memory::Memory;
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::write_root_goal;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::skill_package::land_active_skill_with_files;
use oneiron::verbs::{
    research_archive_install, research_archive_record, research_archive_repropose,
};
use oneiron::{ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    project: EntityId,
    goal_ref: EntityId,
    agent: EntityId,
    ruler: ArchiveQualityMetric,
}

/// A rooted vault (the five-step install, as `verb_vault_research_create_root`
/// opens it), the owner's authenticated root-project goal, the root's agent and
/// the seeded judge's ruler.
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
    let owner_proof: AuthenticatedOwner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("the owner's goal");
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
    let agent = define_agent(&vault, "archive-research-target").expect("the root's agent");
    let ruler = judge_ruler(&vault);
    Fixture {
        vault,
        _dir: dir,
        owner,
        project,
        goal_ref,
        agent,
        ruler,
    }
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

fn owner_memory(f: &Fixture) -> Memory<'_> {
    f.vault.memory(f.owner, EdgeActorClass::Human)
}

/// A config campaign over a fresh root, as `verb_vault_research_create_root`
/// binds one, under `campaign_id`.
fn bound_root(f: &Fixture, intent_key: &str, campaign_id: &str) -> EntityId {
    let owner = owner_memory(f);
    let created = invoke(
        &owner,
        "vault.research.create_root",
        json!({
            "agent": f.agent.to_hex(),
            "intent_key": intent_key,
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
                "campaign_id": campaign_id,
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
            "target": { "config": { "subject": campaign_id } },
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

fn task(f: &Fixture, summary: &str) -> EntityId {
    let receipt = invoke(
        &owner_memory(f),
        "tasks.create",
        json!({
            "spec": { "summary": summary },
            "assignee": { "child": { "actor_ref": f.agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    serde_json::from_value(receipt["task_ref"].clone()).expect("task id")
}

/// An owner-uploaded ARTIFACT at its first retained version's content hash.
fn artifact(f: &Fixture, name: &str, body: &str) -> ArchiveOutputRef {
    let view: Value = invoke(
        &owner_memory(f),
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

fn descriptor() -> ArchiveDescriptor {
    ArchiveDescriptor::Axes {
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
    }
}

fn mint_axes(
    f: &Fixture,
    root: EntityId,
    from: Option<EntityId>,
    task: EntityId,
    ruler: &ArchiveQualityMetric,
    samples: &[ArchiveOutputRef],
) -> Result<ArchiveAxesProposal, String> {
    mint_archive_axes(
        &f.vault,
        ArchiveAxesMint {
            root,
            from,
            task,
            project: f.project,
            goal_ref: f.goal_ref,
            quality_metric: ruler.clone(),
            sample_outputs: samples.to_vec(),
            descriptor: descriptor(),
            producer: f.owner,
            method: ArchiveAxesMethod::CoachRecipe {
                recipe_revision: "fixture-recipe".into(),
                model: "fixture-model".into(),
            },
        },
    )
    .map_err(|error| format!("{error:?}"))
}

fn install(
    f: &Fixture,
    root: EntityId,
    task: EntityId,
    ruler: &ArchiveQualityMetric,
    samples: &[ArchiveOutputRef],
    proposal: ArchiveAxesProposal,
) -> Result<CampaignArchiveView, String> {
    research_archive_install(
        &owner_memory(f),
        CampaignArchiveInstall {
            root,
            task,
            project: f.project,
            goal_ref: f.goal_ref,
            quality_metric: ruler.clone(),
            sample_outputs: samples.to_vec(),
            proposal,
        },
    )
    .map_err(|error| format!("{error:?}"))
}

/// A typed decision as the decision ladder returns one, on the Big rung.
fn decision(f: &Fixture, answer: DecisionAnswer) -> TypedDecision {
    TypedDecision {
        answer,
        probability: Some(0.99),
        evidence: Vec::new(),
        in_band: true,
        receipt: DecisionReceipt {
            question: EntityId::derive(b"archive-fixture", &[b"question".as_slice()])
                .expect("question id"),
            question_version: 1,
            principal: f.owner,
            providers: vec![ProviderPin {
                rung: DecisionRung::Big,
                model: "fixture-model".into(),
                version: "1".into(),
            }],
            band: DecisionBand {
                low: 0.35,
                high: 0.65,
            },
            band_version: 0,
            evidence_versions: Vec::new(),
            cost_per_thousand: None,
            paired: Vec::new(),
            person: Vec::new(),
            time: None,
            images: Vec::new(),
            think_row: None,
            person_row: None,
            rule: None,
            asked: None,
            state_cut: None,
        },
        human_ask: None,
    }
}

fn judgment(placement: CampaignArchivePlacement) -> ArchiveCellJudgment {
    match placement {
        CampaignArchivePlacement::Judgment { judgment } => judgment,
        other => panic!("a typed placement, not {other:?}"),
    }
}

fn place(
    f: &Fixture,
    root: EntityId,
    revision: &str,
    output: &ArchiveOutputRef,
    bins: [&str; 2],
) -> Result<ArchiveCellJudgment, String> {
    mint_archive_placement(
        &f.vault,
        root,
        revision,
        output.clone(),
        ArchivePlacementBasis::Judgment {
            decisions: bins
                .iter()
                .map(|bin| decision(f, DecisionAnswer::Choice((*bin).into())))
                .collect(),
        },
        f.owner,
    )
    .map(judgment)
    .map_err(|error| format!("{error:?}"))
}

fn score(
    f: &Fixture,
    root: EntityId,
    revision: &str,
    output: &ArchiveOutputRef,
    quality: f64,
) -> Result<ArchiveOutputScore, String> {
    mint_archive_score(
        &f.vault,
        root,
        revision,
        output.clone(),
        decision(f, DecisionAnswer::Score(quality)),
        f.owner,
    )
    .map_err(|error| format!("{error:?}"))
}

fn record(
    f: &Fixture,
    root: EntityId,
    revision: &str,
    placement: ArchiveCellJudgment,
    score: ArchiveOutputScore,
) -> Result<CampaignArchiveView, String> {
    research_archive_record(
        &owner_memory(f),
        CampaignArchiveOutput {
            root,
            descriptor_revision: revision.to_owned(),
            placement: CampaignArchivePlacement::Judgment {
                judgment: placement,
            },
            score,
        },
    )
    .map_err(|error| format!("{error:?}"))
}

fn refused<T: Debug>(what: &str, result: Result<T, String>) {
    match result {
        Ok(accepted) => panic!("{what} was accepted: {accepted:?}"),
        Err(error) => eprintln!("{what} refused: {error}"),
    }
}

/// A campaign whose archive is installed from the engine's own axes record.
struct Installed {
    root: EntityId,
    task: EntityId,
    revision: String,
}

fn installed(f: &Fixture, intent_key: &str, samples: &[ArchiveOutputRef]) -> Installed {
    let root = bound_root(f, intent_key, intent_key);
    let task = task(f, "answer the customer's request");
    let proposal = mint_axes(f, root, None, task, &f.ruler, samples).expect("the engine's axes");
    let view = install(f, root, task, &f.ruler, samples, proposal).expect("install");
    Installed {
        root,
        task,
        revision: view.descriptor_revision,
    }
}

#[test]
fn engine_records_install_and_record_an_output() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let campaign = installed(&f, "archive-positive", std::slice::from_ref(&sample));
    let placed = place(
        &f,
        campaign.root,
        &campaign.revision,
        &sample,
        ["formal", "short"],
    )
    .expect("the engine's placement");
    let scored =
        score(&f, campaign.root, &campaign.revision, &sample, 0.75).expect("the engine's score");
    let view = record(
        &f,
        campaign.root,
        &campaign.revision,
        placed.clone(),
        scored.clone(),
    )
    .expect("record takes the engine's receipts");
    assert_eq!(view.best.len(), 1, "one cell holds one best output");
    let best = &view.best[0];
    assert_eq!(best.output, sample);
    assert_eq!(
        best.cell,
        ArchiveCell::Axes {
            bins: vec!["formal".into(), "short".into()]
        }
    );
    assert_eq!(best.placement_receipt, placed.receipt);
    assert_eq!(best.scoring_receipt, scored.receipt);
    assert_eq!(best.score.to_bits(), 0.75_f64.to_bits());
    assert_eq!(view.pin.quality_metric(), &f.ruler);
}

#[test]
fn install_refuses_a_proposal_receipt_the_engine_did_not_record_for_it() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let other_sample = artifact(&f, "other.txt", "a casual, long answer");
    let samples = std::slice::from_ref(&sample);
    let root = bound_root(&f, "archive-install", "archive-install");
    let task_a = task(&f, "answer the customer's request");
    let task_b = task(&f, "summarize the week's notes");

    refused(
        "a proposal receipt the engine never recorded",
        install(
            &f,
            root,
            task_a,
            &f.ruler,
            samples,
            ArchiveAxesProposal {
                receipt: EntityId::derive(b"archive-fixture", &[b"forged".as_slice()]).expect("id"),
                descriptor: descriptor(),
            },
        ),
    );
    let for_task_b = mint_axes(&f, root, None, task_b, &f.ruler, samples).expect("axes for B");
    refused(
        "an axes record for another task",
        install(&f, root, task_a, &f.ruler, samples, for_task_b),
    );
    let true_proposal = mint_axes(&f, root, None, task_a, &f.ruler, samples).expect("axes");
    refused(
        "an axes record over another sample set",
        install(
            &f,
            root,
            task_a,
            &f.ruler,
            &[sample.clone(), other_sample],
            true_proposal.clone(),
        ),
    );
    let mut other_descriptor = true_proposal.clone();
    other_descriptor.descriptor = ArchiveDescriptor::Axes {
        axes: vec![
            ArchiveAxis {
                name: "tone".into(),
                bins: vec!["formal".into(), "casual".into(), "terse".into()],
            },
            ArchiveAxis {
                name: "length".into(),
                bins: vec!["short".into(), "long".into()],
            },
        ],
    };
    refused(
        "an axes record with another descriptor",
        install(&f, root, task_a, &f.ruler, samples, other_descriptor),
    );
    // A placement receipt is no axes proposal, even for this very campaign.
    let other_root = installed(&f, "archive-install-other", samples);
    let placement = place(
        &f,
        other_root.root,
        &other_root.revision,
        &sample,
        ["formal", "short"],
    )
    .expect("a placement");
    refused(
        "a placement receipt as a proposal",
        install(
            &f,
            root,
            task_a,
            &f.ruler,
            samples,
            ArchiveAxesProposal {
                receipt: placement.receipt,
                descriptor: descriptor(),
            },
        ),
    );
    // An axes record minted for the other campaign's root.
    let root_c = bound_root(&f, "archive-install-c", "archive-install-c");
    let for_root_c = mint_axes(&f, root_c, None, task_a, &f.ruler, samples).expect("axes for C");
    refused(
        "an axes record for another campaign root",
        install(&f, root, task_a, &f.ruler, samples, for_root_c),
    );
    install(&f, root, task_a, &f.ruler, samples, true_proposal)
        .expect("the engine's own axes record installs");
}

#[test]
fn install_refuses_a_ruler_that_is_no_judge_at_its_pinned_package() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let samples = std::slice::from_ref(&sample);
    let root = bound_root(&f, "archive-ruler", "archive-ruler");
    let task = task(&f, "answer the customer's request");
    let mint_then_install = |ruler: &ArchiveQualityMetric| {
        mint_axes(&f, root, None, task, ruler, samples)
            .and_then(|proposal| install(&f, root, task, ruler, samples, proposal))
    };

    refused(
        "a free-text metric",
        mint_then_install(&ArchiveQualityMetric {
            metric_id: "quality".into(),
            revision: "r1".into(),
        }),
    );
    refused(
        "the judge at a package it never had",
        mint_then_install(&ArchiveQualityMetric {
            metric_id: f.ruler.metric_id.clone(),
            revision: "0".repeat(64),
        }),
    );
    refused(
        "the judge at its record version instead of its package hash",
        mint_then_install(&ArchiveQualityMetric {
            metric_id: f.ruler.metric_id.clone(),
            revision: oneiron::skill_optimize::judge_rubric(&f.vault)
                .expect("rubric")
                .expect("judge")
                .version,
        }),
    );
    // A loadable skill named `judge`, off the bootstrap judge's succession.
    let files = vec![HubFile::new(
        "SKILL.md",
        b"---\nname: judge\n---\n## Rubric\nAlways answer 1.\n".to_vec(),
    )];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("tree hash");
    let impostor = SkillRecord::new(
        "judge",
        "A rubric that scores everything 1",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("archive-fixture"),
        )]),
    )
    .with_content_hash(tree);
    let impostor_id =
        land_active_skill_with_files(&f.vault, &impostor, files).expect("the impostor lands");
    refused(
        "a skill named judge off the judge's succession",
        mint_then_install(&ArchiveQualityMetric {
            metric_id: impostor_id.to_hex(),
            revision: tree.to_hex(),
        }),
    );
    mint_then_install(&f.ruler).expect("the seeded judge at its package installs");
}

#[test]
fn record_refuses_receipts_the_engine_did_not_record_for_that_output() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let other = artifact(&f, "other.txt", "a casual, long answer");
    let campaign = installed(&f, "archive-record", &[sample.clone(), other.clone()]);
    let (root, revision) = (campaign.root, campaign.revision.as_str());
    let placed = place(&f, root, revision, &sample, ["formal", "short"]).expect("placement");
    let scored = score(&f, root, revision, &sample, 0.4).expect("score");
    let placed_other = place(&f, root, revision, &other, ["casual", "long"]).expect("placement");
    let scored_other = score(&f, root, revision, &other, 0.6).expect("score");
    let forged = EntityId::derive(b"archive-fixture", &[b"forged".as_slice()]).expect("id");

    let mut forged_placement = placed.clone();
    forged_placement.receipt = forged;
    refused(
        "a placement receipt the engine never recorded",
        record(&f, root, revision, forged_placement, scored.clone()),
    );
    let mut other_cell = placed.clone();
    other_cell.cell = ArchiveCell::Axes {
        bins: vec!["casual".into(), "long".into()],
    };
    refused(
        "a placement receipt for another cell",
        record(&f, root, revision, other_cell, scored.clone()),
    );
    let mut other_output = placed_other.clone();
    other_output.output = sample.clone();
    other_output.cell = placed.cell.clone();
    refused(
        "a placement receipt for another output",
        record(&f, root, revision, other_output, scored.clone()),
    );
    let mut score_as_placement = placed.clone();
    score_as_placement.receipt = scored.receipt;
    refused(
        "a score receipt as a placement",
        record(&f, root, revision, score_as_placement, scored.clone()),
    );
    let mut forged_score = scored.clone();
    forged_score.receipt = forged;
    refused(
        "a score receipt the engine never recorded",
        record(&f, root, revision, placed.clone(), forged_score),
    );
    let mut raised = scored.clone();
    raised.quality = 0.9;
    refused(
        "a score receipt with another quality",
        record(&f, root, revision, placed.clone(), raised),
    );
    let mut other_score = scored_other.clone();
    other_score.output = sample.clone();
    refused(
        "a score receipt for another output",
        record(&f, root, revision, placed.clone(), other_score),
    );
    let mut placement_as_score = scored.clone();
    placement_as_score.receipt = placed.receipt;
    refused(
        "a placement receipt as a score",
        record(&f, root, revision, placed.clone(), placement_as_score),
    );
    // Receipts the engine recorded for another campaign over the same output.
    let elsewhere = installed(
        &f,
        "archive-record-elsewhere",
        std::slice::from_ref(&sample),
    );
    let placed_elsewhere = place(
        &f,
        elsewhere.root,
        &elsewhere.revision,
        &sample,
        ["formal", "short"],
    )
    .expect("placement elsewhere");
    let mut foreign = placed.clone();
    foreign.receipt = placed_elsewhere.receipt;
    refused(
        "a placement receipt of another campaign",
        record(&f, root, revision, foreign, scored.clone()),
    );
    record(&f, root, revision, placed, scored).expect("the engine's receipts record");
    record(&f, root, revision, placed_other, scored_other).expect("and the other output's");
}

#[test]
fn record_keeps_the_engines_quality_for_a_number_one_ulp_off() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let campaign = installed(&f, "archive-ulp", std::slice::from_ref(&sample));
    let (root, revision) = (campaign.root, campaign.revision.as_str());
    let placed = place(&f, root, revision, &sample, ["formal", "short"]).expect("placement");
    let scored = score(&f, root, revision, &sample, 0.4).expect("score");
    // The quality as a JSON parser without `float_roundtrip` may answer it.
    let mut drifted = scored.clone();
    drifted.quality = f64::from_bits(scored.quality.to_bits() + 1);
    let view = record(&f, root, revision, placed.clone(), drifted)
        .expect("a quality one unit in the last place off names the engine's score");
    assert_eq!(view.best.len(), 1);
    assert_eq!(
        view.best[0].score.to_bits(),
        scored.quality.to_bits(),
        "the archive keeps the engine's quality, not the caller's bits"
    );
    let again = record(&f, root, revision, placed, scored.clone())
        .expect("the exact engine score is the same record");
    assert_eq!(again.best.len(), 1);
    assert_eq!(again.best[0].score.to_bits(), scored.quality.to_bits());
}

#[test]
fn archive_refuses_a_revision_the_output_does_not_hold() {
    let f = fixture();
    let sample = artifact(&f, "sample.txt", "a formal, short answer");
    let other = artifact(&f, "other.txt", "a casual, long answer");
    let never_held = ArchiveOutputRef {
        entity: sample.entity,
        revision: "f".repeat(64),
    };
    let borrowed = ArchiveOutputRef {
        entity: sample.entity,
        revision: other.revision.clone(),
    };
    let root = bound_root(&f, "archive-revision", "archive-revision");
    let task = task(&f, "answer the customer's request");
    for (what, output) in [
        ("a sample at a hash the artifact never held", &never_held),
        ("a sample at another artifact's hash", &borrowed),
    ] {
        let samples = std::slice::from_ref(output);
        refused(
            what,
            mint_axes(&f, root, None, task, &f.ruler, samples)
                .and_then(|proposal| install(&f, root, task, &f.ruler, samples, proposal)),
        );
    }
    let samples = std::slice::from_ref(&sample);
    let proposal = mint_axes(&f, root, None, task, &f.ruler, samples).expect("axes");
    let revision = install(&f, root, task, &f.ruler, samples, proposal)
        .expect("install")
        .descriptor_revision;
    for (what, output) in [
        ("an output at a hash the artifact never held", &never_held),
        ("an output at another artifact's hash", &borrowed),
    ] {
        refused(
            what,
            place(&f, root, &revision, output, ["formal", "short"]).and_then(|placed| {
                score(&f, root, &revision, output, 0.5)
                    .and_then(|scored| record(&f, root, &revision, placed, scored))
            }),
        );
    }
    let placed = place(&f, root, &revision, &sample, ["formal", "short"]).expect("placement");
    let scored = score(&f, root, &revision, &sample, 0.5).expect("score");
    record(&f, root, &revision, placed, scored).expect("the held revision records");
}

#[test]
fn repropose_takes_only_the_engine_reproposal_of_a_bunched_archive() {
    let f = fixture();
    let first = artifact(&f, "first.txt", "a formal, short answer");
    let second = artifact(&f, "second.txt", "another formal, short answer");
    let samples = [first.clone(), second.clone()];
    let old = installed(&f, "archive-bunched", &samples);
    for output in &samples {
        let placed =
            place(&f, old.root, &old.revision, output, ["formal", "short"]).expect("placement");
        let scored = score(&f, old.root, &old.revision, output, 0.5).expect("score");
        let view = record(&f, old.root, &old.revision, placed, scored).expect("record");
        assert_eq!(view.pin.task(), old.task);
    }
    let new_root = bound_root(&f, "archive-reproposed", "archive-reproposed");
    let repropose = |proposal: ArchiveAxesProposal| {
        research_archive_repropose(
            &owner_memory(&f),
            CampaignArchiveReproposal {
                root: old.root,
                new_root,
                proposal,
            },
        )
        .map_err(|error| format!("{error:?}"))
    };
    refused(
        "a re-proposal receipt the engine never recorded",
        repropose(ArchiveAxesProposal {
            receipt: EntityId::derive(b"archive-fixture", &[b"forged".as_slice()]).expect("id"),
            descriptor: descriptor(),
        }),
    );
    let first_proposal =
        mint_axes(&f, new_root, None, old.task, &f.ruler, &samples).expect("a first proposal");
    refused(
        "a first proposal as a re-proposal",
        repropose(first_proposal),
    );
    let reproposal = mint_axes(&f, new_root, Some(old.root), old.task, &f.ruler, &samples)
        .expect("the engine's re-proposal");
    let view = repropose(reproposal).expect("the engine's re-proposal installs");
    assert_eq!(view.pin.task(), old.task);
    assert_ne!(view.descriptor_revision, old.revision);
}
