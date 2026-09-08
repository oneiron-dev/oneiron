//! Fixture and task generation plus atomic JSON writers.

use super::cli_and_pinned_config::{campaign_config_for, interface_bench_1_config};
use super::config_types::{
    BenchTask, BrowseRubric, CAMPAIGN_ID, CLAIM_COUNT, ClaimProvenance, DETERMINISTIC_SEED,
    FIXTURE_ID, FULL_TASK_COUNT, FixtureClaim, FixtureVault, GenerationProof, GoldLabel,
    HoldoutClassFreeze, HoldoutFreeze, HoldoutPolicy, OWNER_SPOTCHECK_COUNT, PERSON_COUNT,
    RunSettings, SCHEMA_VERSION, ScorerConfig, TOPIC_COUNT, TaskBundle, TaskClass, TaskgenReport,
};
use super::reports_and_fixture_helpers::{
    claim_id_for, fixture_claim, learned_at, object_id, object_name, organization_id,
    organization_name, person_id, person_name, source_ref, stance_for, superseded_by_for, topic_id,
    topic_name,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::Path;
pub(super) fn build_task_bundle() -> TaskBundle {
    let fixture = FixtureVault {
        schema_version: SCHEMA_VERSION,
        fixture_id: FIXTURE_ID.to_owned(),
        campaign: CAMPAIGN_ID.to_owned(),
        seed: DETERMINISTIC_SEED,
        claim_count: CLAIM_COUNT,
        claims: generate_claims(),
    };
    let mut full_tasks = generate_tasks(&fixture);
    mark_holdout_and_smoke(&mut full_tasks);
    let smoke_tasks = full_tasks
        .iter()
        .filter(|task| task.smoke)
        .cloned()
        .collect::<Vec<_>>();
    let holdout = freeze_holdout(&full_tasks);
    let spotcheck = owner_spotcheck_sample(&full_tasks);

    TaskBundle {
        config: interface_bench_1_config(),
        fixture,
        full_tasks,
        smoke_tasks,
        holdout,
        spotcheck,
    }
}

fn generate_claims() -> Vec<FixtureClaim> {
    let mut claims = Vec::with_capacity(CLAIM_COUNT);
    for person_index in 0..PERSON_COUNT {
        for topic_index in 0..TOPIC_COUNT {
            claims.push(claim_for_indices(person_index, topic_index));
        }
    }
    claims
}

fn claim_for_indices(person_index: usize, topic_index: usize) -> FixtureClaim {
    let claim_id = claim_id_for(person_index, topic_index);
    let topic_id_value = topic_id(topic_index);
    let person_id = person_id(person_index);
    let object_id = object_id(person_index);
    let organization_id = organization_id(person_index);
    let source_ref = source_ref(person_index, topic_index);
    let learned_at_epoch_s = learned_at(person_index, topic_index);
    let learned_at_label = format!("day-{}", learned_at_epoch_s / 86_400);
    let stance = stance_for(person_index, topic_index);
    let topic = topic_name(topic_index);
    let person = person_name(person_index);
    let owned_object = object_name(person_index);
    let organization = organization_name(person_index);
    let changed_after = format!("after-{}", topic_id(topic_index / 10));
    let superseded_by = superseded_by_for(person_index, topic_index);
    let mut relations = BTreeMap::new();
    relations.insert("owner_of".to_owned(), vec![object_id.clone()]);
    relations.insert("employed_by".to_owned(), vec![organization_id.clone()]);
    relations.insert("has_topic".to_owned(), vec![topic_id_value.clone()]);
    relations.insert("cites_source".to_owned(), vec![source_ref.clone()]);

    FixtureClaim {
        claim_id,
        topic_id: topic_id_value,
        topic: topic.clone(),
        person_id,
        person: person.clone(),
        owned_object_id: object_id,
        owned_object: owned_object.clone(),
        organization_id,
        organization: organization.clone(),
        stance: stance.clone(),
        source_ref: source_ref.clone(),
        learned_at_epoch_s,
        learned_at_label: learned_at_label.clone(),
        superseded_by,
        text: format!(
            "{person} at {organization} {stance} about {topic}; {person} owns {owned_object}. Source {source_ref} learned {learned_at_label}."
        ),
        relations,
        provenance: ClaimProvenance {
            source_ref,
            learned_at_epoch_s,
            changed_after,
            source_kind: "seeded_fixture".to_owned(),
        },
    }
}

fn generate_tasks(fixture: &FixtureVault) -> Vec<BenchTask> {
    let mut tasks = Vec::with_capacity(FULL_TASK_COUNT);
    tasks.extend((0..30).map(|ordinal| retrieval_task(fixture, ordinal)));
    tasks.extend((0..20).map(|ordinal| multi_hop_task(fixture, ordinal)));
    tasks.extend((0..20).map(|ordinal| provenance_task(fixture, ordinal)));
    tasks.extend((0..10).map(|ordinal| browse_task(fixture, ordinal)));
    tasks
}

fn retrieval_task(_fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let topic_index = ordinal;
    let topic = topic_name(topic_index);
    let relevant_claim_ids = (0..PERSON_COUNT)
        .map(|person_index| claim_id_for(person_index, topic_index))
        .collect::<Vec<_>>();
    let task_id = format!("retrieval-qa-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::RetrievalQa,
        prompt: format!("Find the claims about {topic}. Cite the claim ids you used."),
        gold: GoldLabel::RetrievalQa {
            relevant_claim_ids: relevant_claim_ids.clone(),
        },
        scorer: ScorerConfig {
            scorer: "set_f1(relevant_claim_ids)".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: relevant_claim_ids.clone(),
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "topic sweep selected from seeded fixture topic index".to_owned(),
            selected_subgraph: relevant_claim_ids,
            verified_by_construction: true,
        },
    }
}

fn multi_hop_task(fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let person_index = (ordinal * 7) % PERSON_COUNT;
    let topic_index = 30 + (ordinal * 3) % 60;
    let claim = fixture_claim(fixture, person_index, topic_index);
    let task_id = format!("multi-hop-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::MultiHop,
        prompt: format!(
            "What does the person who owns {} think about {}? Cite the supporting claim id.",
            claim.owned_object, claim.topic
        ),
        gold: GoldLabel::MultiHop {
            exact_answer: claim.stance.clone(),
            supporting_ids: vec![claim.claim_id.clone()],
        },
        scorer: ScorerConfig {
            scorer: "exact_answer + supporting_ids_f1".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: vec![claim.claim_id.clone()],
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "object owner relation plus topic claim selected from fixture graph".to_owned(),
            selected_subgraph: vec![
                claim.person_id.clone(),
                claim.owned_object_id.clone(),
                claim.topic_id.clone(),
                claim.claim_id.clone(),
            ],
            verified_by_construction: true,
        },
    }
}

fn provenance_task(fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let person_index = (ordinal * 11) % PERSON_COUNT;
    let topic_index = 55 + (ordinal * 2) % 40;
    let claim = fixture_claim(fixture, person_index, topic_index);
    let (field, value, question) = match ordinal % 3 {
        0 => (
            "source_ref",
            claim.source_ref.clone(),
            format!(
                "Which source said what {} thinks about {}?",
                claim.person, claim.topic
            ),
        ),
        1 => (
            "learned_at_epoch_s",
            claim.learned_at_epoch_s.to_string(),
            format!(
                "What learned_at_epoch_s value records when we learned what {} thinks about {}?",
                claim.person, claim.topic
            ),
        ),
        _ => (
            "changed_after",
            claim.provenance.changed_after.clone(),
            format!(
                "What changed-after marker is attached to the claim about {} and {}?",
                claim.person, claim.topic
            ),
        ),
    };
    let task_id = format!("provenance-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::Provenance,
        prompt: format!("{question} Cite the claim id."),
        gold: GoldLabel::Provenance {
            field: field.to_owned(),
            value,
            supporting_ids: vec![claim.claim_id.clone()],
        },
        scorer: ScorerConfig {
            scorer: "field_match + supporting_ids_f1".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: vec![claim.claim_id.clone()],
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "provenance field selected from constructed claim metadata".to_owned(),
            selected_subgraph: vec![claim.claim_id.clone(), claim.source_ref.clone()],
            verified_by_construction: true,
        },
    }
}

fn browse_task(_fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let topic_index = 80 + ordinal * 2;
    let topic = topic_name(topic_index);
    let required_claim_ids = (0..10)
        .map(|person_index| claim_id_for(person_index, topic_index))
        .collect::<Vec<_>>();
    let task_id = format!("browse-then-answer-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::BrowseThenAnswer,
        prompt: format!("Summarize what the vault knows about {topic}. Cite claim ids."),
        gold: GoldLabel::BrowseThenAnswer {
            topic,
            required_claim_ids: required_claim_ids.clone(),
            rubric: BrowseRubric {
                coverage: "mentions multiple fixture claims for the topic".to_owned(),
                faithfulness: "uses only facts present in cited claims".to_owned(),
                citation_validity: "claim ids must exist and support the summary".to_owned(),
                scale: "1-5".to_owned(),
            },
        },
        scorer: ScorerConfig {
            scorer: "blind browse_rubric judge".to_owned(),
            blind_judge: true,
        },
        supporting_claim_ids: required_claim_ids.clone(),
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "topic synthesis task selected from fixture topic cluster".to_owned(),
            selected_subgraph: required_claim_ids,
            verified_by_construction: true,
        },
    }
}

fn mark_holdout_and_smoke(tasks: &mut [BenchTask]) {
    for class in TaskClass::ALL {
        let indices = tasks
            .iter()
            .enumerate()
            .filter_map(|(index, task)| (task.class == class).then_some(index))
            .collect::<Vec<_>>();
        let holdout_start = indices.len() - indices.len() / 5;
        for (class_position, task_index) in indices.iter().enumerate() {
            if class_position >= holdout_start {
                tasks[*task_index].holdout = true;
            }
            if class_position < 2 {
                tasks[*task_index].smoke = true;
            }
        }
    }
}

fn freeze_holdout(tasks: &[BenchTask]) -> HoldoutFreeze {
    let mut per_class = BTreeMap::new();
    for class in TaskClass::ALL {
        let class_tasks = tasks
            .iter()
            .filter(|task| task.class == class)
            .collect::<Vec<_>>();
        let task_ids = class_tasks
            .iter()
            .filter(|task| task.holdout)
            .map(|task| task.task_id.clone())
            .collect::<Vec<_>>();
        per_class.insert(
            class.as_str().to_owned(),
            HoldoutClassFreeze {
                total: class_tasks.len(),
                holdout: task_ids.len(),
                task_ids,
            },
        );
    }

    HoldoutFreeze {
        campaign: CAMPAIGN_ID.to_owned(),
        frozen_on: "2026-07-07-after-first-smoke".to_owned(),
        policy: HoldoutPolicy {
            fraction_per_class: 0.20,
            freeze_after: "first_smoke".to_owned(),
        },
        per_class,
    }
}

fn owner_spotcheck_sample(tasks: &[BenchTask]) -> Vec<BenchTask> {
    let mut sample = Vec::with_capacity(OWNER_SPOTCHECK_COUNT);
    for class in TaskClass::ALL {
        let class_tasks = tasks
            .iter()
            .filter(|task| task.class == class)
            .collect::<Vec<_>>();
        if let Some(first) = class_tasks.first() {
            sample.push((*first).clone());
        }
        if let Some(holdout) = class_tasks.iter().find(|task| task.holdout) {
            sample.push((*holdout).clone());
        }
    }
    sample
}

pub(super) fn write_taskgen_outputs(
    out_dir: &Path,
    settings: &RunSettings,
) -> Result<TaskgenReport, String> {
    let mut bundle = build_task_bundle();
    bundle.config = campaign_config_for(settings);
    fs::create_dir_all(out_dir).map_err(|error| format!("create output dir: {error}"))?;

    let files = BTreeMap::from([
        (
            "directory".to_owned(),
            out_dir
                .canonicalize()
                .unwrap_or_else(|_| out_dir.to_path_buf())
                .display()
                .to_string(),
        ),
        (
            "campaign_config".to_owned(),
            out_dir.join("campaign_config.json").display().to_string(),
        ),
        (
            "fixture_vault".to_owned(),
            out_dir.join("fixture_vault.json").display().to_string(),
        ),
        (
            "tasks_full".to_owned(),
            out_dir.join("tasks_full.json").display().to_string(),
        ),
        (
            "tasks_smoke".to_owned(),
            out_dir.join("tasks_smoke.json").display().to_string(),
        ),
        (
            "holdout_freeze".to_owned(),
            out_dir.join("holdout_freeze.json").display().to_string(),
        ),
        (
            "owner_spotcheck_sample".to_owned(),
            out_dir
                .join("owner_spotcheck_sample.json")
                .display()
                .to_string(),
        ),
        (
            "taskgen_report".to_owned(),
            out_dir.join("taskgen_report.json").display().to_string(),
        ),
    ]);

    write_json(&out_dir.join("campaign_config.json"), &bundle.config)?;
    write_json(&out_dir.join("fixture_vault.json"), &bundle.fixture)?;
    write_json(&out_dir.join("tasks_full.json"), &bundle.full_tasks)?;
    write_json(&out_dir.join("tasks_smoke.json"), &bundle.smoke_tasks)?;
    write_json(&out_dir.join("holdout_freeze.json"), &bundle.holdout)?;
    write_json(
        &out_dir.join("owner_spotcheck_sample.json"),
        &bundle.spotcheck,
    )?;

    let report = TaskgenReport {
        campaign: CAMPAIGN_ID.to_owned(),
        fixture_id: FIXTURE_ID.to_owned(),
        generated_claims: bundle.fixture.claims.len(),
        full_tasks: bundle.full_tasks.len(),
        smoke_tasks: bundle.smoke_tasks.len(),
        holdout_by_class: bundle
            .holdout
            .per_class
            .iter()
            .map(|(class, freeze)| (class.clone(), freeze.holdout))
            .collect(),
        smoke_task_ids: bundle
            .smoke_tasks
            .iter()
            .map(|task| task.task_id.clone())
            .collect(),
        owner_spotcheck_sample_ids: bundle
            .spotcheck
            .iter()
            .map(|task| task.task_id.clone())
            .collect(),
        output_files: files,
    };
    write_json(&out_dir.join("taskgen_report.json"), &report)?;

    Ok(report)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

pub(super) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let tmp_path = path.with_extension("json.tmp");
    write_json(&tmp_path, value)?;
    fs::rename(&tmp_path, path).map_err(|error| {
        format!(
            "rename {} to {}: {error}",
            tmp_path.display(),
            path.display()
        )
    })
}

pub(super) fn read_json<T>(path: &Path) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    serde_json::from_reader(file).map_err(|error| format!("parse {}: {error}", path.display()))
}
