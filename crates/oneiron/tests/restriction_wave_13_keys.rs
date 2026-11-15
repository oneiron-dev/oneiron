//! Restriction wave 13: the reattach offer count and the drift miss count are owner keys.
//!
//! Guards prove today's defaults (16 offers, 3 misses); owner tests set
//! `anchored_annotation.reattach.max_offers` and `browser.library.drift_misses`.
//!
//! `cargo test --locked -p oneiron --all-features --test restriction_wave_13_keys`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use oneiron::anchored_annotation::{
    Anchor, AnnotationThread, Locator, ReanchorOp, ReanchorSummary,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::browser_library::{
    DRIFT_REASON, Filing, file_workflow, record_workflow_run, retired_workflow, workflow,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_browser::{
    BatchStep, BatchStopCause, BrowserEngine, ExpectInput, LibraryRunMode, ReplayGuest, RunOutcome,
    WorkflowProgram, WorkflowProof,
};
use serde_json::json;

const TEXT_MIME: &str = "text/plain";
const WORDS: &str = "Budget: 40k.";

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_actor(vault: &Vault, at: u64) -> (EntityId, WriteActor) {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
        .expect("put actor");
    (actor_id, WriteActor::new(actor_id, EdgeActorClass::Human))
}

fn put_artifact(vault: &Vault, name: &str, mime: &str, v1: &[u8], actor: WriteActor) -> EntityId {
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(name, mime),
            test_time(10),
            10,
        )
        .expect("put artifact");
    let version = vault
        .append_blob_artifact_version(
            &artifact,
            v1,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(10),
            10,
        )
        .expect("append version 1")
        .version;
    assert_eq!(version, 1);
    artifact
}

fn upload(vault: &Vault, artifact: &EntityId, actor: WriteActor, bytes: &[u8], at: u64) -> u64 {
    vault
        .append_blob_artifact_version(
            artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(at),
            at,
        )
        .expect("append version")
        .version
}

fn open_thread(
    vault: &Vault,
    artifact: EntityId,
    version: u64,
    locator: &Locator,
    actor: WriteActor,
) -> AnnotationThread {
    vault
        .open_annotation_thread(
            &Anchor::new(artifact, version, locator.clone()),
            actor,
            "Check this.",
            test_time(11),
            11,
        )
        .expect("open thread")
}

fn sweep(
    vault: &Vault,
    artifact: &EntityId,
    from: u64,
    to: u64,
    ops: &[ReanchorOp],
    actor: WriteActor,
    at: u64,
) -> ReanchorSummary {
    vault
        .reanchor_annotation_threads(artifact, from, to, ops, actor, test_time(at), at)
        .expect("reanchor sweep")
}

fn set_owner_key(vault: &Vault, key: &str, n: u32) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner_proof = vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&owner_proof),
            SetSetting::vault_value(key, json!(n)),
        )
        .expect("the owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

fn v1_bytes() -> Vec<u8> {
    format!("Intro.\n{WORDS}\n").into_bytes()
}

fn v2_bytes() -> Vec<u8> {
    b"Intro.\n".to_vec()
}

fn v3_bytes() -> Vec<u8> {
    format!("{WORDS}\n").repeat(20).into_bytes()
}

fn reattach_fixture(vault: &Vault) -> (EntityId, EntityId) {
    let (_, actor) = put_actor(vault, 10);
    let artifact = put_artifact(vault, "notes.txt", TEXT_MIME, &v1_bytes(), actor);
    let locator = Locator::text(7, 19).expect("text locator");
    let thread = open_thread(vault, artifact, 1, &locator, actor);
    let thread_id = thread.thread_id;
    assert_eq!(upload(vault, &artifact, actor, &v2_bytes(), 12), 2);
    let summary = sweep(vault, &artifact, 1, 2, &[], actor, 13);
    assert_eq!(summary.drifted.len(), 1, "{summary:?}");
    assert!(summary.remapped.is_empty(), "{summary:?}");
    let unattached = vault
        .unattached_annotation_threads(&artifact)
        .expect("unattached list");
    assert_eq!(unattached.len(), 1, "{unattached:?}");
    assert_eq!(unattached[0].snapshot.as_deref(), Some(WORDS));
    assert_eq!(upload(vault, &artifact, actor, &v3_bytes(), 14), 3);
    let summary = sweep(vault, &artifact, 2, 3, &[], actor, 15);
    assert!(summary.remapped.is_empty(), "{summary:?}");
    assert!(summary.drifted.is_empty(), "{summary:?}");
    (artifact, thread_id)
}

fn assert_offers(vault: &Vault, artifact: &EntityId, thread_id: EntityId, want: usize) {
    let offers = vault
        .annotation_reattach_offers(artifact)
        .expect("reattach offers");
    assert_eq!(offers.len(), want, "{offers:?}");
    let v3 = String::from_utf8(v3_bytes()).expect("v3 is UTF-8");
    let chars: Vec<char> = v3.chars().collect();
    for (index, offer) in offers.iter().enumerate() {
        assert_eq!(offer.thread_id, thread_id);
        assert_eq!(offer.version, 3);
        let (start, end) = match &offer.locator {
            Locator::Text {
                char_start,
                char_end,
            } => (*char_start, *char_end),
            other => panic!("offer {index} is a text span, not {other:?}"),
        };
        let text: String = chars[start as usize..end as usize].iter().collect();
        assert_eq!(text, WORDS, "offer {index} selects the exact words");
        let want_start = index as u64 * 13;
        assert_eq!(
            (start, end),
            (want_start, want_start + 12),
            "offer {index} in file order"
        );
    }
}

fn test_program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "file the expense report".to_owned(),
        params: Vec::new(),
        secret_params: Vec::new(),
        steps: vec![BatchStep::Open {
            url: "https://example.com/expenses".to_owned(),
        }],
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("Report filed".to_owned()),
            ..Default::default()
        }],
    }
}

fn test_proof() -> WorkflowProof {
    WorkflowProof {
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        held_out: false,
        seed: None,
        solved_url: "https://example.com/expenses".to_owned(),
        solved_title: "Expenses".to_owned(),
        replay_receipts: Vec::new(),
        replay_decisions: Vec::new(),
        replay_url: "https://example.com/expenses".to_owned(),
        replay_guest: ReplayGuest {
            engine: BrowserEngine::Lightpanda,
            carried: Vec::new(),
            not_carried: Vec::new(),
        },
    }
}

fn file_test_program(vault: &Vault, by: EntityId, at: u64) -> EntityId {
    let program = test_program();
    let proof = test_proof();
    match file_workflow(
        vault,
        by,
        "example.com",
        &program,
        &proof,
        at,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("file program")
    {
        Filing::Filed { id, .. } => id,
        Filing::Refused(why) => panic!("filing refused: {why:?}"),
    }
}

fn strict_miss() -> RunOutcome {
    RunOutcome {
        mode: LibraryRunMode::Strict,
        done: false,
        stop_cause: Some(BatchStopCause::PostconditionUnmet),
    }
}

#[test]
fn reattach_offers_list_sixteen_places_by_default() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let (artifact, thread_id) = reattach_fixture(&vault);
    assert_offers(&vault, &artifact, thread_id, 16);
}

#[test]
fn owner_reattach_offer_count_lists_every_place() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    set_owner_key(&vault, "anchored_annotation.reattach.max_offers", 24);
    let (artifact, thread_id) = reattach_fixture(&vault);
    assert_offers(&vault, &artifact, thread_id, 20);
}

#[test]
fn three_strict_misses_retire_a_program_by_default() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let (by, _) = put_actor(&vault, 10);
    let id = file_test_program(&vault, by, 11);
    let miss = strict_miss();
    record_workflow_run(&vault, id, &miss, by, 12).expect("first miss");
    record_workflow_run(&vault, id, &miss, by, 13).expect("second miss");
    let live = workflow(&vault, id)
        .expect("read program")
        .expect("still filed after 2 misses");
    assert_eq!(live.strict_misses, 2);
    record_workflow_run(&vault, id, &miss, by, 14).expect("third miss");
    assert!(
        workflow(&vault, id).expect("read program").is_none(),
        "retired after the third strict miss"
    );
    let retired = retired_workflow(&vault, id)
        .expect("read retire")
        .expect("the retire is kept");
    assert_eq!(retired.reason.as_deref(), Some(DRIFT_REASON));
}

#[test]
fn owner_drift_count_keeps_a_program_filed() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    set_owner_key(&vault, "browser.library.drift_misses", 5);
    let (by, _) = put_actor(&vault, 10);
    let id = file_test_program(&vault, by, 11);
    let miss = strict_miss();
    record_workflow_run(&vault, id, &miss, by, 12).expect("first miss");
    record_workflow_run(&vault, id, &miss, by, 13).expect("second miss");
    record_workflow_run(&vault, id, &miss, by, 14).expect("third miss");
    let live = workflow(&vault, id)
        .expect("read program")
        .expect("still filed after 3 misses with count 5");
    assert_eq!(live.strict_misses, 3);
    record_workflow_run(&vault, id, &miss, by, 15).expect("fourth miss");
    record_workflow_run(&vault, id, &miss, by, 16).expect("fifth miss");
    assert!(
        workflow(&vault, id).expect("read program").is_none(),
        "retired after the fifth strict miss"
    );
    let retired = retired_workflow(&vault, id)
        .expect("read retire")
        .expect("the retire is kept");
    assert_eq!(retired.reason.as_deref(), Some(DRIFT_REASON));
}
