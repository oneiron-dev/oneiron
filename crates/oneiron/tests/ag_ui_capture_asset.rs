//! An AG-UI capture lands as its own ASSET (Engine RULING L2-15-CAPTURE-SUBJECT = C). The owner
//! captures a file through the door `vault.ingest.ag_ui.import` calls, and the capture claim is
//! about the file's ASSET, scoped to the project, never about the project itself (the project hub
//! refuses a claim about a project, so main refused every capture). The capture reads back
//! through the door `vault.ingest.ag_ui.read` calls, bound to its asset. Deleting or purging the
//! capture deletes its asset; deleting the asset leaves no readable capture; deleting one capture
//! leaves another capture's asset standing.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test ag_ui_capture_asset`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteEntityOptions;
use oneiron::ingest::{
    AG_UI_FILE_PREDICATE, AgUiFileImport, AgUiFileReadInput, AgUiFileReceipt, AgUiFileView,
};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, Vault, VaultConfig,
};
use serde_json::{Value, json};

/// The app the owner names at capture.
const APP: &str = "notes-app";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    project: EntityId,
}

/// A rooted vault with its install enrolled, its embedded owner and proof, and its root
/// project, where every capture lands.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
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
    let project = vault.root_project().expect("root project");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
        project,
    }
}

/// One app run's events, as the app reports them: three events, one of them a CUSTOM event
/// no mapping names.
fn run_jsonl(run: &str) -> String {
    [
        json!({"type": "RUN_STARTED", "threadId": "thread-1", "runId": run}),
        json!({"type": "CUSTOM", "name": "draft_saved", "value": {"run": run}}),
        json!({"type": "RUN_FINISHED", "threadId": "thread-1", "runId": run}),
    ]
    .iter()
    .map(Value::to_string)
    .collect::<Vec<_>>()
    .join("\n")
}

/// One capture through the owner's import door.
struct Capture {
    jsonl: String,
    receipt: AgUiFileReceipt,
    claim: EntityId,
}

fn capture(fixture: &Fixture, run: &str) -> Capture {
    let jsonl = run_jsonl(run);
    let receipt = fixture
        .vault
        .ingest_ag_ui_file(
            &fixture.owner_proof,
            &AgUiFileImport {
                claim_ref: None,
                project_ref: fixture.project.to_hex(),
                app_id: APP.to_owned(),
                custom_mappings: Vec::new(),
                jsonl: jsonl.clone(),
            },
        )
        .expect("the owner captures the file");
    let claim = EntityId::from_hex(&receipt.claim_ref).expect("capture claim id");
    Capture {
        jsonl,
        receipt,
        claim,
    }
}

/// The entity the capture claim is about.
fn subject_of(vault: &Vault, claim: &EntityId) -> EntityId {
    let body = vault
        .get_claim(claim)
        .expect("read the capture claim")
        .expect("the capture claim is stored");
    let ClaimSubject::Entity(subject) = body.subject else {
        panic!("the capture claim is about an entity: {:?}", body.subject);
    };
    subject
}

/// Whether `id` is a live ASSET row.
fn is_live_asset(vault: &Vault, id: &EntityId) -> bool {
    vault.get_entity_type(id).expect("read the entity type") == Some(ENTITY_TYPE_ASSET)
        && !vault.is_deleted_shell(id).expect("read the deletion state")
}

/// The capture as the owner reads it through the read door; `None` when the read withholds it.
fn read_capture(fixture: &Fixture, capture: &Capture) -> Option<AgUiFileView> {
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let read = memory
        .read_ag_ui_file(&AgUiFileReadInput {
            claim_ref: capture.receipt.claim_ref.clone(),
            source_hash: capture.receipt.source_hash.clone(),
        })
        .expect("the owner reads the capture");
    read.source
}

/// The read door returns no view of the capture: it withholds it or refuses it.
fn assert_unreadable(fixture: &Fixture, capture: &Capture, why: &str) {
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let read = memory.read_ag_ui_file(&AgUiFileReadInput {
        claim_ref: capture.receipt.claim_ref.clone(),
        source_hash: capture.receipt.source_hash.clone(),
    });
    if let Ok(read) = read {
        assert!(read.source.is_none(), "{why}: {:?}", read.source);
    }
}

#[test]
fn a_capture_lands_as_a_claim_about_its_own_asset_in_the_project() {
    let fixture = fixture();
    let capture = capture(&fixture, "run-1");
    assert_eq!(capture.receipt.event_count, 3);

    let body = fixture
        .vault
        .get_claim(&capture.claim)
        .expect("read the capture claim")
        .expect("the capture claim is stored");
    assert_eq!(body.predicate, AG_UI_FILE_PREDICATE);
    assert_eq!(body.source, Some(ClaimSource::Imported));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);

    let asset = subject_of(&fixture.vault, &capture.claim);
    assert_ne!(asset, fixture.project, "the claim is not about the project");
    assert!(
        is_live_asset(&fixture.vault, &asset),
        "the capture lands as a live ASSET"
    );
    let stored = fixture
        .vault
        .get(&asset)
        .expect("read the asset")
        .expect("the asset has a body");
    let stored: Value = rmp_serde::from_slice(&stored).expect("the asset body is MessagePack");
    assert_eq!(
        stored,
        json!({
            "source": "imported",
            "source_id": "ag-ui",
            "project_ref": fixture.project.to_hex(),
            "app_id": APP,
            "claim_ref": capture.claim.to_hex(),
        }),
        "the asset is scoped to the project and names its capture"
    );
}

#[test]
fn a_landed_capture_reads_through_its_binding() {
    let fixture = fixture();
    let capture = capture(&fixture, "run-1");

    let view = read_capture(&fixture, &capture).expect("the owner reads the capture");
    assert_eq!(view.claim_ref, capture.receipt.claim_ref);
    assert_eq!(view.source_hash, capture.receipt.source_hash);
    assert_eq!(view.project_ref, fixture.project.to_hex());
    assert_eq!(view.app_id, APP);
    assert_eq!(view.jsonl, capture.jsonl);
    assert_eq!(view.event_count, 3);
}

#[test]
fn deleting_the_capture_deletes_its_asset() {
    let fixture = fixture();
    let capture = capture(&fixture, "run-1");
    let asset = subject_of(&fixture.vault, &capture.claim);

    assert!(
        fixture
            .vault
            .delete_entity(&capture.claim)
            .expect("the owner deletes the capture"),
        "the capture existed"
    );

    assert!(
        !is_live_asset(&fixture.vault, &asset),
        "the capture's asset is deleted with it"
    );
    assert_unreadable(&fixture, &capture, "a deleted capture reads as nothing");
}

#[test]
fn purging_the_capture_deletes_its_asset() {
    let fixture = fixture();
    let capture = capture(&fixture, "run-1");
    let asset = subject_of(&fixture.vault, &capture.claim);

    fixture
        .vault
        .delete_entity_with_options(&capture.claim, DeleteEntityOptions { purge: true })
        .expect("the owner purges the capture");

    assert!(
        !is_live_asset(&fixture.vault, &asset),
        "the purged capture's asset is deleted with it"
    );
    assert_unreadable(&fixture, &capture, "a purged capture reads as nothing");
}

#[test]
fn deleting_the_asset_unbinds_its_capture() {
    let fixture = fixture();
    let capture = capture(&fixture, "run-1");
    let asset = subject_of(&fixture.vault, &capture.claim);

    assert!(
        fixture
            .vault
            .delete_entity(&asset)
            .expect("the owner deletes the asset"),
        "the asset existed"
    );

    assert_unreadable(
        &fixture,
        &capture,
        "a capture whose asset is gone is no readable capture",
    );
}

#[test]
fn deleting_one_capture_leaves_the_other_captures_asset() {
    let fixture = fixture();
    let first = capture(&fixture, "run-1");
    let second = capture(&fixture, "run-2");
    let first_asset = subject_of(&fixture.vault, &first.claim);
    let second_asset = subject_of(&fixture.vault, &second.claim);
    assert_ne!(first_asset, second_asset, "each capture has its own asset");

    fixture
        .vault
        .delete_entity(&first.claim)
        .expect("the owner deletes the first capture");

    assert!(!is_live_asset(&fixture.vault, &first_asset));
    assert!(
        is_live_asset(&fixture.vault, &second_asset),
        "the other capture's asset stands"
    );
    let view = read_capture(&fixture, &second).expect("the other capture still reads");
    assert_eq!(view.jsonl, second.jsonl);
}
