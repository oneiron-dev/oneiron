//! A ref an organ call holds is held for every settle door (FIX 22386). The
//! hold checked the ledger, the waiting proposals and the other holds when
//! it was made, but the proposal and settle doors never read the holds: a
//! retained proposal and a settlement each took a held ref, and the held
//! call's redrive then found its own ref taken.
//!
//! Each refusal names the holding call and the door that releases it
//! (Engine ruling 13 Nov 14:16): the owner releases the hold or lets the
//! call run, so a hold is never a dead end. Only the held call's own landing
//! takes the ref, and its hold ends in the same writer.
//!
//! The in-memory keystore needs the test-support feature. Run with
//! `cargo test -p oneiron --all-features --test edit_settle_organ_wait_ref`.
#![cfg(feature = "test-support")]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::blob_artifact::BlobArtifactBody;
use oneiron::edit_roundtrip::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditProposal, MutationMode, OfficeFormat,
    RecalcStatus, StructureSummary, ValidationReport,
};
use oneiron::edit_settle::{OrganWait, SettleConsent};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

const WORKBOOK_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const HELD_REF: &str = "organ-run-forecast-export";
const ORGAN: &str = "sheets";
const VERB: &str = "export";
/// The door the refusal names for letting a held call go.
const RELEASE_DOOR: &str = "vault.artifacts.release_wait";

struct Fixture {
    vault: Vault,
    owner: WriteActor,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        Self {
            vault,
            owner: WriteActor::new(owner, EdgeActorClass::Human),
            _directory: directory,
        }
    }

    fn artifact(&self, name: &str, media_type: &str) -> EntityId {
        let artifact = EntityId::now();
        let at = self.vault.now_recorded_at();
        self.vault
            .put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new(name, media_type),
                TimeRange { start: at, end: at },
                at,
            )
            .expect("put artifact");
        artifact
    }

    /// The organ call the owner asked for, held under [`HELD_REF`].
    fn held_call(&self, artifact: EntityId) -> OrganWait {
        OrganWait {
            artifact_id: artifact,
            run_ref: HELD_REF.to_owned(),
            organ: ORGAN.to_owned(),
            verb: VERB.to_owned(),
            call: b"the call as the organ host encodes it".to_vec(),
            trigger: None,
            submitter: None,
            held_by: self.owner,
            held_at: self.vault.now_recorded_at(),
        }
    }

    fn hold(&self, artifact: EntityId) -> OrganWait {
        let wait = self.held_call(artifact);
        self.vault
            .hold_organ_wait(&wait, "no node can run sheets.export now")
            .expect("FIXTURE: the call is held under a fresh ref");
        wait
    }

    fn retain(&self, artifact: EntityId) -> oneiron::Result<()> {
        self.vault
            .retain_edit_proposal(
                &artifact,
                &proposal(HELD_REF),
                None,
                None,
                self.owner,
                self.vault.now_recorded_at(),
                None,
            )
            .map(drop)
    }
}

/// A proposal that passed its gate, built inline: retention and a discard
/// never re-parse its bytes.
fn proposal(run_ref: &str) -> EditProposal {
    EditProposal {
        run_ref: run_ref.to_owned(),
        format: OfficeFormat::Xlsx,
        new_bytes: b"edited workbook bytes".to_vec(),
        manifest: EditManifest {
            schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Xlsx,
            ops: Vec::new(),
            touched_parts: BTreeSet::new(),
            mutation_mode: MutationMode::Full,
            warnings: Vec::new(),
            pptx_holder_limits: None,
            slide_judgments: Vec::new(),
            paragraph_judgments: Vec::new(),
            paragraph_question: None,
            slide_question: None,
        },
        inspection: StructureSummary {
            format: OfficeFormat::Xlsx,
            sheets: Vec::new(),
            defined_names: Vec::new(),
            has_pivots: false,
            has_charts: false,
            has_macros: false,
            cross_sheet_dependencies: Vec::new(),
            unknown_parts: Vec::new(),
        },
        validation: ValidationReport {
            ok: true,
            checks: Vec::new(),
        },
        recalc: RecalcStatus::NotNeeded,
        calc_engine: None,
        base_version: None,
        base_content_hash: [0; 32],
        sheet_answers: None,
    }
}

fn owner_consent() -> SettleConsent {
    SettleConsent::OwnerConsent { brief_ref: None }
}

/// The refusal names the holding call and the door that releases it.
fn assert_names_the_hold(refusal: &oneiron::Error, door: &str) {
    let text = refusal.to_string();
    assert!(
        text.contains(HELD_REF) && text.contains(&format!("{ORGAN}.{VERB}")),
        "the {door} refusal names the holding call; got {text:?}"
    );
    assert!(
        text.contains(RELEASE_DOOR),
        "the {door} refusal names the door that releases the hold; got {text:?}"
    );
}

#[test]
fn organ_wait_ref_refuses_pending_landing_and_settle() {
    let fixture = Fixture::new();
    let artifact = fixture.artifact("forecast.xlsx", WORKBOOK_MEDIA_TYPE);
    fixture.hold(artifact);

    let retained = fixture.retain(artifact);
    let refusal = retained
        .expect_err("a ref an organ call holds refuses a retained proposal under it, got Ok");
    assert_names_the_hold(&refusal, "retain");

    let discarded = fixture.vault.settle_discard_edit_proposal(
        &artifact,
        &proposal(HELD_REF),
        &owner_consent(),
        fixture.owner,
        "not wanted",
        fixture.vault.now_recorded_at(),
    );
    let refusal =
        discarded.expect_err("a ref an organ call holds refuses a settlement under it, got Ok");
    assert_names_the_hold(&refusal, "settle");

    let waits = fixture.vault.organ_waits(&artifact).expect("read waits");
    assert_eq!(
        waits.len(),
        1,
        "the refused doors leave the call waiting: {waits:?}"
    );
    assert!(
        fixture
            .vault
            .blob_artifact_settlement(&artifact, HELD_REF)
            .expect("read the ledger")
            .is_none(),
        "the refused settle writes no ledger row"
    );
}

#[test]
fn a_failed_hold_names_its_release_door() {
    let fixture = Fixture::new();
    let artifact = fixture.artifact("forecast.xlsx", WORKBOOK_MEDIA_TYPE);
    fixture.hold(artifact);
    fixture
        .vault
        .fail_organ_wait(
            &artifact,
            HELD_REF,
            "the node ran the call and it failed",
            fixture.vault.now_recorded_at(),
        )
        .expect("record the failure");

    let refusal = fixture
        .retain(artifact)
        .expect_err("a failed hold still holds its ref until released, got Ok");

    assert_names_the_hold(&refusal, "retain");
    assert!(
        refusal.to_string().contains("ran and failed"),
        "the refusal says the call failed, so only a release ends it; got {refusal}"
    );
}

#[test]
fn a_released_wait_frees_its_ref() {
    let fixture = Fixture::new();
    let artifact = fixture.artifact("forecast.xlsx", WORKBOOK_MEDIA_TYPE);
    fixture.hold(artifact);

    let released = fixture
        .vault
        .release_organ_wait_as(&artifact, HELD_REF, &owner_consent(), fixture.owner)
        .expect("the owner releases the hold");

    assert!(released, "a hold stood under the ref");
    fixture
        .retain(artifact)
        .expect("a released ref takes a retained proposal");
}

#[test]
fn a_held_organ_calls_own_landing_consumes_its_wait() {
    let fixture = Fixture::new();
    let artifact = fixture.artifact("chart.png", "image/png");
    let wait = fixture.hold(artifact);
    let output = |run_ref: &str| oneiron::edit_settle::NativeOutput {
        run_ref: run_ref.to_owned(),
        name: "chart.png".to_owned(),
        media_type: "image/png".to_owned(),
        bytes: b"exported chart bytes".to_vec(),
        report: "{}".to_owned(),
        made_by: None,
    };
    let at = fixture.vault.now_recorded_at();

    let foreign = fixture
        .vault
        .propose_held_organ_output(&wait, &output("another-run"), at, &[]);
    assert!(
        foreign.is_err(),
        "a held call lands only its own files: {foreign:?}"
    );
    let other_call = OrganWait {
        call: b"another call under the same ref".to_vec(),
        ..wait.clone()
    };
    let refusal = fixture
        .vault
        .propose_held_organ_output(&other_call, &output(HELD_REF), at, &[])
        .expect_err("only the call that holds the ref lands under it");
    assert_names_the_hold(&refusal, "held landing");

    fixture
        .vault
        .propose_held_organ_output(&wait, &output(&format!("{HELD_REF}/1")), at, &[])
        .expect("a file of several lands under its own ref");
    assert_eq!(
        fixture
            .vault
            .organ_waits(&artifact)
            .expect("read waits")
            .len(),
        1,
        "a file under its own ref leaves the call's hold for the redrive's release"
    );

    fixture
        .vault
        .propose_held_organ_output(&wait, &output(HELD_REF), at, &[])
        .expect("the held call's own file lands under the ref it holds");

    assert!(
        fixture
            .vault
            .organ_waits(&artifact)
            .expect("read waits")
            .is_empty(),
        "the landing ended the hold in the same writer"
    );
    assert!(
        fixture
            .vault
            .pending_proposal(&artifact, HELD_REF)
            .expect("read the landing")
            .is_some(),
        "the file waits for Keep under the held ref"
    );
    let second = fixture
        .vault
        .propose_held_organ_output(&wait, &output(HELD_REF), at, &[]);
    assert!(
        second.is_err(),
        "the hold is consumed once; a second landing finds a waiting proposal: {second:?}"
    );
}
