//! Whole-vault archive restore of a vault that holds a maintenance row no
//! import door restores (L10-23, OF-222).
//!
//! On main the whole-vault export writes every ISSUE, RECEIPT_RECORD,
//! WORLD_KEY_PAD and EMBEDDING_SETUP row through its raw entity walk, the
//! manifest lists none of them as an import omission, and the import stops
//! on the first such row at the public entity-type check: one row aborts the
//! whole restore. Each kind is now archive-only with a declared reason, so the
//! rest of the vault restores and the manifest names what was left out.
//!
//! * `a_fresh_owner_vault_restores_whole_as_its_owner`: the control. The same
//!   source vault with no report restores on main as well.
//! * `an_archive_with_an_issue_row_restores_whole_as_its_owner`: the owner
//!   files one report (`Memory::report` writes one ISSUE row); the owner's
//!   restore into a fresh vault succeeds, brings the ISSUE back with the
//!   source's actor, request, filing time and review as an
//!   `OwnerArchiveRestore`, and restores the PERSON it is about. The manifest
//!   still lists the ISSUE as `LocalHistoryNotRestored`.
//! * `the_actorless_import_of_an_issue_row_archive_succeeds`: the same
//!   archive through the actorless import.
//! * `an_archive_with_a_declared_embedding_space_restores_whole_as_its_owner`:
//!   a seeded embedding space publishes EMBEDDING_SETUP rows; the restore
//!   leaves them out (`LocalProjectionNotRestored`), declares the space from
//!   the archive's embedding-space section and publishes its own rows again.
//!
//! Public doors only; neutral fixtures (`owen`); vaults in tempdirs. Each
//! destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), as in `archive_import_reserved_claims.rs`. Reasons are compared
//! in their `Debug` form.
//! `cargo test --locked -p oneiron --all-features --test archive_import_maintenance_kinds`.

use std::collections::BTreeSet;
use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::{EmbeddingSpace, InputKind};
use oneiron::feedback::{IssueCategory, ReportKind, ReportRequest};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A source vault opened as the report door's own test opens it
/// (`report_route_one_reader.rs`).
fn open_source_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open source vault");
    (dir, vault)
}

/// A fresh destination whose engine-seed seconds differ from the source's:
/// any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault, id: &EntityId, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode map body");
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("ordinary row");
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// The manifest's import omissions of `archive`, as (entity id, reason in
/// its `Debug` form).
fn import_omissions(reader: &Vault, archive: &[u8]) -> Vec<(String, String)> {
    reader
        .read_whole_vault_archive(archive)
        .expect("read the archive")
        .manifest
        .import_omissions
        .iter()
        .map(|omission| (omission.entity_id.clone(), format!("{:?}", omission.reason)))
        .collect()
}

/// Restores `archive` into a fresh vault as that vault's bound owner, the
/// door the CLI `import archive` takes when the owner authenticates.
fn restore_into_fresh_vault_as_owner(
    archive: &[u8],
) -> (
    tempfile::TempDir,
    Vault,
    oneiron::Result<WholeVaultImportReceipt>,
) {
    let (dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let restored = dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner);
    (dir, dest, restored)
}

/// A source vault holding the PERSON `owen`, and, when it filed a report,
/// the owner's report about `owen` (one ISSUE row); `archive` is its whole
/// archive.
struct Source {
    vault: Vault,
    owen: EntityId,
    issue: Option<EntityId>,
    archive: Vec<u8>,
    // Close the vault before removing its directory.
    _dir: tempfile::TempDir,
}

fn source_with_person(report: bool) -> Source {
    let (dir, vault) = open_source_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owen = EntityId::now();
    put_person(&vault, &owen, "owen");
    let issue = report.then(|| {
        let receipt = vault
            .memory(owner, EdgeActorClass::Human)
            .report(ReportRequest {
                subject_ref: owen.to_hex(),
                category: IssueCategory::SkillDefect,
                kind: ReportKind::Problem,
                note: Some("The summary of owen names the wrong city.".to_owned()),
                evidence_refs: Vec::new(),
                why: None,
                proposal: None,
            })
            .expect("the owner's report lands");
        let issue = EntityId::from_hex(&receipt.issue_ref).expect("issue id");
        assert!(
            vault
                .report_issue(&issue)
                .expect("read the issue")
                .is_some(),
            "the source holds the ISSUE row"
        );
        issue
    });
    let archive = export_whole(&vault);
    Source {
        vault,
        owen,
        issue,
        archive,
        _dir: dir,
    }
}

#[test]
fn a_fresh_owner_vault_restores_whole_as_its_owner() {
    let source = source_with_person(false);

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&source.archive);

    if let Err(error) = restored {
        panic!("a fresh owner vault's whole archive must restore: {error:?}");
    }
    assert_eq!(
        dest.get_entity_type(&source.owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON)
    );
}

#[test]
fn an_archive_with_an_issue_row_restores_whole_as_its_owner() {
    let source = source_with_person(true);
    let issue = source.issue.expect("the source filed a report");
    let expected = source
        .vault
        .report_issue(&issue)
        .expect("read the source issue")
        .expect("the source holds the ISSUE row");

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&source.archive);

    let _receipt = match restored {
        Ok(receipt) => receipt,
        Err(error) => {
            panic!("the owner's whole archive holding one ISSUE row must restore: {error:?}")
        }
    };
    assert_eq!(
        dest.get_entity_type(&source.owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON),
        "the rest of the vault restores"
    );
    let recovered = dest
        .report_issue(&issue)
        .expect("read the restored issue")
        .expect("the owner's restore must bring the ISSUE row back");
    assert_eq!(
        recovered.actor_ref, expected.actor_ref,
        "the restored report keeps the source actor"
    );
    assert_eq!(
        recovered.request, expected.request,
        "the restored report keeps the full source request"
    );
    assert_eq!(
        recovered.received_at, expected.received_at,
        "the restored report keeps the source filing time"
    );
    assert_eq!(
        recovered.review, expected.review,
        "the restored report keeps the source review"
    );
    assert_eq!(
        recovered.origin,
        oneiron::feedback::ReportIssueOrigin::OwnerArchiveRestore,
        "the restored report is marked as an owner-archive restore"
    );
    let omissions = import_omissions(&source.vault, &source.archive);
    assert!(
        omissions
            .iter()
            .any(|(id, reason)| *id == issue.to_hex() && reason == "LocalHistoryNotRestored"),
        "the manifest names the ISSUE row as LocalHistoryNotRestored: {omissions:?}"
    );
}

#[test]
fn the_actorless_import_of_an_issue_row_archive_succeeds() {
    let source = source_with_person(true);
    let issue = source.issue.expect("the source filed a report");
    let (_dest_dir, dest) = open_later_vault();

    if let Err(error) = dest.import_whole_vault_archive_from(Cursor::new(&source.archive)) {
        panic!("an actorless import of an archive holding one ISSUE row must succeed: {error:?}");
    }

    assert_eq!(
        dest.get_entity_type(&source.owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON)
    );
    assert!(
        dest.report_issue(&issue).expect("read the issue").is_none(),
        "the ISSUE row stays archive data"
    );
}

#[test]
fn an_archive_with_a_declared_embedding_space_restores_whole_as_its_owner() {
    let (_source_dir, source) = open_source_vault();
    let _owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let owen = EntityId::now();
    put_person(&source, &owen, "owen");
    let space = EmbeddingSpace {
        id: "archive-probe-embedder@r1@own_server".to_owned(),
        dimensions: 4,
        accepts: BTreeSet::from([InputKind::Text]),
        query_towers: BTreeSet::from([InputKind::Text]),
        evidence: None,
    };
    source
        .seed_embedding_space(space.clone())
        .expect("the host seeds an embedding space");
    let archive = export_whole(&source);

    let (_dest_dir, dest, restored) = restore_into_fresh_vault_as_owner(&archive);

    if let Err(error) = restored {
        panic!("the owner's whole archive holding EMBEDDING_SETUP rows must restore: {error:?}");
    }
    assert_eq!(
        dest.get_entity_type(&owen).expect("read owen"),
        Some(ENTITY_TYPE_PERSON)
    );
    let spaces = dest.embedding_spaces().expect("the restored spaces");
    assert!(
        spaces.iter().any(|held| held.id == space.id),
        "the restore declares the archived space from its section: {spaces:?}"
    );
    let omissions = import_omissions(&source, &archive);
    assert!(
        omissions
            .iter()
            .any(|(_, reason)| reason == "LocalProjectionNotRestored"),
        "the manifest names the raw EMBEDDING_SETUP row as LocalProjectionNotRestored: {omissions:?}"
    );
}
