//! FIX-LIST RESTORE-REFUSES-NULLED-ROW (ARCH-0069 "Export nulls a tainted
//! row"): a whole-vault archive carries a host-marked artifact with its body
//! nulled, and its manifest refuses that row's import as a redacted body. A
//! restore leaves that one row out and restores the rest, instead of refusing
//! the whole archive.
//!
//! Public doors only. Each destination opens at least one wall-clock second
//! after its source (sleep 1100 ms), as in `archive_import_reserved_claims.rs`.

use oneiron::batch::export::{ExportImportRefusal, ImportRefusalReason};
use oneiron::blob_artifact::BlobArtifactBody;
use oneiron::secret_lease::SecretTaintRef;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: TimeRange = TimeRange { start: 10, end: 10 };

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// A fresh seeded destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

/// An artifact put clean, as a build output is before its host marks it.
fn artifact(vault: &Vault, name: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new(name, "application/octet-stream"),
        AT,
        10,
    )?;
    Ok(id)
}

fn mark(vault: &Vault, id: &EntityId) -> TestResult {
    vault.mark_artifact_tainted(
        id,
        &[SecretTaintRef {
            secret_ref: "build-token".to_owned(),
            generation: 0,
        }],
    )?;
    Ok(())
}

fn refuses_as_redacted(refusals: &[ExportImportRefusal], id: &EntityId) -> bool {
    refusals.iter().any(|refusal| {
        matches!(
            refusal,
            ExportImportRefusal::Entity {
                entity_id,
                reason: ImportRefusalReason::RedactedBody,
            } if entity_id == &id.to_hex()
        )
    })
}

#[test]
fn a_whole_vault_restore_leaves_a_host_marked_artifact_out() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let kept = artifact(&source, "notes.bin")?;
    let marked = artifact(&source, "build.bin")?;
    mark(&source, &marked)?;
    let archive = source.export_whole_vault(true)?;
    assert!(
        refuses_as_redacted(&archive.manifest().import_refusals, &marked),
        "the archive carries the host-marked artifact only redacted"
    );

    let (_dest_dir, dest) = open_later_vault()?;
    let receipt = dest.import_whole_vault_archive(archive.bytes())?;
    assert!(
        dest.get(&marked)?.is_none(),
        "the restore leaves the nulled artifact out"
    );
    assert!(
        dest.get_blob_artifact(&kept)?.is_some(),
        "the restore brings the rest of the archive back"
    );
    assert!(
        receipt.omitted_entities >= 1,
        "the receipt counts the nulled artifact as omitted: {receipt:?}"
    );
    Ok(())
}

#[test]
fn a_restore_over_a_held_artifact_keeps_the_destinations_row() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let marked = artifact(&source, "build.bin")?;
    let clean = source.export_whole_vault(true)?;
    let (_dest_dir, dest) = open_later_vault()?;
    dest.import_whole_vault_archive(clean.bytes())?;
    let held = dest
        .get(&marked)?
        .ok_or("the first restore brings the clean artifact")?;

    mark(&source, &marked)?;
    let archive = source.export_whole_vault(true)?;
    let receipt = dest.import_whole_vault_archive(archive.bytes())?;
    assert_eq!(
        dest.get(&marked)?,
        Some(held),
        "the destination keeps its own row of the artifact"
    );
    assert!(
        receipt.omitted_entities >= 1,
        "the receipt counts the nulled archived row as omitted: {receipt:?}"
    );
    Ok(())
}
