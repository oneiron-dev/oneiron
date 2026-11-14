//! Census L6-32 (ARCH-0069 `#exhaust-taint-open`; Engine RULING
//! L6-32-CARRIER = A): a host's taint mark rides the BLOB_ARTIFACT body, the
//! one carrier that replicates. A synced replica reads the mark and exports
//! the artifact redacted, a second mark keeps each secret's lowest
//! generation, and a mark on any other row is refused.
//!
//! Public doors only, plus `test_doors::host_taint_replica` for the
//! own-device replay.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::batch::export::{ExportImportRefusal, ImportRefusalReason};
use oneiron::blob_artifact::BlobArtifactBody;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_lease::SecretTaintRef;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::host_taint_replica::replicate_entities;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SECRET: &str = "build-token";
const OTHER: &str = "deploy-key";
const AT: TimeRange = TimeRange { start: 10, end: 10 };

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn taint(secret_ref: &str, generation: u32) -> SecretTaintRef {
    SecretTaintRef {
        secret_ref: secret_ref.to_owned(),
        generation,
    }
}

/// An artifact put clean, as a build output is before its host marks it.
fn untainted_artifact(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("build.bin", "application/octet-stream"),
        AT,
        10,
    )?;
    Ok(id)
}

#[test]
fn a_host_mark_reaches_a_synced_replica() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let marked = source.artifact_taint_refs(&id)?;
    assert_eq!(
        marked,
        vec![taint(SECRET, 0)],
        "the vault that took the mark reads it"
    );

    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;
    assert_eq!(
        replica.artifact_taint_refs(&id)?,
        marked,
        "the replica reads the host's mark from the replicated artifact row"
    );
    assert!(
        replica.artifact_taint_state(&id)?.is_tainted(),
        "the replica's artifact is not clean"
    );
    let body = replica
        .get_blob_artifact(&id)?
        .ok_or("the replica holds the artifact")?;
    assert_eq!(
        (body.name.as_str(), body.media_type.as_str()),
        ("build.bin", "application/octet-stream"),
        "the mark keeps the body's other keys"
    );
    assert_eq!(body.secret_taint_refs, marked, "the body is the carrier");
    Ok(())
}

#[test]
fn a_replica_exports_a_host_marked_artifact_redacted() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;

    let bundle: serde_json::Value =
        serde_json::from_slice(&replica.export_entity_bundle_json(&[id])?)?;
    let hex = id.to_hex();
    let row = bundle["entities"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["id"].as_str() == Some(hex.as_str()))
        })
        .ok_or("the replica's bundle carries the artifact row")?;
    assert!(
        row["body"].is_null(),
        "the replica nulls the host-marked artifact's body: {row}"
    );
    assert_eq!(
        bundle["manifest"]["secrets_nulled"]["payloads"],
        serde_json::Value::Bool(true),
        "and its manifest says the payloads are nulled: {}",
        bundle["manifest"]
    );
    Ok(())
}

#[test]
fn a_second_host_mark_keeps_each_secrets_lowest_generation() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 1)])?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 3), taint(OTHER, 0)])?;
    // The carrier keeps the refs sorted by secret name, as the read does.
    let want = vec![taint(SECRET, 1), taint(OTHER, 0)];
    assert_eq!(
        source.artifact_taint_refs(&id)?,
        want,
        "the marks are a union, and a secret named twice keeps its lowest generation"
    );

    let (_replica_dir, replica) = open_vault()?;
    replicate_entities(&source, &replica, &[id])?;
    assert_eq!(
        replica.artifact_taint_refs(&id)?,
        want,
        "the replica reads the same union"
    );
    Ok(())
}

#[test]
fn a_host_mark_on_a_row_that_is_no_artifact_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, AT, 10, b"owen")?;
    let absent = EntityId::now();
    for id in [person, absent] {
        assert!(
            vault
                .mark_artifact_tainted(&id, &[taint(SECRET, 0)])
                .is_err(),
            "a host mark rides a blob artifact only: {id:?}"
        );
        assert_eq!(
            vault.artifact_taint_refs(&id)?,
            Vec::<SecretTaintRef>::new(),
            "a refused mark writes nothing: {id:?}"
        );
    }
    Ok(())
}

/// Guard, not a red case: the whole-vault archive carries a host-marked
/// artifact only redacted, and its manifest refuses the row's import as a
/// redacted body, on main (the sidecar) as on this head (the body carrier).
/// A restore of that archive fails on main today (FIX-LIST
/// RESTORE-REFUSES-NULLED-ROW), so the guard reads the archive's manifest.
#[test]
fn a_host_marked_artifact_goes_redacted_in_the_whole_vault_archive() -> TestResult {
    let (_source_dir, source) = open_vault()?;
    let id = untainted_artifact(&source)?;
    source.mark_artifact_tainted(&id, &[taint(SECRET, 0)])?;
    let archive = source.export_whole_vault(true)?;
    let refusals = &archive.manifest().import_refusals;
    assert!(
        refusals.iter().any(|refusal| matches!(
            refusal,
            ExportImportRefusal::Entity {
                entity_id,
                reason: ImportRefusalReason::RedactedBody,
            } if entity_id == &id.to_hex()
        )),
        "the archive carries the host-marked artifact only redacted: {refusals:?}"
    );
    Ok(())
}
