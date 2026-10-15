//! #1465 R2 checks: the ingest gate, a late reference under a hold, and the list and put doors.

use super::*;
use crate::deletion::TombstoneReason;

fn arrive(source: &Vault, target: &Vault, id: &EntityId) -> Result<bool> {
    let raw = source.get_raw(id)?.expect("stored at the origin");
    let header = EntityMetadataHeader::parse(&raw).expect("stored header");
    target.with_write_txn_grouped(|txn| {
        target.refuse_erased_blob_arrival_in_txn(
            txn,
            id,
            &header,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
    })
}

fn fenced(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::deletion::ROW_DELETION_FENCE.contains(&vault.store, &txn, &HexId(*id))
}

/// Bug repro (#1465 R2, Sol F3 and Astra F1): a late reference at an id another kind holds is the
/// put's to refuse. The ingest gate leaves that row as it was: no fence, no erased mark.
#[test]
fn a_late_reference_at_an_id_another_kind_holds_leaves_that_row_alone() -> Result<()> {
    let origin = Shared::open()?;
    let claim = origin.shared.claim_id;
    let (_dir, replica) = open_test_vault_with(embedding_test_config());
    // The replica's own walk takes the bytes, so a reference to them arrives late.
    replicate(
        &origin.vault,
        &replica,
        &[origin.person, origin.erased, origin.erased_version.claim_id],
    )?;
    apply_tombstone(
        &replica,
        &origin.erased,
        &tombstone(TombstoneReason::GdprDelete),
    )?;
    {
        let txn = replica.store.env.read_txn()?;
        assert!(content_erased(&replica.store, &txn, &origin.shared.content_hash)?.is_some());
    }
    replica.put_entity(&claim, ENTITY_TYPE_PERSON, at(20), 20, b"someone else")?;
    assert_eq!(replicate(&origin.vault, &replica, &[claim])?, [false]);
    assert_eq!(
        replica
            .get_raw(&claim)?
            .map(|raw| raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec()),
        Some(b"someone else".to_vec())
    );
    assert!(
        !fenced(&replica, &claim)?,
        "the gate fenced a row it does not own"
    );
    let txn = replica.store.env.read_txn()?;
    assert!(!reference_erased(&replica.store, &txn, &claim)?);
    Ok(())
}

/// The erasing vault of [`Shared`] after a hard erase of `erased`, and a late reference to bytes
/// the erase did not reach yet: a `blob.version` claim naming `erased` with `OTHER_ONLY`, as a
/// second vault appended them to the artifact before the erase reached it. `other` still holds
/// `OTHER_ONLY` as v1 here.
pub(super) fn erased_with_late_reference() -> Result<(Shared, tempfile::TempDir, Vault, EntityId)> {
    let origin = Shared::open()?;
    let (dir, appender) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &appender, &[origin.person, origin.erased])?;
    let late = appender
        .append_blob_artifact_version(
            &origin.erased,
            OTHER_ONLY,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(origin.person, EdgeActorClass::Human),
            at(15),
            15,
        )?
        .claim_id;
    origin
        .vault
        .delete_entity_with_reason(&origin.erased, DeleteReason::GdprDelete)?;
    Ok((origin, dir, appender, late))
}

/// Bug repro (#1465 R2, Sol F9 and Astra F7): a late reference whose walk would tear a carrier
/// under a legal hold waits. Its arrival is skipped with nothing marked, so the window's next pass
/// retries it; it never fails the pass. Once the hold is released, the next arrival pierces.
#[test]
fn a_held_carrier_defers_a_late_reference_without_failing_the_pass() -> Result<()> {
    let (origin, _dir, appender, late) = erased_with_late_reference()?;
    let vault = &origin.vault;
    let held = vault
        .blob_artifact_version_metadata(&origin.other, 1)?
        .expect("the other artifact's first version")
        .claim_id;
    let hash = *blake3::hash(OTHER_ONLY).as_bytes();
    vault.set_gate_decision_partition_hold(Some(*held.as_bytes()), true)?;
    assert!(
        arrive(&appender, vault, &late)?,
        "a held carrier let the late reference materialize"
    );
    assert!(!fenced(vault, &late)? && !fenced(vault, &held)?);
    {
        let txn = vault.store.env.read_txn()?;
        assert!(!reference_erased(&vault.store, &txn, &held)?);
        assert!(content_erased(&vault.store, &txn, &hash)?.is_none());
    }
    assert_eq!(
        vault.read_blob_artifact_version(&origin.other, 1)?,
        Some(OTHER_ONLY.to_vec())
    );
    vault.set_gate_decision_partition_hold(Some(*held.as_bytes()), false)?;
    assert!(arrive(&appender, vault, &late)?);
    assert!(erased(vault.read_blob_artifact_version(&origin.other, 1)));
    Ok(())
}

/// Bug repro (#1465 R2, Astra F9): a version listed as erased names nothing of its bytes, and an
/// agent run's reference is such a name.
#[test]
fn an_erased_version_lists_no_run_reference() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let person = EntityId::now();
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at(10), 10, b"uploader")?;
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let mut artifacts = Vec::new();
    for (provenance, learned) in [
        (BlobVersionProvenance::UserUpload, 11),
        (
            BlobVersionProvenance::AgentRun {
                run_ref: "run reference placeholder".into(),
            },
            12,
        ),
    ] {
        let id = EntityId::now();
        vault.put_blob_artifact(
            &id,
            &BlobArtifactBody::new("shared.bin", "application/octet-stream"),
            at(10),
            10,
        )?;
        vault.append_blob_artifact_version(
            &id,
            SHARED,
            &provenance,
            actor,
            at(learned),
            learned,
        )?;
        artifacts.push(id);
    }
    vault.delete_entity_with_reason(&artifacts[0], DeleteReason::GdprDelete)?;
    let listed = vault.blob_artifact_versions(&artifacts[1])?;
    assert!(listed[0].erased);
    assert_eq!(listed[0].provenance.run_ref(), Some(""));
    Ok(())
}

/// Bug repro (#1465 R2, Astra F3): a text a hard erase scrubbed from the bytes is not written
/// again by a local put: that is no sanctioned recreation, it brings the erased words back.
#[test]
fn a_local_put_over_a_scrubbed_derived_text_is_refused() -> Result<()> {
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let derived = EntityId::now();
    vault.put_entity(
        &derived,
        ENTITY_TYPE_ASSET_TEXT,
        at(14),
        14,
        b"words from the bytes",
    )?;
    vault.put_edge(&derived, EdgeKind::DerivedFrom, &fixture.asset()?, 1.0)?;
    vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    assert!(
        matches!(
            vault.put_entity(
                &derived,
                ENTITY_TYPE_ASSET_TEXT,
                at(40),
                40,
                b"words from the bytes"
            ),
            Err(Error::Artifact(ArtifactError::BlobContentErased))
        ),
        "a local put wrote a scrubbed derived text back"
    );
    Ok(())
}
