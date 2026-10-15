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
            header.entity_type,
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
    let claim = origin.erased_version.claim_id;
    let (_dir, replica) = open_test_vault_with(embedding_test_config());
    apply_tombstone(
        &replica,
        &origin.erased,
        &tombstone(TombstoneReason::GdprDelete),
    )?;
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

/// Bug repro (#1465 R2, Sol F1 and Astra F4): a replica that applied the tombstone of the erased
/// bytes' ASSET before any body named them learns the bytes from the first body that does. A
/// reference to them arriving later, at any id, is pierced on arrival, and the bytes are refused
/// at a fresh id.
#[test]
fn an_asset_tombstone_first_teaches_the_bytes_to_every_later_body() -> Result<()> {
    let origin = Shared::open()?;
    let (_dir, replica) = open_test_vault_with(embedding_test_config());
    apply_tombstone(
        &replica,
        &origin.asset()?,
        &tombstone(TombstoneReason::GdprDelete),
    )?;
    assert_eq!(
        replicate(
            &origin.vault,
            &replica,
            &[origin.person, origin.other, origin.shared.claim_id]
        )?,
        [true, true, false],
        "a reference to the erased bytes materialized"
    );
    {
        let txn = replica.store.env.read_txn()?;
        assert!(reference_erased(
            &replica.store,
            &txn,
            &origin.shared.claim_id
        )?);
        assert!(content_erased(&replica.store, &txn, &origin.shared.content_hash)?.is_some());
    }
    assert!(
        matches!(
            replica.put_entity(&EntityId::now(), ENTITY_TYPE_ASSET, at(30), 30, SHARED),
            Err(Error::Artifact(ArtifactError::BlobContentErased))
        ),
        "the erased bytes were stored at a fresh id"
    );
    Ok(())
}

/// Bug repro (#1465 R2, Sol F9 and Astra F7): a late reference whose walk would tear a carrier
/// under a legal hold waits. Its arrival is skipped with nothing marked, so the window's next pass
/// retries it; it never fails the pass. Once the hold is released, the next arrival pierces.
#[test]
fn a_held_carrier_defers_a_late_reference_without_failing_the_pass() -> Result<()> {
    let origin = Shared::open()?;
    let (_dir, replica) = open_test_vault_with(embedding_test_config());
    let held = origin.shared.claim_id;
    let late = origin.erased_version.claim_id;
    replicate(
        &origin.vault,
        &replica,
        &[origin.person, origin.other, held, origin.erased],
    )?;
    apply_tombstone(
        &replica,
        &origin.erased,
        &tombstone(TombstoneReason::GdprDelete),
    )?;
    replica.set_gate_decision_partition_hold(Some(*held.as_bytes()), true)?;
    assert!(
        arrive(&origin.vault, &replica, &late)?,
        "a held carrier let the late reference materialize"
    );
    assert!(!fenced(&replica, &late)? && !fenced(&replica, &held)?);
    {
        let txn = replica.store.env.read_txn()?;
        assert!(!reference_erased(&replica.store, &txn, &held)?);
        assert!(content_erased(&replica.store, &txn, &origin.shared.content_hash)?.is_none());
    }
    replica.set_gate_decision_partition_hold(Some(*held.as_bytes()), false)?;
    assert!(arrive(&origin.vault, &replica, &late)?);
    assert!(erased(replica.read_blob_artifact_version(&origin.other, 2)));
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
