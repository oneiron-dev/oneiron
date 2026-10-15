//! #1465 R3 checks (Engine ruling 1): an erase is never walked back, so only typed evidence of one
//! widens it. A hard-delete marker a peer can cause on an id it controls teaches no bytes and no
//! erased ASSET, while the owner's own erase still reaches every reference (the checks above).

use super::*;
use crate::deletion::TombstoneReason;

/// A vault holding a live artifact with one version, and a record of another kind a peer may
/// delete, deleted: its hard-delete marker stands. Returns the vault, the artifact's version and
/// the deleted record.
fn live_bytes_beside_a_deleted_record() -> Result<(Shared, EntityId)> {
    let fixture = Shared::open()?;
    let record = EntityId::now();
    fixture.vault.put_entity(
        &record,
        ENTITY_TYPE_PERSON,
        at(20),
        20,
        b"a peer's own record",
    )?;
    apply_tombstone(
        &fixture.vault,
        &record,
        &tombstone(TombstoneReason::UserHardDelete),
    )?;
    Ok((fixture, record))
}

/// A vault holding, at `id`, the body of `claim` read from `source` with its subject replaced by
/// `subject`: a crafted `blob.version` claim as a peer would send it.
fn crafted_claim(
    source: &Vault,
    claim: &EntityId,
    id: &EntityId,
    subject: EntityId,
) -> Result<(tempfile::TempDir, Vault)> {
    let raw = source.get_raw(claim)?.expect("the claim is stored");
    let mut body =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)?;
    body.subject = crate::claim::ClaimSubject::Entity(subject);
    let (dir, peer) = open_test_vault_with(embedding_test_config());
    peer.batch()
        .put_replicated(
            id,
            crate::registry::ENTITY_TYPE_CLAIM,
            at(30),
            30,
            &crate::claim::encode_claim_body(&body)?,
        )
        .commit()?;
    Ok((dir, peer))
}

fn intact(fixture: &Shared) -> Result<bool> {
    let txn = fixture.vault.store.env.read_txn()?;
    Ok(
        content_erased(&fixture.vault.store, &txn, &fixture.shared.content_hash)?.is_none()
            && !reference_erased(&fixture.vault.store, &txn, &fixture.shared.claim_id)?
            && fixture
                .vault
                .read_blob_artifact_version(&fixture.other, 2)?
                == Some(SHARED.to_vec())
            && fixture.vault.get_raw(&fixture.asset()?)?.is_some(),
    )
}

/// Bug repro (#1465 R3, Sol 2): a crafted `blob.version` claim at the id of a record the peer
/// deleted, naming live bytes, erases nothing: the record's hard-delete marker says nothing
/// about any bytes.
#[test]
fn a_crafted_reference_at_a_deleted_record_erases_no_bytes() -> Result<()> {
    let (fixture, record) = live_bytes_beside_a_deleted_record()?;
    let (_dir, peer) = crafted_claim(
        &fixture.vault,
        &fixture.shared.claim_id,
        &record,
        fixture.other,
    )?;
    assert_eq!(replicate(&peer, &fixture.vault, &[record])?, [false]);
    assert!(
        intact(&fixture)?,
        "a crafted claim at a deleted record erased live bytes"
    );
    Ok(())
}

/// Bug repro (#1465 R3, Sol 2): a claim naming a deleted record as its artifact erases nothing:
/// only an artifact whose version chain was recorded here is an erased artifact's subject.
#[test]
fn a_reference_naming_a_deleted_record_as_its_artifact_erases_no_bytes() -> Result<()> {
    let (fixture, record) = live_bytes_beside_a_deleted_record()?;
    let late = EntityId::now();
    let (_dir, peer) = crafted_claim(&fixture.vault, &fixture.shared.claim_id, &late, record)?;
    replicate(&peer, &fixture.vault, &[late])?;
    assert!(
        intact(&fixture)?,
        "a claim naming a deleted record as its artifact erased live bytes"
    );
    let txn = fixture.vault.store.env.read_txn()?;
    assert!(!reference_erased(&fixture.vault.store, &txn, &late)?);
    Ok(())
}

/// Bug repro (#1465 R3, Sol 3; Astra 4): a DerivedFrom edge from a live text to a deleted record
/// of another kind leaves the text readable: only an ASSET a hard erase's walk took here takes
/// the texts derived from it.
#[cfg(feature = "sync")]
#[test]
fn a_derived_from_edge_to_a_deleted_record_leaves_the_text() -> Result<()> {
    let (fixture, record) = live_bytes_beside_a_deleted_record()?;
    let vault = &fixture.vault;
    let text = EntityId::now();
    vault.put_entity(
        &text,
        ENTITY_TYPE_ASSET_TEXT,
        at(21),
        21,
        b"words of a live text",
    )?;
    let scrubbed = vault.with_write_txn_grouped(|txn| {
        vault.scrub_text_derived_from_erased_in_txn(txn, &text, &record)
    })?;
    assert!(!scrubbed, "an edge to a deleted record took the text");
    assert_eq!(
        vault
            .get_raw(&text)?
            .map(|raw| raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec()),
        Some(b"words of a live text".to_vec())
    );
    Ok(())
}

/// Bug repro (#1465 R3, Engine ruling 1 (i) and (ii), both failing): a record of another kind can
/// stand at the id the bytes' hash names, and a peer can hard-delete it. A vault that holds that
/// marker and then learns of live bytes neither erases them nor tombstones their references,
/// which would carry the erase to every vault holding them.
#[test]
fn a_deleted_record_at_the_bytes_id_erases_no_bytes() -> Result<()> {
    let origin = Shared::open()?;
    let asset = origin.asset()?;
    let (_dir, replica) = open_test_vault_with(embedding_test_config());
    replica.put_entity(
        &asset,
        ENTITY_TYPE_PERSON,
        at(20),
        20,
        b"a peer's own record",
    )?;
    apply_tombstone(
        &replica,
        &asset,
        &tombstone(TombstoneReason::UserHardDelete),
    )?;
    replicate(
        &origin.vault,
        &replica,
        &[origin.person, origin.other, origin.shared.claim_id],
    )?;
    assert!(
        replica
            .get_raw(&origin.shared.claim_id)?
            .is_some_and(|raw| raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN),
        "a live reference arriving after the marker was refused"
    );
    let txn = replica.store.env.read_txn()?;
    assert!(content_erased(&replica.store, &txn, &origin.shared.content_hash)?.is_none());
    assert!(!reference_erased(
        &replica.store,
        &txn,
        &origin.shared.claim_id
    )?);
    drop(txn);
    assert!(
        !fenced(&replica, &origin.shared.claim_id)?,
        "the live reference was fenced"
    );
    replica.put_entity(&EntityId::now(), ENTITY_TYPE_ASSET, at(30), 30, SHARED)?;
    Ok(())
}

/// Bug repro (#1465 R3, Astra 2): a late reference widens an erase only as the replicated put
/// would admit it. The same claim carrying a forged machine signature, which that put refuses,
/// leaves the bytes it names and every reference to them as they were.
#[test]
fn a_forged_machine_claim_widens_no_erase() -> Result<()> {
    let (origin, _dir, appender, late) = super::late::erased_with_late_reference()?;
    let vault = &origin.vault;
    let raw = appender.get_raw(&late)?.expect("the late reference");
    let header = EntityMetadataHeader::parse(&raw).expect("stored header");
    let mut body =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)?;
    let mut evidence = match body.evidence.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    evidence.push((
        rmpv::Value::from("machine_signature"),
        rmpv::Value::Binary(b"forged".to_vec()),
    ));
    body.evidence = Some(rmpv::Value::Map(evidence));
    let data = crate::claim::encode_claim_body(&body)?;
    let forged = EntityId::now();
    let refused = vault.with_write_txn_grouped(|txn| {
        vault.refuse_erased_blob_arrival_in_txn(txn, &forged, &header, &data)
    })?;
    assert!(!refused, "the gate acted on a body the put refuses");
    let txn = vault.store.env.read_txn()?;
    assert!(
        content_erased(&vault.store, &txn, blake3::hash(OTHER_ONLY).as_bytes())?.is_none(),
        "a forged claim erased the bytes it names"
    );
    drop(txn);
    assert_eq!(
        vault.read_blob_artifact_version(&origin.other, 1)?,
        Some(OTHER_ONLY.to_vec())
    );
    Ok(())
}

fn fenced(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::deletion::ROW_DELETION_FENCE.contains(&vault.store, &txn, &HexId(*id))
}
