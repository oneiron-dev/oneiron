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
    let marked = {
        let txn = fixture.vault.store.env.read_txn()?;
        content_erased(&fixture.vault.store, &txn, &fixture.shared.content_hash)?.is_some()
            || reference_erased(&fixture.vault.store, &txn, &fixture.shared.claim_id)?
    };
    Ok(!marked
        && fixture
            .vault
            .read_blob_artifact_version(&fixture.other, 2)?
            == Some(SHARED.to_vec())
        && fixture.vault.get_raw(&fixture.asset()?)?.is_some())
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

/// Bug repro (#1465 R3 Astra 2, R4 Astra F1, R5 Astra P1): a late reference widens an erase only
/// as far as the replicated put would take it. The same claim with a forged machine signature, with
/// its occurred range reversed, or replacing a live claim of another record scope, all of which
/// the put refuses, leaves the bytes it names and every reference to them as they were.
#[test]
fn a_late_reference_the_put_refuses_widens_no_erase() -> Result<()> {
    let (origin, _dir, appender, late) = super::late::erased_with_late_reference()?;
    let vault = &origin.vault;
    let raw = appender.get_raw(&late)?.expect("the late reference");
    let header = EntityMetadataHeader::parse(&raw).expect("stored header");
    let data = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let mut body = crate::claim::decode_claim_body(data, true)?;
    let mut evidence = match body.evidence.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    evidence.push((
        rmpv::Value::from("machine_signature"),
        rmpv::Value::Binary(b"forged".to_vec()),
    ));
    body.evidence = Some(rmpv::Value::Map(evidence));
    let forged = crate::claim::encode_claim_body(&body)?;
    let mut reversed = header;
    reversed.occurred_start = header.occurred_end + 1;
    // A live claim in another project: the put refuses the restamp after the claim's projection.
    let existing = EntityId::now();
    let mut prior = crate::claim::decode_claim_body(data, true)?;
    assert_ne!(prior.scope_project, origin.person);
    prior.predicate = "fixture.topic".to_owned();
    prior.scope_project = origin.person;
    vault
        .batch()
        .put_replicated(
            &existing,
            header.entity_type,
            crate::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            &crate::claim::encode_claim_body(&prior)?,
        )
        .commit()?;
    for (case, id, header, data) in [
        (
            "a forged machine signature",
            EntityId::now(),
            header,
            forged.as_slice(),
        ),
        ("a reversed occurred range", EntityId::now(), reversed, data),
        ("a restamp of a live claim", existing, header, data),
    ] {
        let refused = vault.with_write_txn_grouped(|txn| {
            vault.refuse_erased_blob_arrival_in_txn(txn, &id, &header, data)
        })?;
        assert!(!refused, "{case}: the gate acted on a body the put refuses");
        let txn = vault.store.env.read_txn()?;
        assert!(
            content_erased(&vault.store, &txn, blake3::hash(OTHER_ONLY).as_bytes())?.is_none(),
            "{case}: the claim erased the bytes it names"
        );
        drop(txn);
        assert_eq!(
            vault.read_blob_artifact_version(&origin.other, 1)?,
            Some(OTHER_ONLY.to_vec()),
            "{case}"
        );
    }
    Ok(())
}

/// Bug repro (#1465 R4, Astra F2): a vault that holds an artifact only as a replica, and erases
/// it, still takes the bytes a version of it that arrives later names: the row the erase tore was
/// an artifact, typed evidence as a version chain recorded here is.
#[test]
fn a_late_version_of_a_replicated_artifact_the_owner_erased_takes_its_bytes() -> Result<()> {
    let origin = Shared::open()?;
    let (_dir, vault, other, _shared) = only_other()?;
    replicate(
        &origin.vault,
        &vault,
        &[origin.person, origin.erased, origin.erased_version.claim_id],
    )?;
    vault.delete_entity_with_reason(&origin.erased, DeleteReason::GdprDelete)?;
    let (_appender_dir, appender) = open_test_vault_with(embedding_test_config());
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
    assert_eq!(replicate(&appender, &vault, &[late])?, [false]);
    assert!(
        erased(vault.read_blob_artifact_version(&other, 1)),
        "the late version's bytes outlived the owner's erase of its artifact"
    );
    Ok(())
}

/// Bug repro (#1465 R4, Astra F3): a text an ordinary delete fenced before its DerivedFrom edge
/// and its body arrived still takes a hard erase's own fence on arrival: a local put of it is
/// refused, as for any text the erase took, also after the ordinary delete is replayed again
/// (#1465 R5, Astra P2).
#[cfg(feature = "sync")]
#[test]
fn an_ordinary_fence_on_a_derived_text_is_raised_to_the_erase_fence() -> Result<()> {
    const WORDS: &[u8] = b"words from the erased bytes";
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let asset = fixture.asset()?;
    vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    let (_dir, peer) = open_test_vault_with(embedding_test_config());
    let text = EntityId::now();
    peer.put_entity(&text, ENTITY_TYPE_ASSET_TEXT, at(40), 40, WORDS)?;
    apply_tombstone(vault, &text, &tombstone(TombstoneReason::UserDelete))?;
    assert!(vault.with_write_txn_grouped(|txn| {
        vault.scrub_text_derived_from_erased_in_txn(txn, &text, &asset)
    })?);
    let refused = vault.with_write_txn_grouped(|txn| {
        let raw = peer.get_raw(&text)?.expect("the peer's text");
        let header = EntityMetadataHeader::parse(&raw).expect("stored header");
        vault.refuse_erased_blob_arrival_in_txn(
            txn,
            &text,
            &header,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
    })?;
    assert!(refused, "the text's arrival was not refused");
    // The soft tombstone replayed again (Astra R5 P2): its ordinary fence leaves the erase's.
    apply_tombstone(vault, &text, &tombstone(TombstoneReason::UserDelete))?;
    assert!(
        matches!(
            vault.put_entity(&text, ENTITY_TYPE_ASSET_TEXT, at(50), 50, WORDS),
            Err(Error::Artifact(ArtifactError::BlobContentErased))
        ),
        "a local put wrote the erased words back over an ordinary fence"
    );
    Ok(())
}

/// Bug repro (#1465 R6, Astra P2): the generic sync-state door neither lowers nor drops a hard
/// erase's fence or its hard-delete marker: a host write of either key is refused.
#[cfg(feature = "sync")]
#[test]
fn the_generic_sync_state_door_leaves_an_erase_fence() -> Result<()> {
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    let carrier = fixture.shared.claim_id;
    let erase_fenced = || -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        crate::blob_artifact::erase_fenced(&vault.store, &txn, &carrier)
    };
    assert!(erase_fenced()?);
    let fence = format!("df:{}", carrier.to_hex());
    assert!(
        vault.sync_state_put(&fence, b"").is_err(),
        "a host lowered the erase fence"
    );
    assert!(
        vault.sync_state_delete(&fence).is_err(),
        "a host dropped the erase fence"
    );
    assert!(
        vault
            .sync_state_delete(&format!("dt:{}", fixture.erased.to_hex()))
            .is_err(),
        "a host dropped the hard-delete marker"
    );
    assert!(erase_fenced()?);
    Ok(())
}

fn fenced(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::deletion::ROW_DELETION_FENCE.contains(&vault.store, &txn, &HexId(*id))
}
