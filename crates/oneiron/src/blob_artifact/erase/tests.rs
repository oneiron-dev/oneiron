use super::*;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::blob_artifact::{BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance};
use crate::deletion::{DeleteEntityOptions, DeleteReason};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{ArtifactError, Error};
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::write_envelope::WriteActor;

const SHARED: &[u8] = b"bytes the erased artifact and another both hold";
const OTHER_ONLY: &[u8] = b"bytes only the other artifact holds";
const HARD_REASONS: [DeleteReason; 3] = [
    DeleteReason::UserHardDelete,
    DeleteReason::GdprDelete,
    DeleteReason::PolicyDelete,
];

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// A vault holding two artifacts that share one blob: `erased` holds `SHARED` as its only
/// version, and `other` holds `OTHER_ONLY` as v1 and `SHARED` as v2, its head.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
    erased: EntityId,
    erased_version: BlobArtifactVersion,
    other: EntityId,
    shared: BlobArtifactVersion,
}

impl Shared {
    fn open() -> Result<Self> {
        let (dir, vault) = open_test_vault_with(embedding_test_config());
        let person = EntityId::now();
        vault.put_entity(&person, ENTITY_TYPE_PERSON, at(10), 10, b"uploader")?;
        let actor = WriteActor::new(person, EdgeActorClass::Human);
        let artifact = |learned: u64| -> Result<EntityId> {
            let id = EntityId::now();
            vault.put_blob_artifact(
                &id,
                &BlobArtifactBody::new("shared.bin", "application/octet-stream"),
                at(learned),
                learned,
            )?;
            Ok(id)
        };
        let append = |id: &EntityId, bytes: &[u8], learned: u64| {
            vault.append_blob_artifact_version(
                id,
                bytes,
                &BlobVersionProvenance::UserUpload,
                actor,
                at(learned),
                learned,
            )
        };
        let erased = artifact(10)?;
        let other = artifact(10)?;
        let erased_version = append(&erased, SHARED, 11)?;
        append(&other, OTHER_ONLY, 12)?;
        let shared = append(&other, SHARED, 13)?;
        Ok(Self {
            _dir: dir,
            vault,
            person,
            erased,
            erased_version,
            other,
            shared,
        })
    }

    fn asset(&self) -> Result<EntityId> {
        blob_artifact_asset_entity_id(&self.shared.content_hash)
    }
}

/// Every hold row any artifact keeps on the shared bytes: `asset_ref` rows and claim pairs.
fn holds(vault: &Vault, hash: &ContentHash) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    holders(&vault.store, &txn, hash, &[])
}

fn erased(result: Result<impl std::fmt::Debug>) -> bool {
    matches!(
        result,
        Err(Error::Artifact(ArtifactError::BlobVersionErased))
    )
}

/// Done-means (ARCH-0005a, ARCH-0038 carrier 13): a hard erase of one of two artifacts sharing a
/// blob, for each of the three hard reasons, takes the bytes off the vault and out of every
/// derived carrier, and the other artifact's reference to them reads as erased on every door,
/// never as intact and never as missing. Its unrelated version stays.
#[test]
fn a_hard_erase_takes_shared_bytes_and_every_reference_to_them() -> Result<()> {
    for reason in HARD_REASONS {
        let fixture = Shared::open()?;
        let vault = &fixture.vault;
        let asset = fixture.asset()?;
        let hash = fixture.shared.content_hash;
        // A text derived from the bytes, and search rows over them.
        let derived = EntityId::now();
        vault
            .batch()
            .put(
                &derived,
                ENTITY_TYPE_ASSET_TEXT,
                at(14),
                14,
                b"words from the bytes",
            )
            .text(&derived, &[("body", "pierceword derived")])
            .text(&asset, &[("body", "pierceword asset")])
            .commit()?;
        vault.put_edge(&derived, EdgeKind::DerivedFrom, &asset, 1.0)?;
        assert_eq!(vault.search_text("pierceword", 10)?.len(), 2);
        assert_eq!(
            vault
                .blob_fingerprint(&fixture.other)?
                .map(|tree| tree.asset_hash),
            Some(hash)
        );

        let outcome = vault.delete_entity_with_reason(&fixture.erased, reason)?;

        assert!(
            vault.get_raw(&asset)?.is_none(),
            "{reason:?}: the shared bytes outlived the hard erase"
        );
        assert!(
            holds(vault, &hash)?.is_empty(),
            "{reason:?}: a hold on the erased bytes survived"
        );
        for read in [
            erased(vault.read_blob_artifact_version(&fixture.other, 2)),
            erased(vault.blob_artifact_version_metadata(&fixture.other, 2)),
            erased(vault.lend_blob_artifact_version(&fixture.other, 2, |_, _| ())),
        ] {
            assert!(
                read,
                "{reason:?}: the other artifact's reference did not read as erased"
            );
        }
        assert_eq!(
            vault.read_blob_artifact_version(&fixture.other, 1)?,
            Some(OTHER_ONLY.to_vec()),
            "{reason:?}: the other artifact's unrelated version went too"
        );
        // Both artifacts' version claims naming the bytes, and the derived text, are scrubbed
        // to shells.
        let references = [fixture.shared.claim_id, fixture.erased_version.claim_id];
        for carrier in [references[0], references[1], derived] {
            let raw = vault.get_raw(&carrier)?.expect("the scrubbed shell stays");
            assert_eq!(
                raw.len(),
                crate::batch::ENTITY_METADATA_HEADER_LEN,
                "{reason:?}: a carrier of the erased bytes kept its body"
            );
        }
        assert!(
            vault.search_text("pierceword", 10)?.is_empty(),
            "{reason:?}: search rows over the erased bytes survived"
        );
        assert_eq!(
            vault.blob_fingerprint(&fixture.other)?,
            None,
            "{reason:?}: the other artifact's fingerprint tree over the erased bytes survived"
        );
        // One receipt line each for the bytes, the erased reference and the derived text.
        let receipt = vault
            .get_raw(&outcome.receipt_id.expect("a hard erase writes a receipt"))?
            .expect("the receipt row");
        let body: serde_json::Value =
            rmp_serde::from_slice(&receipt[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .expect("decode receipt body");
        let lines = body["scope"]["entity_ids"].to_string();
        for carrier in [asset, references[0], references[1], derived] {
            assert!(
                lines.contains(&carrier.to_hex()),
                "{reason:?}: the receipt has no line for a carrier the erase took"
            );
        }
        // The memory door (MCP, NAPI) says erased, not NOT_FOUND.
        let refused = vault
            .memory(EntityId::now(), EdgeActorClass::Human)
            .read_blob_version(&fixture.other.to_hex(), 2)
            .expect_err("an erased version read through the memory door");
        assert_eq!(
            refused.code,
            crate::memory::MEMORY_CODE_INVALID_STATE,
            "{reason:?}: the memory door read an erased version as missing"
        );
    }
    Ok(())
}

/// Positive control (ARCH-0005a: delete acts on a reference): a plain delete of one of two
/// artifacts sharing a blob, through the delete door or the batch door, leaves the bytes to the
/// other, whose version still reads them.
#[test]
fn a_plain_delete_leaves_shared_bytes_to_the_other_artifact() -> Result<()> {
    for batch in [false, true] {
        let fixture = Shared::open()?;
        let vault = &fixture.vault;
        if batch {
            vault.batch().delete(&fixture.erased).commit()?;
        } else {
            vault.delete_entity_with_options(
                &fixture.erased,
                DeleteEntityOptions { purge: false },
            )?;
        }
        assert!(vault.get_raw(&fixture.asset()?)?.is_some());
        assert_eq!(
            vault.read_blob_artifact_version(&fixture.other, 2)?,
            Some(SHARED.to_vec())
        );
    }
    Ok(())
}

/// Done-means (ARCH-0005a): the delete impact preview tells one reference of several from the
/// last one, and names each other artifact version a hard erase takes, so the confirm can say
/// which act it is. The erase's receipt then lists that version's reference.
#[test]
fn the_delete_preview_tells_one_of_several_from_the_last_reference() -> Result<()> {
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let preview = |id: &EntityId| -> Result<crate::deletion::DeleteEntityPreview> {
        let txn = vault.store.env.read_txn()?;
        vault.preview_entity_delete_in_txn(&txn, id)
    };
    let erased = preview(&fixture.erased)?;
    let [held] = erased.held_bytes() else {
        panic!("the erased artifact holds one blob");
    };
    assert_eq!(held.asset(), fixture.asset()?);
    assert!(
        !held.is_last_reference(),
        "one of several read as the last reference"
    );
    let [other] = held.others() else {
        panic!("the preview names one other version");
    };
    assert_eq!(
        (other.artifact(), other.name(), other.version()),
        (fixture.other, Some("shared.bin"), fixture.shared.version),
        "the preview did not name the other artifact's version the erase takes"
    );

    let only = blob_artifact_asset_entity_id(blake3::hash(OTHER_ONLY).as_bytes())?;
    let last: Vec<_> = preview(&fixture.other)?
        .held_bytes()
        .iter()
        .filter(|held| held.is_last_reference())
        .map(|held| held.asset())
        .collect();
    assert_eq!(last, [only], "the last reference read as one of several");

    let outcome = vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    let receipt = vault
        .get_raw(&outcome.receipt_id.expect("a hard erase writes a receipt"))?
        .expect("the receipt row");
    let body: serde_json::Value =
        rmp_serde::from_slice(&receipt[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .expect("decode receipt body");
    assert!(
        body["scope"]["entity_ids"]
            .to_string()
            .contains(&fixture.shared.claim_id.to_hex()),
        "the receipt has no line for the other artifact's erased version"
    );

    // A preview taken before another artifact let go of the bytes is stale at confirm.
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let txn = vault.store.env.read_txn()?;
    let erased = vault.preview_entity_delete_in_txn(&txn, &fixture.erased)?;
    drop(txn);
    vault.delete_entity_with_options(&fixture.other, DeleteEntityOptions { purge: false })?;
    let txn = vault.store.env.read_txn()?;
    assert!(matches!(
        erased.check_before_unshare(vault, &txn),
        Err(Error::ConcurrentWrite(_))
    ));
    Ok(())
}

/// Done-means (ARCH-0005a): a reference the erase took, put again through the replicated door
/// with the ASSET carrying its bytes, brings nothing back. The materialization gate refuses both,
/// and the version still reads as erased.
#[test]
fn an_erased_reference_put_again_brings_no_bytes_back() -> Result<()> {
    let fixture = Shared::open()?;
    let vault = &fixture.vault;
    let asset = fixture.asset()?;
    let claim = fixture.shared.claim_id;
    let stale: Vec<(EntityId, Vec<u8>)> = [claim, asset]
        .into_iter()
        .map(|id| Ok((id, vault.get_raw(&id)?.expect("stored before the erase"))))
        .collect::<Result<_>>()?;

    vault.delete_entity_with_reason(&fixture.erased, DeleteReason::GdprDelete)?;
    for (id, raw) in &stale {
        let header = EntityMetadataHeader::parse(raw).expect("stored header");
        let put = vault
            .batch()
            .put_replicated(
                id,
                header.entity_type,
                at(header.occurred_start),
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit();
        assert!(
            put.is_err(),
            "the replicated door took back an erased carrier"
        );
    }
    assert!(
        vault.get_raw(&asset)?.is_none(),
        "a re-sent reference brought the bytes back"
    );
    assert!(holds(vault, &fixture.shared.content_hash)?.is_empty());
    assert!(erased(vault.read_blob_artifact_version(&fixture.other, 2)));
    Ok(())
}

/// Copies each id's stored row to `target` through the replicated put door, one batch per row.
/// Returns whether each put was taken.
fn replicate(source: &Vault, target: &Vault, ids: &[EntityId]) -> Result<Vec<bool>> {
    let mut taken = Vec::new();
    for id in ids {
        let raw = source.get_raw(id)?.expect("stored at the origin");
        let header = EntityMetadataHeader::parse(&raw).expect("stored header");
        let put = target
            .batch()
            .put_replicated(
                id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit();
        taken.push(put.is_ok());
    }
    Ok(taken)
}

/// Bug repro (Engine ruling on #1465, 10-15) and done-means: a replica learns which bytes an
/// erased artifact held only from its version claims, and those can arrive after the erase's
/// tombstone. In every arrival order the replica ends with no bytes, the other artifact's
/// reference erased and no hold on the bytes, and a stale carrier of the bytes sent afterwards is
/// never stored.
#[test]
fn a_replica_pierces_the_bytes_in_every_arrival_order() -> Result<()> {
    let origin = Shared::open()?;
    let source = &origin.vault;
    let asset = origin.asset()?;
    let hash = origin.shared.content_hash;
    let (erased_claim, other_claim) = (origin.erased_version.claim_id, origin.shared.claim_id);
    let mut tombstone = vec![crate::deletion::TombstoneReason::GdprDelete.wire_byte()];
    tombstone.extend_from_slice(&60_u64.to_le_bytes());
    tombstone.extend_from_slice(&[0xE5; 16]);
    let erase_on = |replica: &Vault| -> Result<()> {
        replica.with_write_txn_grouped(|txn| {
            replica
                .apply_replayed_tombstone_in_txn(txn, &origin.erased, &tombstone)
                .map(|_| ())
        })
    };
    let before = [
        origin.erased,
        origin.other,
        erased_claim,
        other_claim,
        asset,
    ];
    // Claims first, tombstone after; tombstone first, the erased artifact's claim before the other
    // artifact's reference and the bytes; tombstone first, its claim last.
    let orders: [&[&[EntityId]]; 3] = [
        &[&before],
        &[
            &[origin.erased, erased_claim],
            &[origin.other, other_claim, asset],
        ],
        &[
            &[origin.other, other_claim, asset],
            &[origin.erased, erased_claim],
        ],
    ];
    for (n, order) in orders.iter().enumerate() {
        let (_dir, replica) = open_test_vault_with(embedding_test_config());
        replicate(source, &replica, &[origin.person])?;
        if n > 0 {
            erase_on(&replica)?;
        }
        for ids in *order {
            replicate(source, &replica, ids)?;
        }
        if n == 0 {
            assert!(
                replica.get_raw(&asset)?.is_some(),
                "order {n}: the bytes reached the replica"
            );
            erase_on(&replica)?;
        }
        assert!(
            replica.get_raw(&asset)?.is_none(),
            "order {n}: the erased bytes stayed on the replica"
        );
        assert!(
            holds(&replica, &hash)?.is_empty(),
            "order {n}: a hold survived"
        );
        let txn = replica.store.env.read_txn()?;
        assert!(
            reference_erased(&replica.store, &txn, &other_claim)?,
            "order {n}: the other artifact's reference was not erased"
        );
        drop(txn);
        // A stale carrier of the bytes, and the other reference again, store nothing.
        replicate(source, &replica, &[other_claim, asset])?;
        assert!(
            replica.get_raw(&asset)?.is_none(),
            "order {n}: a stale carrier stored the erased bytes again"
        );
        assert!(
            holds(&replica, &hash)?.is_empty(),
            "order {n}: a re-sent reference took a hold"
        );
    }
    Ok(())
}
