use super::*;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::write_envelope::WriteActor;

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// Both keyings of the projection: by content hash, and by artifact.
type Rows = (
    Vec<((ContentHash, EntityId), EntityId)>,
    Vec<(EntityId, ContentHash, EntityId)>,
);

fn projection(vault: &Vault) -> Result<Rows> {
    let txn = vault.store.env.read_txn()?;
    Ok((
        VERSION_CLAIM.scan(&vault.store, &txn)?,
        CLAIMED_HASH.scan_keys(&vault.store, &txn, &[])?,
    ))
}

/// Copies `id`'s stored row to `target` through the replicated put door.
fn replicate(source: &Vault, target: &Vault, ids: &[EntityId]) -> Result<()> {
    let mut batch = target.batch();
    for id in ids {
        let raw = source.get_raw(id)?.ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(Error::InvalidKey)?;
        batch = batch.put_replicated(
            id,
            header.entity_type,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        );
    }
    batch.commit()?;
    Ok(())
}

/// Substrate invariant (H125): the version-claim projection is a function of the claim rows
/// alone. A vault that receives the origin's version claims through the replicated put door, as
/// a replica or a rebuild from claims does, projects exactly the origin's rows, so the two agree
/// on which artifacts hold which bytes.
#[test]
fn the_version_claim_projection_rebuilds_from_the_claim_rows() -> Result<()> {
    let (_origin_dir, origin) = open_test_vault_with(embedding_test_config());
    let person = EntityId::now();
    origin.put_entity(&person, ENTITY_TYPE_PERSON, at(10), 10, b"uploader")?;
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    origin.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new("h125.bin", "application/octet-stream"),
        at(10),
        10,
    )?;
    let mut claims = Vec::new();
    for (n, bytes) in [b"first bytes".as_slice(), b"second bytes"]
        .iter()
        .enumerate()
    {
        let learned = 11 + n as u64;
        let version = origin.append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            at(learned),
            learned,
        )?;
        claims.push(version.claim_id);
    }
    let rows = projection(&origin)?;
    assert_eq!(rows.0.len(), 2, "one row per version claim");
    assert_eq!(rows.1.len(), 2, "one row per version claim");
    assert!(rows.0.iter().all(|(_, named)| *named == artifact));
    assert!(rows.1.iter().all(|(named, _, _)| *named == artifact));

    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin, &replica, &[person, artifact])?;
    replicate(&origin, &replica, &claims)?;
    assert!(
        replica
            .get_raw(&claims[0])?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CLAIM))
    );
    assert_eq!(projection(&replica)?, rows);

    // A claim's delete takes its rows out of both keyings.
    replica.delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)?;
    let (by_hash, by_artifact) = projection(&replica)?;
    assert_eq!(by_hash.len(), 1);
    assert_eq!(by_artifact.len(), 1);
    assert_eq!(by_hash[0].0.1, claims[1]);
    assert_eq!(by_artifact[0].2, claims[1]);
    Ok(())
}
