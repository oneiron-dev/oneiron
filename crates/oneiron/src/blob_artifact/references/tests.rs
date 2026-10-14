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

const VERSION_BYTES: [&[u8]; 2] = [b"first bytes", b"second bytes"];

fn asset_of(bytes: &[u8]) -> Result<EntityId> {
    super::super::versions::blob_artifact_asset_entity_id(blake3::hash(bytes).as_bytes())
}

fn stored(vault: &Vault, id: &EntityId) -> Result<bool> {
    Ok(vault.get_raw(id)?.is_some())
}

fn fenced(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::deletion::ROW_DELETION_FENCE.contains(&vault.store, &txn, &HexId(*id))
}

/// An origin vault and the person who uploads to it.
struct Origin {
    _dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
    actor: WriteActor,
}

impl Origin {
    fn open() -> Result<Self> {
        let (dir, vault) = open_test_vault_with(embedding_test_config());
        let person = EntityId::now();
        vault.put_entity(&person, ENTITY_TYPE_PERSON, at(10), 10, b"uploader")?;
        Ok(Self {
            _dir: dir,
            vault,
            person,
            actor: WriteActor::new(person, EdgeActorClass::Human),
        })
    }

    /// A new artifact holding `bytes` as its versions. Returns it and its version claims.
    fn artifact(&self, bytes: &[&[u8]], learned: u64) -> Result<(EntityId, Vec<EntityId>)> {
        let artifact = EntityId::now();
        self.vault.put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("h125.bin", "application/octet-stream"),
            at(learned),
            learned,
        )?;
        let mut claims = Vec::new();
        for (n, bytes) in bytes.iter().enumerate() {
            let learned = learned + 1 + n as u64;
            let version = self.vault.append_blob_artifact_version(
                &artifact,
                bytes,
                &BlobVersionProvenance::UserUpload,
                self.actor,
                at(learned),
                learned,
            )?;
            claims.push(version.claim_id);
        }
        Ok((artifact, claims))
    }
}

/// Substrate invariant (H125): the version-claim projection is a function of the claim rows
/// alone. A vault that receives the origin's version claims through the replicated put door, as
/// a replica or a rebuild from claims does, projects exactly the origin's rows, so the two agree
/// on which artifacts hold which bytes.
#[test]
fn the_version_claim_projection_rebuilds_from_the_claim_rows() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES, 10)?;
    let rows = projection(&origin.vault)?;
    assert_eq!(rows.0.len(), 2, "one row per version claim");
    assert_eq!(rows.1.len(), 2, "one row per version claim");
    assert!(rows.0.iter().all(|(_, named)| *named == artifact));
    assert!(rows.1.iter().all(|(named, _, _)| *named == artifact));

    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, artifact])?;
    replicate(&origin.vault, &replica, &claims)?;
    assert!(
        replica
            .get_raw(&claims[0])?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CLAIM))
    );
    assert_eq!(projection(&replica)?, rows);
    Ok(())
}

/// Bug repro (SOL-R1-001, H125): a replica that deletes a version claim before its artifact
/// still takes that version's bytes off when the artifact goes. The claim's rows stand in for the
/// origin's `asset_ref` row, which a claim's delete does not touch either, and they go with the
/// artifact.
#[test]
fn a_version_claim_deleted_first_still_takes_its_bytes_with_the_artifact() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES, 10)?;
    let assets = [asset_of(VERSION_BYTES[0])?, asset_of(VERSION_BYTES[1])?];
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, artifact])?;
    replicate(&origin.vault, &replica, &assets)?;
    replicate(&origin.vault, &replica, &claims)?;
    let rows = projection(&replica)?;

    replica.delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)?;
    assert_eq!(
        projection(&replica)?,
        rows,
        "a claim's delete leaves the rows of the artifact it names while that artifact lives"
    );
    assert!(stored(&replica, &assets[0])?);

    replica.delete_entity_with_reason(&artifact, DeleteReason::UserHardDelete)?;
    for asset in &assets {
        assert!(
            !stored(&replica, asset)?,
            "a deleted artifact's version bytes stayed on the replica"
        );
        assert!(fenced(&replica, asset)?);
    }
    assert_eq!(projection(&replica)?, (Vec::new(), Vec::new()));
    Ok(())
}

/// Bug repro (SOL-R1-004, H125): a version claim that reaches a replica after its artifact's
/// delete takes the bytes it names off at once, and leaves no row behind.
#[test]
fn a_version_claim_arriving_after_its_artifact_delete_takes_the_bytes() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, artifact, asset])?;
    replica.delete_entity_with_reason(&artifact, DeleteReason::UserHardDelete)?;
    assert!(
        stored(&replica, &asset)?,
        "no claim names the bytes yet, so the delete had nothing to release"
    );

    replicate(&origin.vault, &replica, &claims)?;
    assert!(
        !stored(&replica, &asset)?,
        "the late claim's bytes outlived their deleted artifact"
    );
    assert!(fenced(&replica, &asset)?);
    assert_eq!(projection(&replica)?, (Vec::new(), Vec::new()));
    Ok(())
}

/// Bug repro (SOL-R1-005, H125): bytes a replica released come back when a live artifact's
/// version claim names them again before their carrier arrives: the claim lifts the fence, so
/// the carrier is no longer refused as a deleted row.
#[test]
fn a_live_artifact_claim_lifts_the_fence_before_the_bytes_arrive() -> Result<()> {
    let origin = Origin::open()?;
    let (gone, gone_claims) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, gone, asset])?;
    replicate(&origin.vault, &replica, &gone_claims)?;
    origin
        .vault
        .delete_entity_with_reason(&gone, DeleteReason::UserHardDelete)?;
    replica.delete_entity_with_reason(&gone, DeleteReason::UserHardDelete)?;
    assert!(!stored(&replica, &asset)? && fenced(&replica, &asset)?);

    let (again, again_claims) = origin.artifact(&VERSION_BYTES[..1], 20)?;
    replicate(&origin.vault, &replica, &[again])?;
    replicate(&origin.vault, &replica, &again_claims)?;
    assert!(!fenced(&replica, &asset)?);
    replicate(&origin.vault, &replica, &[asset])?;
    assert!(
        stored(&replica, &asset)?,
        "a re-upload's bytes are refused after its claim arrived"
    );
    Ok(())
}

/// Bug repro (SOL-R1-003, H125): a `blob.version` claim whose subject is the ASSET itself does
/// not make that ASSET's delete release itself again and recurse until the stack overflows.
#[test]
fn a_version_claim_naming_its_own_asset_does_not_recurse_on_delete() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, _claims) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, artifact, asset])?;
    let body = ClaimBody::new(
        BLOB_VERSION_CLAIM_PREDICATE,
        ClaimSubject::Entity(asset),
        Value::Map(vec![(
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(blake3::hash(VERSION_BYTES[0]).as_bytes().to_vec()),
        )]),
        1.0,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let claim = EntityId::now();
    replica
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            at(12),
            12,
            &crate::claim::encode_claim_body(&body)?,
        )
        .commit()?;

    replica.delete_entity_with_reason(&asset, DeleteReason::UserHardDelete)?;
    assert!(!stored(&replica, &asset)?);
    Ok(())
}
