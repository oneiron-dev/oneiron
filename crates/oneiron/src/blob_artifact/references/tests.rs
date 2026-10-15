use super::*;
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::side_table::SideTableDbs;
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::write_envelope::WriteActor;

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// The stored keys of both keyings: by content hash, and by artifact.
type Rows = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn projection(vault: &Vault) -> Result<Rows> {
    let txn = vault.store.env.read_txn()?;
    let keys = |prefix: &[u8]| -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        for row in SideTableDbs::side_vault_meta(&vault.store).prefix_iter(&txn, prefix)? {
            keys.push(row?.0.into_owned());
        }
        Ok(keys)
    };
    Ok((
        keys(VERSION_CLAIM.decl().prefix)?,
        keys(CLAIMED_HASH.decl().prefix)?,
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

/// A `blob.version` claim body naming `subject` as the holder of `bytes`.
fn version_claim(subject: EntityId, bytes: &[u8]) -> Result<ClaimBody> {
    ClaimBody::new(
        BLOB_VERSION_CLAIM_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::Map(vec![(
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(blake3::hash(bytes).as_bytes().to_vec()),
        )]),
        1.0,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    )
}

fn put_claim(vault: &Vault, id: &EntityId, body: &ClaimBody, learned: u64) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            id,
            ENTITY_TYPE_CLAIM,
            at(learned),
            learned,
            &crate::claim::encode_claim_body(body)?,
        )
        .commit()?;
    Ok(())
}

/// A v2 hard tombstone value: `[reason:1][deleted_at:8 LE][request_id:16]`.
fn hard_tombstone() -> Vec<u8> {
    let mut value = vec![crate::deletion::TombstoneReason::UserHardDelete.wire_byte()];
    value.extend_from_slice(&60_u64.to_le_bytes());
    value.extend_from_slice(&[0xAE; 16]);
    value
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

/// Substrate invariant (H125): which artifacts hold which bytes is a function of the claim rows
/// alone. A vault that receives the origin's version claims through the replicated put door, as
/// a replica or a rebuild from claims does, records exactly the origin's pairs, so the two agree.
#[test]
fn the_version_claim_projection_rebuilds_from_the_claim_rows() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES, 10)?;
    let rows = projection(&origin.vault)?;
    assert_eq!(rows.0.len(), 2, "one row per version");
    assert_eq!(rows.1.len(), 2, "one row per version");
    let by_artifact = [CLAIMED_HASH.decl().prefix, artifact.as_bytes()].concat();
    assert!(rows.1.iter().all(|key| key.starts_with(&by_artifact)));

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

    // A plain delete: a hard erase of the claim takes the bytes it names at once (ARCH-0005a).
    replica.delete_entity_with_reason(&claims[0], DeleteReason::UserDelete)?;
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
    // A plain delete: a version of an artifact a hard erase took is a late reference (ARCH-0005a).
    replica.delete_entity_with_reason(&artifact, DeleteReason::UserDelete)?;
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
    // Plain deletes: bytes a hard erase took are never stored again (ARCH-0005a).
    origin
        .vault
        .delete_entity_with_reason(&gone, DeleteReason::UserDelete)?;
    replica.delete_entity_with_reason(&gone, DeleteReason::UserDelete)?;
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
    put_claim(
        &replica,
        &EntityId::now(),
        &version_claim(asset, VERSION_BYTES[0])?,
        12,
    )?;

    replica.delete_entity_with_reason(&asset, DeleteReason::UserHardDelete)?;
    assert!(!stored(&replica, &asset)?);
    Ok(())
}

/// Bug repro (SOL-R2-001, ASTRA-R2-001, H125): a version claim deleted before its artifact ever
/// arrives here still takes its bytes off when that artifact's delete does arrive.
#[test]
fn a_claim_deleted_before_its_artifact_arrives_still_takes_the_bytes() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, asset])?;
    replicate(&origin.vault, &replica, &claims)?;
    // A plain delete: a hard erase of the claim takes the bytes it names at once (ARCH-0005a).
    replica.delete_entity_with_reason(&claims[0], DeleteReason::UserDelete)?;
    assert!(stored(&replica, &asset)?);

    replica.with_write_txn_grouped(|txn| {
        replica
            .apply_replayed_tombstone_in_txn(txn, &artifact, &hard_tombstone())
            .map(|_| ())
    })?;
    assert!(
        !stored(&replica, &asset)?,
        "the bytes of an artifact deleted before it arrived stayed on the replica"
    );
    assert!(fenced(&replica, &asset)?);
    assert_eq!(projection(&replica)?, (Vec::new(), Vec::new()));
    Ok(())
}

/// Bug repro (SOL-R2-002, H125): a claim rewritten to name another artifact for the same bytes
/// leaves both artifacts holding them, so deleting the first keeps the bytes the second holds.
/// The put door keeps a stored claim's scope facet, not its subject, so the rewrite keeps the
/// facet it was first stamped with.
#[test]
fn a_claim_rewritten_to_another_artifact_keeps_both_holders() -> Result<()> {
    let origin = Origin::open()?;
    let (first, _) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let (second, _) = origin.artifact(&VERSION_BYTES[..1], 20)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(
        &origin.vault,
        &replica,
        &[origin.person, first, second, asset],
    )?;
    let claim = EntityId::now();
    let stamped = version_claim(first, VERSION_BYTES[0])?;
    put_claim(&replica, &claim, &stamped, 30)?;
    let mut rewritten = version_claim(second, VERSION_BYTES[0])?;
    rewritten.scope_facet = stamped.scope_facet;
    put_claim(&replica, &claim, &rewritten, 31)?;

    // A plain delete; a hard erase takes every holder's reference with the bytes (ARCH-0005a).
    replica.delete_entity_with_reason(&first, DeleteReason::UserDelete)?;
    assert!(
        stored(&replica, &asset)?,
        "deleting one holder took the bytes another live artifact holds"
    );
    replica.delete_entity_with_reason(&second, DeleteReason::UserHardDelete)?;
    assert!(!stored(&replica, &asset)?);
    Ok(())
}

/// Bug repro (SOL-R2-003, H125): a late claim lifts only the fence a release planted. An ASSET
/// whose own delete was accepted here but has not been applied yet stays fenced.
#[test]
fn a_late_claim_leaves_an_explicit_asset_delete_fenced() -> Result<()> {
    let origin = Origin::open()?;
    let (artifact, claims) = origin.artifact(&VERSION_BYTES[..1], 10)?;
    let asset = asset_of(VERSION_BYTES[0])?;
    let (_replica_dir, replica) = open_test_vault_with(embedding_test_config());
    replicate(&origin.vault, &replica, &[origin.person, artifact, asset])?;
    replica.with_write_txn_grouped(|txn| {
        replica.fence_unapplied_delete_in_txn(txn, &asset, &hard_tombstone())
    })?;
    assert!(fenced(&replica, &asset)?);

    replicate(&origin.vault, &replica, &claims)?;
    assert!(
        fenced(&replica, &asset)?,
        "a version claim withdrew an accepted delete of its ASSET"
    );
    Ok(())
}
