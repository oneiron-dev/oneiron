//! A room step's response version (FIX 4818): the fresh artifact an
//! off-record room's compaction step keeps an answer over the inline bound
//! in, staged in the room's overlay and never in base.
//!
//! It is the version an append writes, built by the same rules and codecs
//! (`super::append`): the named artifact derived from the step's sources,
//! its content-addressed ASSET body, its `blob.version` ledger claim, and
//! the version, head and high-water rows with their born-from index. The
//! rows stage through the room's own apply and view, in the write segment
//! that stages the step, so they commit or abort with it, and close drops
//! them with the room. Nothing goes to base: no ASSET file, change log,
//! fingerprint, signature, birth stamp or authority row.

use heed::{RoTxn, RwTxn};
use oneiron_contracts::affect::Vad;

use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM};
use crate::store::{ManifestDbs, SessionStoreView};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::super::body::{BlobArtifactBody, encode_blob_artifact_body};
use super::super::made_by::default_version_made_by;
use super::super::provenance::{BlobVersionProvenance, validate_provenance};
use super::super::store_keys::blob_artifact_asset_ref_key;
use super::append::{
    VersionEntry, VersionPlacement, place_version_in_txn, put_version_rows_in_txn,
};
use super::{BlobArtifactVersion, blob_artifact_asset_entity_id};

/// One fresh response artifact's version, built before the room's write
/// segment opens: what its chain rows hold, and the exact version a step
/// claim pins.
pub(crate) struct RoomResponseVersion {
    artifact_id: EntityId,
    record: BlobArtifactVersion,
}

impl RoomResponseVersion {
    /// Version one of the fresh artifact `artifact_id`, named `name` of
    /// `media_type`, holding `bytes`, derived from each of `sources`, as
    /// `actor` appends it under `provenance`; with the ops that stage its
    /// rows through the room's apply, in order: the artifact and its
    /// `DerivedFrom` edges, its ASSET body, and its `blob.version` claim
    /// with that claim's `claim_of` edge. The version rules read the
    /// artifact's chain on `view`, the room's, in `txn`.
    ///
    /// # Errors
    ///
    /// A provenance the version codec refuses; an artifact id the room
    /// already versions; codec and storage errors.
    #[expect(
        clippy::too_many_arguments,
        reason = "the room's view, then one fresh artifact's own version axes"
    )]
    pub(crate) fn prepare(
        view: &SessionStoreView<'_>,
        txn: &RoTxn<'_>,
        artifact_id: EntityId,
        name: &str,
        media_type: &str,
        bytes: &[u8],
        sources: &[EntityId],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(Self, Vec<BatchOp>)> {
        validate_provenance(provenance)?;
        let content_hash = *blake3::hash(bytes).as_bytes();
        let VersionPlacement::Next(place) =
            place_version_in_txn(view, txn, &artifact_id, None, &content_hash)?
        else {
            return Err(Error::InvariantViolation(
                "a room response artifact is versioned once",
            ));
        };
        let made_by = default_version_made_by(&actor, provenance, place.parent_claim, learned_at);
        let claim_id = view.clock().entity_id()?;
        let body = BlobArtifactBody::new(name, media_type);
        let artifact = encode_blob_artifact_body(&body)?;
        let VersionEntry {
            record,
            candidate,
            envelope,
        } = VersionEntry::new(
            &artifact_id,
            body,
            &place,
            content_hash,
            provenance,
            None,
            None,
            made_by,
            claim_id,
            actor,
            learned_at,
        )?;
        let facet = crate::claim::default_facet_in(view.read().base(), txn)?;
        let claim = crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope, facet)?)?;
        let put = |id: EntityId, entity_type: u8, data: Vec<u8>| BatchOp::Put {
            id,
            entity_type,
            occurred,
            learned_at,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        let mut ops = vec![put(artifact_id, ENTITY_TYPE_BLOB_ARTIFACT, artifact)];
        ops.extend(sources.iter().map(|source| BatchOp::Edge {
            src: artifact_id,
            kind: EdgeKind::DerivedFrom,
            tgt: *source,
            weight: 1.0,
            vad: Vad::NEUTRAL,
        }));
        ops.push(put(
            blob_artifact_asset_entity_id(&content_hash)?,
            ENTITY_TYPE_ASSET,
            bytes.to_vec(),
        ));
        ops.push(put(claim_id, ENTITY_TYPE_CLAIM, claim));
        ops.push(BatchOp::Edge {
            src: claim_id,
            kind: EdgeKind::ClaimOf,
            tgt: artifact_id,
            weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
            vad: Vad::NEUTRAL,
        });
        Ok((
            Self {
                artifact_id,
                record,
            },
            ops,
        ))
    }

    pub(crate) fn artifact_id(&self) -> EntityId {
        self.artifact_id
    }

    pub(crate) fn version(&self) -> u64 {
        self.record.version
    }

    pub(crate) fn content_hash(&self) -> [u8; 32] {
        self.record.content_hash
    }

    /// Stages the version's chain rows on `view`, a fresh view of the room
    /// inside the segment that staged its ops: the ASSET reference, then
    /// the version, head and high-water rows and the born-from index.
    ///
    /// # Errors
    ///
    /// Storage errors; the room's budget refusal.
    pub(crate) fn stage_chain_rows_in_txn(
        &self,
        view: &SessionStoreView<'_>,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<()> {
        view.vault_meta.put(
            wtxn,
            &blob_artifact_asset_ref_key(&self.record.content_hash, &self.artifact_id),
            &[],
        )?;
        put_version_rows_in_txn(view, wtxn, &self.artifact_id, &self.record)
    }
}
