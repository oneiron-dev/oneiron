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
//!
//! The room stages no row over a row base holds (FIX 4818). When the room
//! reads a live ASSET with the answer's bytes, base's or its own, the
//! version names that ASSET and stages none, so a base export still carries
//! it. Otherwise the room stages its own ASSET with a `FacetOf` edge to the
//! facet a room NOTE is born under, and its writer places it as it places
//! each row it stages.

use heed::{RoTxn, RwTxn};
use oneiron_contracts::affect::Vad;

use crate::batch::{BatchOp, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET,
};
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

/// The refusal a room response version takes when its artifact is already
/// versioned, or a fresh id it stages names a row the room reads.
const VERSIONED_ONCE: &str = "a room response artifact is versioned once";

/// One fresh response artifact's version, built before the room's write
/// segment opens: what its chain rows hold, the exact version a step claim
/// pins, and the ops that stage it.
pub(crate) struct RoomResponseVersion {
    artifact_id: EntityId,
    record: BlobArtifactVersion,
    /// The artifact and its `DerivedFrom` edges.
    artifact_ops: Vec<BatchOp>,
    /// The `blob.version` claim and its `claim_of` edge.
    claim_ops: Vec<BatchOp>,
    /// The answer's bytes: the body of the ASSET the room stages, if any.
    bytes: Vec<u8>,
    /// The facet the claim is stamped at: the birth facet of a room ASSET.
    facet: EntityId,
    occurred: TimeRange,
    learned_at: u64,
}

impl RoomResponseVersion {
    /// Version one of the fresh artifact `artifact_id`, named `name` of
    /// `media_type`, holding `bytes`, derived from each of `sources`, as
    /// `actor` appends it under `provenance`. The version rules read the
    /// artifact's chain on `view`, the room's, in `txn`. Its ops stage in
    /// the segment ([`Self::take_staging_ops_in_txn`]).
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
    ) -> Result<Self> {
        validate_provenance(provenance)?;
        let content_hash = *blake3::hash(bytes).as_bytes();
        let VersionPlacement::Next(place) =
            place_version_in_txn(view, txn, &artifact_id, None, &content_hash)?
        else {
            return Err(Error::InvariantViolation(VERSIONED_ONCE));
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
            None,
        )?;
        let facet = crate::claim::default_facet_in(view.read().base(), txn)?;
        let claim = crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope, facet)?)?;
        let mut artifact_ops = vec![row_put(
            artifact_id,
            ENTITY_TYPE_BLOB_ARTIFACT,
            occurred,
            learned_at,
            artifact,
        )];
        artifact_ops.extend(sources.iter().map(|source| BatchOp::Edge {
            src: artifact_id,
            kind: EdgeKind::DerivedFrom,
            tgt: *source,
            weight: 1.0,
            vad: Vad::NEUTRAL,
        }));
        let claim_ops = vec![
            row_put(claim_id, ENTITY_TYPE_CLAIM, occurred, learned_at, claim),
            BatchOp::Edge {
                src: claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: artifact_id,
                weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            },
        ];
        Ok(Self {
            artifact_id,
            record,
            artifact_ops,
            claim_ops,
            bytes: bytes.to_vec(),
            facet,
            occurred,
            learned_at,
        })
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

    /// Takes the ops that stage the version, judged on `view`, a fresh view
    /// of the room inside the segment, in its transaction `txn`: the
    /// artifact and its `DerivedFrom` edges, the ASSET if the room stages
    /// one, then the claim and its `claim_of` edge. A live ASSET the room
    /// reads with these bytes, base's or its own, holds the body: none
    /// stages, and the reference row names it. Where no row holds them, the
    /// room's own ASSET stages, with a `FacetOf` edge to the claim's facet
    /// while the room reads that as a FACET, as a room NOTE takes its birth
    /// facet. The chain rows stage after these ops.
    ///
    /// `None` when base holds a row under the ASSET's id that the room does
    /// not read as a live ASSET: a body withdrawn there, or one the room
    /// hides. No room row may stage over it, so its writer refuses.
    ///
    /// # Errors
    ///
    /// [`Self::prepare`]'s refusal for an artifact already versioned when
    /// the artifact's or the claim's fresh id names a row the room reads;
    /// storage errors.
    pub(crate) fn take_staging_ops_in_txn(
        &mut self,
        view: &SessionStoreView<'_>,
        txn: &RoTxn<'_>,
    ) -> Result<Option<Vec<BatchOp>>> {
        for id in [self.artifact_id, self.record.claim_id] {
            if view.port_entity_present(txn, &id)? {
                return Err(Error::InvariantViolation(VERSIONED_ONCE));
            }
        }
        let asset = blob_artifact_asset_entity_id(&self.record.content_hash)?;
        let mut ops = std::mem::take(&mut self.artifact_ops);
        if stored_kind(view, txn, &asset)? != Some(ENTITY_TYPE_ASSET)
            || crate::ports::withdrawn_in_txn(view, txn, &asset)?
        {
            if view.read().base().port_entity_present(txn, &asset)? {
                return Ok(None);
            }
            let bytes = std::mem::take(&mut self.bytes);
            ops.push(row_put(
                asset,
                ENTITY_TYPE_ASSET,
                self.occurred,
                self.learned_at,
                bytes,
            ));
            if stored_kind(view, txn, &self.facet)? == Some(ENTITY_TYPE_FACET) {
                ops.push(BatchOp::Edge {
                    src: asset,
                    kind: EdgeKind::FacetOf,
                    tgt: self.facet,
                    weight: 1.0,
                    vad: Vad::NEUTRAL,
                });
            }
        }
        ops.append(&mut self.claim_ops);
        Ok(Some(ops))
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

/// A fresh row's put, as the room's apply stages it.
fn row_put(
    id: EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: Vec<u8>,
) -> BatchOp {
    BatchOp::Put {
        id,
        entity_type,
        occurred,
        learned_at,
        row_version: None,
        data,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }
}

/// The type of the row `view` reads under `id` in `txn`, from its header.
fn stored_kind(view: &SessionStoreView<'_>, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    view.port_entity_with_raw(txn, id, |raw| {
        EntityMetadataHeader::parse(raw)
            .map(|header| header.entity_type)
            .ok_or(Error::CorruptedIndex("entity header"))
    })
}
