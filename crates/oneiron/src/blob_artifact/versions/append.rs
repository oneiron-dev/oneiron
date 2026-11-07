//! The version append every door takes (moved out of `versions`): one
//! ASSET body, its `blob.version` ledger claim and the version, head and
//! high-water rows, in the caller's write transaction.
//!
//! The version rules, the record and claim a version takes, and its chain
//! rows are read and written through any write target (FIX 4818), so a
//! room's response version (`super::room`) is built by the same code as a
//! base append. Authority, the ASSET put, signing, the change log, births,
//! fingerprints and re-anchoring stay with the base append.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::federation::record_scope::BirthPosition;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::store::ManifestDbs;
use crate::temporal::TimeRange;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::provenance::made_by::MadeBy;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::super::body::BlobArtifactBody;
use super::super::made_by::{
    bind_version_made_by, births_row, default_version_made_by, made_by_text,
    validate_version_made_by_in_txn,
};
use super::super::provenance::{
    BLOB_VERSION_CLAIM_PREDICATE, BlobVersionProvenance, blob_version_claim_value,
    validate_provenance, write_provenance_value,
};
use super::super::store_keys::{BLOB_ARTIFACT_CONTENT_HASH_LEN, require_entity_type};
use super::{
    BlobArtifactVersion, CalcEngineStamp, HEAD, HIGHWATER, VERSIONS, VersionAuthority, VersionBody,
    read_blob_artifact_head_in_txn, read_blob_artifact_highwater_in_txn,
};

impl Vault {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn append_blob_artifact_version_with_parent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_with_parent_and_engine_in_txn(
            wtxn,
            artifact_id,
            bytes,
            provenance,
            actor,
            occurred,
            learned_at,
            fork_parent,
            None,
            None,
            lane,
        )
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn append_blob_artifact_version_with_parent_and_engine_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        calc_engine: Option<&CalcEngineStamp>,
        made_by: Option<&MadeBy>,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_body_in_txn(
            wtxn,
            artifact_id,
            VersionBody::Bytes(bytes),
            provenance,
            actor,
            occurred,
            learned_at,
            fork_parent,
            calc_engine,
            made_by,
            false,
            true,
            lane,
        )
    }

    /// The one version append every door takes, over a slice or a staged
    /// body (FIX 12091). `preserve_made_by` is the trusted Keep path only:
    /// the retained envelope lands validated but unbound, so the keeper is
    /// never rebound as producer (blind review of #4554). Direct doors re-anchor
    /// HTML here; Keep and settlement keep their existing behavior and results.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn append_blob_artifact_version_body_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        body: VersionBody<'_>,
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        calc_engine: Option<&CalcEngineStamp>,
        made_by: Option<&MadeBy>,
        preserve_made_by: bool,
        reanchor_html: bool,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_body_with_authority_in_txn(
            wtxn,
            artifact_id,
            body,
            provenance,
            VersionAuthority::Actor(actor),
            occurred,
            learned_at,
            fork_parent,
            calc_engine,
            made_by,
            preserve_made_by,
            reanchor_html,
            BirthPosition::default(),
            lane,
        )
    }

    /// [`Self::append_blob_artifact_version_body_in_txn`] under `authority`.
    /// `producer_position` is where the producing run's host bound it
    /// (FIX 3171): the version's claim is born there. The default position,
    /// which an unbound append passes, keeps the birth default.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn append_blob_artifact_version_body_with_authority_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        body: VersionBody<'_>,
        provenance: &BlobVersionProvenance,
        authority: VersionAuthority<'_, '_>,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        calc_engine: Option<&CalcEngineStamp>,
        made_by: Option<&MadeBy>,
        preserve_made_by: bool,
        reanchor_html: bool,
        producer_position: BirthPosition,
        lane: crate::core_write::CoreWriteLaneRef<'_>,
    ) -> Result<BlobArtifactVersion> {
        let actor = match &authority {
            VersionAuthority::Actor(actor) => *actor,
            VersionAuthority::QueueCheck(token) => {
                WriteActor::new(token.recorded_actor(), crate::edge::EdgeActorClass::Human)
            }
        };
        validate_provenance(provenance)?;
        if let Some(stamp) = calc_engine {
            stamp.validate()?;
        }
        let content_hash = body.content_hash();
        let claim_id = EntityId::from_bytes(self.store.clock.ulid()?)?;

        require_entity_type(
            &self.store,
            wtxn,
            artifact_id,
            ENTITY_TYPE_BLOB_ARTIFACT,
            "append target must be a BLOB_ARTIFACT entity",
        )?;
        let artifact = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let fingerprint = match body.held_bytes() {
            Some(bytes) => crate::store::blob_fingerprint::prepare_blob_artifact_birth(
                &self.store,
                wtxn,
                artifact_id,
                bytes,
            )?,
            // A body file is never text: its birth reads none of its bytes.
            None => crate::store::blob_fingerprint::prepare_binary_blob_artifact_birth(
                &self.store,
                wtxn,
                artifact_id,
                content_hash,
            )?,
        };
        let placement =
            place_version_in_txn(&self.store, wtxn, artifact_id, fork_parent, &content_hash)?;
        let place = match placement {
            VersionPlacement::Head(head) => {
                fingerprint.persist(&self.store, wtxn, artifact_id)?;
                return Ok(head);
            }
            VersionPlacement::Next(place) => place,
        };
        let made_by = match made_by {
            Some(named) => {
                validate_version_made_by_in_txn(self, wtxn, named)?;
                if preserve_made_by {
                    named.clone()
                } else {
                    bind_version_made_by(&actor, provenance, named, learned_at)
                }
            }
            None => default_version_made_by(&actor, provenance, place.parent_claim, learned_at),
        };
        let VersionEntry {
            record,
            candidate,
            mut envelope,
        } = VersionEntry::new(
            artifact_id,
            artifact,
            &place,
            content_hash,
            provenance,
            calc_engine,
            fork_parent,
            made_by,
            claim_id,
            actor,
            learned_at,
        )?;
        // Placed before it is signed, so the signature covers the position.
        let candidate = place_claim_at_producer_position(candidate, producer_position);
        // The artifact is the logical owner of this content-addressed version.
        // The ASSET bytes and head/index rows are supporting effects of it;
        // the canonical claim is a second semantic content owner.
        if let VersionAuthority::Actor(actor) = &authority {
            self.authorize_shared_content_write_in_txn(wtxn, *artifact_id, actor)?;
        }
        match body {
            VersionBody::Bytes(bytes) => {
                crate::ports::BlobStore::port_blob_put(
                    self,
                    wtxn,
                    artifact_id,
                    bytes,
                    occurred,
                    learned_at,
                )?;
            }
            VersionBody::Staged(staged) => {
                self.put_staged_blob_in_txn(wtxn, artifact_id, staged, occurred, learned_at)?;
            }
        }
        self.sign_retained_machine_claim_in_txn(&*wtxn, &claim_id, &candidate, &mut envelope)?;
        let claim = self
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, learned_at);
        match &authority {
            VersionAuthority::Actor(actor) => claim.apply_actor(wtxn, actor, lane)?,
            VersionAuthority::QueueCheck(_) => claim.apply(wtxn)?,
        }

        let recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        crate::ports::ChangeLogStore::port_changelog_append(
            self,
            wtxn,
            &crate::ports::ChangeLogRecord {
                id: self.store.clock.ulid()?,
                entity: *artifact_id,
                op: crate::ports::ChangeOp::Update,
                actor_principal: actor.entity_ref(),
                actor_person: None,
                occurred_at: occurred.start,
                recorded_at,
                input_hash: content_hash,
                patch: None,
                reason: Some("blob version appended".into()),
            },
        )?;
        put_version_rows_in_txn(&self.store, wtxn, artifact_id, &record)?;
        // The first version is the artifact's birth: its envelope is the
        // artifact row's Rule A birth, read backwards by `rows_born_from`.
        if place.previous_version == 0 && births_row(&record.made_by) {
            crate::store::birth_record::stamp_row_birth_in_txn(
                &self.store,
                wtxn,
                artifact_id,
                &crate::store::row_birth::RowBirth {
                    made_by: record.made_by.clone(),
                    content_hash: crate::store::row_birth::RowBirth::content_hash_of(&[
                        content_hash.as_slice(),
                    ]),
                    withheld: Vec::new(),
                    room_evidence: None,
                },
            )?;
        }

        fingerprint.persist(&self.store, wtxn, artifact_id)?;
        if reanchor_html && let Some(head) = place.head {
            self.reanchor_html_append_in_txn(
                wtxn,
                artifact_id,
                &record.export_media_type,
                head.version,
                record.version,
                actor,
                occurred,
                learned_at,
            )?;
        }
        Ok(record)
    }
}

/// FIX 3171: a version's `blob.version` claim is born at the world and
/// facet its producing run's host bound, as that host's TASKs are. Base
/// reality names no world. Its relationships, opaque scope and project stay
/// the defaults. The other position axes wait for a producing host that owns
/// them. The position is data: it grants no read or write.
fn place_claim_at_producer_position(
    mut candidate: ClaimCandidate,
    position: BirthPosition,
) -> ClaimCandidate {
    if let Some(world) = position.claim_world() {
        candidate = candidate.with_world(world);
    }
    if let Some(facet) = position.facet {
        candidate = candidate.with_scope_stamps(facet, crate::claim::default_project_id());
    }
    candidate
}

/// Where the next version of one artifact goes, as [`place_version_in_txn`]
/// read its chain.
pub(super) struct VersionPlace {
    /// The head the version is appended over.
    pub(super) head: Option<BlobArtifactVersion>,
    pub(super) parent_version: Option<u64>,
    /// The parent version's `blob.version` claim.
    pub(super) parent_claim: Option<EntityId>,
    /// The high-water mark before the version: zero for the first one.
    pub(super) previous_version: u64,
    pub(super) next_version: u64,
}

/// What the version rules make of one append.
pub(super) enum VersionPlacement {
    /// The head already holds these bytes: an append on it is a no-op.
    Head(BlobArtifactVersion),
    Next(VersionPlace),
}

/// The version rules every append takes, read from `dbs` (FIX 4818: a
/// room's view for a room's response version). HEAD is the greatest version
/// that stays; a fork names an existing parent; an append of the head's
/// bytes is a no-op; the next number is above every one ever issued.
pub(super) fn place_version_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    artifact_id: &EntityId,
    fork_parent: Option<u64>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<VersionPlacement> {
    let head = read_blob_artifact_head_in_txn(dbs, txn, artifact_id)?;
    let highwater = read_blob_artifact_highwater_in_txn(dbs, txn, artifact_id)?;
    // HEAD is the greatest version that stays; a released one (FIX 6225)
    // leaves the high-water mark above it, never below.
    if head
        .as_ref()
        .is_some_and(|head| highwater.is_none_or(|highwater| highwater < head.version))
    {
        return Err(Error::CorruptedIndex("blob artifact version highwater"));
    }
    let (parent_version, parent_claim) = match (fork_parent, &head) {
        (Some(parent), Some(head)) if parent > 0 && parent <= head.version => {
            let record =
                VERSIONS
                    .get(dbs, txn, &(*artifact_id, parent))?
                    .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                        "fork parent version does not exist",
                    )))?;
            if record.version != parent {
                return Err(Error::CorruptedIndex("blob artifact fork parent"));
            }
            (Some(parent), Some(record.claim_id))
        }
        (Some(_), _) => {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "fork parent version does not exist",
            )));
        }
        (None, Some(head)) if head.content_hash == *content_hash => {
            return Ok(VersionPlacement::Head(head.clone()));
        }
        (None, Some(head)) => (Some(head.version), Some(head.claim_id)),
        (None, None) => (None, None),
    };
    // Deletion removes the current chain, and a response pin's release
    // one version (FIX 6225), but never the high-water mark: the next
    // number is above every one ever issued, never reused.
    let previous_version = highwater.unwrap_or(0);
    let next_version = previous_version
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))?;
    if VERSIONS.contains(dbs, txn, &(*artifact_id, next_version))? {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "blob artifact version is already recorded",
        )));
    }
    Ok(VersionPlacement::Next(VersionPlace {
        head,
        parent_version,
        parent_claim,
        previous_version,
        next_version,
    }))
}

/// One version's record, and its `blob.version` ledger claim with that
/// claim's envelope, as every append builds them (FIX 4818: a room's
/// response version too).
pub(super) struct VersionEntry {
    pub(super) record: BlobArtifactVersion,
    pub(super) candidate: ClaimCandidate,
    pub(super) envelope: WriteEnvelope,
}

impl VersionEntry {
    /// The entry of the version `place` names on `artifact_id`, whose body
    /// `artifact` pins the version's export name and media type.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn new(
        artifact_id: &EntityId,
        artifact: BlobArtifactBody,
        place: &VersionPlace,
        content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
        provenance: &BlobVersionProvenance,
        calc_engine: Option<&CalcEngineStamp>,
        fork_parent: Option<u64>,
        made_by: MadeBy,
        claim_id: EntityId,
        actor: WriteActor,
        learned_at: u64,
    ) -> Result<Self> {
        let candidate = ClaimCandidate::new(
            BLOB_VERSION_CLAIM_PREDICATE,
            ClaimSubject::Entity(*artifact_id),
            blob_version_claim_value(
                place.next_version,
                &content_hash,
                provenance,
                place.parent_version,
                fork_parent,
                calc_engine,
                &made_by_text(&made_by)?,
            ),
            1.0,
        );
        let envelope = WriteEnvelope::new(
            actor,
            provenance.claim_source(),
            WriteProvenance::new(write_provenance_value(provenance))?,
            provenance.approval_status(),
        );
        let record = BlobArtifactVersion {
            version: place.next_version,
            content_hash,
            provenance: provenance.clone(),
            calc_engine: calc_engine.cloned(),
            claim_id,
            created_at: learned_at,
            export_name: artifact.name,
            export_media_type: artifact.media_type,
            parent_version: place.parent_version,
            fork_of_version: fork_parent,
            made_by,
        };
        Ok(Self {
            record,
            candidate,
            envelope,
        })
    }
}

/// The chain rows `record` takes on `dbs` (FIX 4818: a room's view for a
/// room's response version): the version, the head, the high-water mark and
/// the born-from index.
pub(super) fn put_version_rows_in_txn(
    dbs: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    artifact_id: &EntityId,
    record: &BlobArtifactVersion,
) -> Result<()> {
    VERSIONS.put(dbs, wtxn, &(*artifact_id, record.version), record)?;
    HEAD.put(dbs, wtxn, artifact_id, record)?;
    HIGHWATER.put(dbs, wtxn, artifact_id, &record.version.to_be_bytes())?;
    super::super::born_from::index_version_in_txn(dbs, wtxn, artifact_id, record)
}
