//! Blob version chain: version record codec and the Vault version-chain API.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edit_settle::{MadeByReader, PendingProposalView};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::store::code_snapshot::entity_id_from_hash_material;
use crate::store::{BodyMint, StagedAssetBody, Store};
use crate::temporal::TimeRange;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::body::{BlobArtifactBody, decode_blob_artifact_body, encode_blob_artifact_body};
use super::made_by::{
    bind_version_made_by, births_row, default_version_made_by, made_by_text,
    validate_version_made_by_in_txn,
};
use super::provenance::{
    BLOB_VERSION_CLAIM_PREDICATE, BlobVersionProvenance, blob_version_claim_value,
    validate_provenance, write_provenance_value,
};
use super::store_keys::{
    BLOB_ARTIFACT_ASSET_ID_DOMAIN, BLOB_ARTIFACT_CONTENT_HASH_LEN, require_entity_type,
};
pub(super) use super::version_codec::decode_blob_artifact_version_record;
use super::version_codec::encode_blob_artifact_version_record;
use crate::error::ArtifactError;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::write_envelope::provenance::made_by::MadeBy;

// The version chain's reads: the head, the tree, one version's metadata
// and its bytes, with the gate on a compaction step's response (FIX 5977).
mod checked;
mod queue_check;
mod reads;
pub(crate) use queue_check::{append_queue_check_output_in_txn, mint_queue_check_artifact_id};
pub use reads::BlobBytes;

/// Blob artifact version record. Key: id16 (artifact) + u64be (version).
pub(super) const VERSIONS: SideTable<(EntityId, u64), BlobArtifactVersion, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_VERSION);
/// Blob artifact head version — the same record shape as [`VERSIONS`], keyed by artifact alone.
/// Key: id16 (artifact).
pub(super) const HEAD: SideTable<EntityId, BlobArtifactVersion, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_HEAD);

/// Last issued version survives artifact deletion, as u64 big endian.
const HIGHWATER: SideTable<EntityId, [u8; 8], Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_HIGHWATER);

/// The bytes one appended version holds: a slice, or a body staged from a
/// reader before the append writes anything (FIX 12091).
#[derive(Clone, Copy)]
enum VersionBody<'b> {
    Bytes(&'b [u8]),
    Staged(&'b StagedAssetBody),
}

impl<'b> VersionBody<'b> {
    /// The version's content hash: the body's BLAKE3.
    fn content_hash(self) -> [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN] {
        match self {
            Self::Bytes(bytes) => *blake3::hash(bytes).as_bytes(),
            Self::Staged(staged) => staged.facts().blake3,
        }
    }

    /// The body's bytes when they are held in memory: `None` for a staged
    /// body held as a body file.
    fn held_bytes(self) -> Option<&'b [u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::Staged(staged) => staged.inline_bytes(),
        }
    }
}

impl RawValue for BlobArtifactVersion {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_blob_artifact_version_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_blob_artifact_version_record(bytes)?)
    }
}

/// The calculator that last computed an artifact version's cached values.
/// An upload or a version that was never recalculated has no stamp; absence is
/// explicit in both the version record and its ledger claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalcEngineStamp {
    engine: String,
    version: String,
}

impl CalcEngineStamp {
    pub fn new(engine: impl Into<String>, version: impl Into<String>) -> Result<Self> {
        let stamp = Self {
            engine: engine.into(),
            version: version.into(),
        };
        stamp.validate()?;
        Ok(stamp)
    }

    #[must_use]
    pub fn engine(&self) -> &str {
        &self.engine
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    fn validate(&self) -> Result<()> {
        for text in [&self.engine, &self.version] {
            if text.trim().is_empty() || text.len() > 128 {
                return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                    "calc engine and version must be non-empty and at most 128 bytes",
                )));
            }
            crate::batch::secret_scan::scan_metadata_field(text)?;
        }
        Ok(())
    }
}

/// One record of the append-only version tree: content hash + provenance +
/// the `blob.version` claim id (the LEDGER event for this version).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactVersion {
    pub version: u64,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    pub provenance: BlobVersionProvenance,
    /// `None` means no known calculator computed the cached values.
    pub calc_engine: Option<CalcEngineStamp>,
    pub claim_id: EntityId,
    pub created_at: u64,
    /// Export presentation pinned when this version was appended, not read
    /// from the mutable artifact body at serve time.
    pub export_name: String,
    pub export_media_type: String,
    /// The version this record descends from. Absent for roots and legacy rows.
    pub parent_version: Option<u64>,
    /// The selected base of an explicit fork; absent on ordinary head appends.
    pub fork_of_version: Option<u64>,
    /// What this version was made from, what made it and when (ARCH-0078
    /// "The provenance receipt"). Its trigger is the version's born-from.
    pub made_by: MadeBy,
}

pub const BLOB_ARTIFACT_VERSION_RECORD_KEYS: [&str; 13] = [
    "version",
    "content_hash",
    "provenance",
    "run_ref",
    "claim_id",
    "created_at",
    "parent_version",
    "fork_of_version",
    "calc_engine",
    "calc_engine_version",
    "export_name",
    "export_media_type",
    "made_by",
];

pub(super) const KEY_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[0];

pub(super) const KEY_CONTENT_HASH: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[1];

pub(super) const KEY_PROVENANCE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[2];

pub(super) const KEY_RUN_REF: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[3];

pub(super) const KEY_CLAIM_ID: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[4];

pub(super) const KEY_CREATED_AT: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[5];

pub(super) const KEY_PARENT_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[6];

pub(super) const KEY_FORK_OF_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[7];

pub(super) const KEY_CALC_ENGINE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[8];

pub(super) const KEY_CALC_ENGINE_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[9];

pub(super) const KEY_EXPORT_NAME: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[10];
pub(super) const KEY_EXPORT_MEDIA_TYPE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[11];
pub(super) const KEY_MADE_BY: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[12];

/// What a checked direct append did: landed immediately, or retained through
/// the ordinary proposal door for an authorized Keep (FIX 8208).
#[derive(Debug, Clone)]
pub enum BlobArtifactAppendOutcome {
    Landed(BlobArtifactVersion),
    Proposed(PendingProposalView),
}

enum VersionAuthority<'proof, 'bytes> {
    Actor(WriteActor),
    QueueCheck(&'proof crate::merge_queue::QueueCheckFieldToken<'bytes>),
}

impl Vault {
    pub fn put_blob_artifact(
        &self,
        id: &EntityId,
        body: &BlobArtifactBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_blob_artifact_body(body)?;
        self.put_entity(id, ENTITY_TYPE_BLOB_ARTIFACT, occurred, learned_at, &data)
    }

    pub fn get_blob_artifact(&self, id: &EntityId) -> Result<Option<BlobArtifactBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_blob_artifact_in_txn(&rtxn, id)
    }

    pub(crate) fn get_blob_artifact_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<BlobArtifactBody>> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, rtxn, id)?
        else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_record::reject_secret_custody_byte());
        }
        if header.entity_type != ENTITY_TYPE_BLOB_ARTIFACT {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "entity is not a type-85 BLOB_ARTIFACT",
            )));
        }
        decode_blob_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// A direct door's checked append. User uploads and first versions land as
    /// before. A later AgentRun append without settlement waits as the same
    /// native-output proposal any organ result uses, with the caller's live
    /// content-write authority checked beside it; HEAD stays untouched until
    /// Keep takes the existing authorized settlement path (FIX 8208). The read
    /// lane is constructed only for a retained envelope naming sources beyond
    /// its writer, never for a landed append (FIX 12562).
    #[expect(clippy::too_many_arguments)]
    pub fn append_blob_artifact_version_checked<'reader, E>(
        &self,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        made_by: Option<&MadeBy>,
        reader: impl FnOnce() -> std::result::Result<Option<MadeByReader<'reader>>, E>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> std::result::Result<BlobArtifactAppendOutcome, E>
    where
        E: From<Error>,
    {
        let (version, fork_base) = self.with_write_txn_grouped(|wtxn| {
            self.decide_blob_artifact_append_in_txn(
                wtxn,
                artifact_id,
                fork_parent,
                bytes,
                provenance,
                made_by,
                actor,
                occurred,
                learned_at,
                crate::core_write::CoreWriteLaneRef::Unbound,
            )
        })?;
        if let Some(version) = version {
            return Ok(BlobArtifactAppendOutcome::Landed(version));
        }
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let output =
            checked::direct_append_output(body, bytes, provenance, made_by, actor, learned_at);
        let reader = if made_by.is_some_and(|named| {
            named.process.actor != actor.entity_ref()
                || !named.inputs.is_empty()
                || named.trigger.is_some()
        }) {
            reader()?
        } else {
            None
        };
        self.propose_native_output_with_write_grant(
            artifact_id,
            &output,
            reader,
            actor,
            learned_at,
            fork_base,
            None,
        )
        .map(BlobArtifactAppendOutcome::Proposed)
        .map_err(E::from)
    }

    /// Appends one version to the artifact's append-only chain.
    ///
    /// The whole append is ONE LMDB write transaction: the content-addressed
    /// ASSET bytes (blake3), the `blob.version` claim — the LEDGER event —
    /// the version record, the head record, and the asset reference row all
    /// land together or roll back together, so a failed append can never
    /// leave an orphan claim or asset asserting a version that does not
    /// exist. Re-appending the exact bytes of the current head is a dedupe
    /// no-op that returns the existing head version.
    pub fn append_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.with_write_txn_grouped(|wtxn| {
            self.append_blob_artifact_version_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                learned_at,
            )
        })
    }

    /// Appends a new version descending from any existing version of this artifact.
    /// The scalar version number still advances past the high-water mark;
    /// only the ancestry pointer branches. Unlike an ordinary append,
    /// identical bytes do not suppress the explicit fork event.
    #[expect(clippy::too_many_arguments)]
    pub fn fork_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        parent_version: u64,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.with_write_txn_grouped(|wtxn| {
            self.append_blob_artifact_version_with_parent_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                learned_at,
                Some(parent_version),
                crate::core_write::CoreWriteLaneRef::Unbound,
            )
        })
    }

    /// Appends one version carrying the made_by envelope its writer names:
    /// what it was made from, the process that made it, and the task or ask
    /// that triggered it (its born-from). `fork_parent` names any earlier
    /// version as the parent, as [`Vault::fork_blob_artifact_version`] does;
    /// `None` appends on the head. The envelope's time is the append's.
    #[expect(clippy::too_many_arguments)]
    pub fn append_blob_artifact_version_made_by(
        &self,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        made_by: &MadeBy,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.with_write_txn_grouped(|wtxn| {
            self.append_blob_artifact_version_made_by_in_txn(
                wtxn,
                artifact_id,
                fork_parent,
                bytes,
                provenance,
                made_by,
                actor,
                occurred,
                learned_at,
            )
        })
    }

    /// Transaction-composable body of [`Vault::append_blob_artifact_version_made_by`].
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_made_by_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        made_by: &MadeBy,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
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
            Some(made_by),
            crate::core_write::CoreWriteLaneRef::Unbound,
        )
    }

    /// Binds a caller-supplied envelope to the authenticated producer once,
    /// at proposal retention, so the trusted Keep path can preserve it
    /// instead of rebinding it to the keeper (blind review of #4554). The
    /// provenance matches what Keep settles under.
    pub(crate) fn bind_retained_producer_envelope(
        actor: &WriteActor,
        provenance: &BlobVersionProvenance,
        made_by: &MadeBy,
        at: u64,
    ) -> MadeBy {
        bind_version_made_by(actor, provenance, made_by, at)
    }

    /// The trusted Keep path: the retained envelope was bound to its
    /// producer when the proposal was authenticated, so it lands validated
    /// but unchanged. The keeper's write authority stays out of the producer
    /// receipt: no rebind to the approver (blind review of #4554).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_kept_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        fork_parent: Option<u64>,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        made_by: &MadeBy,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
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
            None,
            Some(made_by),
            true,
            false,
            crate::core_write::CoreWriteLaneRef::Unbound,
        )
    }

    /// Transaction-composable body of [`Vault::append_blob_artifact_version`].
    ///
    /// ARTL-4 settle-select needs the version append, its re-anchor sweep, and
    /// the consume-once ledger insert to commit or roll back as one unit, so it
    /// drives this against a shared `wtxn` rather than the self-contained public
    /// method's own transaction.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_with_parent_in_txn(
            wtxn,
            artifact_id,
            bytes,
            provenance,
            actor,
            occurred,
            learned_at,
            None,
            crate::core_write::CoreWriteLaneRef::Unbound,
        )
    }

    /// An artifact content writer's append, under that writer's actual read lane.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_in_lane(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
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
            None,
            None,
            None,
            false,
            true,
            lane,
        )
    }

    /// [`Self::append_blob_artifact_version_in_txn`] of the bytes `body`
    /// yields (FIX 12091): they are staged as they stream, before the append
    /// writes anything, so the version's hash, its dedupe on the head and
    /// the writer's authority are judged before its blob is put, as for a
    /// slice. A long body the asset plane files goes to its body file under
    /// an instance of `mint`, which the caller took before `wtxn` opened
    /// (KS-2A, FIX 6021), and an opaque one never sits whole in memory; with
    /// the plane off, or no mint, it is read once into its row, as a slice
    /// is put.
    ///
    /// The staged body comes back beside the version: hold it, or the
    /// [`StagedAssetBody::into_hold`] that drops its bytes, until `wtxn` has
    /// committed or aborted, so its pin keeps a published file from the
    /// collector until the row naming it is durable (FIX 5399b).
    ///
    /// # Errors
    ///
    /// The reader's and the staging errors, and the slice append's.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_from_reader_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        body: &mut dyn std::io::Read,
        mint: Option<&BodyMint>,
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(BlobArtifactVersion, StagedAssetBody)> {
        // Checked before a byte is staged, as the slice append checks it
        // before it hashes one.
        validate_provenance(provenance)?;
        let staged = self.stage_blob_body_in_txn(wtxn, body, mint)?;
        let version = self.append_blob_artifact_version_body_in_txn(
            wtxn,
            artifact_id,
            VersionBody::Staged(&staged),
            provenance,
            actor,
            occurred,
            learned_at,
            None,
            None,
            None,
            false,
            true,
            crate::core_write::CoreWriteLaneRef::Unbound,
        )?;
        Ok((version, staged))
    }

    /// Settle's append door, with the calculator that produced cached values
    /// and the kept proposal's made_by envelope.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_with_engine_and_parent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        calc_engine: Option<&CalcEngineStamp>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        made_by: Option<&MadeBy>,
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
            false,
            crate::core_write::CoreWriteLaneRef::Unbound,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn append_blob_artifact_version_with_parent_in_txn(
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
    fn append_blob_artifact_version_with_parent_and_engine_in_txn(
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
    fn append_blob_artifact_version_body_in_txn(
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
            lane,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn append_blob_artifact_version_body_with_authority_in_txn(
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
        let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
        let highwater = read_blob_artifact_highwater_in_txn(&self.store, wtxn, artifact_id)?;
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
                let record = VERSIONS
                    .get(&self.store, wtxn, &(*artifact_id, parent))?
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
            (None, Some(head)) if head.content_hash == content_hash => {
                fingerprint.persist(&self.store, wtxn, artifact_id)?;
                return Ok(head.clone());
            }
            (None, Some(head)) => (Some(head.version), Some(head.claim_id)),
            (None, None) => (None, None),
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
            None => default_version_made_by(&actor, provenance, parent_claim, learned_at),
        };
        let made_by_json = made_by_text(&made_by)?;
        // Deletion removes the current chain, and a response pin's release
        // one version (FIX 6225), but never the high-water mark: the next
        // number is above every one ever issued, never reused.
        let previous_version = highwater.unwrap_or(0);
        let next_version = previous_version
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))?;
        if VERSIONS.contains(&self.store, wtxn, &(*artifact_id, next_version))? {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "blob artifact version is already recorded",
            )));
        }

        let candidate = ClaimCandidate::new(
            BLOB_VERSION_CLAIM_PREDICATE,
            ClaimSubject::Entity(*artifact_id),
            blob_version_claim_value(
                next_version,
                &content_hash,
                provenance,
                parent_version,
                fork_parent,
                calc_engine,
                &made_by_json,
            ),
            1.0,
        );
        let mut envelope = WriteEnvelope::new(
            actor,
            provenance.claim_source(),
            WriteProvenance::new(write_provenance_value(provenance))?,
            provenance.approval_status(),
        );
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

        let record = BlobArtifactVersion {
            version: next_version,
            content_hash,
            provenance: provenance.clone(),
            calc_engine: calc_engine.cloned(),
            claim_id,
            created_at: learned_at,
            export_name: artifact.name,
            export_media_type: artifact.media_type,
            parent_version,
            fork_of_version: fork_parent,
            made_by,
        };
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
        VERSIONS.put(&self.store, wtxn, &(*artifact_id, next_version), &record)?;
        HEAD.put(&self.store, wtxn, artifact_id, &record)?;
        HIGHWATER.put(&self.store, wtxn, artifact_id, &next_version.to_be_bytes())?;
        super::born_from::index_version_in_txn(&self.store, wtxn, artifact_id, &record)?;
        // The first version is the artifact's birth: its envelope is the
        // artifact row's Rule A birth, read backwards by `rows_born_from`.
        if previous_version == 0 && births_row(&record.made_by) {
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
        if reanchor_html && let Some(head) = head {
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

fn read_blob_artifact_highwater_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
) -> Result<Option<u64>> {
    let Some(bytes) = HIGHWATER.get(store, rtxn, artifact_id)? else {
        return Ok(None);
    };
    let version = u64::from_be_bytes(bytes);
    if version == 0 {
        return Err(Error::CorruptedIndex("blob artifact version highwater"));
    }
    Ok(Some(version))
}

pub(crate) fn read_blob_artifact_head_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
) -> Result<Option<BlobArtifactVersion>> {
    HEAD.get(store, rtxn, artifact_id)
}

pub(crate) fn blob_artifact_asset_entity_id(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(BLOB_ARTIFACT_ASSET_ID_DOMAIN, &[content_hash])
}

/// OF-222 (FIX 2768) archive seam: the version chain tables a whole-vault archive carries
/// beside the artifact (versions, head, highwater and the asset refcount markers), lent to
/// the archive's side-row reader and restorer with their own key types and codec.
pub(crate) fn archive_version_tables() -> [crate::batch::export::LentSideTable; 4] {
    [&VERSIONS, &HEAD, &HIGHWATER, &super::store_keys::ASSET_REF]
}
