//! ARTL-1 (OF-368 D1): versioned blob artifact store for foreign binary
//! (office) files.
//!
//! Rides the OF-320 bitemporal code-artifact shape instead of forking a
//! second artifact model:
//!
//! * the artifact is a typed entity ([`ENTITY_TYPE_BLOB_ARTIFACT`]) whose
//!   body carries pinned metadata keys and never inline content;
//! * version bytes live in content-addressed [`ENTITY_TYPE_ASSET`] entities
//!   (blake3 content hash → deterministic asset id), so identical bytes are
//!   stored once per vault;
//! * each version is an append-only `vault_meta` record carrying the content
//!   hash, per-version provenance (user upload | agent-run ref), and the id
//!   of its `blob.version` claim — the LEDGER event for that version;
//! * history is append-only: a version is only ever added at head+1, and
//!   existing version records are never rewritten or deleted while the
//!   artifact lives. Re-appending the current head bytes is a dedupe no-op
//!   that returns the existing head version.
//!
//! Content-hash dedupe is vault-scoped ONLY. A vault is one tenant's sealed
//! store (OF-307): a content hash computed from one tenant's bytes never
//! resolves storage for another tenant, even when byte-identical.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, secret_scan};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT};
use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{taint_refs_from_value, taint_refs_to_value, validate_taint_refs};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use heed::{RoTxn, RwTxn};

/// The REQUIRED artifact-body keys. A body missing any of them fails closed
/// — an artifact is complete on write.
pub const BLOB_ARTIFACT_BODY_KEYS: [&str; 2] = ["name", "media_type"];

/// The OPTIONAL artifact-body keys (SECRET-04, ONE-1922).
///
/// Pinned exactly like the required set — a key outside the UNION of the two
/// still rejects, and duplicates within either still reject — but ABSENCE is
/// meaningful rather than fatal: an artifact with no `secret_taint.refs`
/// consumed no secret and reads `Clean`. That is what keeps every body
/// written before this key existed decodable, and it is why the key could
/// not simply join [`BLOB_ARTIFACT_BODY_KEYS`], whose whole contract is that
/// each of its members is mandatory.
///
/// Encode emits the key only when the list is non-empty, so an untainted
/// body is BYTE-IDENTICAL to what it was before SECRET-04.
///
/// There is deliberately no `secret_taint.state` key beside it: taint STATE
/// is derived at read time (ARCH-0069 S7, amended 2026-08-05), and a stored
/// state is exactly the thing that amendment removed.
pub const BLOB_ARTIFACT_OPTIONAL_BODY_KEYS: [&str; 1] = ["secret_taint.refs"];
pub const BLOB_ARTIFACT_NAME_MAX_BYTES: usize = 512;
pub const BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES: usize = 256;
pub const BLOB_ARTIFACT_CONTENT_HASH_LEN: usize = 32;
pub const BLOB_ARTIFACT_RUN_REF_MAX_BYTES: usize = 1024;
pub const BLOB_ARTIFACT_VERSION_RECORD_KEYS: [&str; 6] = [
    "version",
    "content_hash",
    "provenance",
    "run_ref",
    "claim_id",
    "created_at",
];

pub(crate) const BLOB_VERSION_CLAIM_PREDICATE: &str = "blob.version";

const KEY_NAME: &str = BLOB_ARTIFACT_BODY_KEYS[0];
const KEY_MEDIA_TYPE: &str = BLOB_ARTIFACT_BODY_KEYS[1];
const KEY_SECRET_TAINT_REFS: &str = BLOB_ARTIFACT_OPTIONAL_BODY_KEYS[0];

/// Every key the pinned-key law admits: required followed by optional.
/// Decode resolves each body key against THIS union, so an unknown key is
/// still a reject and a duplicate of either kind is still a reject.
const BLOB_ARTIFACT_KNOWN_BODY_KEYS: [&str; 3] = [KEY_NAME, KEY_MEDIA_TYPE, KEY_SECRET_TAINT_REFS];

const KEY_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[0];
const KEY_CONTENT_HASH: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[1];
const KEY_PROVENANCE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[2];
const KEY_RUN_REF: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[3];
const KEY_CLAIM_ID: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[4];
const KEY_CREATED_AT: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[5];

const BLOB_ARTIFACT_VERSION_KEY_PREFIX: &[u8] = b"blob_artifact:version:v1:";
const BLOB_ARTIFACT_HEAD_KEY_PREFIX: &[u8] = b"blob_artifact:head:v1:";
const BLOB_ARTIFACT_ASSET_REF_KEY_PREFIX: &[u8] = b"blob_artifact:asset_ref:v1:";
const BLOB_ARTIFACT_ASSET_ID_DOMAIN: &[u8] = b"oneiron:blob-artifact-asset:v1";

const PROVENANCE_USER_UPLOAD: &str = "user_upload";
const PROVENANCE_AGENT_RUN: &str = "agent_run";

/// Who produced one blob artifact version: a direct user upload or an agent
/// run identified by its stable run reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobVersionProvenance {
    UserUpload,
    AgentRun { run_ref: String },
}

impl BlobVersionProvenance {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UserUpload => PROVENANCE_USER_UPLOAD,
            Self::AgentRun { .. } => PROVENANCE_AGENT_RUN,
        }
    }

    #[must_use]
    pub fn run_ref(&self) -> Option<&str> {
        match self {
            Self::UserUpload => None,
            Self::AgentRun { run_ref } => Some(run_ref),
        }
    }

    fn from_parts(kind: &str, run_ref: Option<String>) -> Result<Self> {
        match (kind, run_ref) {
            (PROVENANCE_USER_UPLOAD, None) => Ok(Self::UserUpload),
            (PROVENANCE_AGENT_RUN, Some(run_ref)) => Ok(Self::AgentRun { run_ref }),
            _ => Err(Error::InvalidBlobArtifactBody(
                "provenance must be user_upload without run_ref or agent_run with run_ref",
            )),
        }
    }

    fn claim_source(&self) -> ClaimSource {
        match self {
            Self::UserUpload => ClaimSource::UserStated,
            Self::AgentRun { .. } => ClaimSource::Generated,
        }
    }

    /// Generated sources need an explicit Gate permit for `Auto`, so
    /// agent-run LEDGER events park as `Proposed` — the same stance as the
    /// OF-320 code-run dispatcher for first-party generated effects.
    fn approval_status(&self) -> ClaimApprovalStatus {
        match self {
            Self::UserUpload => ClaimApprovalStatus::Auto,
            Self::AgentRun { .. } => ClaimApprovalStatus::Proposed,
        }
    }
}

/// Artifact-level metadata. Stable across versions; content bytes never live
/// here (OF-320 reference-not-content law) — they are content-addressed
/// ASSET entities resolved through the version records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactBody {
    pub name: String,
    pub media_type: String,
    /// SECRET-04 (ONE-1922): the secrets whose values were consumed
    /// producing this artifact, each pinned to the custody generation the
    /// value was read at.
    ///
    /// REFS, not state. A consumer derives `Clean | TaintedLive |
    /// TaintedStale` by comparing these generations against the records'
    /// current ones ([`crate::Vault::artifact_taint_state`]); nothing here
    /// is ever flipped when a secret rotates. Empty is the overwhelmingly
    /// common case and costs nothing on the wire.
    pub secret_taint_refs: Vec<SecretTaintRef>,
}

impl BlobArtifactBody {
    /// An UNTAINTED artifact body — the shape every existing caller wants
    /// and the reason this constructor did not grow an argument.
    #[must_use]
    pub fn new(name: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            media_type: media_type.into(),
            secret_taint_refs: Vec::new(),
        }
    }

    /// Attaches the taint refs of the action that produced this artifact.
    ///
    /// The attach is the artifact PUT itself: the refs live in the body, so
    /// they land in the same transaction as the artifact they mark and
    /// cannot drift apart from it.
    #[must_use]
    pub fn with_secret_taint_refs(mut self, refs: Vec<SecretTaintRef>) -> Self {
        self.secret_taint_refs = refs;
        self
    }
}

/// One record of the append-only version chain: content hash + provenance +
/// the `blob.version` claim id (the LEDGER event for this version).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactVersion {
    pub version: u64,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    pub provenance: BlobVersionProvenance,
    pub claim_id: EntityId,
    pub created_at: u64,
}

pub fn encode_blob_artifact_body(body: &BlobArtifactBody) -> Result<Vec<u8>> {
    validate_blob_artifact_body(body)?;
    let mut entries = vec![
        (Value::from(KEY_NAME), Value::from(body.name.as_str())),
        (
            Value::from(KEY_MEDIA_TYPE),
            Value::from(body.media_type.as_str()),
        ),
    ];
    // Emitted ONLY when non-empty: an untainted body keeps the exact bytes
    // it had before this key existed.
    if !body.secret_taint_refs.is_empty() {
        entries.push((
            Value::from(KEY_SECRET_TAINT_REFS),
            taint_refs_to_value(&body.secret_taint_refs),
        ));
    }
    encode_value(
        &Value::Map(entries),
        "BLOB artifact body MessagePack encode failed",
    )
}

pub fn decode_blob_artifact_body(bytes: &[u8]) -> Result<BlobArtifactBody> {
    let value = read_value(bytes, "body")?;
    decode_blob_artifact_body_value(&value)
}

pub(crate) fn validate_blob_artifact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_blob_artifact_body(bytes).map(|_| ())
}

fn decode_blob_artifact_body_value(value: &Value) -> Result<BlobArtifactBody> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidBlobArtifactBody(
            "body must be a MessagePack map",
        ));
    };

    let mut name: Option<String> = None;
    let mut media_type: Option<String> = None;
    let mut secret_taint_refs: Vec<SecretTaintRef> = Vec::new();
    let mut seen = [false; BLOB_ARTIFACT_KNOWN_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidBlobArtifactBody("body keys must be strings"));
        };
        let Some(index) = BLOB_ARTIFACT_KNOWN_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidBlobArtifactBody(
                "body key is not in the pinned BLOB_ARTIFACT_BODY_KEYS / BLOB_ARTIFACT_OPTIONAL_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidBlobArtifactBody("duplicate body key"));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_KNOWN_BODY_KEYS[index] {
            KEY_NAME => {
                let text = value.as_str().ok_or(Error::InvalidBlobArtifactBody(
                    "name must be a UTF-8 string",
                ))?;
                name = Some(text.to_owned());
            }
            KEY_MEDIA_TYPE => {
                let text = value.as_str().ok_or(Error::InvalidBlobArtifactBody(
                    "media_type must be a UTF-8 string",
                ))?;
                media_type = Some(text.to_owned());
            }
            KEY_SECRET_TAINT_REFS => {
                secret_taint_refs =
                    taint_refs_from_value(value).ok_or(Error::InvalidBlobArtifactBody(
                        "secret_taint.refs must be an array of {secret_ref, generation} maps with bounded, non-duplicated names",
                    ))?;
            }
            _ => unreachable!("index resolved from BLOB_ARTIFACT_KNOWN_BODY_KEYS"),
        }
    }

    let body = BlobArtifactBody {
        name: name.ok_or(Error::InvalidBlobArtifactBody(
            "missing required body key name",
        ))?,
        media_type: media_type.ok_or(Error::InvalidBlobArtifactBody(
            "missing required body key media_type",
        ))?,
        // OPTIONAL by contract: an absent key is an artifact that consumed
        // no secret, which reads Clean.
        secret_taint_refs,
    };
    validate_blob_artifact_body(&body)?;
    Ok(body)
}

fn validate_blob_artifact_body(body: &BlobArtifactBody) -> Result<()> {
    validate_text_field(
        &body.name,
        BLOB_ARTIFACT_NAME_MAX_BYTES,
        "name must be non-empty and at most 512 bytes",
    )?;
    validate_text_field(
        &body.media_type,
        BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES,
        "media_type must be non-empty and at most 256 bytes",
    )?;
    validate_taint_refs(&body.secret_taint_refs).map_err(|_| {
        Error::InvalidBlobArtifactBody(
            "secret_taint.refs entries must carry bounded, non-empty, non-duplicated secret names",
        )
    })?;
    Ok(())
}

fn validate_provenance(provenance: &BlobVersionProvenance) -> Result<()> {
    if let BlobVersionProvenance::AgentRun { run_ref } = provenance {
        validate_text_field(
            run_ref,
            BLOB_ARTIFACT_RUN_REF_MAX_BYTES,
            "run_ref must be non-empty and at most 1024 bytes",
        )?;
        if run_ref.trim().is_empty() {
            return Err(Error::InvalidBlobArtifactBody(
                "run_ref must be non-empty and at most 1024 bytes",
            ));
        }
        secret_scan::scan_metadata_field(run_ref)?;
    }
    Ok(())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidBlobArtifactBody(context));
    }
    Ok(())
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
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_BLOB_ARTIFACT {
            return Err(Error::InvalidBlobArtifactBody(
                "entity is not a type-85 BLOB_ARTIFACT",
            ));
        }
        decode_blob_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
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
        self.with_write_txn(|wtxn| {
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
        validate_provenance(provenance)?;
        if bytes.is_empty() {
            return Err(Error::InvalidBlobArtifactBody(
                "blob artifact version bytes must be non-empty",
            ));
        }
        let content_hash = *blake3::hash(bytes).as_bytes();
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let claim_id = EntityId::now();

        require_entity_type(
            &self.store,
            wtxn,
            artifact_id,
            ENTITY_TYPE_BLOB_ARTIFACT,
            "append target must be a BLOB_ARTIFACT entity",
        )?;
        let next_version = match read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)? {
            Some(head) if head.content_hash == content_hash => return Ok(head),
            Some(head) => head
                .version
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))?,
            None => 1,
        };
        let version_key = blob_artifact_version_key(artifact_id, next_version);
        if self.store.vault_meta.get(wtxn, &version_key)?.is_some() {
            return Err(Error::InvalidBlobArtifactBody(
                "blob artifact version is already recorded",
            ));
        }

        let candidate = ClaimCandidate::new(
            BLOB_VERSION_CLAIM_PREDICATE,
            ClaimSubject::Entity(*artifact_id),
            blob_version_claim_value(next_version, &content_hash, provenance),
            1.0,
        );
        let envelope = WriteEnvelope::new(
            actor,
            provenance.claim_source(),
            WriteProvenance::new(write_provenance_value(provenance))?,
            provenance.approval_status(),
        );
        self.batch_in()
            .put(&asset_id, ENTITY_TYPE_ASSET, occurred, learned_at, bytes)
            .claim_candidate(&claim_id, candidate, &envelope, occurred, learned_at)
            .apply(wtxn)?;

        let record = BlobArtifactVersion {
            version: next_version,
            content_hash,
            provenance: provenance.clone(),
            claim_id,
            created_at: learned_at,
        };
        let encoded = encode_blob_artifact_version_record(&record)?;
        self.store.vault_meta.put(wtxn, &version_key, &encoded)?;
        self.store
            .vault_meta
            .put(wtxn, &blob_artifact_head_key(artifact_id), &encoded)?;
        self.store.vault_meta.put(
            wtxn,
            &blob_artifact_asset_ref_key(&content_hash, artifact_id),
            &[],
        )?;
        Ok(record)
    }

    pub fn blob_artifact_head(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Option<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)
    }

    /// Returns the full version chain, oldest first, verifying it is a
    /// contiguous append-only sequence starting at version 1.
    pub fn blob_artifact_versions(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = blob_artifact_version_prefix(artifact_id);
        let mut versions = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, raw) = entry?;
            let record = decode_blob_artifact_version_record(&raw)?;
            let expected = u64::try_from(versions.len())
                .map_err(|_| Error::ArithmeticOverflow("blob artifact version overflow"))?
                + 1;
            if record.version != expected || !key.ends_with(&record.version.to_be_bytes()) {
                return Err(Error::CorruptedIndex("blob artifact version chain"));
            }
            versions.push(record);
        }
        if let Some(head) = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)? {
            if versions.last() != Some(&head) {
                return Err(Error::CorruptedIndex("blob artifact version head"));
            }
        } else if !versions.is_empty() {
            return Err(Error::CorruptedIndex("blob artifact version head"));
        }
        Ok(versions)
    }

    /// Reads the stored bytes for one version, verifying the content hash on
    /// the way out.
    pub fn read_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let record = {
            let rtxn = self.store.env.read_txn()?;
            let Some(raw) = self
                .store
                .vault_meta
                .get(&rtxn, &blob_artifact_version_key(artifact_id, version))?
            else {
                return Ok(None);
            };
            decode_blob_artifact_version_record(&raw)?
        };
        read_blob_asset(self, &record.content_hash).map(Some)
    }
}

/// Outcome of blob-artifact lifecycle cleanup: index flags and graph
/// neighbors from any orphaned ASSET entities deleted with the chain, for
/// the caller to fold into its own deletion accounting.
#[derive(Debug, Default)]
pub(crate) struct BlobArtifactLifecycleCleanup {
    pub(crate) had_vector: bool,
    pub(crate) had_graph_mutation: bool,
    pub(crate) neighbors: Vec<EntityId>,
}

/// Removes an artifact's version chain, head record, and asset-reference
/// rows, hard-deleting every ASSET entity this chain was the LAST reference
/// to — version bytes never outlive the last chain that references them.
/// The refcount is the `blob_artifact:asset_ref:v1:` rows (one per
/// content-hash × artifact pair, vault-scoped like the dedupe itself).
/// Runs inside every entity delete path (batch delete, purge, soft erase)
/// and is a cheap no-op for entities without a version chain. Side-deleted
/// assets carry no sync tombstone of their own: they are derived
/// content-addressed storage, and a replay-rematerialized asset is a
/// harmless orphan that the next last-reference delete removes again.
pub(crate) fn delete_blob_artifact_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BlobArtifactLifecycleCleanup> {
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    let prefix = blob_artifact_version_prefix(id);
    let mut keys = Vec::new();
    let mut hashes: Vec<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]> = Vec::new();
    for entry in store.vault_meta.prefix_iter(wtxn, &prefix)? {
        let (key, raw) = entry?;
        let record = decode_blob_artifact_version_record(&raw)?;
        if !hashes.contains(&record.content_hash) {
            hashes.push(record.content_hash);
        }
        keys.push(key.to_vec());
    }
    store.vault_meta.delete(wtxn, &blob_artifact_head_key(id))?;
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    for content_hash in hashes {
        store
            .vault_meta
            .delete(wtxn, &blob_artifact_asset_ref_key(&content_hash, id))?;
        let ref_prefix = blob_artifact_asset_ref_prefix(&content_hash);
        let still_referenced = store
            .vault_meta
            .prefix_iter(wtxn, &ref_prefix)?
            .next()
            .transpose()?
            .is_some();
        if still_referenced {
            continue;
        }
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let (_existed, had_vector, had_graph_mutation, neighbors) =
            crate::batch::deindex_entity(store, wtxn, &asset_id)?;
        ppr::invalidate_ppr_for_delete(store, wtxn, &asset_id, &neighbors)?;
        cleanup.had_vector |= had_vector;
        cleanup.had_graph_mutation |= had_graph_mutation;
        cleanup.neighbors.extend(neighbors);
    }
    cleanup.neighbors.sort_unstable();
    cleanup.neighbors.dedup();
    Ok(cleanup)
}

pub(crate) fn read_blob_artifact_head_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
) -> Result<Option<BlobArtifactVersion>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &blob_artifact_head_key(artifact_id))?
    else {
        return Ok(None);
    };
    decode_blob_artifact_version_record(&raw).map(Some)
}

fn read_blob_asset(
    vault: &Vault,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    let asset_id = blob_artifact_asset_entity_id(content_hash)?;
    let Some(raw) = vault.get_raw(&asset_id)? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::InvalidBlobArtifactBody(
            "version content hash did not resolve to an ASSET",
        ));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if blake3::hash(&body).as_bytes() != content_hash {
        return Err(Error::CorruptedIndex("blob artifact asset content hash"));
    }
    Ok(body)
}

pub(crate) fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != expected_type {
        return Err(Error::InvalidBlobArtifactBody(context));
    }
    Ok(())
}

fn blob_artifact_asset_entity_id(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(BLOB_ARTIFACT_ASSET_ID_DOMAIN, &[content_hash])
}

fn blob_version_claim_value(
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    provenance: &BlobVersionProvenance,
) -> Value {
    let mut entries = vec![
        (Value::from(KEY_VERSION), Value::Integer(version.into())),
        (
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(content_hash.to_vec()),
        ),
        (
            Value::from(KEY_PROVENANCE),
            Value::from(provenance.as_str()),
        ),
    ];
    if let Some(run_ref) = provenance.run_ref() {
        entries.push((Value::from(KEY_RUN_REF), Value::from(run_ref)));
    }
    Value::Map(entries)
}

fn write_provenance_value(provenance: &BlobVersionProvenance) -> Value {
    let mut entries = vec![
        (Value::from("surface"), Value::from("blob_artifact")),
        (Value::from("op"), Value::from("append_version")),
    ];
    if let Some(run_ref) = provenance.run_ref() {
        entries.push((Value::from(KEY_RUN_REF), Value::from(run_ref)));
    }
    Value::Map(entries)
}

fn encode_blob_artifact_version_record(record: &BlobArtifactVersion) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_VERSION),
            Value::Integer(record.version.into()),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(record.content_hash.to_vec()),
        ),
        (
            Value::from(KEY_PROVENANCE),
            Value::from(record.provenance.as_str()),
        ),
        (
            Value::from(KEY_RUN_REF),
            record.provenance.run_ref().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CLAIM_ID),
            Value::Binary(record.claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::Integer(record.created_at.into()),
        ),
    ]);
    encode_value(&value, "blob artifact version MessagePack encode failed")
}

fn decode_blob_artifact_version_record(bytes: &[u8]) -> Result<BlobArtifactVersion> {
    let value = read_value(bytes, "version record")?;
    let Value::Map(entries) = value else {
        return Err(Error::InvalidBlobArtifactBody(
            "version record must be a MessagePack map",
        ));
    };

    let mut version = None;
    let mut content_hash = None;
    let mut provenance_kind: Option<String> = None;
    let mut run_ref: Option<Option<String>> = None;
    let mut claim_id = None;
    let mut created_at = None;
    let mut seen = [false; BLOB_ARTIFACT_VERSION_RECORD_KEYS.len()];

    for (key, value) in &entries {
        let key = key.as_str().ok_or(Error::InvalidBlobArtifactBody(
            "version record keys must be strings",
        ))?;
        let Some(index) = BLOB_ARTIFACT_VERSION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidBlobArtifactBody(
                "version record key is not in the pinned BLOB_ARTIFACT_VERSION_RECORD_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidBlobArtifactBody(
                "duplicate version record key",
            ));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_VERSION_RECORD_KEYS[index] {
            KEY_VERSION => version = Some(u64_value(value, "version")?),
            KEY_CONTENT_HASH => content_hash = Some(hash_from_value(value, "content_hash")?),
            KEY_PROVENANCE => {
                let text = value.as_str().ok_or(Error::InvalidBlobArtifactBody(
                    "provenance must be a UTF-8 string",
                ))?;
                provenance_kind = Some(text.to_owned());
            }
            KEY_RUN_REF => {
                run_ref = Some(match value {
                    Value::Nil => None,
                    other => Some(
                        other
                            .as_str()
                            .ok_or(Error::InvalidBlobArtifactBody(
                                "run_ref must be a UTF-8 string or nil",
                            ))?
                            .to_owned(),
                    ),
                });
            }
            KEY_CLAIM_ID => claim_id = Some(entity_value(value, "claim_id")?),
            KEY_CREATED_AT => created_at = Some(u64_value(value, "created_at")?),
            _ => unreachable!("index resolved from BLOB_ARTIFACT_VERSION_RECORD_KEYS"),
        }
    }

    let version = version.ok_or(Error::InvalidBlobArtifactBody(
        "missing required version record key version",
    ))?;
    if version == 0 {
        return Err(Error::InvalidBlobArtifactBody(
            "version record version must be at least 1",
        ));
    }
    let provenance = BlobVersionProvenance::from_parts(
        &provenance_kind.ok_or(Error::InvalidBlobArtifactBody(
            "missing required version record key provenance",
        ))?,
        run_ref.ok_or(Error::InvalidBlobArtifactBody(
            "missing required version record key run_ref",
        ))?,
    )?;
    validate_provenance(&provenance)?;
    Ok(BlobArtifactVersion {
        version,
        content_hash: content_hash.ok_or(Error::InvalidBlobArtifactBody(
            "missing required version record key content_hash",
        ))?,
        provenance,
        claim_id: claim_id.ok_or(Error::InvalidBlobArtifactBody(
            "missing required version record key claim_id",
        ))?,
        created_at: created_at.ok_or(Error::InvalidBlobArtifactBody(
            "missing required version record key created_at",
        ))?,
    })
}

fn read_value(bytes: &[u8], context: &'static str) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidBlobArtifactBody(match context {
            "body" => "body is not valid MessagePack",
            _ => "version record is not valid MessagePack",
        })
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidBlobArtifactBody(match context {
            "body" => "trailing bytes after body map",
            _ => "trailing bytes after version record map",
        }));
    }
    Ok(value)
}

fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidBlobArtifactBody(field));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBlobArtifactBody(field))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidBlobArtifactBody(field))
}

fn hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidBlobArtifactBody(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBlobArtifactBody(field))
}

fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value.as_u64().ok_or(Error::InvalidBlobArtifactBody(field))
}

fn blob_artifact_head_key(artifact_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(BLOB_ARTIFACT_HEAD_KEY_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(BLOB_ARTIFACT_HEAD_KEY_PREFIX);
    key.extend_from_slice(artifact_id.as_bytes());
    key
}

fn blob_artifact_version_prefix(artifact_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(BLOB_ARTIFACT_VERSION_KEY_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(BLOB_ARTIFACT_VERSION_KEY_PREFIX);
    key.extend_from_slice(artifact_id.as_bytes());
    key
}

fn blob_artifact_version_key(artifact_id: &EntityId, version: u64) -> Vec<u8> {
    let mut key = blob_artifact_version_prefix(artifact_id);
    key.extend_from_slice(&version.to_be_bytes());
    key
}

fn blob_artifact_asset_ref_prefix(content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        BLOB_ARTIFACT_ASSET_REF_KEY_PREFIX.len() + BLOB_ARTIFACT_CONTENT_HASH_LEN + ENTITY_ID_LEN,
    );
    key.extend_from_slice(BLOB_ARTIFACT_ASSET_REF_KEY_PREFIX);
    key.extend_from_slice(content_hash);
    key
}

fn blob_artifact_asset_ref_key(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    artifact_id: &EntityId,
) -> Vec<u8> {
    let mut key = blob_artifact_asset_ref_prefix(content_hash);
    key.extend_from_slice(artifact_id.as_bytes());
    key
}

#[cfg(test)]
mod tests;
