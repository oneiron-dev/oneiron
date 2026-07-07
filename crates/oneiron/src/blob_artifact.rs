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
use crate::error::{Error, Result};
use crate::ppr;
use crate::store::Store;
use crate::types::{
    ClaimCandidate, ENTITY_ID_LEN, ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, EntityId,
    TimeRange, WriteActor, WriteEnvelope, WriteProvenance,
};
use heed::{RoTxn, RwTxn};

pub const BLOB_ARTIFACT_BODY_KEYS: [&str; 2] = ["name", "media_type"];
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
}

impl BlobArtifactBody {
    #[must_use]
    pub fn new(name: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            media_type: media_type.into(),
        }
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
    let value = Value::Map(vec![
        (Value::from(KEY_NAME), Value::from(body.name.as_str())),
        (
            Value::from(KEY_MEDIA_TYPE),
            Value::from(body.media_type.as_str()),
        ),
    ]);
    encode_value(&value, "BLOB artifact body MessagePack encode failed")
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
    let mut seen = [false; BLOB_ARTIFACT_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidBlobArtifactBody("body keys must be strings"));
        };
        let Some(index) = BLOB_ARTIFACT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidBlobArtifactBody(
                "body key is not in the pinned BLOB_ARTIFACT_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidBlobArtifactBody("duplicate body key"));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_BODY_KEYS[index] {
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
            _ => unreachable!("index resolved from BLOB_ARTIFACT_BODY_KEYS"),
        }
    }

    let body = BlobArtifactBody {
        name: name.ok_or(Error::InvalidBlobArtifactBody(
            "missing required body key name",
        ))?,
        media_type: media_type.ok_or(Error::InvalidBlobArtifactBody(
            "missing required body key media_type",
        ))?,
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
        validate_provenance(provenance)?;
        if bytes.is_empty() {
            return Err(Error::InvalidBlobArtifactBody(
                "blob artifact version bytes must be non-empty",
            ));
        }
        let content_hash = *blake3::hash(bytes).as_bytes();
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let claim_id = EntityId::now();

        self.with_write_txn(|wtxn| {
            require_entity_type(
                &self.store,
                wtxn,
                artifact_id,
                ENTITY_TYPE_BLOB_ARTIFACT,
                "append target must be a BLOB_ARTIFACT entity",
            )?;
            let next_version = match read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
            {
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
        })
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
            let record = decode_blob_artifact_version_record(raw)?;
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
            decode_blob_artifact_version_record(raw)?
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
        let record = decode_blob_artifact_version_record(raw)?;
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

fn read_blob_artifact_head_in_txn(
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
    decode_blob_artifact_version_record(raw).map(Some)
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

fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
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
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::types::{
        ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, EdgeActorClass,
        EntityClassification, HnswConfig, TextAnalyzerConfig, TypeByteBand, VaultConfig,
        entity_type_registry_entry, short_id_prefix,
    };

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config.text_analyzer = TextAnalyzerConfig::default();
        config
    }

    fn test_body() -> BlobArtifactBody {
        BlobArtifactBody::new(
            "forecast.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    }

    fn test_time(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn put_actor(vault: &Vault, learned_at: u64) -> Result<WriteActor> {
        let actor_id = EntityId::now();
        vault.put_entity(
            &actor_id,
            ENTITY_TYPE_PERSON,
            test_time(learned_at),
            learned_at,
            b"uploader",
        )?;
        Ok(WriteActor::new(actor_id, EdgeActorClass::Human))
    }

    fn put_artifact(vault: &Vault, learned_at: u64) -> Result<EntityId> {
        let id = EntityId::now();
        vault.put_blob_artifact(&id, &test_body(), test_time(learned_at), learned_at)?;
        Ok(id)
    }

    fn encode_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(
            &mut out,
            &Value::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (Value::from(key), value))
                    .collect(),
            ),
        )
        .expect("encode msgpack");
        out
    }

    #[test]
    fn blob_artifact_codec_round_trips_pinned_keys() -> Result<()> {
        let body = test_body();
        let encoded = encode_blob_artifact_body(&body)?;
        let decoded = decode_blob_artifact_body(&encoded)?;
        assert_eq!(decoded, body);

        // Inline content slots are rejected by the pinned-key law.
        let with_content = encode_map(vec![
            ("name", Value::from("forecast.xlsx")),
            ("media_type", Value::from("application/x-test")),
            ("content", Value::Binary(vec![1, 2, 3])),
        ]);
        let err = decode_blob_artifact_body(&with_content)
            .expect_err("BLOB artifact body must reject inline content slots");
        assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);

        for missing_key in BLOB_ARTIFACT_BODY_KEYS {
            let entries = BLOB_ARTIFACT_BODY_KEYS
                .into_iter()
                .filter(|key| *key != missing_key)
                .map(|key| (key, Value::from("value")))
                .collect();
            let err = decode_blob_artifact_body(&encode_map(entries))
                .expect_err("missing pinned key must fail closed");
            assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
        }
        Ok(())
    }

    #[test]
    fn blob_artifact_registry_and_vault_helpers_round_trip() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = put_artifact(&vault, 11)?;

        let decoded = vault.get_blob_artifact(&id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(decoded, test_body());
        assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_BLOB_ARTIFACT));
        assert_eq!(short_id_prefix(ENTITY_TYPE_BLOB_ARTIFACT)?, "ba");
        let entry = entity_type_registry_entry(ENTITY_TYPE_BLOB_ARTIFACT)
            .expect("BLOB_ARTIFACT registry row");
        assert_eq!(entry.kind, "BLOB_ARTIFACT");
        assert_eq!(entry.classification, EntityClassification::Pack);
        assert_eq!(entry.band, TypeByteBand::Productivity);
        Ok(())
    }

    #[test]
    fn blob_artifact_upload_creates_v1_with_ledger_event() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let artifact_id = put_artifact(&vault, 10)?;
        let actor = put_actor(&vault, 10)?;

        let version = vault.append_blob_artifact_version(
            &artifact_id,
            b"office bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )?;

        assert_eq!(version.version, 1);
        assert_eq!(
            version.content_hash,
            *blake3::hash(b"office bytes v1").as_bytes()
        );
        assert_eq!(version.provenance, BlobVersionProvenance::UserUpload);
        // The LEDGER event landed as a CLAIM entity.
        assert_eq!(
            vault.get_entity_type(&version.claim_id)?,
            Some(ENTITY_TYPE_CLAIM)
        );
        assert_eq!(
            vault.read_blob_artifact_version(&artifact_id, 1)?,
            Some(b"office bytes v1".to_vec())
        );
        assert_eq!(vault.blob_artifact_head(&artifact_id)?, Some(version));
        Ok(())
    }

    #[test]
    fn blob_artifact_identical_bytes_dedupe() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let artifact_id = put_artifact(&vault, 10)?;
        let actor = put_actor(&vault, 10)?;

        let first = vault.append_blob_artifact_version(
            &artifact_id,
            b"same bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )?;
        let second = vault.append_blob_artifact_version(
            &artifact_id,
            b"same bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )?;

        // Same content hash, same version, no new chain entry or claim.
        assert_eq!(second, first);
        assert_eq!(vault.blob_artifact_versions(&artifact_id)?.len(), 1);

        // Identical bytes uploaded into ANOTHER artifact keep their own
        // chain but share the content-addressed asset entity.
        let other_id = put_artifact(&vault, 13)?;
        let other = vault.append_blob_artifact_version(
            &other_id,
            b"same bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(14),
            14,
        )?;
        assert_eq!(other.version, 1);
        assert_eq!(other.content_hash, first.content_hash);
        assert_eq!(
            blob_artifact_asset_entity_id(&other.content_hash)?,
            blob_artifact_asset_entity_id(&first.content_hash)?
        );
        Ok(())
    }

    #[test]
    fn blob_artifact_version_chain_is_append_only() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let artifact_id = put_artifact(&vault, 10)?;
        let actor = put_actor(&vault, 10)?;

        let v1 = vault.append_blob_artifact_version(
            &artifact_id,
            b"bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )?;
        let v2 = vault.append_blob_artifact_version(
            &artifact_id,
            b"bytes v2",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )?;
        // Returning to v1's bytes appends a NEW version — history is never
        // rewritten, mirroring the OF-320 non-destructive revert law.
        let v3 = vault.append_blob_artifact_version(
            &artifact_id,
            b"bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(13),
            13,
        )?;

        assert_eq!((v1.version, v2.version, v3.version), (1, 2, 3));
        assert_eq!(v3.content_hash, v1.content_hash);
        let versions = vault.blob_artifact_versions(&artifact_id)?;
        assert_eq!(versions, vec![v1, v2, v3.clone()]);
        // Every version's bytes stay readable after later appends.
        assert_eq!(
            vault.read_blob_artifact_version(&artifact_id, 1)?,
            Some(b"bytes v1".to_vec())
        );
        assert_eq!(
            vault.read_blob_artifact_version(&artifact_id, 2)?,
            Some(b"bytes v2".to_vec())
        );
        assert_eq!(vault.blob_artifact_head(&artifact_id)?, Some(v3));
        assert_eq!(vault.read_blob_artifact_version(&artifact_id, 4)?, None);
        Ok(())
    }

    #[test]
    fn blob_artifact_provenance_round_trips_per_version() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let artifact_id = put_artifact(&vault, 10)?;
        let actor = put_actor(&vault, 10)?;

        let v1 = vault.append_blob_artifact_version(
            &artifact_id,
            b"uploaded by user",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )?;
        let agent_run = BlobVersionProvenance::AgentRun {
            run_ref: "run:2026-07-07T00:00:00Z#42".to_owned(),
        };
        let v2 = vault.append_blob_artifact_version(
            &artifact_id,
            b"edited by agent",
            &agent_run,
            actor,
            test_time(12),
            12,
        )?;

        let versions = vault.blob_artifact_versions(&artifact_id)?;
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].provenance, BlobVersionProvenance::UserUpload);
        assert_eq!(versions[1].provenance, agent_run);
        assert_ne!(v1.claim_id, v2.claim_id);
        for version in &versions {
            assert_eq!(
                vault.get_entity_type(&version.claim_id)?,
                Some(ENTITY_TYPE_CLAIM)
            );
        }
        Ok(())
    }

    #[test]
    fn blob_artifact_delete_cleans_chain_and_orphaned_assets() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10)?;
        let artifact_a = put_artifact(&vault, 10)?;
        let artifact_b = put_artifact(&vault, 10)?;

        vault.append_blob_artifact_version(
            &artifact_a,
            b"shared bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )?;
        let a_only = vault.append_blob_artifact_version(
            &artifact_a,
            b"a-only bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )?;
        let shared = vault.append_blob_artifact_version(
            &artifact_b,
            b"shared bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(13),
            13,
        )?;
        let a_only_asset = blob_artifact_asset_entity_id(&a_only.content_hash)?;
        let shared_asset = blob_artifact_asset_entity_id(&shared.content_hash)?;

        // Batch-path delete (BatchOp::Delete routes through deindex_entity).
        vault.batch().delete(&artifact_a).commit()?;
        assert!(vault.blob_artifact_versions(&artifact_a)?.is_empty());
        assert_eq!(vault.blob_artifact_head(&artifact_a)?, None);
        // Bytes only artifact A referenced die with their last reference…
        assert!(vault.get_raw(&a_only_asset)?.is_none());
        // …while the shared asset survives because artifact B still holds a
        // reference, and B's chain stays fully readable.
        assert!(vault.get_raw(&shared_asset)?.is_some());
        assert_eq!(
            vault.read_blob_artifact_version(&artifact_b, 1)?,
            Some(b"shared bytes".to_vec())
        );

        // Deleting the LAST referencing artifact removes the shared bytes.
        vault.delete_entity(&artifact_b)?;
        assert!(vault.blob_artifact_versions(&artifact_b)?.is_empty());
        assert!(vault.get_raw(&shared_asset)?.is_none());
        Ok(())
    }

    #[test]
    fn blob_artifact_append_fails_closed_on_bad_input() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10)?;

        // Unknown artifact.
        let err = vault
            .append_blob_artifact_version(
                &EntityId::now(),
                b"bytes",
                &BlobVersionProvenance::UserUpload,
                actor,
                test_time(11),
                11,
            )
            .expect_err("append to unknown artifact must fail");
        assert_eq!(err.kind(), ErrorKind::EntityNotFound);

        // Wrong entity type.
        let session_id = EntityId::now();
        vault.put_entity(
            &session_id,
            ENTITY_TYPE_SESSION,
            test_time(11),
            11,
            b"session",
        )?;
        let err = vault
            .append_blob_artifact_version(
                &session_id,
                b"bytes",
                &BlobVersionProvenance::UserUpload,
                actor,
                test_time(12),
                12,
            )
            .expect_err("append to non-BLOB_ARTIFACT must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);

        // Empty bytes and blank agent run refs fail closed.
        let artifact_id = put_artifact(&vault, 13)?;
        let err = vault
            .append_blob_artifact_version(
                &artifact_id,
                b"",
                &BlobVersionProvenance::UserUpload,
                actor,
                test_time(14),
                14,
            )
            .expect_err("empty bytes must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
        let err = vault
            .append_blob_artifact_version(
                &artifact_id,
                b"bytes",
                &BlobVersionProvenance::AgentRun {
                    run_ref: "   ".to_owned(),
                },
                actor,
                test_time(15),
                15,
            )
            .expect_err("blank run_ref must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
        assert!(vault.blob_artifact_versions(&artifact_id)?.is_empty());
        Ok(())
    }
}
