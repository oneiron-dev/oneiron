//! ARTL-1 (OF-368 D1): versioned blob artifact store for foreign binary
//! (office) files.
//!
//! Rides the OF-320 bitemporal code-artifact shape instead of forking a
//! second artifact model:
//!
//! * the artifact is a typed entity
//!   ([`ENTITY_TYPE_BLOB_ARTIFACT`](crate::registry::ENTITY_TYPE_BLOB_ARTIFACT))
//!   whose body carries pinned metadata keys and never inline content;
//! * version bytes live in content-addressed
//!   ([`ENTITY_TYPE_ASSET`](crate::registry::ENTITY_TYPE_ASSET)) entities
//!   (blake3 content hash → deterministic asset id), so identical bytes are
//!   stored once per vault;
//! * each version is an append-only `vault_meta` record carrying the content
//!   hash, per-version provenance (user upload | agent-run ref), and the id
//!   of its `blob.version` claim — the LEDGER event for that version;
//! * history is append-only: a version is only ever added above the highest
//!   number ever issued (its high-water mark), with an optional parent/fork
//!   pointer to any earlier version. Existing records are never rewritten.
//!   While the artifact lives a version is deleted only when the last step
//!   claim pinning it as its response lets go of it (FIX 6225): only that
//!   version goes, its number is never issued again, the head falls back to
//!   the greatest version that stays, and the chain keeps the gap.
//!   Re-appending the current head bytes normally dedupes; explicit forks
//!   always append.
//!
//! Content-hash dedupe is vault-scoped ONLY. A vault is one tenant's sealed
//! store (OF-307): a content hash computed from one tenant's bytes never
//! resolves storage for another tenant, even when byte-identical.

mod body;
mod born_from;
pub(crate) mod checkpoint;
mod create;
pub mod deck_creation;
mod deck_doors;
mod family;
mod holders;
mod lifecycle;
mod made_by;
mod provenance;
mod references;
mod store_keys;
mod verbs;
mod version_codec;
mod version_rows;
mod versions;

pub(crate) use self::body::validate_blob_artifact_body_bytes;
pub use self::body::{
    BLOB_ARTIFACT_BODY_KEYS, BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES, BLOB_ARTIFACT_NAME_MAX_BYTES,
    BLOB_ARTIFACT_OPTIONAL_BODY_KEYS, BlobArtifactBody, decode_blob_artifact_body,
    encode_blob_artifact_body,
};
pub(crate) use self::born_from::archive_born_from_table;
pub use self::born_from::{BornFromArtifact, BornFromSource};
pub use self::create::ArtifactCreateRequest;
pub use self::deck_doors::{
    DeckCommentInspection, DeckInspectRequest, DeckInspectionView, DeckProposeRejection,
    DeckRejectionCheck, DeckRejectionReport,
};
pub(crate) use self::family::hash_hex;
pub use self::family::{
    ArtifactExport, ArtifactKind, ArtifactVersionView, ArtifactView, VersionReconciliation,
};
pub(crate) use self::holders::{
    artifact_author_in_txn, carrier_content_hash, content_holders_in_txn,
    held_content_hashes_in_txn,
};
pub(crate) use self::lifecycle::delete_blob_artifact_lifecycle_in_txn;
// FIX 6225: a step response's exact version, released by its last pin.
pub(crate) use self::lifecycle::{release_response_version_in_txn, response_version_stands_in_txn};
pub use self::provenance::BlobVersionProvenance;
pub(crate) use self::references::archive_version_claim_tables;
pub(crate) use self::references::{
    artifacts_claiming, claimed_hash_rows_exist, record_version_claim,
};
#[cfg(feature = "sync")]
pub(crate) use self::references::{readmit_held_asset_in_txn, release_fenced_only};
pub(crate) use self::store_keys::require_entity_type;
pub use self::store_keys::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BLOB_ARTIFACT_RUN_REF_MAX_BYTES};
pub use self::verbs::{
    ArtifactAdmitSubmit, ArtifactAskOutcome, ArtifactAskSubmit, ArtifactAskUnits,
    ArtifactExportFile, ArtifactExportRequest, ArtifactRefRequest, BornFromRequest, BornFromView,
    DeckProposeOutcome, DeckProposeRequest, DiscardedProposal, FolderItemInput, KeptProposal,
    NativeOutputRequest, ProposalSettleRequest, ReleasedWait, SlideReviewOutcome,
    SlideReviewSubmit, SlideReviewUnitInput, SlideUnitRefused, UndoneKeep,
};
pub(crate) use self::versions::archive_version_tables;
pub(crate) use self::versions::read_blob_artifact_head_in_txn;
pub use self::versions::{
    BLOB_ARTIFACT_VERSION_RECORD_KEYS, BlobArtifactVersion, BlobBytes, CalcEngineStamp,
};

/// The closed deck transaction grammar a deck proposal carries.
pub use oneiron_docedit::edit::transaction::DeckTransaction;

#[cfg(test)]
mod tests;

// The sibling `tests.rs` module resolves its bare names through `use super::*`:
// the one private blob-internal item the tests name
// (`blob_artifact_asset_entity_id`; every other blob name they use is
// re-exported above) plus the parent-scope crate/std imports the flat file
// used to provide. After the directory split the seam re-imports both so
// `tests.rs` resolves exactly as it did before.
pub(crate) use self::store_keys::{blob_artifact_asset_ref_key, blob_artifact_asset_ref_prefix};
pub(crate) use self::versions::blob_artifact_asset_entity_id;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;

pub mod esign;
