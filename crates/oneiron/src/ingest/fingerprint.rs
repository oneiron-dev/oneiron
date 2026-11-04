//! Entity-local four-rung birth fingerprints over the ingest pipeline's own segments.
pub use crate::store::blob_fingerprint::{
    BlobBirthDecision, BlobFingerprintSnapshot, FingerprintRung,
};
pub(crate) use crate::store::blob_fingerprint::{
    FingerprintUpdate, invalidate_blob_fingerprint, prepare_binary_blob_artifact_birth,
    prepare_blob_artifact_birth,
};
pub(super) use crate::store::blob_fingerprint::{prepare_blob_birth, prepare_new_blob_birth};
