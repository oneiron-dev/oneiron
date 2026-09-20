//! Ingest source registry and source-local normalization.
//!
//! Source normalization stops before semantic extraction: sources normalize
//! raw fixture/input records into text-bearing records. Imported evidence can
//! only mint claim writes through an explicit admission helper that requires
//! entity resolution and routes through the normal Gate-backed candidate path.

mod fingerprint;
pub use fingerprint::{BlobBirthDecision, BlobFingerprintSnapshot, FingerprintRung};
pub(crate) use fingerprint::{invalidate_blob_fingerprint, prepare_blob_artifact_birth};
mod docs;
mod docs_import;
mod summary_ladder;
pub use docs::{
    DOCS_EXPORT_SOURCE_ID, DocsExport, DocsExportSource, DocsPage, DocsSegment, docs_extraction_id,
    docs_semantic_segments,
};
pub use docs_import::{
    DocsDerivationEnvelope, DocsImportCeiling, DocsImportReceipt, DocsInjectionClassifier,
    DocsSummaryModel,
};
pub use summary_ladder::DocsSummaryHit;
mod identity_key;
pub use identity_key::identity_fields_for_kind;
pub(crate) use identity_key::reindex_identity_hints;
mod admission;
pub mod image;
mod registry;
mod resolution;
mod transcripts;
mod types;

pub use image::{
    CAPTION_RECOGNIZER, ExifEvidence, GeoPoint, IMAGE_SOURCE_ID, ImageCaptionRecognizer,
    ImageIngestSource, ImageTextRecognizer, LocalityRung, NormalizedIngestEntity, RecognizedText,
    parse_exif_evidence, register_image_caption_recognizer, register_image_text_recognizer,
};

pub use self::admission::{
    ImportedEvidenceAdmission, ImportedEvidenceEntityResolution, admit_imported_entity,
    admit_imported_evidence_claim, admit_imported_evidence_claim_typed,
    admit_imported_mention_claim,
};
pub use self::registry::{
    FILE_DROP_TRANSCRIPT_SOURCE_ID, ICS_FEED_SOURCE_ID, INGEST_SOURCE_REGISTRY,
    IngestAdapterSkillRef, IngestHarnessConfig, IngestSource, IngestSourceConfig,
    IngestSourceFormat, IngestSourceRegistration, IngestSourceRegistry, IngestTrustCeiling,
    JSONL_TRANSCRIPT_SOURCE_ID, KNOWN_INGEST_HARNESS_CONFIG, MEETING_TRANSCRIPT_SCHEMA_V1,
    MEETING_TRANSCRIPT_SOURCE_ID,
};
pub use self::resolution::{
    EntityResolutionCandidate, EntityResolutionRoute, EntityResolutionWaterfallDecision,
    ScoredEntityResolutionCandidate, evaluate_entity_resolution_waterfall,
};
pub use self::transcripts::{JsonlTranscriptSource, MeetingTranscriptSource};
pub use self::types::{
    IngestError, IngestResult, NormalizedIngestBatch, NormalizedIngestClaim, NormalizedIngestNote,
    NormalizedIngestRecord,
};

#[cfg(test)]
mod docs_tests;
#[cfg(test)]
mod tests;

// The flat ingest.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header.
// After the directory split the seam re-imports them so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value as MsgpackValue;
#[cfg(test)]
use serde_json::Value;

pub mod exports;
mod parsed;
pub use parsed::{ParsedImport, ParsedMessage};
