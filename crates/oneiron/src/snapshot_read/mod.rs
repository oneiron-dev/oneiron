//! Primitive A (slice 6.4, SLICE6-MAP row A): reads any agent makes behind
//! its own grant, with the version of every source it read, so a later commit
//! can prove it cites the same words.
//!
//! Nothing here holds a storage snapshot across calls. A version names a row
//! as one scoped read served it (its type, learned time and the
//! domain-separated hash of its logical body; for a TURN also the fingerprint
//! of the MESSAGE rows its text was projected from), and
//! [`SourceVersion::recheck_in_txn`] judges it again in the caller's own
//! transaction under the caller's live read: the row still reads, and it is
//! the same revision. Every read goes through the caller's `ScopedRead`, so
//! authority, privacy, relationship, audience, sensitivity, device and world
//! filters, source finality and deletion apply to each row.

mod evidence_spans;
mod run_reader;
mod settings_doors;
mod snapshot;
mod source_version;
pub(crate) mod tables;

pub use evidence_spans::{
    EVIDENCE_SPANS_MAX_RANGES, EvidenceMessageSlice, EvidenceRange, EvidenceSourceStatus,
    EvidenceSpan, EvidenceSpans, EvidenceSpansRequest, evidence_spans, validate_evidence_spans,
};
pub use run_reader::{
    checkpoint_as_reader, checkpoint_embedded, settled_step_as_reader, settled_step_embedded,
};
pub use settings_doors::{read_snapshot_read_settings, replace_snapshot_read_settings};
pub(crate) use snapshot::erase_snapshot_handles_of_actor_in_txn;
pub use snapshot::{
    SNAPSHOT_MAX_KINDS, SnapshotHandle, SnapshotKind, SnapshotOpenRequest, SnapshotPage,
    SnapshotPageRequest, SnapshotRow, snapshot_open, snapshot_page, validate_snapshot_open,
};
pub use source_version::{SourceVersion, SourceVersionCheck};
