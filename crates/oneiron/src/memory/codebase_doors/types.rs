//! Codebase snapshot request, file, view and definition records.
//! `CodeRepoPointer` is the first of its records.
//! Local definitions, plus projection kinds re-exported from `crate::origin::secret_projection`.

// The projection descriptor's own leaf is crate-private; the wire names it here.
pub use crate::origin::secret_projection::types::{RepoFileProjectionKind, RepoFileProjectionView};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::codebase_doors::types::{
    CodeRepoPointer, CodeSnapshotCaptureRequest, CodeSnapshotDefinition,
    CodeSnapshotDefinitionsRequest, CodeSnapshotDefinitionsView, CodeSnapshotFile,
    CodeSnapshotIngestRequest, CodeSnapshotPinnedFile, CodeSnapshotReadRequest,
    CodeSnapshotRequest, CodeSnapshotView,
};
