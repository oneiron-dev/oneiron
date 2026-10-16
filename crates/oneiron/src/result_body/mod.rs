//! Result body lifetime (OF-597): reader pins, the collector of released and
//! orphan body files, and the copy of an off-record body into the vault's
//! `bodies/`. A checkpoint seals its bodies inside its own artifact, so none
//! outlives the image that carries it.
//!
//! A body file goes only once nothing names it: no descriptor holds its digest
//! (`provenance::body`), and no reader pins it. The collector drops the body's
//! raw-output row and sidecars in a write transaction and unlinks the file only
//! after that commits, keeping new pins out while it unlinks. A reader that
//! pins a body before the read transaction that finds its row so finds row and
//! file, or neither. Every file is reached through the body directory's
//! descriptor, never a joined path.

#[cfg(unix)]
mod collect;
#[cfg(unix)]
mod files;
mod pins;
#[cfg(unix)]
mod promote;

#[cfg(unix)]
pub use collect::ResultBodyCollectReport;
pub(crate) use pins::{ResultBodyPin, ResultBodyPins};

#[cfg(unix)]
use crate::side_table::{self, Raw, SideTable};

/// How old a body file no row names must be before it goes: a body is
/// whole on disk before the row naming it commits.
#[cfg(unix)]
const BODY_GRACE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The raw-output rows, keyed by content handle. Only presence and removal
/// are read here; the row's codec stays with `code_run`.
#[cfg(unix)]
const RAW_OUTPUT_ROWS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

/// The taint sidecar beside a raw-output row, keyed by the same handle.
#[cfg(unix)]
const RAW_OUTPUT_TAINTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_TAINT);

/// The secret scan's mark on a raw-output body, keyed by the same handle.
#[cfg(unix)]
const RAW_OUTPUT_SECRETS: SideTable<String, String, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_SECRET);

/// The content handle the raw-output row of the body `digest` is keyed by.
#[cfg(unix)]
fn raw_output_handle(digest: &[u8; 32]) -> String {
    crate::code_run::CodeRunRawOutput::of_ref(crate::compaction::output::OutputRef {
        hash: *digest,
        byte_len: 0,
    })
    .handle
}
