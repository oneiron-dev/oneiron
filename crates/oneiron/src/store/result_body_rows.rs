//! Core half of `store::result_body_rows`: its store-layer items live in `oneiron_store::result_body_rows` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::result_body_rows::*;

use crate::side_table::{self, Raw, SideTable};
use crate::store::result_manifest::CodeRunRawOutput;

/// One result body, keyed by its deterministic content handle: inline, or the
/// file beside `data.mdb` that holds it (OF-597).
pub(crate) const RAW_OUTPUTS: SideTable<String, StoredBody, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

/// Where one body's bytes are: in its row, within `[limits]
/// code_result_inline_bytes`, or in the body file named by its digest, of
/// `len` bytes. The row is written only once the file is whole on disk, so a
/// row naming a file never names a partial one.
///
/// `held`: the row holds its body on its own, as a raw output no descriptor
/// holds (FIX 5399b). A put that publishes no descriptor sets it and every
/// later put of the same bytes keeps it, so no other holder's release
/// queues or collects the body; only an erase lifts it. It owns nothing
/// and grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredBody {
    Inline { bytes: Vec<u8>, held: bool },
    File { len: u64, held: bool },
}

/// The raw `vault_meta` key of the result body row of `digest`.
pub(crate) fn code_run_body_row_key(digest: &[u8; 32]) -> Vec<u8> {
    RAW_OUTPUTS.key_bytes(&body_handle(digest))
}

/// The content handle the result body row of `digest` is keyed by.
pub(crate) fn body_handle(digest: &[u8; 32]) -> String {
    CodeRunRawOutput::of_ref(crate::compaction::output::OutputRef {
        hash: *digest,
        byte_len: 0,
    })
    .handle
}
