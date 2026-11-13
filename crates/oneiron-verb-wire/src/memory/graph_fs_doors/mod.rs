//! Moved from `crates/oneiron/src/memory/graph_fs_doors/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::graph_fs_doors::types::*;
use base64::Engine;
use oneiron_store::graph_fs::model::GraphFsOptions;
use serde::Deserialize;
use serde::Serialize;

impl GraphFsMountRequest {
    fn options(&self) -> GraphFsOptions {
        let options = GraphFsOptions::default();
        let options = self
            .page_byte_cap
            .map_or(options, |cap| options.with_page_byte_cap(cap));
        self.max_entries
            .map_or(options, |cap| options.with_max_entries(cap))
    }
}
pub mod types;
