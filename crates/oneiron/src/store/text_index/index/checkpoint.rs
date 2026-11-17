//! The checkpoint getter of the bm25 index source (KS7-2): the canonical
//! caller-supplied text fields each document's postings are rebuilt from,
//! whole, under the document's entity tree. The postings themselves are an
//! index, rebuilt after a restore, and are not captured here. Nothing calls
//! this until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::INDEX_SOURCE_TEXT;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, ExactTable, Join, Restore,
};

/// Every index-source text row, whole under its document's tree, restored
/// exactly.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[&ExactTable {
        table: INDEX_SOURCE_TEXT,
        owner: OwnerRef::entity,
    }],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
    restore: Restore::Parts,
};
