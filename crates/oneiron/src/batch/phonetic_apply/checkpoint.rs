//! The checkpoint getter of the phonetic index source (KS7-2): the supplied
//! and generated codes each entity's phonetic postings are reconciled from,
//! whole, under the entity's tree. The postings themselves are an index,
//! rebuilt after a restore, and are not captured here. Nothing calls this
//! until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::PHONETIC_SOURCE;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, ExactTable, Join,
};

/// Every phonetic source row, whole under its entity's tree, restored
/// exactly.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[&ExactTable {
        table: PHONETIC_SOURCE,
        owner: OwnerRef::entity,
    }],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::NoSplit,
};
