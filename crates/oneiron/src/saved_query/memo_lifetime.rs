//! Standing-query memo erasure facade.

pub(crate) use crate::store::query_memo_lifetime::erase_memos_for_source_in_txn;
pub(crate) use crate::store::query_memos::{memo_carriage, memo_owners};
