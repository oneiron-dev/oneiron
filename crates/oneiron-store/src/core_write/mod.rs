//! Core entity writes as typed rows (OF-181): the rows' inputs and receipts,
//! and the shape every write stages through ([`shape`]): its id, interval,
//! normalized body and text index. The Vault and Memory doors that run each
//! row, the write lane and the batch staging are the engine's (`core_write`
//! in `oneiron`).

mod batch;
mod conversations;
mod dag;
pub mod shape;

pub use batch::{
    CoreBatchCommit, CoreBatchEntityInput, CoreBatchEntityReceipt, CoreBatchWriteInput,
    CoreBatchWriteReceipt,
};
pub use conversations::{
    ConversationCreateInput, ConversationTurnCreateInput, CoreEntityWriteReceipt,
};
pub use dag::{
    CoreDagAddressMode, CoreDagQuoteInput, DagRecordAppendInput, DagRecordAppendReceipt,
};
pub use shape::{AnnouncementAuthority, CoreWriteTextField, CoreWriteTimes};
