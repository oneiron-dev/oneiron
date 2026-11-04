//! Core entity writes as typed rows (OF-181): the conversation container,
//! a TURN under it, a DAG record and the atomic batch. Each row and its
//! REST route run one Vault door, and every write stages through one
//! shape ([`shape`]): its id, interval, normalized body and text index.

mod batch;
mod conversations;
mod dag;
pub mod shape;

pub use batch::CoreWriteLane;
pub use oneiron_store::core_write::{
    ConversationCreateInput, ConversationTurnCreateInput, CoreBatchCommit, CoreBatchEntityInput,
    CoreBatchEntityReceipt, CoreBatchWriteInput, CoreBatchWriteReceipt, CoreDagAddressMode,
    CoreDagQuoteInput, CoreEntityWriteReceipt, DagRecordAppendInput, DagRecordAppendReceipt,
};
pub use shape::{AnnouncementAuthority, CoreWriteTextField, CoreWriteTimes};
