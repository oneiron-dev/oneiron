//! Core entity writes as typed rows (OF-181): the conversation container,
//! a TURN under it, a DAG record and the atomic batch. Each row and its
//! REST route run one Vault door, and every write stages through one
//! shape ([`shape`]): its id, interval, normalized body and text index.

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
pub use shape::{CoreWriteTextField, CoreWriteTimes};
