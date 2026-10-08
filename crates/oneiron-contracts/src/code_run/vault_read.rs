//! The vault-read contract table, the method vocabulary it generates, the request
//! shapes and the error taxonomy every adapter shares.

mod context_pack;
mod contract;
mod error;
mod types;

pub use self::context_pack::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackRetrievalBudgetControls,
    CoreContextPackRequest,
};
pub use self::contract::{
    MEMORY_VERBS, VAULT_READ_METHOD_MAP, VaultReadAdapterKind, VaultReadAvailability,
    VaultReadMethod, VaultReadMethodMapping, VaultReadWireOp, request_schema,
};
pub use self::error::{VaultReadError, VaultReadResult};
pub use self::types::{
    AskRequest, CodeExecuteRequest, CodeSearchRequest, CoreBatchShortIdHydrateRequest,
    CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryRequest, CountMode, View,
    default_limit,
};
