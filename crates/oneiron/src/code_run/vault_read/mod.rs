//! One Rust vault-read contract whose behavior does not change with deployment
//! topology (ONE-1433).
//!
//! The same typed call reaches the same accepted vault-read operation through
//! an in-process adapter ([`InProcessVaultReadAdapter`]), a transport-injected
//! adapter ([`WireTransportVaultReadAdapter`]), or the cloud placeholder
//! ([`CloudVaultReadAdapter`]). The contract is engine-side Rust: no HTTP, MCP,
//! async, or cloud dependency enters this crate, and no TypeScript ships here.
//!
//! The v1 inventory is CLOSED at eight methods — five structured reads mapped
//! 1:1 onto the accepted `/v1/core` operations, plus three M8-reserved runtime
//! peers whose generated wrappers return [`VaultReadError::RuntimeUnavailable`]
//! before any validation, backend, or transport work. Method enum values, wire
//! ops, request/response union arms, trait methods, and
//! [`VAULT_READ_METHOD_MAP`] are generated from ONE declaration
//! (`vault_read_contract!`), so a new method is a wire-contract change that
//! adds exactly one row.
//!
//! Request DTOs copy the accepted route serde exactly (canonical spellings plus
//! every accepted alias) and are pinned by hand-written golden vectors.
//! Response DTOs are local engine-canonical records constructible ENTIRELY from
//! [`ScopedRead`](crate::claim::ScopedRead) and public [`ContextPack`](crate::context_pack::ContextPack) fields: this module imports no
//! `facade`/`memory` DTO type (`EntityView`, `MemoryPack`, `Memory::recall`),
//! and never performs a naked-vault read or a second unscoped existence check
//! after `ScopedRead` answers absence. Scope denial and absence are therefore
//! the SAME typed outcome: `Engine { engine_code: "NOT_FOUND", .. }`.

mod context_pack;
mod contract;
mod dispatch;
mod error;
mod in_process;
mod projection;
mod remote;
mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use self::context_pack::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackRetrievalBudgetControls,
    CoreContextPackAccounting, CoreContextPackAccountingReason, CoreContextPackEdgeProvenance,
    CoreContextPackEdgeRecord, CoreContextPackEmpty, CoreContextPackEmptyReason,
    CoreContextPackEntityRecord, CoreContextPackItemTokenStats, CoreContextPackProjection,
    CoreContextPackRequest, CoreContextPackResponse, CoreContextPackSectionTokenStats,
    CoreContextPackSignal, CoreContextPackStats, CoreContextPackTokenStats, CoreContextPackVad,
};
pub use self::contract::{
    VAULT_READ_METHOD_MAP, VaultReadAdapterKind, VaultReadAvailability, VaultReadClient,
    VaultReadMethod, VaultReadMethodMapping, VaultReadRequest, VaultReadResponse, VaultReadWireOp,
};
pub use self::error::{VaultReadError, VaultReadResult};
pub use self::in_process::InProcessVaultReadAdapter;
pub use self::remote::{CloudVaultReadAdapter, WireTransport, WireTransportVaultReadAdapter};
pub use self::types::{
    AskRequest, AskResponse, CodeExecuteRequest, CodeExecuteResponse, CodeSearchRequest,
    CodeSearchResponse, CoreBatchShortIdHydrateItem, CoreBatchShortIdHydrateRequest,
    CoreBatchShortIdHydrateResponse, CoreEntityRecord, CoreHydrateRequest, CoreHydrateResponse,
    CoreHydrateStatus, CoreMemoryTimelineRecord, CoreMemoryTimelineRequest,
    CoreMemoryTimelineResponse, CoreQueryMeta, CoreQueryRequest, CoreQueryResponse,
    CoreShortIdHydrateOutcome, CountMode, VAULT_READ_MAX_BATCH_REFS, View,
};

// ─── One validated dispatch path ─────────────────────────────────────────────

// `sealed` stays at this level: its `pub(super)` constructor and `into_inner`
// are what every adapter child (and the test doubles) reach for.
pub(crate) mod sealed {
    use super::{VaultReadRequest, VaultReadResponse, VaultReadResult};

    /// A request that has already passed the accepted-route validation door.
    /// Backends can only ever receive one of these.
    #[derive(Debug)]
    pub(crate) struct ValidatedVaultReadRequest(pub(super) VaultReadRequest);

    impl ValidatedVaultReadRequest {
        pub(super) fn into_inner(self) -> VaultReadRequest {
            self.0
        }
    }

    /// The sealed adapter seam. Implemented only by this module's three
    /// adapters; hosts inject behavior through `WireTransport` instead.
    pub(crate) trait Backend: Send + Sync {
        fn dispatch_validated(
            &self,
            request: ValidatedVaultReadRequest,
        ) -> VaultReadResult<VaultReadResponse>;
    }
}

// The flat vault_read.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate/std import header,
// and every module-internal item the tests name bare. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::{error::*, in_process::*, projection::*, remote::*, types::*, validate::*};
#[cfg(test)]
use crate::claim::ScopedReadActorKey;
#[cfg(test)]
use crate::context_pack::{FieldProfile, MAX_EDGE_HOP, TokenAllocation};
#[cfg(test)]
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_CLAIM;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::sync::Arc;
