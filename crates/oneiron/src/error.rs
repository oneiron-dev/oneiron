//! The engine error type: `Error` with its flat bag variants and per-domain enums, and
//! the stable `ErrorKind`. Defined in `oneiron-contracts`; every `oneiron::error` path
//! is unchanged.

pub use oneiron_contracts::error::{
    ArtifactError, ClaimError, CodeError, CompactionPacketError, Error, ErrorKind, GateDenial,
    GateDenialOutcome, GateDenialReason, GateError, MaintenanceError, OffRecordError, RecordError,
    RegistryError, RelayError, Result, SecretError, SideTableRowProblem, StoreError, SyncError,
    VaultRootEntry, VaultRootProblem,
};
#[cfg(feature = "sync")]
pub use oneiron_contracts::error::{
    SyncConfigField, SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation,
    SyncRollbackError, SyncSelectorValidation,
};
