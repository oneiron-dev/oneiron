//! The engine error type: `Error` with its flat bag variants and per-domain enums, and
//! the stable `ErrorKind`. Defined in `oneiron-contracts`; every `oneiron::error` path
//! is unchanged.

pub use oneiron_contracts::error::{
    ArtifactError, ClaimError, CodeError, CompactionPacketError, ErasedHoldTarget, Error,
    ErrorKind, GateDenial, GateDenialOutcome, GateDenialReason, GateError,
    HOLD_TARGET_ERASED_SUGGESTION, KitRecord, LEGAL_HOLD_SUGGESTION, LegalHoldBound,
    LegalHoldBoundKind, LegalHoldNotice, LegalHoldState, LiveDeckRefusal, MaintenanceError,
    OffRecordError, RecordError, RegistryError, RelayError, Result, RoomLiveSpeakersHold,
    SecretError, SideTableRowProblem, StoreError, SyncError, VaultRootEntry, VaultRootProblem,
    VerbHookStop,
};
#[cfg(feature = "sync")]
pub use oneiron_contracts::error::{
    SyncConfigField, SyncEngineContext, SyncProtocolPruneScope, SyncProtocolValidation,
    SyncRollbackError, SyncSelectorValidation,
};
