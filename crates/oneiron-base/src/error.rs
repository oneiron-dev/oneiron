//! The engine error type: `Error` with its flat bag variants and per-domain enums, and
//! the stable `ErrorKind`. Defined in `oneiron-contracts`; every `oneiron::error` path
//! is unchanged.

pub use oneiron_contracts::error::{
    ArtifactError, ClaimError, CodeError, CompactionPacketError, DevicePinRefusal,
    ErasedHoldTarget, Error, ErrorKind, GateDenial, GateDenialOutcome, GateDenialReason, GateError,
    HOLD_TARGET_ERASED_SUGGESTION, KitRecord, LEGAL_HOLD_SUGGESTION, LegalHoldBound,
    LegalHoldBoundKind, LegalHoldNotice, LegalHoldState, LiveDeckRefusal, MaintenanceError,
    OWNER_KEY_REQUIRED, OWNER_PRESENCE_HERE_REASON_PREFIX, OWNER_PRESENCE_REQUIRED, OffRecordError,
    OwnerKeyMoveStep, OwnerPresenceRefusal, RecordError, RegistryError, RelayError, Result,
    RoomLiveSpeakersHold, SecretError, SideTableRowProblem, StoreError, SyncError,
    TASK_ASSIGNMENT_CONFLICT_SUGGESTION, VaultRootEntry, VaultRootProblem, VerbHookStop,
};
#[cfg(feature = "sync")]
pub use oneiron_contracts::error::{
    FederationReplayEnd, SyncConfigField, SyncEngineContext, SyncProtocolPruneScope,
    SyncProtocolValidation, SyncRollbackError, SyncSelectorValidation,
};
