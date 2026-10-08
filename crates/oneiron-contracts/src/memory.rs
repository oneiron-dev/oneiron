//! The memory facade's error vocabulary: `MemoryError`, the stable `MEMORY_CODE_*`
//! strings and the one engine-error mapping. `oneiron::memory` re-exports all of it.

mod error;

pub use self::error::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_NOT_FOUND,
    MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError, MemoryGateDenial, MemoryPolicyDenial,
    MemoryPolicyExceptionProposal, MemoryResult,
};
