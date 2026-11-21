//! Frozen dispatch receipt identity and approval field vocabulary.

use serde::{Deserialize, Serialize};

/// Exact effect binding. The full frozen bytes, not a connector-local field list,
/// are the only replay identity. Receipt id/time are separate per-try evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenDispatchIdentity {
    pub(crate) attempt_ref: String,
    pub(crate) payload: Vec<u8>,
}

#[doc(hidden)]
pub(crate) use oneiron_records::receipt::dispatch_identity::APPROVAL_DIGEST_FIELD;
