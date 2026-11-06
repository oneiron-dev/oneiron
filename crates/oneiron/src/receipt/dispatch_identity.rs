//! Frozen dispatch receipt identity and approval field vocabulary.

use serde::{Deserialize, Serialize};

/// Exact effect binding. The full frozen bytes, not a connector-local field list,
/// are the only replay identity. Receipt id/time are separate per-try evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenDispatchIdentity {
    pub(crate) attempt_ref: String,
    pub(crate) payload: Vec<u8>,
}

/// FIX 6424 (Engine 10-20 20:4x): the receipt field a held send's
/// approve-once digest rides, beside its gate outcome.
pub(crate) const APPROVAL_DIGEST_FIELD: &str = "approval_digest";
