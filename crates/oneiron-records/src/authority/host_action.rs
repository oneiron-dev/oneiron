//! Moved from `crates/oneiron/src/authority/host_action.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_base::error::ClaimError;
use oneiron_base::error::Error;

/// Whether `error` is a host action's refusal, the typed one or the owner
/// refusal, rather than a failure to judge it.
pub fn host_action_refused(error: &Error) -> bool {
    matches!(
        error,
        Error::HostActionRequiresSupportGrant | Error::Claim(ClaimError::ScopedReadOwnerNotLive(_))
    )
}
