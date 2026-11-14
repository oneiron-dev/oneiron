//! Owner review and approve-once doors for held campaign enrollments.

use serde::{Deserialize, Serialize};

use crate::campaign::enrollment::CampaignEnrollmentHeldCall;
use crate::consent::AuthenticatedOwner;
use crate::consent::lifecycle::ConsentActReceipt;
use crate::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::campaign_enrollment::CampaignEnrollmentApproveOnceRequest;

fn campaign_enrollment_error(error: IntentLedgerError) -> MemoryError {
    match error {
        IntentLedgerError::Engine(error) => MemoryError::from(error),
        IntentLedgerError::InvalidInput(message) => MemoryError::bad_request(message),
        other => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            other.to_string(),
            &["Report this campaign enrollment failure."],
        ),
    }
}

/// Lists last-observed campaign holds under the caller's native owner proof.
/// An approved redrive records queued work, not a completed or sent call.
pub fn campaign_enrollment_held(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: super::EmptyRequest,
) -> MemoryResult<Vec<CampaignEnrollmentHeldCall>> {
    vault
        .campaign_enrollment_held_calls(owner)
        .map_err(campaign_enrollment_error)
}

/// Approves only the current, reviewed hold and queues its original work in
/// the same writer. The redrive still passes the ordinary send checks.
pub fn approve_campaign_enrollment_once(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CampaignEnrollmentApproveOnceRequest,
) -> MemoryResult<ConsentActReceipt> {
    let call_ref = EntityId::from_hex(&input.call_ref)
        .map_err(|_| MemoryError::bad_request("call_ref must be 32 hex"))?;
    vault
        .approve_campaign_enrollment_once(owner, &call_ref, &input.approval_digest)
        .map(Into::into)
        .map_err(campaign_enrollment_error)
}
