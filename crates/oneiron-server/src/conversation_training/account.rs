//! C1 (CALLS-1): a self-hosted vault's binding to the publisher's intake as
//! the person's Oneiron account, through the cloud registration path
//! (ARCH-0054) and its RFC 8628 device-code flow.
//!
//! No device-code client exists in this tree, so the hook answers
//! unavailable and a self-hosted vault writes no offer; its withdrawals
//! still flow. There is no shared or anonymous fallback. The install
//! signature on every file binds a payload to this vault install, not to an
//! account. Managed mode does not ask: the supervisor binds the registry
//! vault id and the node's bearer outside the engine's offer.

use oneiron::feedback::TrainingUnavailable;

/// The self-hosted vault's account binding to the intake: unavailable until
/// a device-code client exists in-tree.
pub(super) fn intake_account_binding() -> Result<(), TrainingUnavailable> {
    Err(TrainingUnavailable::NoAccountBinding)
}
