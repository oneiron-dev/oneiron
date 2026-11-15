//! Doors for `tests/pack_keys_linkedin.rs` (owner ruling PACK-SETTINGS-ALL = B; RULING
//! PACK-KEYS-LINKEDIN-SWEEPS = A): a LinkedIn seat's policy under the vault's seat Setting keys,
//! as the outbound seat wall and the transport apply them.

use crate::Vault;
use crate::error::Result;
use crate::linkedin_connector::LinkedInSeatSandboxPolicy;

/// `policy` under the vault's `linkedin.sweeps_allowed` and `linkedin.seat.cap_day_reset` at
/// `now`: the owner's sweep setting named, and the instant its daily caps reset.
///
/// # Errors
///
/// Storage errors.
pub fn seat_policy_under_settings(
    vault: &Vault,
    policy: LinkedInSeatSandboxPolicy,
    now: u64,
) -> Result<LinkedInSeatSandboxPolicy> {
    crate::linkedin_connector::setting_keys::seat_policy_under_settings(vault, policy, now)
}
