//! Door for `tests/dreamer_signed_claim_recall.rs` (FIX row
//! DREAMER-MESO-CLAIM-RECALL-MISS): the Dreamer's Auto grant on a vault the
//! test opened itself, so a promotion there lands a claim the engine's
//! MACHINE writer signs.

use crate::error::Result;
use crate::vault::Vault;

/// Puts the policy manifest that grants the Dreamer's Auto request (the one
/// [`super::dreamer_promotion_seconds::open_auto_promotion_vault`] puts) into
/// the default manifest slot of `vault`.
///
/// # Errors
///
/// The store's, or a manifest that does not encode.
pub fn permit_dreamer_auto_promotion(vault: &Vault) -> Result<()> {
    crate::test_fixtures::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &super::dreamer_promotion_seconds::auto_permitting_manifest()?,
    )
}
