//! Door for the vault data-key generation test: the owner's act with another
//! writer's commit between its reads and its write, as a recovery preset
//! switch committed at that moment lands.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Vault;
use crate::authority::ActAuthority;
use crate::world_keys::{DataKeyGenerationCause, DataKeyGenerationOutcome, DataKeyGenerationWays};

/// Starts a new data-key generation on `vault` as `authority`, running
/// `between` after the act's reads outside its write and before the write.
pub fn start_generation_across(
    vault: &Vault,
    authority: &ActAuthority,
    cause: DataKeyGenerationCause,
    ways: &DataKeyGenerationWays<'_>,
    between: impl FnOnce(),
) -> crate::error::Result<DataKeyGenerationOutcome> {
    vault.start_data_key_generation_across(authority, cause, ways, between)
}
