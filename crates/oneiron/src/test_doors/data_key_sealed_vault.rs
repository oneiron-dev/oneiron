//! Doors for the sealed vault data-key generation test: a sealed owner vault
//! on a given keystore, and two interrupted acts, one whose write never
//! committed and one whose mirror rewrite never ran.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::Path;
use std::sync::Arc;

use crate::authority::ActAuthority;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::world_keys::{DataKeyGenerationCause, DataKeyGenerationOutcome, DataKeyGenerationWays};

/// A sealed vault whose install can carry the embedded owner's signed acts,
/// as [`super::steward::open_owner_carrier_vault`]: a fresh page seal at
/// `path`, the engine's MACHINE writers provisioned, the embedded owner
/// seeded, the given in-memory device keystore installed, and this install's
/// machine profile enrolled, so the owner's act has a carrier.
///
/// # Errors
///
/// The seal's, the vault's, or the authority log's.
pub fn create_sealed_owner_vault(
    path: &Path,
    keystore: Arc<oneiron_keystore::MemoryKeystore>,
) -> Result<Vault> {
    let seal = crate::world_keys::new_page_seal(path)?;
    let mut config = crate::VaultConfig::device();
    config.page_seal = Some(seal);
    let vault = Vault::open(path, config)?;
    let issuer = crate::test_support::provision_engine_machines(&vault);
    vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    vault.install_device_keystore(keystore);
    vault.ensure_serving_install_profile(&issuer, crate::authority::MachineRole::Unanswered)?;
    Ok(vault)
}

/// Runs the act's write and aborts it after the stage: the transaction rolls
/// back, and the staged mirror stays, naming both generations.
///
/// # Errors
///
/// The draft's; the act's own refusal when its write refuses first; and a
/// door fault when the write commits instead of aborting.
pub fn abort_data_key_generation_after_stage(
    vault: &Vault,
    authority: &ActAuthority,
    ways: &DataKeyGenerationWays<'_>,
) -> Result<()> {
    let draft = vault.prepare_data_key_generation(ways)?;
    let transition = vault.begin_wrap_transition()?;
    let aborted: Result<()> = vault.with_write_txn(|txn| {
        vault.start_data_key_generation_in_txn(
            txn,
            authority,
            DataKeyGenerationCause::OwnerRequest,
            &draft,
            ways,
            &transition,
        )?;
        Err(Error::InvalidConfig("test door: abort after stage".into()))
    });
    drop(transition);
    match aborted {
        Err(Error::InvalidConfig(message)) if message == "test door: abort after stage" => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(Error::InvalidConfig(
            "test door: abort after stage committed".into(),
        )),
    }
}

/// Runs the act's write and commits it, but never finishes the transition:
/// a crash after the commit, before the mirror rewrite. The staged mirror
/// stays, naming both generations, and this handle still holds the old key.
///
/// # Errors
///
/// The draft's, and the act's own refusal when its write refuses.
pub fn start_data_key_generation_without_mirror_finish(
    vault: &Vault,
    authority: &ActAuthority,
    ways: &DataKeyGenerationWays<'_>,
) -> Result<DataKeyGenerationOutcome> {
    let draft = vault.prepare_data_key_generation(ways)?;
    let transition = vault.begin_wrap_transition()?;
    let outcome = vault.with_write_txn(|txn| {
        vault.start_data_key_generation_in_txn(
            txn,
            authority,
            DataKeyGenerationCause::OwnerRequest,
            &draft,
            ways,
            &transition,
        )
    })?;
    drop(transition);
    drop(draft);
    Ok(outcome)
}
