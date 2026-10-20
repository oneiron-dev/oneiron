//! What a managed vault reports of its backups on every `Ping` (Engine 10-20
//! row (b)): this install's checkpoint signer, read once at boot.

use oneiron::error::SecretError;
use oneiron_vault_contract::{
    CheckpointSignerObservation, CheckpointSignerUnavailable, MANAGED_BACKUP_SCHEMA_VERSION,
    ManagedBackupFacts,
};

use crate::owner::vault_key::{SignerPin, hex};

/// This vault's backup facts, read once at boot after its keystore is
/// installed: the vault id its checkpoints bind and this install's public
/// checkpoint signer, spelled as its pin file spells it. The first read may
/// make the signer's seed in its keystore slot, so it runs here, before ctl
/// serves, and never on a `Ping` or under a reap freeze. A signer that does
/// not read is reported unavailable by closed reason and logged by kind;
/// the vault serves on. This build takes no managed backup of its own: no
/// cadence, and none before an idle reap.
pub(super) fn observe(vault: &oneiron::Vault) -> ManagedBackupFacts {
    let checkpoint_signer = match vault.checkpoint_signer() {
        Ok(signer) => {
            let pin = SignerPin::from(signer);
            CheckpointSignerObservation::Available {
                install: pin.install,
                ed25519: pin.ed25519,
                slhdsa: pin.slhdsa,
            }
        }
        Err(error) => {
            let reason = if matches!(
                error,
                oneiron::Error::Secret(SecretError::KeystoreUnavailable(_))
            ) {
                CheckpointSignerUnavailable::KeystoreUnavailable
            } else {
                CheckpointSignerUnavailable::CheckpointSignerFailed
            };
            tracing::warn!(
                kind = ?error.kind(),
                reason = reason.as_str(),
                "this install's checkpoint signer did not read; Ping reports it unavailable and the vault serves on"
            );
            CheckpointSignerObservation::Unavailable { reason }
        }
    };
    ManagedBackupFacts {
        schema_version: MANAGED_BACKUP_SCHEMA_VERSION,
        engine_vault_id: hex(&vault.vault_key_vault_id()),
        cadence_secs: None,
        prepare_idle_reap: false,
        checkpoint_signer,
    }
}
