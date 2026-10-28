//! The one opener every owner command that opens the vault data key shares
//! (FIX 1489, 1945, 2201, 2559): this install's keystore by default, as
//! before, or the unlock the owner names. A sealed vault's pages unlock with
//! it before the vault opens; a plain vault's key unlocks after. The unlock
//! is read apart from the secret the command enrolls, and at most one of a
//! command's secrets comes from stdin.

use std::path::{Path, PathBuf};

use oneiron::world_keys::{self, VaultKeyStatus};

use super::super::{base_vault_config, open_stopped_vault, open_stopped_vault_with};
use super::{HostUnlock, prepare_page_seal, refuse_orphaned_page_seal};
use crate::cli::{
    RestoreArgs, SecretSourceArgs, UnlockMethod, VaultKeyAddDeviceArgs, VaultUnlockArgs,
};
use crate::config::ServeConfig;

/// What a command needs of the vault key once the vault opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::commands::owner) enum KeyNeed {
    /// The vault open: a read, or a change the engine checks on its own.
    Open,
    /// The key held, for a wrap the command adds. With this install's
    /// keystore, a vault with no key yet mints one wrapped to it, as before.
    Held,
    /// The key held when the vault has one; a vault with none opens as it
    /// is (a kit confirm gives it no wrap).
    HeldIfAny,
}

/// The unlock an owner command names, by its flags: `--unlock` and its
/// inputs, and where its secret is read.
pub(in crate::commands::owner) struct UnlockRequest<'a> {
    pub(super) method: UnlockMethod,
    pub(super) credential: Option<&'a str>,
    pub(super) label: Option<&'a str>,
    pub(super) capsule: Option<&'a Path>,
    pub(super) pieces: &'a [PathBuf],
    pub(super) vault_id: Option<&'a str>,
    pub(super) secret: SecretSourceArgs,
    /// What the command's unlock flags start with after `--`: nothing for
    /// `vault-key add-device`'s own, `unlock-` for the shared ones.
    prefix: &'static str,
}

impl<'a> UnlockRequest<'a> {
    /// The unlock the shared `--unlock` flags name.
    pub(in crate::commands::owner) fn of(args: &'a VaultUnlockArgs) -> Self {
        Self {
            method: args.unlock,
            credential: args.unlock_credential.as_deref(),
            label: args.unlock_label.as_deref(),
            capsule: args.unlock_capsule.as_deref(),
            pieces: &args.unlock_pieces,
            vault_id: args.unlock_vault_id.as_deref(),
            secret: args.secret_source(),
            prefix: "unlock-",
        }
    }

    /// The unlock `oneiron restore` names with its own flags.
    pub(in crate::commands::owner) fn restore(args: &'a RestoreArgs) -> Self {
        Self {
            method: args.unlock,
            credential: args.credential.as_deref(),
            label: args.label.as_deref(),
            capsule: args.capsule.as_deref(),
            pieces: &args.pieces,
            vault_id: args.vault_id.as_deref(),
            secret: args.secret.clone(),
            prefix: "",
        }
    }

    /// The unlock `vault-key add-device` names with its own flags.
    pub(super) fn add_device(args: &'a VaultKeyAddDeviceArgs) -> Self {
        Self {
            method: args.unlock,
            credential: args.credential.as_deref(),
            label: args.label.as_deref(),
            capsule: args.capsule.as_deref(),
            pieces: &args.pieces,
            vault_id: args.vault_id.as_deref(),
            secret: args.secret.clone(),
            prefix: "",
        }
    }

    pub(in crate::commands::owner) fn is_device(&self) -> bool {
        self.method == UnlockMethod::Device
    }

    /// Whether reading this unlock takes its secret from stdin: a password,
    /// a PRF output or an escrow secret with no file or recovery box named,
    /// and a kit opened with one piece and no passphrase file.
    pub(in crate::commands::owner) fn reads_stdin(&self) -> bool {
        let no_file = self.secret.secret_file.is_none();
        match self.method {
            UnlockMethod::Device => false,
            UnlockMethod::Password | UnlockMethod::Passkey => no_file,
            UnlockMethod::Escrow => {
                no_file && self.secret.box_dir.is_none() && self.secret.box_command.is_none()
            }
            UnlockMethod::Kit => no_file && self.pieces.len() == 1,
        }
    }

    /// Refuses a flag the unlock does not read: the kit's pieces and vault
    /// id with any other unlock, a capsule with any but escrow, and a
    /// credential, a label or a recovery box with the kit.
    fn refuse_unused(&self) -> anyhow::Result<()> {
        let kit = self.method == UnlockMethod::Kit;
        let unused = [
            ("piece", !kit && !self.pieces.is_empty()),
            ("vault-id", !kit && self.vault_id.is_some()),
            ("credential", kit && self.credential.is_some()),
            ("label", kit && self.label.is_some()),
            ("box-dir", kit && self.secret.box_dir.is_some()),
            ("box-command", kit && self.secret.box_command.is_some()),
        ];
        let prefix = self.prefix;
        if self.capsule.is_some() && self.method != UnlockMethod::Escrow {
            anyhow::bail!("--{prefix}capsule opens the vault key with --unlock escrow");
        }
        match unused.iter().find(|(_, given)| *given) {
            Some((flag, _)) if kit => anyhow::bail!(
                "--unlock kit reads its pieces and the kit passphrase; --{prefix}{flag} is not one \
                 of them"
            ),
            Some((flag, _)) => anyhow::bail!("--{prefix}{flag} is read only with --unlock kit"),
            None => Ok(()),
        }
    }
}

/// Refuses a command whose unlock and whose own secret would both be read
/// from stdin: one stream holds one secret. `what` names the command's own
/// secret, and `file_flag` the flag that reads it from a file instead.
pub(in crate::commands::owner) fn refuse_two_stdin_secrets(
    unlock: &UnlockRequest<'_>,
    own_reads_stdin: bool,
    what: &str,
    file_flag: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(own_reads_stdin && unlock.reads_stdin()),
        "both the unlock's secret and {what} would be read from stdin, which holds one: read \
         one of them from a file ({file_flag} or --{}secret-file)",
        unlock.prefix
    );
    Ok(())
}

/// The stopped vault at `config`, opened for an owner command with the
/// unlock `request` names, and its key as `need` asks. With this install's
/// keystore the paths are as before. Any other unlock opens a sealed vault's
/// pages before the open, which holds its key, and unlocks a plain vault's
/// key after it; a plain vault with no key yet opens as it is unless `need`
/// asks for the key. A registry capsule's released recipient is named on
/// stderr, to retire. `instead` says what to do while a server holds the
/// vault.
pub(in crate::commands::owner) fn open_with_unlock(
    config: &ServeConfig,
    request: &UnlockRequest<'_>,
    need: KeyNeed,
    instead: &str,
) -> anyhow::Result<oneiron::Vault> {
    request.refuse_unused()?;
    if request.is_device() {
        let vault = open_stopped_vault(config, instead)?;
        let held = match need {
            KeyNeed::Open => Ok(()),
            KeyNeed::Held => vault.ensure_vault_key(),
            KeyNeed::HeldIfAny if vault.vault_key_status()? == VaultKeyStatus::Locked => {
                vault.unlock_vault_key()
            }
            KeyNeed::HeldIfAny => Ok(()),
        };
        held.map_err(|error| {
            anyhow::anyhow!("the vault key does not unlock with this install's keystore: {error}")
        })?;
        return Ok(vault);
    }
    let path = &config.vault_path;
    if world_keys::vault_is_sealed(path)? {
        refuse_orphaned_page_seal(path)?;
        let unlock = HostUnlock::read_for_vault(request, || {
            world_keys::page_seal_vault_id(path)
                .map_err(|error| anyhow::anyhow!("read the vault's page seal: {error}"))
        })?;
        let opened = open_sealed(config, &unlock, instead);
        name_released(&unlock);
        return opened;
    }
    let vault = open_stopped_vault(config, instead)?;
    if need != KeyNeed::Held && vault.vault_key_status()? == VaultKeyStatus::NoKey {
        return Ok(vault);
    }
    let unlock = HostUnlock::read_for_vault(request, || Ok(vault.vault_key_vault_id()))?;
    let unlocked = unlock.unlock_live(&vault).map_err(|error| {
        anyhow::anyhow!("the vault key did not unlock with {}: {error}", unlock.name())
    });
    name_released(&unlock);
    unlocked?;
    Ok(vault)
}

/// The sealed vault at `config`, its pages unlocked with `unlock` before it
/// opens, which holds its key.
fn open_sealed(
    config: &ServeConfig,
    unlock: &HostUnlock,
    instead: &str,
) -> anyhow::Result<oneiron::Vault> {
    let mut vault_config = base_vault_config(config);
    vault_config.page_seal = prepare_page_seal(config, Some(unlock))?;
    open_stopped_vault_with(config, vault_config, instead)
}

/// A registry capsule's recipient released into this process is named on
/// stderr, to retire, whether or not the open went through
/// (CROSS-ARCH-0022 #ov-custody-backend).
fn name_released(unlock: &HostUnlock) {
    if let Some(note) = unlock.released_note() {
        eprintln!("{note}");
    }
}
