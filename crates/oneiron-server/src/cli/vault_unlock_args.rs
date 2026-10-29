//! Flags that unlock a stopped vault's data key for an owner command, and
//! that wrap a restored key to a target the owner picks (FIX 1489, 1945,
//! 2201, 2558). Each is named apart from the secret the command enrolls, a
//! kit's pieces and passphrase, and the serve flags, so no two flags of one
//! command read the same thing.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::{SecretSourceArgs, UnlockMethod};

/// How a command that opens the vault data key unlocks it. This install's
/// keystore by default, as before; any other way unlocks a sealed vault's
/// pages before it opens, and a plain vault's key after. Its secret comes
/// from stdin, `--unlock-secret-file` or the recovery box, read as
/// `oneiron restore --unlock` reads it. At most one secret of a command is
/// read from stdin.
#[derive(Args, Clone, Debug, Default)]
pub struct VaultUnlockArgs {
    /// How the vault key unlocks: `device` (this install's keystore),
    /// `password`, `passkey`, `escrow` (a wrap the vault carries, or a
    /// registry's capsule with `--unlock-capsule`) or `kit`.
    #[arg(long = "unlock", value_enum, default_value_t = UnlockMethod::Device)]
    pub unlock: UnlockMethod,

    /// With `--unlock passkey`: the passkey's credential name.
    #[arg(long = "unlock-credential", value_name = "NAME")]
    pub unlock_credential: Option<String>,

    /// With `--unlock escrow`: the escrow wrap's label.
    #[arg(
        long = "unlock-label",
        value_name = "NAME",
        conflicts_with = "unlock_capsule"
    )]
    pub unlock_label: Option<String>,

    /// With `--unlock escrow`: a registry's escrow capsule report (JSON) for
    /// this vault, opened in place of a wrap it carries. Its recipient is
    /// released, and is retired after.
    #[arg(long = "unlock-capsule", value_name = "REPORT")]
    pub unlock_capsule: Option<PathBuf>,

    /// With `--unlock kit`: a world kit or data-key kit piece file. Give
    /// two, or one and the kit passphrase.
    #[arg(long = "unlock-piece", value_name = "FILE")]
    pub unlock_pieces: Vec<PathBuf>,

    /// With `--unlock kit`: the vault id the kit is bound to, 64 hex digits.
    #[arg(long = "unlock-vault-id", value_name = "HEX")]
    pub unlock_vault_id: Option<String>,

    /// Read the unlock's secret from this file, which only its owner may
    /// read, instead of stdin.
    #[arg(
        long = "unlock-secret-file",
        value_name = "FILE",
        conflicts_with_all = ["unlock_box_dir", "unlock_box_command"]
    )]
    pub unlock_secret_file: Option<PathBuf>,

    /// With `--unlock escrow`: the recovery box directory that keeps the
    /// escrow seed.
    #[arg(
        long = "unlock-box-dir",
        value_name = "DIR",
        conflicts_with = "unlock_box_command"
    )]
    pub unlock_box_dir: Option<PathBuf>,

    /// With `--unlock escrow`: the recovery box program that releases the
    /// escrow seed.
    #[arg(long = "unlock-box-command", value_name = "PROGRAM")]
    pub unlock_box_command: Option<PathBuf>,
}

impl VaultUnlockArgs {
    /// Where the unlock's secret is read, as `SecretSourceArgs` names it.
    #[must_use]
    pub fn secret_source(&self) -> SecretSourceArgs {
        SecretSourceArgs {
            secret_file: self.unlock_secret_file.clone(),
            box_dir: self.unlock_box_dir.clone(),
            box_command: self.unlock_box_command.clone(),
        }
    }
}

/// A durable wrap a restore adds where no vault is yet, before the vault is
/// kept: the restoring owner's pick, so a host whose keystore is off still
/// holds a wrap it can open later. None is added unless named.
#[derive(Args, Clone, Debug, Default)]
pub struct RestoreWrapArgs {
    /// Also wrap the restored key to `password`, `passkey` or `escrow` (a
    /// fresh recipient whose seed the named recovery box keeps). Its secret
    /// comes from stdin or `--wrap-secret-file`, never the one that unlocked
    /// the backup.
    #[arg(long = "wrap-to", value_enum, value_name = "WRAP")]
    pub wrap_to: Option<RestoreWrapKind>,

    /// With `--wrap-to passkey`: the passkey's credential name.
    #[arg(long = "wrap-credential", value_name = "NAME", requires = "wrap_to")]
    pub wrap_credential: Option<String>,

    /// With `--wrap-to escrow`: the new escrow wrap's label.
    #[arg(long = "wrap-label", value_name = "NAME", requires = "wrap_to")]
    pub wrap_label: Option<String>,

    /// Read the new wrap's secret (the password, or the PRF output) from
    /// this owner-only file instead of stdin.
    #[arg(
        long = "wrap-secret-file",
        value_name = "FILE",
        requires = "wrap_to",
        conflicts_with_all = ["wrap_box_dir", "wrap_box_command"]
    )]
    pub wrap_secret_file: Option<PathBuf>,

    /// With `--wrap-to escrow`: the recovery box directory that keeps the
    /// new seed.
    #[arg(
        long = "wrap-box-dir",
        value_name = "DIR",
        requires = "wrap_to",
        conflicts_with = "wrap_box_command"
    )]
    pub wrap_box_dir: Option<PathBuf>,

    /// With `--wrap-to escrow`: the recovery box program that keeps the new
    /// seed.
    #[arg(
        long = "wrap-box-command",
        value_name = "PROGRAM",
        requires = "wrap_to"
    )]
    pub wrap_box_command: Option<PathBuf>,
}

impl RestoreWrapArgs {
    /// Where the new wrap's secret is read, or its seed kept.
    #[must_use]
    pub fn secret_source(&self) -> SecretSourceArgs {
        SecretSourceArgs {
            secret_file: self.wrap_secret_file.clone(),
            box_dir: self.wrap_box_dir.clone(),
            box_command: self.wrap_box_command.clone(),
        }
    }
}

/// The durable wrap a restore adds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RestoreWrapKind {
    /// The vault password.
    Password,
    /// A passkey, by its PRF output at the input `--inspect` prints.
    Passkey,
    /// A fresh escrow recipient whose seed a recovery box keeps.
    Escrow,
}
