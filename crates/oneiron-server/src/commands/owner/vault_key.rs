//! The vault data key on a stopped vault and on a clean host (OF-570 E1):
//! `oneiron vault-key` enrolls and lists the wraps, and `oneiron restore`
//! unlocks a backup with the vault password, a passkey's PRF output or an
//! escrow recipient a recovery box releases, trusting only the checkpoint
//! signers the owner pinned.
//!
//! Secrets come from stdin or an owner-only file, never the command line, and
//! are wiped on drop. Each is taken exactly as given but for one trailing line
//! break, so a password set and a password restored always agree.
//!
//! An escrow wrap enrolled here seals to the recipient a 32-byte seed grows
//! into ([`oneiron::world_keys::escrow_recipient`]). A recovery box keeps the
//! seed and releases it; the vault keeps only the capsule. A box is the seam
//! a provider plugs into: a directory the owner holds (removable media, the
//! self-hoster's own box), or a program speaking one line protocol, which is
//! how a hosted guess-limited box ships from outside this repository:
//! - `PROGRAM store <vault id hex> <label>`: the seed as 64 hex digits and a
//!   line break on stdin; exit 0 once it is kept.
//! - `PROGRAM release <vault id hex> <label>`: the seed as 64 hex digits on
//!   stdout and exit 0, after its own sign-in on the terminal.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use oneiron::recovery::checkpoint::{CheckpointKey, CheckpointSigner};
use oneiron::world_keys::{HybridSecretKey, NewVaultKeyWrap, VaultKeyUnlock, VaultKeyWrapInfo};
use oneiron_keystore::DeviceKeystore;
use rand_core::RngCore as _;
use serde::Serialize;
use zeroize::Zeroizing;

use super::{emit, open_stopped_vault, raw_stdin, vault_config};
use crate::cli::{
    RestoreArgs, SecretSourceArgs, UnlockMethod, VaultKeyArgs, VaultKeyCommand, VaultKeyNamedArgs,
};
use crate::commands::credential_file;
use crate::config::{ServeConfig, resolve_serve_config};
use crate::owner::backup::{self, RestoredFresh};
use crate::owner::local_owner;
use crate::owner::vault_key::{self as view, SignerPin, hex, secret32};

/// The most a secret read is: a password is at most 1024 bytes.
const SECRET_LIMIT: usize = 4096;

/// What a command that runs on a stopped vault does instead while a server
/// holds it.
const INSTEAD: &str = "or ask it at `/v1/owner/vault-key`";

pub fn vault_key(command: VaultKeyCommand) -> anyhow::Result<()> {
    match command {
        VaultKeyCommand::Status(args) => {
            let vault = open(&args.serve)?;
            emit(&view::report(&vault)?)
        }
        VaultKeyCommand::Signer(args) => {
            let vault = open(&args.serve)?;
            emit(&SignerPin::from(vault.checkpoint_signer()?))
        }
        VaultKeyCommand::PrfInput(args) => {
            let vault = open(&args.serve)?;
            emit(&view::prf_input(&vault, &args.name)?)
        }
        VaultKeyCommand::SetPassword(args) => set_password(*args),
        VaultKeyCommand::AddPasskey(args) => add_passkey(*args),
        VaultKeyCommand::AddEscrow(args) => add_escrow(*args),
        VaultKeyCommand::AddDevice(args) => {
            let vault = open_held(&args.serve)?;
            let owner = local_owner(&vault)?;
            emit(&vault.add_vault_key_wrap_as(&owner, NewVaultKeyWrap::Device)?)
        }
        VaultKeyCommand::Remove(args) => {
            let vault = open(&args.serve)?;
            let owner = local_owner(&vault)?;
            vault.remove_vault_key_wrap_as(&owner, &args.name)?;
            emit(&serde_json::json!({ "removed": args.name }))
        }
    }
}

fn open(serve: &crate::config::ServeArgs) -> anyhow::Result<oneiron::Vault> {
    let config = resolve_serve_config(serve)?;
    open_stopped_vault(&config, INSTEAD)
}

/// The stopped vault, holding its data key: unlocked with this device's wrap,
/// or minted and wrapped to this device when it has none yet.
fn open_held(serve: &crate::config::ServeArgs) -> anyhow::Result<oneiron::Vault> {
    let vault = open(serve)?;
    vault.ensure_vault_key().map_err(|error| {
        anyhow::anyhow!("the vault key does not unlock with this install's keystore: {error}")
    })?;
    Ok(vault)
}

fn set_password(args: VaultKeyArgs) -> anyhow::Result<()> {
    let password = read_secret(&args.secret, "the password")?;
    let vault = open_held(&args.serve)?;
    let owner = local_owner(&vault)?;
    emit(&vault.add_vault_key_wrap_as(
        &owner,
        NewVaultKeyWrap::Password {
            password: &password,
            cost: None,
        },
    )?)
}

fn add_passkey(args: VaultKeyNamedArgs) -> anyhow::Result<()> {
    let prf = secret32(
        &read_secret(&args.secret, "the PRF output")?,
        "a PRF output",
    )?;
    let vault = open_held(&args.serve)?;
    let owner = local_owner(&vault)?;
    emit(&vault.add_vault_key_wrap_as(
        &owner,
        NewVaultKeyWrap::Passkey {
            credential: &args.name,
            prf: *prf,
        },
    )?)
}

/// What enrolling an escrow recipient did.
#[derive(Serialize)]
struct EscrowEnrolled {
    wrap: VaultKeyWrapInfo,
    /// Where the recipient's seed rests.
    recovery_box: String,
}

fn add_escrow(args: VaultKeyNamedArgs) -> anyhow::Result<()> {
    check_name(&args.name)?;
    let (recovery_box, where_) = recovery_box(&args.secret).ok_or_else(|| {
        anyhow::anyhow!("name the recovery box that keeps the seed: --box-dir or --box-command")
    })?;
    let vault = open_held(&args.serve)?;
    let owner = local_owner(&vault)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(&mut seed[..]);
    let recipient = oneiron::world_keys::escrow_recipient(&seed)?;
    // The box keeps the seed before the vault seals to it: a wrap no box can
    // open is never made.
    recovery_box.store(&vault.vault_key_vault_id(), &args.name, &seed)?;
    let wrap = vault.add_vault_key_wrap_as(
        &owner,
        NewVaultKeyWrap::Escrow {
            label: &args.name,
            recipient: recipient.public_key(),
        },
    )?;
    emit(&EscrowEnrolled {
        wrap,
        recovery_box: where_,
    })
}

/// A wrap name: 1 to 64 letters, digits, dots, dashes or underscores, as the
/// engine checks it. A box files a seed under it, so it is checked first.
fn check_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "a wrap name is 1 to 64 letters, digits, dots, dashes or underscores"
    );
    Ok(())
}

/// One secret, from the named owner-only file or else stdin, exactly as given
/// but for one trailing line break.
fn read_secret(source: &SecretSourceArgs, what: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::with_capacity(SECRET_LIMIT + 1));
    match &source.secret_file {
        Some(path) => read_owner_only(path, &mut value)?,
        None => {
            raw_stdin()?
                .take(SECRET_LIMIT as u64 + 1)
                .read_to_end(&mut value)?;
        }
    }
    anyhow::ensure!(value.len() <= SECRET_LIMIT, "{what} is at most 4 KiB");
    strip_line_break(&mut value);
    anyhow::ensure!(
        !value.is_empty(),
        "{what} is read from stdin unless --secret-file names a file, and none was given"
    );
    Ok(value)
}

fn read_owner_only(path: &Path, value: &mut Vec<u8>) -> anyhow::Result<()> {
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    credential_file::admit(path, &file)?;
    file.take(SECRET_LIMIT as u64 + 1)
        .read_to_end(value)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    Ok(())
}

fn strip_line_break(value: &mut Vec<u8>) {
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
}

/// Where an escrow recipient's seed rests: the seam a recovery box plugs into.
trait RecoveryBox {
    /// Keeps `seed` for the vault's escrow wrap `label`.
    fn store(&self, vault_id: &[u8; 32], label: &str, seed: &[u8; 32]) -> anyhow::Result<()>;
    /// Releases the seed kept for the vault's escrow wrap `label`.
    fn release(&self, vault_id: &[u8; 32], label: &str) -> anyhow::Result<Zeroizing<[u8; 32]>>;
}

/// The box the flags name, and how a report names it.
fn recovery_box(source: &SecretSourceArgs) -> Option<(Box<dyn RecoveryBox>, String)> {
    if let Some(dir) = &source.box_dir {
        return Some((
            Box::new(DirBox(dir.clone())),
            format!("dir:{}", dir.display()),
        ));
    }
    source.box_command.as_ref().map(|program| {
        (
            Box::new(CommandBox(program.clone())) as Box<dyn RecoveryBox>,
            format!("command:{}", program.display()),
        )
    })
}

/// A directory the owner holds: `<dir>/<vault id hex>/<label>.seed`, each
/// directory owner-only and each seed file readable by its owner alone.
struct DirBox(PathBuf);

impl DirBox {
    fn seed_path(&self, vault_id: &[u8; 32], label: &str) -> PathBuf {
        self.0.join(hex(vault_id)).join(format!("{label}.seed"))
    }
}

impl RecoveryBox for DirBox {
    fn store(&self, vault_id: &[u8; 32], label: &str, seed: &[u8; 32]) -> anyhow::Result<()> {
        let path = self.seed_path(vault_id, label);
        if let Some(dir) = path.parent() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(dir)
                .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
        }
        // A new file only: a seed already there is another wrap's.
        let mut file = credential_file::create(&path)?;
        let line = Zeroizing::new(format!("{}\n", hex(seed)));
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    fn release(&self, vault_id: &[u8; 32], label: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let path = self.seed_path(vault_id, label);
        let mut value = Zeroizing::new(Vec::with_capacity(SECRET_LIMIT + 1));
        read_owner_only(&path, &mut value)?;
        strip_line_break(&mut value);
        secret32(&value, "an escrow seed")
    }
}

/// A program that speaks the box's line protocol.
struct CommandBox(PathBuf);

impl RecoveryBox for CommandBox {
    fn store(&self, vault_id: &[u8; 32], label: &str, seed: &[u8; 32]) -> anyhow::Result<()> {
        let mut child = Command::new(&self.0)
            .arg("store")
            .arg(hex(vault_id))
            .arg(label)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| anyhow::anyhow!("run {}: {error}", self.0.display()))?;
        let line = Zeroizing::new(format!("{}\n", hex(seed)));
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(line.as_bytes())?;
        }
        let status = child.wait()?;
        anyhow::ensure!(
            status.success(),
            "the recovery box {} did not keep the seed ({status})",
            self.0.display()
        );
        Ok(())
    }

    fn release(&self, vault_id: &[u8; 32], label: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let output = Command::new(&self.0)
            .arg("release")
            .arg(hex(vault_id))
            .arg(label)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| anyhow::anyhow!("run {}: {error}", self.0.display()))?;
        let mut value = Zeroizing::new(output.stdout);
        anyhow::ensure!(
            output.status.success(),
            "the recovery box {} released nothing ({})",
            self.0.display(),
            output.status
        );
        strip_line_break(&mut value);
        secret32(&value, "the seed a recovery box releases")
    }
}

/// What unlocks a backup's vault key on this host, its secret read once and
/// wiped on drop.
pub(super) enum HostUnlock {
    Device,
    Password(Zeroizing<Vec<u8>>),
    Passkey {
        credential: String,
        prf: Zeroizing<[u8; 32]>,
    },
    Escrow {
        label: String,
        secret: HybridSecretKey,
    },
}

impl HostUnlock {
    /// The unlock `args` name for `backup`, its secret read now. An escrow
    /// secret comes from the named recovery box when there is one.
    pub(super) fn read(args: &RestoreArgs, backup: &Path) -> anyhow::Result<Self> {
        Ok(match args.unlock {
            UnlockMethod::Device => Self::Device,
            UnlockMethod::Password => {
                Self::Password(read_secret(&args.secret, "the vault password")?)
            }
            UnlockMethod::Passkey => {
                let credential = args.credential.clone().ok_or_else(|| {
                    anyhow::anyhow!("--unlock passkey names the passkey: --credential")
                })?;
                let prf = secret32(
                    &read_secret(&args.secret, "the PRF output")?,
                    "a PRF output",
                )?;
                Self::Passkey { credential, prf }
            }
            UnlockMethod::Escrow => {
                let label = args.label.clone().ok_or_else(|| {
                    anyhow::anyhow!("--unlock escrow names the escrow wrap: --label")
                })?;
                check_name(&label)?;
                let seed = match recovery_box(&args.secret) {
                    Some((recovery_box, _)) => {
                        let vault_id = CheckpointKey::unlocks(backup)
                            .map_err(|error| {
                                anyhow::anyhow!("read backup {}: {error}", backup.display())
                            })?
                            .vault_id;
                        recovery_box.release(&vault_id, &label)?
                    }
                    None => secret32(
                        &read_secret(&args.secret, "the escrow seed")?,
                        "an escrow seed",
                    )?,
                };
                let secret = oneiron::world_keys::escrow_recipient(&seed)?;
                Self::Escrow { label, secret }
            }
        })
    }

    fn name(&self) -> String {
        match self {
            Self::Device => "device".to_owned(),
            Self::Password(_) => "password".to_owned(),
            Self::Passkey { credential, .. } => format!("passkey:{credential}"),
            Self::Escrow { label, .. } => format!("escrow:{label}"),
        }
    }

    /// The engine's unlock for this secret; `None` for this device's, which
    /// needs a keystore.
    fn engine(&self) -> Option<VaultKeyUnlock<'_>> {
        match self {
            Self::Device => None,
            Self::Password(password) => Some(VaultKeyUnlock::Password(password)),
            Self::Passkey { credential, prf } => Some(VaultKeyUnlock::Passkey {
                credential,
                prf: **prf,
            }),
            Self::Escrow { label, secret } => Some(VaultKeyUnlock::Escrow { label, secret }),
        }
    }

    /// Unlocks an open vault's data key the same way.
    fn unlock_live(&self, vault: &oneiron::Vault) -> oneiron::Result<()> {
        match self {
            Self::Device => vault.unlock_vault_key(),
            Self::Password(password) => vault.unlock_vault_key_with_password(password),
            Self::Passkey { credential, prf } => {
                vault.unlock_vault_key_with_passkey(credential, **prf)
            }
            Self::Escrow { label, secret } => vault.unlock_vault_key_with_escrow(label, secret),
        }
    }
}

/// The signers the pin file at `path` names.
pub(super) fn read_pins(path: &Path) -> anyhow::Result<Vec<CheckpointSigner>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    view::parse_pins(&text)
}

/// The key `backup` opens with when the restore names an unlock or a trust of
/// its own; `None` leaves this install's device unlock and trust as before.
/// Every unlock but this device's trusts only pinned signers: a host that
/// holds no seed has no other ground to trust a backup on.
pub(super) fn backup_key(
    backup: &Path,
    vault_path: &Path,
    keystore: Option<&Arc<dyn DeviceKeystore>>,
    unlock: &HostUnlock,
    pins: Option<Vec<CheckpointSigner>>,
) -> anyhow::Result<Option<CheckpointKey>> {
    let opened = |result: oneiron::Result<CheckpointKey>| {
        result.map_err(|error| anyhow::anyhow!("backup {} does not open: {error}", backup.display()))
    };
    match (unlock.engine(), pins) {
        (None, None) => Ok(None),
        (None, Some(pins)) => {
            let keystore = match keystore {
                Some(keystore) => Arc::clone(keystore),
                None => oneiron_keystore::default_platform_keystore(&[vault_path])?,
            };
            let key = opened(CheckpointKey::unlock(
                backup,
                &VaultKeyUnlock::Device(keystore.as_ref()),
            ))?;
            Ok(Some(key.trusting(pins)))
        }
        (Some(_), None) => anyhow::bail!(
            "--unlock {} needs --trust: the checkpoint signers to trust the backup by",
            unlock.name()
        ),
        (Some(engine), Some(pins)) => {
            Ok(Some(opened(CheckpointKey::unlock(backup, &engine))?.trusting(pins)))
        }
    }
}

/// What a restore where no vault was did.
#[derive(Serialize)]
pub(super) struct FreshRestore {
    #[serde(flatten)]
    restored: RestoredFresh,
    unlocked_with: String,
    /// The restored vault's wraps, with this install's device wrap when its
    /// keystore is on.
    wraps: Vec<view::WrapView>,
}

/// Restores `backup` where no vault is yet, unlocks the new vault's data key
/// the same way and wraps it to this install's keystore.
pub(super) fn restore_fresh(
    backup: &Path,
    config: &ServeConfig,
    keystore: Option<Arc<dyn DeviceKeystore>>,
    unlock: &HostUnlock,
    pins: Option<Vec<CheckpointSigner>>,
) -> anyhow::Result<FreshRestore> {
    let key = match backup_key(backup, &config.vault_path, keystore.as_ref(), unlock, pins)? {
        Some(key) => key,
        None => match keystore {
            Some(keystore) => {
                CheckpointKey::unlock(backup, &VaultKeyUnlock::Device(keystore.as_ref()))
                    .map(|key| key.trusting_device(keystore))
            }
            None => CheckpointKey::unlock_on_this_device(backup, &config.vault_path),
        }
        .map_err(|error| anyhow::anyhow!("backup {} does not open: {error}", backup.display()))?,
    };
    let (vault, restored) =
        backup::restore_fresh(backup, &config.vault_path, vault_config(config), &key)?;
    let installed = config.keystore.install_on(&vault, &config.vault_path);
    unlock.unlock_live(&vault).map_err(|error| {
        anyhow::anyhow!(
            "the restored vault at {} did not unlock with {}: {error}",
            restored.vault.display(),
            unlock.name()
        )
    })?;
    // A device unlock wraps the key to this install on its own.
    if installed && !matches!(unlock, HostUnlock::Device) {
        vault.add_vault_key_device()?;
    }
    Ok(FreshRestore {
        wraps: view::report(&vault)?.wraps,
        unlocked_with: unlock.name(),
        restored,
    })
}
