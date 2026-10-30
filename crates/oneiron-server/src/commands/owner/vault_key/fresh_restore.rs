//! `oneiron restore` where no vault is yet: the restore on a clean host,
//! its key unlocked the way the owner names and wrapped to this install
//! (moved out of `vault_key` whole), and to the durable wrap the owner
//! names with `--wrap-to` (FIX 2558).

use std::path::Path;
use std::sync::Arc;

use oneiron::recovery::checkpoint::{CheckpointKey, CheckpointSigner};
use oneiron::world_keys::{
    HybridSecretKey, VaultKeyUnlock, VaultKeyWrapInfo, existing_machine_secret,
};
use oneiron_keystore::DeviceKeystore;
use rand_core::RngCore as _;
use serde::Serialize;
use zeroize::Zeroizing;

use super::super::base_vault_config;
use super::super::recovery_kit::kit_custody_seed;
use super::{
    HostUnlock, RecoveryBox, backup_key, check_name, read_secret, recovery_box, secret32, view,
};
use crate::cli::{RestoreWrapArgs, RestoreWrapKind};
use crate::config::ServeConfig;
use crate::owner::backup::{self, CustodyAnchorCredentials, RestoreTarget, RestoredFresh};

/// What a restore where no vault was did.
#[derive(Serialize)]
pub(crate) struct FreshRestore {
    #[serde(flatten)]
    restored: RestoredFresh,
    unlocked_with: String,
    /// The restored vault's wraps, with this install's device wrap when its
    /// keystore is on.
    wraps: Vec<view::WrapView>,
    /// The durable wrap `--wrap-to` added, before the vault was kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    added_wrap: Option<view::WrapView>,
    /// What custody this host holds of the restored key, when it holds no
    /// wrap of its own: its keystore is off and no `--wrap-to` was named.
    #[serde(skip_serializing_if = "Option::is_none")]
    custody_note: Option<String>,
}

/// The durable wrap a restore where no vault is yet adds before the vault
/// is kept (FIX 2558): the restoring owner's pick, its secret read before
/// the restore runs and wiped on drop. A host whose keystore is off then
/// still holds a wrap it can open later. None is added unless named.
pub(in crate::commands::owner) enum RestoreWrap {
    Password(Zeroizing<Vec<u8>>),
    Passkey {
        credential: String,
        prf: Zeroizing<[u8; 32]>,
    },
    /// A fresh recipient whose seed the named recovery box keeps first.
    Escrow {
        label: String,
        recovery_box: Box<dyn RecoveryBox>,
    },
}

impl RestoreWrap {
    /// Whether reading the wrap `args` names takes its secret from stdin.
    pub(in crate::commands::owner) fn reads_stdin(args: &RestoreWrapArgs) -> bool {
        matches!(
            args.wrap_to,
            Some(RestoreWrapKind::Password | RestoreWrapKind::Passkey)
        ) && args.wrap_secret_file.is_none()
    }

    /// The wrap `args` names, its secret read now; `None` when it names
    /// none. A flag the wrap does not read is refused.
    pub(in crate::commands::owner) fn read(args: &RestoreWrapArgs) -> anyhow::Result<Option<Self>> {
        let Some(kind) = args.wrap_to else {
            return Ok(None);
        };
        let escrow = kind == RestoreWrapKind::Escrow;
        let unused = [
            (
                "--wrap-credential",
                kind != RestoreWrapKind::Passkey && args.wrap_credential.is_some(),
            ),
            ("--wrap-label", !escrow && args.wrap_label.is_some()),
            ("--wrap-box-dir", !escrow && args.wrap_box_dir.is_some()),
            (
                "--wrap-box-command",
                !escrow && args.wrap_box_command.is_some(),
            ),
            (
                "--wrap-secret-file",
                escrow && args.wrap_secret_file.is_some(),
            ),
        ];
        if let Some((flag, _)) = unused.iter().find(|(_, given)| *given) {
            anyhow::bail!("{flag} is not read by this --wrap-to");
        }
        let source = args.secret_source();
        Ok(Some(match kind {
            RestoreWrapKind::Password => {
                Self::Password(read_secret(&source, "the new wrap's password")?)
            }
            RestoreWrapKind::Passkey => {
                let credential = args.wrap_credential.clone().ok_or_else(|| {
                    anyhow::anyhow!("--wrap-to passkey names the passkey: --wrap-credential")
                })?;
                let prf = secret32(
                    &read_secret(&source, "the new passkey's PRF output")?,
                    "a PRF output",
                )?;
                Self::Passkey { credential, prf }
            }
            RestoreWrapKind::Escrow => {
                let label = args.wrap_label.clone().ok_or_else(|| {
                    anyhow::anyhow!("--wrap-to escrow names the escrow wrap: --wrap-label")
                })?;
                check_name(&label)?;
                let (recovery_box, _) = recovery_box(&source).ok_or_else(|| {
                    anyhow::anyhow!(
                        "--wrap-to escrow names the recovery box that keeps the seed: \
                         --wrap-box-dir or --wrap-box-command"
                    )
                })?;
                Self::Escrow {
                    label,
                    recovery_box,
                }
            }
        }))
    }

    /// Adds this wrap of the key `vault` holds. An escrow seed is kept by
    /// its recovery box before the vault seals to it, so a wrap no box can
    /// open is never made.
    fn add(&self, vault: &oneiron::Vault) -> oneiron::Result<VaultKeyWrapInfo> {
        match self {
            Self::Password(password) => vault.set_vault_key_password(password, None),
            Self::Passkey { credential, prf } => vault.add_vault_key_passkey(credential, prf),
            Self::Escrow {
                label,
                recovery_box,
            } => {
                let mut seed = Zeroizing::new([0u8; 32]);
                rand_core::OsRng.fill_bytes(&mut seed[..]);
                let recipient = oneiron::world_keys::escrow_recipient(&seed)?;
                recovery_box
                    .store(&vault.vault_key_vault_id(), label, &seed)
                    .map_err(|error| {
                        oneiron::Error::InvalidConfig(format!(
                            "the recovery box did not keep the new escrow seed: {error:#}"
                        ))
                    })?;
                Ok(vault
                    .add_vault_key_escrow(label, recipient.public_key())?
                    .wrap)
            }
        }
    }
}

/// Restores `backup` where no vault is yet, unlocks the new vault's data key
/// the same way and wraps it to this install's keystore, and to `wrap` when
/// the owner named one. The vault is sealed (OF-570 maximum tier) when the
/// config asks for the tier, under the backup's own data key, and is kept
/// only once its key is wrapped here. A custody anchor door is called with
/// `anchor`, the owner credential the restore was handed on its pipe
/// (`--custody-anchor-credentials-fd`). With `pad_machine`, the named
/// admitted machine's key opens the worlds that admit it, as `--open-pads`
/// opens them; a machine whose key this install does not hold opens nothing
/// and is a note on the receipt (FIX 10468). With `custody_home`, the custody
/// head and its log are read from that residence home with the kit, in place
/// of the folder beside the backup (FIX 5846).
#[allow(
    clippy::too_many_arguments,
    reason = "the restore command's unlock, wrap, pins and custody sources"
)]
pub(in crate::commands::owner) fn restore_fresh(
    backup: &Path,
    config: &ServeConfig,
    keystore: Option<Arc<dyn DeviceKeystore>>,
    unlock: &HostUnlock,
    wrap: Option<&RestoreWrap>,
    pins: Option<Vec<CheckpointSigner>>,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
    pad_machine: Option<&str>,
    custody_home: Option<&str>,
) -> anyhow::Result<FreshRestore> {
    // A handle for the machine opener below: unlocking the backup moves the
    // install's keystore into the key it opens.
    let machine_keystore = keystore.clone();
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
    let mut target = base_vault_config(config);
    target.page_seal = backup::restore_target_seal(RestoreTarget::Fresh {
        maximum_tier: config.maximum_tier,
        key: &key,
    })?;
    let path = &config.vault_path;
    // One of the owner's machines, whose key this install's keystore still
    // holds: it opens the worlds that admit it, as `--open-pads` opens them
    // (FIX 10468). A machine whose key is not held opens nothing, and is a
    // note on the receipt, never a failure.
    let mut pad_machine_note = None;
    let machine: Option<(oneiron::EntityId, HybridSecretKey)> = match pad_machine {
        Some(id) => {
            let machine = oneiron::EntityId::from_hex(id)
                .map_err(|error| anyhow::anyhow!("--pad-machine {id}: {error}"))?;
            // No vault yet names its id: the backup's head names the vault
            // whose machine slots this install may hold.
            let vault_id = CheckpointKey::unlocks(backup)
                .map_err(|error| anyhow::anyhow!("read backup {}: {error}", backup.display()))?
                .vault_id;
            let keystore = match &machine_keystore {
                Some(keystore) => Arc::clone(keystore),
                None => {
                    oneiron_keystore::default_platform_keystore(&[config.vault_path.as_path()])?
                }
            };
            let secret = existing_machine_secret(keystore.as_ref(), vault_id, *machine.as_bytes())?;
            if secret.is_none() {
                pad_machine_note = Some(format!(
                    "this install holds no key of machine {id}: it opened nothing"
                ));
            }
            secret.map(|secret| (machine, secret))
        }
        None => None,
    };
    // The custody head beside the backup, checked against the configured
    // anchor (a root or another install's door, called with the piped
    // credential) when there is one, and opened with the kit when the
    // restore was unlocked with it (KS-4A1) and with the named machine's
    // key.
    let mut custody = backup::custody_recovery(backup, &config.backup, anchor);
    if let Some(root) = super::super::recovery_kit::kit_custody_root(unlock) {
        custody = custody.with_kit(root);
    }
    if let Some((machine, secret)) = &machine {
        custody = custody.with_machine(*machine, secret);
    }
    custody = backup::custody_from_home(custody, backup, custody_home, kit_custody_seed(unlock))?;
    // Before the vault is kept: its key unlocks the same way and is wrapped
    // to this install, and to the wrap the owner named, so a sealed one is
    // published only once it opens here.
    let mut installed = false;
    let mut added = None;
    let (vault, mut restored) =
        backup::restore_fresh(backup, path, target, &key, &custody, |vault| {
            installed = config.keystore.install_on(vault, path);
            unlock.unlock_live(vault)?;
            // A device unlock of a plain vault wraps the key to this install on
            // its own; a sealed vault's key is already held from its page seal.
            let sealed = vault.vault_pages_sealed();
            if installed && (sealed || !matches!(unlock, HostUnlock::Device)) {
                vault.add_vault_key_device()?;
            }
            if let Some(wrap) = wrap {
                added = Some(wrap.add(vault)?);
            }
            vault.check_page_custody()
        })?;
    if let Some(note) = pad_machine_note {
        restored.pad_notes.push(note);
    }
    let vault_id = vault.vault_key_vault_id();
    let wraps = view::report(&vault)?.wraps;
    let custody_note = (!installed && added.is_none()).then(|| no_wrap_here(unlock, &wraps));
    Ok(FreshRestore {
        wraps,
        unlocked_with: unlock.name(),
        added_wrap: added.map(|info| view::WrapView::of(&vault_id, info)),
        custody_note,
        restored,
    })
}

/// What the owner is told when the restored key has no wrap of this host's
/// own: the keystore is off, so no device wrap was added, and no
/// `--wrap-to` was named. The keystore setting stays as it is.
fn no_wrap_here(unlock: &HostUnlock, wraps: &[view::WrapView]) -> String {
    let ids = wraps
        .iter()
        .map(|wrap| wrap.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let carried = if ids.is_empty() {
        "no wrap".to_owned()
    } else {
        format!("only the backup's wraps ({ids})")
    };
    let released = if matches!(unlock, HostUnlock::EscrowCapsule { .. }) {
        " The registry capsule's recipient was released and is never reused."
    } else {
        ""
    };
    format!(
        "this host's keystore is off, so no device wrap was added, and no --wrap-to was named: \
         the restored vault key keeps {carried}.{released} To hold a wrap you can open later, \
         name --wrap-to at the restore, or run `oneiron vault-key set-password` (or \
         add-passkey, add-escrow) with an --unlock that still opens this key."
    )
}
