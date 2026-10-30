//! What unlocks a backup's vault key, or a sealed vault's pages, on this
//! host: the unlock the owner names, its secret read once (moved out of
//! `vault_key` whole).

use std::path::Path;

use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::world_keys::{HybridSecretKey, RecoveryRootSeed, VaultKeyUnlock};
use zeroize::Zeroizing;

use super::{
    UnlockRequest, capsule_secret, check_name, hex, read_capsule_report, read_secret, recovery_box,
    secret32,
};
use crate::cli::{RestoreArgs, SecretSourceArgs, UnlockMethod};

/// What unlocks a backup's vault key, or a sealed vault's pages, on this
/// host, its secret read once and wiped on drop.
pub(crate) enum HostUnlock {
    Device,
    Password(Zeroizing<Vec<u8>>),
    Passkey {
        credential: String,
        prf: Zeroizing<[u8; 32]>,
    },
    Escrow {
        label: String,
        secret: HybridSecretKey,
        /// The world kit's seed when the kit gave the secret: its owner
        /// anchor signs a custody fetch from the residence home (FIX 5846).
        kit_seed: Option<RecoveryRootSeed>,
    },
    /// A registry's escrow capsule, presented in place of a wrap, and its
    /// recipient's released secret.
    EscrowCapsule {
        role: String,
        label: String,
        capsule: Vec<u8>,
        secret: HybridSecretKey,
    },
    /// The data-key kit's pieces and, with one piece, its passphrase (FIX
    /// 5614): they rebuild the vault data key itself, bound to the vault id
    /// the owner names, and open it against its commitment with no wrap.
    VaultKeyKit {
        vault_id: [u8; 32],
        pieces: Vec<oneiron::recovery::KitPiece>,
        passphrase: Option<oneiron::recovery::KitPassphrase>,
    },
}

impl HostUnlock {
    /// The unlock `args` name for `backup`, its secret read now. An escrow
    /// secret comes from the named recovery box when there is one, the world
    /// kit's from its pieces, and a registry capsule's with its report.
    pub(in crate::commands::owner) fn read(
        args: &RestoreArgs,
        backup: &Path,
    ) -> anyhow::Result<Self> {
        if let Some(report) = &args.capsule {
            anyhow::ensure!(
                args.unlock == UnlockMethod::Escrow,
                "--capsule opens the backup with --unlock escrow"
            );
            return Self::read_capsule(report, &args.secret, backup);
        }
        if args.unlock == UnlockMethod::Kit {
            return super::super::recovery_kit::kit_unlock(args);
        }
        Self::read_with(
            args.unlock,
            args.credential.as_deref(),
            args.label.as_deref(),
            &args.secret,
            || {
                Ok(CheckpointKey::unlocks(backup)
                    .map_err(|error| anyhow::anyhow!("read backup {}: {error}", backup.display()))?
                    .vault_id)
            },
        )
    }

    /// The registry's escrow capsule report at `path` for `backup`, and its
    /// recipient's secret, read now from the named recovery box or else as a
    /// secret ([`crate::owner::vault_key::escrow_secret`]). A report of
    /// another vault or key is refused before the secret is read.
    fn read_capsule(path: &Path, source: &SecretSourceArgs, backup: &Path) -> anyhow::Result<Self> {
        let report = read_capsule_report(path)?;
        let unlocks = CheckpointKey::unlocks(backup)
            .map_err(|error| anyhow::anyhow!("read backup {}: {error}", backup.display()))?;
        anyhow::ensure!(
            report.vault_id == unlocks.vault_id,
            "capsule report {} is for vault {}, and backup {} is vault {}",
            path.display(),
            hex(&report.vault_id),
            backup.display(),
            hex(&unlocks.vault_id)
        );
        anyhow::ensure!(
            report.commitment == unlocks.commitment,
            "capsule report {} seals another data key of vault {} than backup {} (key commitment \
             {}, the backup's {})",
            path.display(),
            hex(&report.vault_id),
            backup.display(),
            hex(&report.commitment),
            hex(&unlocks.commitment)
        );
        let secret = capsule_secret(&report, source)?;
        Ok(Self::EscrowCapsule {
            role: report.role,
            label: report.label,
            capsule: report.capsule,
            secret,
        })
    }

    /// What the owner is told once a registry capsule's recipient secret was
    /// read: a released recipient is never reused (CROSS-ARCH-0022
    /// #ov-custody-backend), and the restore retires nothing itself. `None`
    /// for every other unlock.
    pub(in crate::commands::owner) fn released_note(&self) -> Option<String> {
        let Self::EscrowCapsule { role, label, .. } = self else {
            return None;
        };
        Some(format!(
            "escrow recipient {label} ({role}) was released for this restore and is never \
             reused. Retire it: `oneiron vault-key retire-escrow {label}` drops its wrap and \
             refuses that label from then on; `oneiron vault-key reseal-capsule REPORT \
             --recipient-file FILE` reseals the capsule to a fresh recipient for the registry; \
             and have the registry delete the released recipient's capsules."
        ))
    }

    /// The unlock `request` names for an existing vault, its secret read
    /// now. A recovery box files an escrow seed under the vault `vault_id`
    /// reads; a registry capsule's report must name that vault, and the
    /// engine opens it only to the key the vault's commitment names. The kit
    /// is bound to the vault id the owner names, never the one a mirror or
    /// the store carries.
    pub(super) fn read_for_vault(
        request: &UnlockRequest<'_>,
        vault_id: impl FnOnce() -> anyhow::Result<[u8; 32]>,
    ) -> anyhow::Result<Self> {
        if let Some(path) = request.capsule {
            let report = read_capsule_report(path)?;
            let vault_id = vault_id()?;
            anyhow::ensure!(
                report.vault_id == vault_id,
                "capsule report {} is for vault {}, and this vault is {}",
                path.display(),
                hex(&report.vault_id),
                hex(&vault_id)
            );
            let secret = capsule_secret(&report, &request.secret)?;
            return Ok(Self::EscrowCapsule {
                role: report.role,
                label: report.label,
                capsule: report.capsule,
                secret,
            });
        }
        if request.method == UnlockMethod::Kit {
            return super::super::recovery_kit::kit_unlock_with(
                request.vault_id,
                request.pieces,
                request.secret.secret_file.as_deref(),
            );
        }
        Self::read_with(
            request.method,
            request.credential,
            request.label,
            &request.secret,
            vault_id,
        )
    }

    /// The unlock `method` names, its secret read now from `secret`. An
    /// escrow seed comes from the named recovery box, which files it under
    /// the vault `vault_id` reads.
    fn read_with(
        method: UnlockMethod,
        credential: Option<&str>,
        label: Option<&str>,
        secret: &SecretSourceArgs,
        vault_id: impl FnOnce() -> anyhow::Result<[u8; 32]>,
    ) -> anyhow::Result<Self> {
        Ok(match method {
            UnlockMethod::Device => Self::Device,
            UnlockMethod::Password => Self::Password(read_secret(secret, "the vault password")?),
            UnlockMethod::Passkey => {
                let credential = credential
                    .ok_or_else(|| {
                        anyhow::anyhow!("--unlock passkey names the passkey: --credential")
                    })?
                    .to_owned();
                let prf = secret32(&read_secret(secret, "the PRF output")?, "a PRF output")?;
                Self::Passkey { credential, prf }
            }
            UnlockMethod::Escrow => {
                let label = label
                    .ok_or_else(|| {
                        anyhow::anyhow!("--unlock escrow names the escrow wrap: --label")
                    })?
                    .to_owned();
                check_name(&label)?;
                let seed = match recovery_box(secret) {
                    Some((recovery_box, _)) => recovery_box.release(&vault_id()?, &label)?,
                    None => secret32(&read_secret(secret, "the escrow seed")?, "an escrow seed")?,
                };
                let secret = oneiron::world_keys::escrow_recipient(&seed)?;
                Self::Escrow {
                    label,
                    secret,
                    kit_seed: None,
                }
            }
            UnlockMethod::Kit => anyhow::bail!(
                "--unlock kit opens with the kit's pieces (--piece) and the vault id it is bound \
                 to (--vault-id)"
            ),
        })
    }

    pub(super) fn name(&self) -> String {
        match self {
            Self::Device => "device".to_owned(),
            Self::Password(_) => "password".to_owned(),
            Self::Passkey { credential, .. } => format!("passkey:{credential}"),
            Self::Escrow { label, .. } => format!("escrow:{label}"),
            Self::EscrowCapsule { label, .. } => format!("escrow-capsule:{label}"),
            // `--unlock kit`, as the flag names it; a world kit's says its wrap.
            Self::VaultKeyKit { .. } => "kit".to_owned(),
        }
    }

    /// The engine's unlock for this secret; `None` for this device's, which
    /// needs a keystore.
    pub(super) fn engine(&self) -> Option<VaultKeyUnlock<'_>> {
        match self {
            Self::Device => None,
            Self::Password(password) => Some(VaultKeyUnlock::Password(password)),
            Self::Passkey { credential, prf } => Some(VaultKeyUnlock::Passkey { credential, prf }),
            Self::Escrow { label, secret, .. } => Some(VaultKeyUnlock::Escrow { label, secret }),
            Self::EscrowCapsule {
                label,
                capsule,
                secret,
                ..
            } => Some(VaultKeyUnlock::EscrowCapsule {
                label,
                capsule,
                secret,
            }),
            Self::VaultKeyKit {
                vault_id,
                pieces,
                passphrase,
            } => Some(VaultKeyUnlock::Kit {
                vault_id: *vault_id,
                pieces,
                passphrase: passphrase.as_ref(),
            }),
        }
    }

    /// Unlocks an open vault's data key the same way.
    pub(super) fn unlock_live(&self, vault: &oneiron::Vault) -> oneiron::Result<()> {
        match self {
            Self::Device => vault.unlock_vault_key(),
            Self::Password(password) => vault.unlock_vault_key_with_password(password),
            Self::Passkey { credential, prf } => {
                vault.unlock_vault_key_with_passkey(credential, prf)
            }
            Self::Escrow { label, secret, .. } => vault.unlock_vault_key_with_escrow(label, secret),
            // The restored vault need not carry the capsule's wrap.
            Self::EscrowCapsule {
                label,
                capsule,
                secret,
                ..
            } => vault.unlock_vault_key_with_escrow_capsule(label, capsule, secret),
            // Nor any wrap at all: the kit rebuilds the key itself.
            Self::VaultKeyKit {
                vault_id,
                pieces,
                passphrase,
            } => vault.unlock_vault_key_with_kit(vault_id, pieces, passphrase.as_ref()),
        }
    }
}
