//! `oneiron recovery-kit issue` and `issue-vault-key`: a kit's pieces, each
//! stored piece's recovery code written to an owner-only file in `--out`, and
//! the kit's public facts printed. A piece, a code, the passphrase or a key
//! never reaches the command line, a log or the JSON printed.

use std::path::{Path, PathBuf};

use oneiron::recovery::{
    CodeKeeping, KitCoverage, KitIssue, KitMachine, KitPassphrase, KitPiece, KitSecretKind,
    PassphraseCost, PieceHome,
};
use oneiron::world_keys::{
    IssuedVaultKeyKit, IssuedWorldKit, KitPasskey, StoredCost, VaultKeyStatus,
};
use serde::Serialize;

use super::super::vault_key::{
    KeyNeed, UnlockRequest, open_with_unlock_for_secret, read_secret_file,
};
use super::{INSTEAD, emit, read_passphrase};
use crate::cli::RecoveryKitIssueArgs;
use crate::commands::credential_file;
use crate::config::resolve_serve_config;
use crate::owner::host_owner;
use crate::owner::recovery_kit::kit_id;
use crate::owner::vault_key::{RecoveryPresetSet, hex, secret32};

/// One stored piece's file.
#[derive(Serialize)]
struct PieceFile {
    x: u8,
    file: PathBuf,
}

/// What issuing a kit did. The pieces are in their files, never here.
#[derive(Serialize)]
struct Issued {
    /// The vault id the kit is bound to: a restore on a new host names it.
    vault_id: String,
    kit_id: String,
    /// The root's fingerprint, to check on another machine.
    root: String,
    homes: [PieceHome; 3],
    coverage: KitCoverage,
    pieces: Vec<PieceFile>,
}

pub(super) fn issue(args: RecoveryKitIssueArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.passkey_credential.is_none() && !args.any_two_pieces,
        "a passkey is a piece of the data-key kit only, and \"any 2 pieces\" turns on with one: \
         recovery-kit issue-vault-key"
    );
    let unlock = UnlockRequest::of(&args.unlock);
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_with_unlock_for_secret(
        &config,
        &unlock,
        KeyNeed::Open,
        INSTEAD,
        passphrase_reads_stdin(&args),
        "the kit passphrase",
        "--secret-file",
    )?;
    let (homes, passphrase) = issue_inputs(&args)?;
    refuse_this_machine_without_keystore(&vault, &homes)?;
    let owner = host_owner(&vault)?;
    let vault_id = vault
        .world_kit_status()?
        .vault_id
        .ok_or_else(|| anyhow::anyhow!("the vault has no authority genesis yet"))?;
    let IssuedWorldKit {
        vault_id,
        root,
        manifest,
        pieces,
    } = vault.issue_world_kit(
        &owner,
        &KitIssue {
            vault_id,
            homes,
            passphrase: passphrase.as_ref(),
            cost: PassphraseCost::DEFAULT,
            only_machine: false,
        },
    )?;
    let files = write_pieces(&args.out, &pieces)?;
    emit(&Issued {
        vault_id: hex(&vault_id),
        kit_id: kit_id(manifest.kit_id),
        root: hex(&root.0),
        homes: manifest.homes,
        coverage: manifest.coverage,
        pieces: files,
    })
}

/// What issuing a data-key kit did: the kit's manifest, the vault id it is
/// bound to, and the files its pieces are in. Never a piece, a code or the
/// key.
#[derive(Serialize)]
struct IssuedVaultKey {
    /// The vault id the data key and the kit are bound to: a restore names it.
    vault_id: String,
    kit_id: String,
    kind: KitSecretKind,
    homes: [PieceHome; 3],
    /// The passphrase piece's Argon2id cost, when a home is the passphrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase_cost: Option<StoredCost>,
    coverage: KitCoverage,
    pieces: Vec<PieceFile>,
    /// Whether the kit's public facts went into the kit inventory (`recovery-kit
    /// status`). Its pieces open the key either way.
    listed: bool,
    /// With `--any-two-pieces`: what turning the switch on did.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_preset: Option<RecoveryPresetSet>,
}

/// `recovery-kit issue-vault-key` (FIX 4532): a kit of the vault data key on
/// a stopped vault, the homes the owner names at today's passphrase cost,
/// each stored piece's recovery code written to its owner-only file as
/// `issue` writes a world kit's. A locked key is unlocked as `confirm`
/// unlocks it (FIX 11386, 2201): this install's keystore by default, or the
/// unlock `--unlock` names. A vault with no key gets none minted. The world
/// kit, its escrow wrap and every other wrap stay as they are, except with
/// `--any-two-pieces`, which turns that switch on: the pieces' files are
/// written and synced first, and only then does the vault drop its sheet,
/// password and passkey wraps.
pub(super) fn issue_vault_key(args: RecoveryKitIssueArgs) -> anyhow::Result<()> {
    let unlock = UnlockRequest::of(&args.unlock);
    let config = resolve_serve_config(&args.serve)?;
    let vault = open_with_unlock_for_secret(
        &config,
        &unlock,
        KeyNeed::HeldIfAny,
        INSTEAD,
        passphrase_reads_stdin(&args),
        "the kit passphrase",
        "--secret-file",
    )?;
    let (homes, passphrase) = issue_inputs(&args)?;
    refuse_this_machine_without_keystore(&vault, &homes)?;
    let owner = host_owner(&vault)?;
    if vault.vault_key_status()? == VaultKeyStatus::NoKey {
        anyhow::bail!("the vault has no data key yet: there is nothing to put in a kit")
    }
    let prf = args
        .passkey_prf_file
        .as_deref()
        .map(|file| {
            secret32(
                &read_secret_file(file, "the passkey's PRF output")?,
                "a PRF output",
            )
        })
        .transpose()?;
    let passkey = match (args.passkey_credential.as_deref(), prf.as_ref()) {
        (Some(credential), Some(prf)) => Some(KitPasskey { credential, prf }),
        _ => None,
    };
    let issue = KitIssue {
        vault_id: vault.vault_key_vault_id(),
        homes,
        passphrase: passphrase.as_ref(),
        cost: PassphraseCost::DEFAULT,
        only_machine: false,
    };
    let (kit, recovery_preset, files) = if args.any_two_pieces {
        // The pieces are written and synced before the write that removes
        // the old wraps (review of #7781): a failed write leaves the vault
        // as it was, and the files it made are removed.
        let mut files = Vec::new();
        let switched = vault.set_recovery_preset_any_two_as(&owner, &issue, passkey, |pieces| {
            files = write_pieces(&args.out, pieces)
                .map_err(|error| oneiron::Error::Io(std::io::Error::other(error.to_string())))?;
            Ok(())
        });
        let switched = switched.map_err(|error| {
            if files.is_empty() {
                anyhow::Error::from(error)
            } else {
                anyhow::anyhow!(
                    "{error}; the kit's pieces in {} still rebuild the vault key",
                    args.out.display()
                )
            }
        })?;
        let (set, _) = RecoveryPresetSet::of(&vault.vault_key_vault_id(), switched.change);
        (switched.kit, Some(set), files)
    } else {
        let kit = vault.issue_vault_key_recovery_kit_with_passkey_as(&owner, &issue, passkey)?;
        let files = write_pieces(&args.out, &kit.pieces)?;
        (kit, None, files)
    };
    let IssuedVaultKeyKit {
        vault_id,
        manifest,
        listed,
        ..
    } = kit;
    emit(&IssuedVaultKey {
        vault_id: hex(&vault_id),
        kit_id: kit_id(manifest.kit_id),
        kind: manifest.kind,
        homes: manifest.homes,
        passphrase_cost: manifest.cost.map(|cost| StoredCost {
            memory_mib: cost.memory_mib(),
            passes: cost.passes(),
        }),
        coverage: manifest.coverage,
        pieces: files,
        listed,
        recovery_preset,
    })
}

/// Whether issuing with `args` reads the kit passphrase from stdin: a
/// `passphrase` home with no `--secret-file`.
fn passphrase_reads_stdin(args: &RecoveryKitIssueArgs) -> bool {
    args.homes.iter().any(|home| home == "passphrase") && args.secret_file.is_none()
}

/// A kit issue's three homes and, for a `passphrase` home, the passphrase,
/// from its flags; `--out` is checked to hold no piece file yet, and made
/// owner-only.
fn issue_inputs(
    args: &RecoveryKitIssueArgs,
) -> anyhow::Result<([PieceHome; 3], Option<KitPassphrase>)> {
    let homes = args
        .homes
        .iter()
        .map(|home| parse_home(home))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let homes: [PieceHome; 3] = homes
        .try_into()
        .map_err(|_| anyhow::anyhow!("a kit has three homes: give --home three times"))?;
    let passphrase = if homes.contains(&PieceHome::Passphrase) {
        Some(read_passphrase(args.secret_file.as_deref())?)
    } else {
        anyhow::ensure!(
            args.secret_file.is_none(),
            "--secret-file is the passphrase of a `passphrase` home, and no home is one"
        );
        None
    };
    for (x, home) in (1u8..).zip(&homes) {
        let file = piece_file(&args.out, x);
        anyhow::ensure!(
            *home == PieceHome::Passphrase || !file.exists(),
            "{} already exists; name an empty --out",
            file.display()
        );
    }
    create_owner_dir(&args.out)?;
    Ok((homes, passphrase))
}

/// Writes each stored piece's recovery code to its new owner-only file in
/// `out`, synced with its directory entry ([`credential_file::write_new`]),
/// and names the files. On a failure the files this call made are removed,
/// and no other: a path it did not create is never touched (review of #7781).
fn write_pieces(out: &Path, pieces: &[KitPiece]) -> anyhow::Result<Vec<PieceFile>> {
    let mut files: Vec<PieceFile> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let file = piece_file(out, piece.x());
        let code = piece.recovery_code();
        if let Err(error) = credential_file::write_new(&file, code.reveal().as_bytes()) {
            for made in &files {
                let _ = std::fs::remove_file(&made.file);
            }
            return Err(error);
        }
        files.push(PieceFile { x: piece.x(), file });
    }
    Ok(files)
}

fn piece_file(out: &Path, x: u8) -> PathBuf {
    out.join(format!("piece-{x}.txt"))
}

/// One `--home`, as the flag's help spells it.
fn parse_home(text: &str) -> anyhow::Result<PieceHome> {
    let machine = |id: &str| {
        oneiron::EntityId::from_hex(id)
            .map_err(|_| anyhow::anyhow!("--home {text}: a machine is its 32-hex id"))
    };
    Ok(match text.split_once(':') {
        Some(("file-on", id)) => {
            PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::Other(machine(id)?)))
        }
        Some(("other-machine", id)) => PieceHome::OtherMachine(machine(id)?),
        _ => match text {
            "paper" => PieceHome::RecoveryCode(CodeKeeping::Paper),
            "password-manager" => PieceHome::RecoveryCode(CodeKeeping::PasswordManager),
            "own-email" => PieceHome::RecoveryCode(CodeKeeping::OwnEmail),
            "file-elsewhere" => PieceHome::RecoveryCode(CodeKeeping::FileElsewhere),
            "file-here" => PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::ThisMachine)),
            "trusted-person" => PieceHome::TrustedPerson,
            "security-key" => PieceHome::SecurityKey,
            "passkey" => PieceHome::Passkey,
            "passphrase" => PieceHome::Passphrase,
            "this-machine" => PieceHome::ThisMachine,
            _ => anyhow::bail!("--home {text} is not a kit home"),
        },
    })
}

/// A `this-machine` home's piece stays in this install's keystore (FIX 2063):
/// refused as before while the host installed none.
fn refuse_this_machine_without_keystore(
    vault: &oneiron::Vault,
    homes: &[PieceHome; 3],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !homes.contains(&PieceHome::ThisMachine) || vault.device_keystore_assurance().is_some(),
        "--home this-machine waits for device-piece custody; pick another home"
    );
    Ok(())
}

/// `dir` and its parents; a directory it makes is owner-only, and its entry
/// is synced into its parent, so the piece files written in it last a crash
/// (review of #7781).
fn create_owner_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    let made: Vec<PathBuf> = dir
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
        .map(Path::to_path_buf)
        .collect();
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
    #[cfg(unix)]
    for made_dir in &made {
        let parent = made_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .and_then(|parent| parent.sync_all())
            .map_err(|error| anyhow::anyhow!("sync {}: {error}", parent.display()))?;
    }
    Ok(())
}
