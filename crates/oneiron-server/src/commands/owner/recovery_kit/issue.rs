//! `oneiron recovery-kit issue` and `issue-vault-key`: a kit's pieces, each
//! stored piece's recovery code written to an owner-only file in `--out`, and
//! the kit's public facts printed. A piece, a code, the passphrase or a key
//! never reaches the command line, a log or the JSON printed.

use std::io::Write;
use std::path::{Path, PathBuf};

use oneiron::recovery::{
    CodeKeeping, KitCoverage, KitIssue, KitMachine, KitPassphrase, KitPiece, KitSecretKind,
    PassphraseCost, PieceHome,
};
use oneiron::world_keys::{IssuedVaultKeyKit, IssuedWorldKit, StoredCost, VaultKeyStatus};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{emit, open, read_passphrase};
use crate::cli::RecoveryKitIssueArgs;
use crate::commands::credential_file;
use crate::owner::local_owner;
use crate::owner::recovery_kit::kit_id;
use crate::owner::vault_key::hex;

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
    let (homes, passphrase) = issue_inputs(&args)?;
    let vault = open(&args.serve)?;
    let owner = local_owner(&vault)?;
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
}

/// `recovery-kit issue-vault-key` (FIX 4532): a kit of the vault data key on
/// a stopped vault, the homes the owner names at today's passphrase cost,
/// each stored piece's recovery code written to its owner-only file as
/// `issue` writes a world kit's. A locked key is unlocked with this machine's
/// wrap; a vault with no key gets none minted. The world kit, its escrow wrap
/// and every other wrap stay as they are.
pub(super) fn issue_vault_key(args: RecoveryKitIssueArgs) -> anyhow::Result<()> {
    let (homes, passphrase) = issue_inputs(&args)?;
    let vault = open(&args.serve)?;
    let owner = local_owner(&vault)?;
    match vault.vault_key_status()? {
        VaultKeyStatus::NoKey => {
            anyhow::bail!("the vault has no data key yet: there is nothing to put in a kit")
        }
        VaultKeyStatus::Locked => vault.unlock_vault_key().map_err(|error| {
            anyhow::anyhow!("the vault key stays locked, so no kit of it is issued: {error}")
        })?,
        VaultKeyStatus::Unlocked => {}
    }
    let IssuedVaultKeyKit {
        vault_id,
        manifest,
        pieces,
        listed,
    } = vault.issue_vault_key_recovery_kit_as(
        &owner,
        &KitIssue {
            vault_id: vault.vault_key_vault_id(),
            homes,
            passphrase: passphrase.as_ref(),
            cost: PassphraseCost::DEFAULT,
            only_machine: false,
        },
    )?;
    let files = write_pieces(&args.out, &pieces)?;
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
    })
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

/// Writes each stored piece's recovery code to its owner-only file in `out`,
/// and names the files.
fn write_pieces(out: &Path, pieces: &[KitPiece]) -> anyhow::Result<Vec<PieceFile>> {
    let mut files = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let file = piece_file(out, piece.x());
        let mut written = credential_file::create(&file)?;
        let line = Zeroizing::new(format!("{}\n", piece.recovery_code().reveal()));
        written.write_all(line.as_bytes())?;
        written.sync_all()?;
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
            "passphrase" => PieceHome::Passphrase,
            "this-machine" => anyhow::bail!(
                "--home this-machine waits for device-piece custody; pick another home"
            ),
            _ => anyhow::bail!("--home {text} is not a kit home"),
        },
    })
}

/// `dir` and its parents; a directory it makes is owner-only.
fn create_owner_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))
}
