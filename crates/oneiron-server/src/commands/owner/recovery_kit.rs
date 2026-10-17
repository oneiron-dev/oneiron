//! `oneiron recovery-kit`: the world kit's ceremony on a stopped vault
//! (OF-173), and the kit unlock `oneiron restore --unlock kit` and
//! `oneiron vault-key add-device --unlock kit` take.
//!
//! Issue writes each stored piece's recovery code to an owner-only file, and
//! nothing goes live until confirm reads two of them back, or one and the
//! passphrase. A piece, a code or the passphrase never reaches the command
//! line, a log or the JSON printed. The `this-machine` home waits for
//! device-piece custody: no keystore slot holds a piece yet.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::authority::EditOrigin;
use oneiron::recovery::{
    CodeKeeping, KitCoverage, KitError, KitIssue, KitMachine, KitPassphrase, KitPiece,
    KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::sync::WindowManager;
use oneiron::sync::bridge::Materializer;
use oneiron::world_keys::{
    IssuedWorldKit, KitConfirmation, RecoveryRootId, RecoveryRootSeed, SealedKeyPads,
    SealedVaultBundle, VaultKeyStatus, WORLD_KIT_ESCROW, Withheld, WorldKeyId, WorldKitRestore,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::vault_key::{HostUnlock, read_secret};
use super::{emit, open_stopped_vault};
use crate::cli::{
    KitPieceArgs, RecoveryKitCommand, RecoveryKitConfirmArgs, RecoveryKitIssueArgs,
    RecoveryKitRestoreArgs, RestoreArgs, SecretSourceArgs,
};
use crate::commands::credential_file;
use crate::config::resolve_serve_config;
use crate::owner::local_owner;
use crate::owner::recovery_kit::{self as view, kit_id};
use crate::owner::vault_key::{WrapView, hex, secret32};

/// The most a piece file is: an export is 89 bytes, a code 99 characters.
const PIECE_LIMIT: usize = 1024;

/// The window manager's user for a bundle restore, as the server names its own.
const RESTORE_USER_ID: &str = "server";

/// What to do instead while a server holds the vault.
const INSTEAD: &str = "or read the kits at `/v1/owner/recovery-kit`";

pub fn recovery_kit(command: RecoveryKitCommand) -> anyhow::Result<()> {
    match command {
        RecoveryKitCommand::Status(args) => {
            let vault = open(&args.serve)?;
            emit(&view::report(&vault)?)
        }
        RecoveryKitCommand::Issue(args) => issue(*args),
        RecoveryKitCommand::Confirm(args) => confirm(*args),
        RecoveryKitCommand::Restore(args) => restore(*args),
    }
}

fn open(serve: &crate::config::ServeArgs) -> anyhow::Result<oneiron::Vault> {
    let config = resolve_serve_config(serve)?;
    open_stopped_vault(&config, INSTEAD)
}

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

fn issue(args: RecoveryKitIssueArgs) -> anyhow::Result<()> {
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
    let mut files = Vec::with_capacity(pieces.len());
    for piece in &pieces {
        let file = piece_file(&args.out, piece.x());
        let mut out = credential_file::create(&file)?;
        let line = Zeroizing::new(format!("{}\n", piece.recovery_code().reveal()));
        out.write_all(line.as_bytes())?;
        out.sync_all()?;
        files.push(PieceFile { x: piece.x(), file });
    }
    emit(&Issued {
        vault_id: hex(&vault_id),
        kit_id: kit_id(manifest.kit_id),
        root: hex(&root.0),
        homes: manifest.homes,
        coverage: manifest.coverage,
        pieces: files,
    })
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

/// The kit passphrase, from the owner-only file or else stdin.
fn read_passphrase(secret_file: Option<&Path>) -> anyhow::Result<KitPassphrase> {
    let source = SecretSourceArgs {
        secret_file: secret_file.map(Path::to_path_buf),
        ..SecretSourceArgs::default()
    };
    let bytes = read_secret(&source, "the kit passphrase")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("the kit passphrase is UTF-8 text"))?;
    Ok(KitPassphrase::new(text)?)
}

/// The pieces in `files`, and the passphrase: from `secret_file` when one is
/// named, else from stdin when only one piece is given.
fn read_kit(
    files: &[PathBuf],
    secret_file: Option<&Path>,
) -> anyhow::Result<(Vec<KitPiece>, Option<KitPassphrase>)> {
    let pieces = files
        .iter()
        .map(|file| read_piece(file))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let passphrase = if secret_file.is_some() || pieces.len() == 1 {
        Some(read_passphrase(secret_file)?)
    } else {
        None
    };
    Ok((pieces, passphrase))
}

fn read_kit_args(args: &KitPieceArgs) -> anyhow::Result<(Vec<KitPiece>, Option<KitPassphrase>)> {
    read_kit(&args.pieces, args.secret_file.as_deref())
}

/// One piece from an owner-only file: a piece export, or a recovery code as
/// text.
fn read_piece(path: &Path) -> anyhow::Result<KitPiece> {
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    credential_file::admit(path, &file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(PIECE_LIMIT + 1));
    file.take(PIECE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= PIECE_LIMIT,
        "{} is not a kit piece",
        path.display()
    );
    KitPiece::import(&bytes)
        .or_else(|_| {
            std::str::from_utf8(&bytes)
                .map_err(|_| KitError::InvalidPiece)
                .and_then(KitPiece::from_recovery_code)
        })
        .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
}

/// One world key, by its world and generation.
#[derive(Serialize)]
struct KeyView {
    world: String,
    generation: u64,
}

impl From<&WorldKeyId> for KeyView {
    fn from(key: &WorldKeyId) -> Self {
        Self {
            world: key.world.to_hex(),
            generation: key.generation,
        }
    }
}

/// A key a door gave no new wrap, and why.
#[derive(Serialize)]
struct WithheldView {
    #[serde(flatten)]
    key: KeyView,
    reason: &'static str,
}

fn withheld(list: &[(WorldKeyId, Withheld)]) -> Vec<WithheldView> {
    list.iter()
        .map(|(key, why)| WithheldView {
            key: KeyView::from(key),
            reason: match why {
                Withheld::NotMine => "not_mine",
                Withheld::NotReadable => "not_readable",
                Withheld::NotLive => "not_live",
                Withheld::NotPrivate => "not_private",
                Withheld::Conflicted => "conflicted",
                Withheld::Unopenable => "unopenable",
                Withheld::FrontierWide => "frontier_wide",
                Withheld::SignerRemoved => "signer_removed",
            },
        })
        .collect()
}

/// What confirming a kit did.
#[derive(Serialize)]
struct Confirmed {
    kit_id: String,
    root: String,
    rewrapped: Vec<KeyView>,
    withheld: Vec<WithheldView>,
    /// Worlds whose settings read differently under the new root.
    narrowed: Vec<String>,
    /// The kits this one replaced. Their pieces still rebuild their own roots.
    replaced: Vec<String>,
    /// The vault key's `world-kit` escrow wrap to this kit's root; none when
    /// the vault has no key yet.
    vault_key_wrap: Option<WrapView>,
}

fn confirm(args: RecoveryKitConfirmArgs) -> anyhow::Result<()> {
    let (pieces, passphrase) = read_kit_args(&args.kit)?;
    let carry = args
        .carry
        .iter()
        .map(|id| {
            oneiron::EntityId::from_hex(id)
                .map_err(|_| anyhow::anyhow!("--carry {id}: a machine is its 32-hex id"))
        })
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    let vault = open(&args.serve)?;
    let owner = local_owner(&vault)?;
    // Confirm replaces the vault key's world-kit wrap, so a vault with a key
    // needs it held: this device's wrap opens it, or nothing is confirmed. A
    // vault with no key gets no wrap.
    if vault.vault_key_status()? == VaultKeyStatus::Locked {
        vault.unlock_vault_key().map_err(|error| {
            anyhow::anyhow!(
                "the vault key stays locked, and confirm must replace its world-kit wrap: {error}"
            )
        })?;
    }
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let confirmed = vault.confirm_world_kit(
        &owner,
        EditOrigin::ThisMachine,
        &pieces,
        passphrase.as_ref(),
        &carry,
    )?;
    let vault_id = vault.vault_key_vault_id();
    let keys = &confirmed.activated.keys;
    emit(&Confirmed {
        kit_id: kit_id(confirmed.kit),
        root: hex(&confirmed.activated.root.0),
        rewrapped: keys.rewrapped.iter().map(KeyView::from).collect(),
        withheld: withheld(&keys.withheld),
        narrowed: keys
            .narrowed
            .iter()
            .map(|narrowed| narrowed.world.to_hex())
            .collect(),
        replaced: confirmed.replaced.iter().copied().map(kit_id).collect(),
        vault_key_wrap: confirmed.escrow.map(|info| WrapView::of(&vault_id, info)),
    })
}

/// What a kit restore did with each key wrapped to the kit's root.
#[derive(Serialize)]
struct Restored {
    kit_id: String,
    root: String,
    /// Opened and readable on this machine.
    usable: Vec<KeyView>,
    /// Kept on another machine: recoverable there, not usable here.
    needs_rehome: Vec<KeyView>,
    withheld: Vec<WithheldView>,
    /// Worlds whose settings read differently under the kit's root.
    narrowed: Vec<String>,
    /// The kit's passphrase cost is below today's default: issue a new kit.
    reissue_advised: bool,
}

impl From<WorldKitRestore> for Restored {
    fn from(restored: WorldKitRestore) -> Self {
        let keys = restored.keys;
        Self {
            kit_id: kit_id(restored.kit),
            root: hex(&restored.root.0),
            usable: keys.usable.iter().map(KeyView::from).collect(),
            needs_rehome: keys.needs_rehome.iter().map(KeyView::from).collect(),
            withheld: withheld(&keys.withheld),
            narrowed: keys
                .narrowed
                .iter()
                .map(|narrowed| narrowed.world.to_hex())
                .collect(),
            reissue_advised: restored.reissue_advised,
        }
    }
}

fn restore(args: RecoveryKitRestoreArgs) -> anyhow::Result<()> {
    let confirm = match &args.fingerprint {
        Some(fingerprint) => {
            let root = secret32(fingerprint.as_bytes(), "a root fingerprint")?;
            Some(KitConfirmation::Fingerprint(RecoveryRootId(*root)))
        }
        None => args.confirm_unverified.then_some(KitConfirmation::Owner),
    };
    if let Some(bundle) = &args.sealed_bundle {
        return restore_from_bundle(&args, bundle, confirm);
    }
    let (pieces, passphrase) = read_kit_args(&args.kit)?;
    let vault = open(&args.serve)?;
    let owner = local_owner(&vault)?;
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let restored = vault.restore_world_kit(
        &owner,
        EditOrigin::ThisMachine,
        &pieces,
        passphrase.as_ref(),
        confirm,
    )?;
    emit(&Restored::from(restored))
}

/// What a kit restore from the sealed cloud bundle did: the keys, as a kit
/// restore reports them, and what the bundle brought in.
#[derive(Serialize)]
struct BundleRestored {
    #[serde(flatten)]
    keys: Restored,
    /// Signed authority entries the bundle's base section carried.
    authority: usize,
    /// Base windows installed here.
    windows: usize,
    /// Base windows that did not install.
    windows_skipped: usize,
    /// Pads stored from the pad object.
    pads: usize,
    /// World sections the kit opened.
    sections: usize,
    /// Their windows merged and materialized here.
    merged: usize,
    /// Their windows that brought nothing new.
    unchanged: usize,
    /// Sections or windows not taken: a world this machine may not read
    /// waits for its re-home.
    skipped: usize,
}

/// `recovery-kit restore --sealed-bundle`: the kit alone restores the vault on
/// an install that holds no copy of it yet, from the sealed cloud bundle and
/// its pad object in owner-given files. The pieces rebuild the kit's seed for
/// the vault `--vault-id` names, never one read from the bundle.
fn restore_from_bundle(
    args: &RecoveryKitRestoreArgs,
    bundle: &Path,
    confirm: Option<KitConfirmation>,
) -> anyhow::Result<()> {
    let vault_id = args.vault_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--sealed-bundle names the vault the kit is bound to: --vault-id")
    })?;
    let vault_id = secret32(vault_id.as_bytes(), "a vault id")?;
    let pads = args.sealed_pads.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--sealed-bundle reads the bundle's pad object: --sealed-pads")
    })?;
    let bundle = SealedVaultBundle::from_bytes(&read_sealed(bundle)?)?;
    let pads = SealedKeyPads::from_bytes(&read_sealed(pads)?)?;
    let (pieces, passphrase) = read_kit_args(&args.kit)?;
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let kit = pieces
        .first()
        .map(|piece| piece.kit_id())
        .ok_or_else(|| anyhow::anyhow!("a kit restore reads the kit's pieces: --piece"))?;
    let secret = restore_kit(
        *vault_id,
        KitSecretKind::RecoveryRoot,
        &pieces,
        passphrase.as_ref(),
    )
    .map_err(|error| anyhow::anyhow!("the kit does not open: {error}"))?;
    let reissue_advised = secret.reissue_advised();
    let seed = RecoveryRootSeed::from_restored_kit(secret)?;
    let root = seed.public(&vault_id)?.id;
    let config = resolve_serve_config(&args.serve)?;
    let vault = Arc::new(open_stopped_vault(&config, INSTEAD)?);
    let owner = local_owner(&vault)?;
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::with_lease_vault_id(config.lease_vault_id)),
        RESTORE_USER_ID,
    ));
    let restored = manager
        .restore_sealed_bundle_with_kit(&owner, &vault_id, &bundle, &pads, &seed, confirm)?;
    let take = restored.take;
    emit(&BundleRestored {
        keys: Restored::from(WorldKitRestore {
            kit,
            root,
            keys: restored.keys,
            reissue_advised,
        }),
        authority: restored.authority,
        windows: restored.windows,
        windows_skipped: restored.windows_skipped,
        pads: restored.pads,
        sections: take.sections,
        merged: take.merged,
        unchanged: take.unchanged,
        skipped: take.skipped,
    })
}

/// A sealed bundle or pad object from the owner's file, read whole.
fn read_sealed(path: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))
}

/// `oneiron restore --unlock kit`: the pieces rebuild the kit's seed, and its
/// root's recovery secret opens the backup's `world-kit` escrow wrap. A kit
/// that does not open the wrap opens nothing.
pub(super) fn kit_unlock(args: &RestoreArgs) -> anyhow::Result<HostUnlock> {
    kit_unlock_with(
        args.vault_id.as_deref(),
        &args.pieces,
        args.secret.secret_file.as_deref(),
    )
}

/// The world kit's unlock from its pieces, the passphrase read from
/// `secret_file` or stdin, for the vault `vault_id` names: the id the kit is
/// bound to, which the caller is given and never reads from a mirror.
/// `oneiron restore --unlock kit` and `oneiron vault-key add-device --unlock
/// kit` both open the `world-kit` escrow wrap with it.
pub(super) fn kit_unlock_with(
    vault_id: Option<&str>,
    files: &[PathBuf],
    secret_file: Option<&Path>,
) -> anyhow::Result<HostUnlock> {
    let vault_id = vault_id.ok_or_else(|| {
        anyhow::anyhow!("--unlock kit names the vault the kit is bound to: --vault-id")
    })?;
    let vault_id = secret32(vault_id.as_bytes(), "a vault id")?;
    anyhow::ensure!(
        !files.is_empty(),
        "--unlock kit reads the kit's pieces: --piece"
    );
    let (pieces, passphrase) = read_kit(files, secret_file)?;
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let secret = restore_kit(
        *vault_id,
        KitSecretKind::RecoveryRoot,
        &pieces,
        passphrase.as_ref(),
    )
    .map_err(|error| anyhow::anyhow!("the kit does not open: {error}"))?;
    let seed = RecoveryRootSeed::from_restored_kit(secret)?;
    Ok(HostUnlock::Escrow {
        label: WORLD_KIT_ESCROW.to_owned(),
        secret: seed.recovery_secret()?,
    })
}
