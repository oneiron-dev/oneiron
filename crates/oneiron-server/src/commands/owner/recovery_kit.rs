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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::authority::EditOrigin;
use oneiron::error::SecretError;
use oneiron::recovery::{KitError, KitPassphrase, KitPiece, KitSecretKind, restore_kit};
use oneiron::sync::WindowManager;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::fetch_sealed_bundle_with_kit;
use oneiron::sync::residence::{RecoveryCheckpointTrust, sealed_generation_from_hex};
use oneiron::world_keys::{
    KitConfirmation, RecoveryRootId, RecoveryRootSeed, SealedKeyPads, SealedVaultBundle,
    VaultKeyStatus, WORLD_KIT_ESCROW, Withheld, WorldKeyId, WorldKitRestore,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::vault_key::{HostUnlock, read_secret};
use super::{emit, open_stopped_vault};
use crate::cli::{
    KitPieceArgs, RecoveryKitCommand, RecoveryKitConfirmArgs, RecoveryKitRestoreArgs, RestoreArgs,
    SecretSourceArgs,
};
use crate::commands::credential_file;
use crate::config::resolve_serve_config;
use crate::owner::local_owner;
use crate::owner::recovery_kit::{self as view, kit_id};
use crate::owner::vault_key::{WrapView, hex, secret32};

mod issue;

/// The most a piece file is: an export is 89 bytes, a code 99 characters.
const PIECE_LIMIT: usize = 1024;

/// The window manager's user for a bundle restore, as the server names its own.
const RESTORE_USER_ID: &str = "server";

/// What to do instead while a server holds the vault.
const INSTEAD: &str = "or read the kits at `/v1/owner/recovery-kit`";

/// What a sealed restore does with the checkpoint image a bundle carries
/// when the owner fixed no pin for it.
enum UnfixedCheckpoint {
    /// Adopt nothing and restore as before: the tail imports alone, whole
    /// from a hydrated publisher, and one that stands on the image refuses
    /// with the rerun that adopts it.
    RestoreWithoutAdopting,
}

/// A carried pin is never taken on the bundle's word (FIX 5541, CALLS:
/// UNFIXED_CHECKPOINT; a refusal would stop a hydrated publisher's restore
/// that works without the image).
const UNFIXED_CHECKPOINT: UnfixedCheckpoint = UnfixedCheckpoint::RestoreWithoutAdopting;

pub fn recovery_kit(command: RecoveryKitCommand) -> anyhow::Result<()> {
    match command {
        RecoveryKitCommand::Status(args) => {
            let vault = open(&args.serve)?;
            emit(&view::report(&vault)?)
        }
        RecoveryKitCommand::Issue(args) => issue::issue(*args),
        RecoveryKitCommand::IssueVaultKey(args) => issue::issue_vault_key(*args),
        RecoveryKitCommand::Confirm(args) => confirm(*args),
        RecoveryKitCommand::Restore(args) => restore(*args),
    }
}

fn open(serve: &crate::config::ServeArgs) -> anyhow::Result<oneiron::Vault> {
    let config = resolve_serve_config(serve)?;
    open_stopped_vault(&config, INSTEAD)
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
        // The go-ahead names the root the refusal showed (FIX 4533).
        None => args
            .confirm_root
            .map(|root| KitConfirmation::Owner(RecoveryRootId(root))),
    };
    if args.sealed_bundle.is_some() || args.sealed_home.is_some() {
        return restore_from_bundle(&args, confirm);
    }
    let (pieces, passphrase) = read_kit_args(&args.kit)?;
    let vault = open(&args.serve)?;
    let owner = local_owner(&vault)?;
    let pieces: Vec<&KitPiece> = pieces.iter().collect();
    let restored = vault
        .restore_world_kit(
            &owner,
            EditOrigin::ThisMachine,
            &pieces,
            passphrase.as_ref(),
            confirm,
        )
        .map_err(show_root)?;
    emit(&Restored::from(restored))
}

/// A kit seed refused for want of a confirmation, worded with the root its
/// pieces rebuild, a public id (FIX 4533): the owner checks it on one of his
/// machines and gives it back with `--fingerprint`, or goes ahead with
/// `--confirm-root`, which holds for that root alone. A go-ahead given for
/// another root is refused with this one, so he confirms again in one step.
fn show_root(error: oneiron::Error) -> anyhow::Error {
    match &error {
        oneiron::Error::Secret(SecretError::UnverifiedKitRestore { root, .. }) => {
            let root = hex(root);
            anyhow::anyhow!(
                "{error}: these pieces rebuild root {root}. Give --fingerprint with the root one \
                 of your machines pins, or go ahead with --confirm-root {root}"
            )
        }
        oneiron::Error::Secret(SecretError::KitConfirmationStale { root, confirmed }) => {
            let (root, confirmed) = (hex(root), hex(confirmed));
            anyhow::anyhow!(
                "--confirm-root {confirmed} is not this kit's root: these pieces rebuild root \
                 {root}. To go ahead with this kit, rerun with --confirm-root {root}"
            )
        }
        _ => error.into(),
    }
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

/// `recovery-kit restore --sealed-bundle` or `--sealed-home`: the kit alone
/// restores the vault on an install that holds no copy of it yet, from the
/// sealed cloud bundle and its pad object, in owner-given files or fetched from
/// the home. The pieces rebuild the kit's seed for the vault `--vault-id`
/// names, never one read from the bundle, before the home is asked.
fn restore_from_bundle(
    args: &RecoveryKitRestoreArgs,
    confirm: Option<KitConfirmation>,
) -> anyhow::Result<()> {
    let vault_id = args.vault_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!("a sealed bundle restore names the vault the kit is bound to: --vault-id")
    })?;
    let vault_id = secret32(vault_id.as_bytes(), "a vault id")?;
    let files = match &args.sealed_bundle {
        Some(bundle) => {
            let pads = args.sealed_pads.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--sealed-bundle reads the bundle's pad object: --sealed-pads")
            })?;
            Some((
                SealedVaultBundle::from_bytes(&read_sealed(bundle)?)?,
                SealedKeyPads::from_bytes(&read_sealed(pads)?)?,
            ))
        }
        None => None,
    };
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
    let (bundle, pads) = match files {
        Some(objects) => objects,
        None => fetch_from_home(args, &vault_id, &seed, root, confirm)?,
    };
    let config = resolve_serve_config(&args.serve)?;
    let vault = Arc::new(open_stopped_vault(&config, INSTEAD)?);
    let owner = local_owner(&vault)?;
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::with_lease_vault_id(config.lease_vault_id)),
        RESTORE_USER_ID,
    ));
    // A checkpoint image the base carries is adopted only under a pin the
    // owner fixed (FIX 5541).
    let carried = manager
        .sealed_bundle_checkpoint_pin(&vault_id, &bundle, &seed)?
        .map(|pin| pin.digest())
        .transpose()?;
    let trust = match carried {
        Some(digest) => checkpoint_trust(args, digest)?,
        None => {
            if args.checkpoint_pin.is_some() || args.confirm_checkpoint.is_some() {
                eprintln!("the sealed bundle carries no checkpoint image: none is adopted");
            }
            None
        }
    };
    let restored = match (carried, trust) {
        (_, Some(trust)) => manager
            .restore_sealed_bundle_with_kit_checkpoint(
                &owner, &vault_id, &bundle, &pads, &seed, confirm, trust,
            )
            .map_err(show_root)?,
        // A tail that stands on the image refuses without it.
        (Some(digest), None) => manager
            .restore_sealed_bundle_with_kit(&owner, &vault_id, &bundle, &pads, &seed, confirm)
            .map_err(|error| {
                anyhow::anyhow!(
                    "{:#}; to adopt the bundle's checkpoint image, rerun with {}",
                    show_root(error),
                    adopt_flags(&digest)
                )
            })?,
        (None, None) => manager
            .restore_sealed_bundle_with_kit(&owner, &vault_id, &bundle, &pads, &seed, confirm)
            .map_err(show_root)?,
    };
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

/// How the owner fixed the pin of the checkpoint image a sealed bundle
/// carries, `digest` being the pin the bundle names: printed first, and never
/// trusted on the bundle's word. `--checkpoint-pin`, carried from one of the
/// owner's machines, or `--confirm-checkpoint`, the printed digest given back,
/// must be it. `None` when the owner gave neither ([`UNFIXED_CHECKPOINT`]).
/// The kit's root confirmation never stands in for either.
fn checkpoint_trust(
    args: &RecoveryKitRestoreArgs,
    digest: [u8; 32],
) -> anyhow::Result<Option<RecoveryCheckpointTrust>> {
    let bundle = hex(&digest);
    eprintln!(
        "the sealed bundle carries a checkpoint image under pin {bundle}: UNTRUSTED, the \
         bundle's own word"
    );
    if let Some(expected) = args.checkpoint_pin {
        anyhow::ensure!(
            expected == digest,
            "the bundle's checkpoint pin is not --checkpoint-pin: expected={} bundle={bundle}",
            hex(&expected)
        );
        return Ok(Some(RecoveryCheckpointTrust::IndependentPin(expected)));
    }
    if let Some(confirmed) = args.confirm_checkpoint {
        anyhow::ensure!(
            confirmed == digest,
            "the bundle's checkpoint pin is not --confirm-checkpoint: confirmed={} \
             bundle={bundle}",
            hex(&confirmed)
        );
        return Ok(Some(RecoveryCheckpointTrust::OwnerConfirmation(digest)));
    }
    match UNFIXED_CHECKPOINT {
        UnfixedCheckpoint::RestoreWithoutAdopting => {
            eprintln!("the restore adopts it only with {}", adopt_flags(&digest));
            Ok(None)
        }
    }
}

/// The flags that adopt a carried checkpoint image under pin `digest`.
fn adopt_flags(digest: &[u8; 32]) -> String {
    format!(
        "--checkpoint-pin <HEX>, read on one of your machines that adopted it, or \
         --confirm-checkpoint {}",
        hex(digest)
    )
}

/// `--sealed-home`: the sealed bundle and its pad object, fetched from the home
/// with the kit's `seed` alone: the generation `--sealed-generation` names, or
/// the newest the home keeps for the kit's `root`. The restore's kit rule goes
/// first, so a kit this install cannot verify asks nothing of the home.
fn fetch_from_home(
    args: &RecoveryKitRestoreArgs,
    vault_id: &[u8; 32],
    seed: &RecoveryRootSeed,
    root: RecoveryRootId,
    confirm: Option<KitConfirmation>,
) -> anyhow::Result<(SealedVaultBundle, SealedKeyPads)> {
    let home = args
        .sealed_home
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--sealed-home names the home to fetch from"))?;
    let generation = args
        .sealed_generation
        .as_deref()
        .map(|hex| {
            sealed_generation_from_hex(hex)
                .ok_or_else(|| anyhow::anyhow!("--sealed-generation is 48 lower-case hex digits"))
        })
        .transpose()?;
    if let Some(confirm) = confirm {
        confirm.check(root).map_err(show_root)?;
    }
    anyhow::ensure!(
        seed.authenticated() || confirm.is_some(),
        "a kit opened with one piece and the passphrase is not verified: these pieces rebuild \
         root {root}. Give --fingerprint with the root one of your machines pins, or go ahead \
         with --confirm-root {root}",
        root = hex(&root.0)
    );
    // The command runs on the CLI's runtime, so the fetch gets a thread and a
    // runtime of its own.
    let fetched = std::thread::scope(|scope| {
        scope
            .spawn(|| -> anyhow::Result<_> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let fetch = fetch_sealed_bundle_with_kit(home, vault_id, seed, generation);
                runtime
                    .block_on(fetch)
                    .map_err(|error| anyhow::anyhow!("fetch from {home}: {error}"))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("the sealed bundle fetch stopped"))?
    })?;
    fetched.ok_or_else(|| anyhow::anyhow!("{home} keeps no sealed bundle this kit may read"))
}

/// A sealed bundle or pad object from the owner's file, read whole.
fn read_sealed(path: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))
}

/// `oneiron restore --unlock kit`: a world kit's pieces rebuild the kit's
/// seed, and its root's recovery secret opens the backup's `world-kit`
/// escrow wrap. A kit that does not open the wrap opens nothing. A data-key
/// kit's pieces rebuild the vault data key itself (FIX 5614).
pub(super) fn kit_unlock(args: &RestoreArgs) -> anyhow::Result<HostUnlock> {
    kit_unlock_with(
        args.vault_id.as_deref(),
        &args.pieces,
        args.secret.secret_file.as_deref(),
    )
}

/// A kit's unlock from its pieces, the passphrase read from `secret_file` or
/// stdin, for the vault `vault_id` names: the id the kit is bound to, which
/// the caller is given and never reads from a mirror. `oneiron restore
/// --unlock kit` and `oneiron vault-key add-device --unlock kit` both open
/// the `world-kit` escrow wrap with a world kit's. A data-key kit's pieces,
/// by the kind they carry, go to the engine whole: they rebuild the vault
/// data key there, checked against its commitment, with no wrap (FIX 5614).
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
    if pieces
        .first()
        .is_some_and(|piece| piece.kind() == KitSecretKind::VaultKey)
    {
        return Ok(HostUnlock::VaultKeyKit {
            vault_id: *vault_id,
            pieces,
            passphrase,
        });
    }
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
