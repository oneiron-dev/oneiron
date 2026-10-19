//! Flags for `oneiron recovery-kit`, the world kit's ceremony on a stopped
//! vault (OF-173). Pieces go in and out through owner-only files, and the
//! passphrase comes from stdin or `--secret-file`; none is ever an argument.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

/// A stopped vault's world recovery kit.
#[derive(Subcommand, Clone, Debug)]
pub enum RecoveryKitCommand {
    /// The kits this vault issued, the current one, and each private world's
    /// no-kit state here.
    Status(Box<RecoveryKitStatusArgs>),
    /// Issue a kit: its pieces are written to `--out`, and nothing is
    /// published until `confirm`.
    Issue(Box<RecoveryKitIssueArgs>),
    /// Confirm a kit by re-entering its saved pieces: its root goes live,
    /// and the vault key gets a `world-kit` escrow wrap to it.
    Confirm(Box<RecoveryKitConfirmArgs>),
    /// Restore this vault's world keys from the kit, on this machine.
    Restore(Box<RecoveryKitRestoreArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct RecoveryKitStatusArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RecoveryKitIssueArgs {
    /// Where one piece lives, given three times in point order: `paper`,
    /// `password-manager`, `own-email`, `file-elsewhere`, `file-here`,
    /// `file-on:<machine>`, `other-machine:<machine>`, `trusted-person`,
    /// `security-key` or `passphrase`. `this-machine` waits for device-piece
    /// custody.
    #[arg(long = "home", value_name = "HOME", required = true)]
    pub homes: Vec<String>,

    /// The directory each stored piece is written to as `piece-<x>.txt`: its
    /// recovery code, readable by its owner alone.
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,

    /// With a `passphrase` home: read the passphrase from this owner-only
    /// file instead of stdin.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// The pieces a kit opens with.
#[derive(Args, Clone, Debug)]
pub struct KitPieceArgs {
    /// A piece file: a recovery code as text, or a piece export. Give two, or
    /// one and the passphrase.
    #[arg(long = "piece", value_name = "FILE", required = true)]
    pub pieces: Vec<PathBuf>,

    /// Read the kit passphrase from this owner-only file. With one piece and
    /// no file, it is read from stdin.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct RecoveryKitConfirmArgs {
    #[command(flatten)]
    pub kit: KitPieceArgs,

    /// On a reissue: another of your machines under the old pin to mark
    /// yours under the new root, by its 32-hex id. Repeat for each.
    #[arg(long, value_name = "MACHINE")]
    pub carry: Vec<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct RecoveryKitRestoreArgs {
    #[command(flatten)]
    pub kit: KitPieceArgs,

    /// The root fingerprint, 64 hex digits, read on one of your machines that
    /// pins it: it vouches for a kit opened with one piece.
    #[arg(long, value_name = "HEX", conflicts_with = "confirm_unverified")]
    pub fingerprint: Option<String>,

    /// Go ahead with a kit this install cannot verify, after reading why.
    #[arg(long)]
    pub confirm_unverified: bool,

    /// Restore the vault from its sealed cloud bundle on an install that holds
    /// no copy of it yet: the bundle's file, with `--sealed-pads` and
    /// `--vault-id`. The kit alone opens it.
    #[arg(
        long,
        value_name = "FILE",
        requires = "sealed_pads",
        group = "sealed_source"
    )]
    pub sealed_bundle: Option<PathBuf>,

    /// With `--sealed-bundle`: the file of the pad object of the bundle's
    /// generation.
    #[arg(long, value_name = "FILE", requires = "sealed_bundle")]
    pub sealed_pads: Option<PathBuf>,

    /// Restore the vault from its sealed cloud bundle as `--sealed-bundle`
    /// does, fetched with the kit alone from the home at this address: the
    /// newest generation it keeps for the kit's root. With `--vault-id`.
    #[arg(long, value_name = "URL", group = "sealed_source")]
    pub sealed_home: Option<String>,

    /// With `--sealed-home`: fetch this generation, 48 hex digits, instead of
    /// the newest.
    #[arg(long, value_name = "HEX", requires = "sealed_home")]
    pub sealed_generation: Option<String>,

    /// With `--sealed-bundle` or `--sealed-home`: the vault id the kit is
    /// bound to, 64 hex digits, as `oneiron recovery-kit status` prints it.
    #[arg(long, value_name = "HEX", requires = "sealed_source")]
    pub vault_id: Option<String>,

    /// With `--sealed-bundle` or `--sealed-home`: the pin digest of the
    /// checkpoint image the bundle carries, 64 hex digits, read on one of your
    /// machines that adopted it. A bundle naming another pin is refused.
    #[arg(
        long,
        value_name = "HEX",
        value_parser = pin_digest,
        requires = "sealed_source",
        conflicts_with = "confirm_checkpoint"
    )]
    pub checkpoint_pin: Option<[u8; 32]>,

    /// With `--sealed-bundle` or `--sealed-home`: the pin digest the restore
    /// printed for the bundle's checkpoint image, given back to adopt the
    /// image under it. A bundle naming another pin is refused.
    #[arg(
        long,
        value_name = "HEX",
        value_parser = pin_digest,
        requires = "sealed_source"
    )]
    pub confirm_checkpoint: Option<[u8; 32]>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// A checkpoint pin's digest: exactly 64 hex digits, either case.
fn pin_digest(text: &str) -> Result<[u8; 32], String> {
    let refused = || "a pin digest is 64 hex digits".to_owned();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    let mut digest = [0u8; 32];
    for (at, byte) in digest.iter_mut().enumerate() {
        let pair = text.get(2 * at..2 * at + 2).ok_or_else(refused)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(digest)
}
