//! A platform runtime's candidate on this machine (FIX 6755 slice 3): the
//! bundle's `mlx-worker` row, found placed, admitted for this host and
//! verified against its archive, or the fixed reason it is not.
//!
//! Only a macOS aarch64 build on a release from the row's `min_os` finds a
//! candidate; every other build checks the same code and starts nothing.
//! Discovery writes nothing and never repairs: a row or archive that is not
//! placed is not installed, a tree that does not verify against its archive
//! is an invalid installation, and the slot serves Candle either way. The
//! program the worker starts is the row's own, resolved inside its verified
//! extraction; no interpreter is looked up on a path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::super::bundle::archive;
use super::super::bundle::{MLX_ROW, Manifest, MlxPlatform, Platform};
use super::super::dispatcher::WorkerDescriptor;
use super::super::mlx::{self, PROTOCOL};
use super::rows::{mac_release, release};

/// Why this machine has no MLX candidate, by a fixed name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Absent {
    /// This build is not macOS on aarch64.
    UnsupportedHost,
    /// The bundle has no MLX row, or neither its archive nor its
    /// extraction is placed.
    NotInstalled,
    /// Its archive or its extraction is placed without the other, the
    /// extraction does not verify against the archive, or the row's program
    /// is not in it.
    InstallInvalid,
    /// This Mac's release is older than the row's `min_os`, or unnamed.
    OsTooOld,
    /// The row names another wire than this engine speaks.
    Protocol,
}

impl Absent {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedHost => "unsupported_host",
            Self::NotInstalled => "not_installed",
            Self::InstallInvalid => "install_invalid",
            Self::OsTooOld => "os_too_old",
            Self::Protocol => "identity_mismatch:protocol",
        }
    }

    /// Logs it once: an unsupported host or an uninstalled row is a plain
    /// Candle machine; the rest are worth an operator's look.
    pub(super) fn log(self) {
        let reason = self.as_str();
        match self {
            Self::UnsupportedHost => {
                tracing::debug!(reason, "oneironer mlx worker not started; Candle serves");
            }
            Self::NotInstalled => {
                tracing::info!(reason, "oneironer mlx worker not started; Candle serves");
            }
            Self::InstallInvalid | Self::OsTooOld | Self::Protocol => {
                tracing::warn!(reason, "oneironer mlx worker not started; Candle serves");
            }
        }
    }
}

/// An MLX row placed, admitted for this host and verified.
pub(super) struct Candidate<'a> {
    pub(super) row: &'a MlxPlatform,
    /// The row's program inside its verified extraction.
    pub(super) program: PathBuf,
}

impl Candidate<'_> {
    /// Its worker's descriptor: `mlx/metal`, its archive's hash and the
    /// row's qualified window.
    pub(super) fn descriptor(&self) -> WorkerDescriptor {
        mlx::descriptor(&self.row.worker().sha256, self.row.max_window_tokens())
    }

    /// The worker's arguments: the row's, then the engine's own, the bundle
    /// directory that holds the manifest and trunk (never the extraction),
    /// and the slot's configured window cap, not the row's window.
    pub(super) fn args(&self, bundle: &Path, max_input_tokens: usize) -> Vec<OsString> {
        let (_, row_args) = self.row.launch();
        let mut args: Vec<OsString> = row_args.iter().map(OsString::from).collect();
        args.push("--bundle".into());
        args.push(bundle.as_os_str().to_owned());
        args.push("--max-input-tokens".into());
        args.push(max_input_tokens.to_string().into());
        args
    }
}

/// `manifest`'s MLX row in the bundle at `dir`, when this build runs it, it
/// is placed whole, this Mac's release is at least its `min_os`, and its
/// extraction verifies against its archive entry by entry; else why not.
pub(super) fn discover<'a>(dir: &Path, manifest: &'a Manifest) -> Result<Candidate<'a>, Absent> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(Absent::UnsupportedHost);
    }
    let Some(Platform::Mlx(row)) = manifest.platform(MLX_ROW) else {
        return Err(Absent::NotInstalled);
    };
    if row.protocol() != PROTOCOL {
        return Err(Absent::Protocol);
    }
    let tar = dir.join(&row.worker().file);
    let extracted = archive::extraction_dir(dir, row.worker())
        .map_err(|_| Absent::InstallInvalid)?;
    match (
        tar.symlink_metadata().is_ok(),
        extracted.symlink_metadata().is_ok(),
    ) {
        (false, false) => return Err(Absent::NotInstalled),
        (true, true) => {}
        _ => return Err(Absent::InstallInvalid),
    }
    let admitted = match (mac_release(), release(row.min_os())) {
        (Some(here), Some(wanted)) => here >= wanted,
        _ => false,
    };
    if !admitted {
        return Err(Absent::OsTooOld);
    }
    if let Err(error) = archive::verify_extraction(&tar, row.worker(), &extracted) {
        tracing::warn!(
            reason = Absent::InstallInvalid.as_str(),
            %error,
            "oneironer mlx installation does not verify against its archive"
        );
        return Err(Absent::InstallInvalid);
    }
    let (program, _) = row.launch();
    let program = extracted.join(program);
    if !program.symlink_metadata().is_ok_and(|held| held.is_file()) {
        return Err(Absent::InstallInvalid);
    }
    Ok(Candidate { row, program })
}
