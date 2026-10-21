//! A platform runtime's candidate on this machine (FIX 6755 slices 3 and
//! 2c): the bundle's `mlx-worker` or `coreml-ane` row, found placed,
//! admitted for this host and verified against its archive, or the fixed
//! reason it is not.
//!
//! Only a macOS aarch64 build on a release from the row's `min_os` finds a
//! candidate; every other build checks the same code and starts nothing.
//! Discovery writes nothing and never repairs: a row or archive that is not
//! placed is not installed, a tree that does not verify against its archive
//! is an invalid installation, and the slot serves Candle either way. The
//! program the MLX worker starts is the row's own, resolved inside its
//! verified extraction; no interpreter is looked up on a path. The model
//! the Core ML worker loads is the Core ML row's verified extraction
//! itself, the stable `.mlmodelc` directory the OS keys its Neural Engine
//! compile cache on.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::super::bundle::archive;
use super::super::bundle::{
    Artifact, COREML_ROW, CoreMlPlatform, MLX_ROW, Manifest, MlxPlatform, Platform,
};
use super::super::coreml;
use super::super::dispatcher::WorkerDescriptor;
use super::super::mlx::{self, PROTOCOL};
use super::rows::{mac_release, release};

/// Why this machine has no candidate for a platform row, by a fixed name.
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
    /// The MLX row names another wire than this engine speaks.
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

    /// Logs it once for the bundle's `row`: an unsupported host or an
    /// uninstalled row is a plain Candle machine; the rest are worth an
    /// operator's look. Candle serves either way.
    pub(super) fn log(self, row: &str) {
        let reason = self.as_str();
        match self {
            Self::UnsupportedHost => {
                tracing::debug!(row, reason, "oneironer platform worker not started");
            }
            Self::NotInstalled => {
                tracing::info!(row, reason, "oneironer platform worker not started");
            }
            Self::InstallInvalid | Self::OsTooOld | Self::Protocol => {
                tracing::warn!(row, reason, "oneironer platform worker not started");
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

/// A Core ML row placed, admitted for this host and verified.
pub(super) struct CoreMlCandidate<'a> {
    pub(super) row: &'a CoreMlPlatform,
    /// The row's verified extraction, `<bundle>/coreml-ane-port-v1.mlmodelc`:
    /// the path the worker loads and the OS keys its compile cache on.
    pub(super) model: PathBuf,
}

impl CoreMlCandidate<'_> {
    /// Its worker's descriptor: `coreml/cpu_and_ne`, its archive's hash and
    /// its qualified window.
    pub(super) fn descriptor(&self) -> WorkerDescriptor {
        coreml::descriptor(&self.row.model().sha256, self.row.window_tokens())
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
    let extracted = placed(dir, row.worker(), row.min_os(), MLX_ROW)?;
    let (program, _) = row.launch();
    let program = extracted.join(program);
    if !program.symlink_metadata().is_ok_and(|held| held.is_file()) {
        return Err(Absent::InstallInvalid);
    }
    Ok(Candidate { row, program })
}

/// `manifest`'s Core ML row in the bundle at `dir`, by the same rules: when
/// this build runs it, it is placed whole, this Mac's release is at least
/// its `min_os` (15.0: multifunction models) and its extraction verifies
/// against its archive (FIX 6755 slice 2c).
pub(super) fn discover_coreml<'a>(
    dir: &Path,
    manifest: &'a Manifest,
) -> Result<CoreMlCandidate<'a>, Absent> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(Absent::UnsupportedHost);
    }
    let Some(Platform::CoreMl(row)) = manifest.platform(COREML_ROW) else {
        return Err(Absent::NotInstalled);
    };
    let model = placed(dir, row.model(), row.min_os(), COREML_ROW)?;
    Ok(CoreMlCandidate { row, model })
}

/// The extraction of `row`'s archive `artifact` in the bundle at `dir`,
/// once the archive and its extraction are both placed, this Mac's release
/// is at least `min_os`, and the extraction verifies against the archive
/// entry by entry; else why not.
fn placed(dir: &Path, artifact: &Artifact, min_os: &str, row: &str) -> Result<PathBuf, Absent> {
    let tar = dir.join(&artifact.file);
    let extracted = archive::extraction_dir(dir, artifact).map_err(|_| Absent::InstallInvalid)?;
    match (
        tar.symlink_metadata().is_ok(),
        extracted.symlink_metadata().is_ok(),
    ) {
        (false, false) => return Err(Absent::NotInstalled),
        (true, true) => {}
        _ => return Err(Absent::InstallInvalid),
    }
    let admitted = match (mac_release(), release(min_os)) {
        (Some(here), Some(wanted)) => here >= wanted,
        _ => false,
    };
    if !admitted {
        return Err(Absent::OsTooOld);
    }
    if let Err(error) = archive::verify_extraction(&tar, artifact, &extracted) {
        tracing::warn!(
            row,
            reason = Absent::InstallInvalid.as_str(),
            %error,
            "oneironer platform installation does not verify against its archive"
        );
        return Err(Absent::InstallInvalid);
    }
    Ok(extracted)
}
