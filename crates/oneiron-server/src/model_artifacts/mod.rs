//! Pinned model weights beyond the embedder: LLM targets, speculative
//! drafters, voice checkpoints and, later, speech recognition (FIX 8315,
//! DESIGN-V2 R0).
//!
//! A [`manifest::ArtifactManifest`] pins one model at one commit, file by
//! file, by size and SHA-256, with its licence, format and provenance. Its
//! schema is serde's, so an operator's manifest file loads into the same
//! type the [`catalog`] is written in. [`licence::admit_download`] is the one
//! policy that says whether a download may start. [`install::ArtifactStore`]
//! places a manifest's files under the embedder's models root, verifies an
//! operator's directory without the network, and reports what is on disk.
//!
//! Nothing here runs a model or executes a fetched file, and a manifest that
//! lists executable code is refused before anything is fetched.

pub(crate) mod catalog;
pub(crate) mod install;
pub(crate) mod licence;
pub(crate) mod manifest;

use licence::LicenceClass;

/// Why an artifact was refused, or could not be placed or verified. Every
/// variant names the model; none carries a hub token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ArtifactError {
    /// A non-commercial or unknown licence: the download never starts.
    #[error("model {model}: licence {licence} is {class}, so the download is refused")]
    LicenceRefused {
        model: String,
        licence: String,
        class: LicenceClass,
    },
    /// A conditional licence with no decision admitting this model.
    #[error(
        "model {model}: licence {licence} is conditional and the manifest names no decision \
         admitting it, so the download is refused"
    )]
    LicenceUndecided { model: String, licence: String },
    /// The manifest lists a file that is executable code.
    #[error("model {model}: {file} is executable code, which a model manifest never lists")]
    ExecutableCode { model: String, file: String },
    #[error("model {model}: invalid manifest: {reason}")]
    Invalid { model: String, reason: String },
    /// A file the manifest pins is not in the directory.
    #[error("model {model}: {file} is missing from {dir}")]
    Missing {
        model: String,
        file: String,
        dir: String,
    },
    /// A file is not its pinned size or SHA-256.
    #[error("model {model}: {file} does not match its pin: {reason}")]
    Mismatch {
        model: String,
        file: String,
        reason: String,
    },
    /// The installed directory is not this manifest's, or a file in it no
    /// longer matches. Nothing here removes or repairs it.
    #[error("model {model}: {dir} does not hold the pinned model ({reason}); it was left as it is")]
    InstalledMismatch {
        model: String,
        dir: String,
        reason: String,
    },
    /// The hub has no such file at the pinned revision (`404`).
    #[error("model {model}: {file} is not at the pinned revision (404)")]
    NotFound { model: String, file: String },
    /// The hub refused the file (`401`, `403`).
    #[error(
        "model {model}: {file} was refused (401/403): the repository needs a read token with access"
    )]
    Unauthorized { model: String, file: String },
    /// A transfer stopped without adding bytes. The partial stays for the
    /// next install to resume.
    #[error("model {model}: {file}: {reason}; install again to resume")]
    Transfer {
        model: String,
        file: String,
        reason: String,
    },
    #[error("model {model}: {action} {path}: {reason}")]
    Io {
        model: String,
        action: &'static str,
        path: String,
        reason: String,
    },
}
