//! The pinned-artifact manifest: one model, one commit, every file by size
//! and SHA-256, with its licence, format and provenance (DESIGN-V2 §10.2).
//!
//! Fields are `Cow<'static, _>` so the shipped catalogue is a static and an
//! operator's manifest file deserializes into the same type. The total size
//! is derived from the files and never stored.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::ArtifactError;
use super::licence::LicenceTerms;

/// The record an installed directory holds, written last: the manifest the
/// directory was verified against, with its digest. No manifest may pin a
/// file by this name.
pub(crate) const RECORD_FILE: &str = "oneiron-artifact.json";

/// What a fetch in progress names its file: `<path>.partial`. No manifest
/// may pin a file ending so.
pub(crate) const PARTIAL_SUFFIX: &str = ".partial";

/// File extensions that are executable code (compared without ASCII case).
/// A manifest that lists one is refused, naming the file: a model card that
/// asks for remote code gets none (DESIGN-V2 §10.2).
pub(crate) const EXECUTABLE_EXTENSIONS: [&str; 7] = ["py", "so", "dylib", "dll", "exe", "sh", "js"];

/// What a model is for. The installer treats every class alike; the worker
/// supervisor picks by it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArtifactClass {
    /// A generation target.
    Llm,
    /// A speculative-decoding draft for a target.
    Drafter,
    /// A speech-synthesis checkpoint.
    Voice,
    /// A speech-recognition checkpoint.
    Asr,
}

/// The on-disk format the files are in: what loads them. Closed: a new
/// format is a new variant and a new loader, never a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ArtifactFormat {
    /// ExLlamaV3 safetensors shards.
    #[serde(rename = "exl3")]
    Exl3,
    /// llama.cpp GGUF, one file or a split set.
    #[serde(rename = "gguf")]
    Gguf,
    /// Plain safetensors weights.
    #[serde(rename = "safetensors")]
    Safetensors,
    /// A VoxCPM2 checkpoint directory.
    #[serde(rename = "voxcpm2_checkpoint")]
    VoxCpm2Checkpoint,
}

/// One file of the model at its pinned revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactFile {
    /// Path within the repository, and under the installed directory.
    pub(crate) path: Cow<'static, str>,
    /// SHA-256 of the exact bytes, lowercase hex.
    pub(crate) sha256: Cow<'static, str>,
    /// Size in bytes, checked before the digest.
    pub(crate) bytes: u64,
}

/// One model pinned at one commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactManifest {
    /// Catalogue id, also the directory the model installs under.
    pub(crate) id: Cow<'static, str>,
    /// Hugging Face repository, `org/name`.
    pub(crate) repo: Cow<'static, str>,
    /// The commit, 40 hex digits: never a branch or a tag, which move.
    pub(crate) revision: Cow<'static, str>,
    pub(crate) class: ArtifactClass,
    pub(crate) format: ArtifactFormat,
    /// The quantisation as its publisher names it, e.g. `4.00bpw` or
    /// `Q4_K_M`; `bf16` for unquantised weights.
    pub(crate) quant: Cow<'static, str>,
    /// The repositories these weights were converted or trained from, as
    /// the card declares them; empty for an original release.
    pub(crate) base_models: Cow<'static, [Cow<'static, str>]>,
    /// Every file a worker loads, and the licence file. Fetched in this
    /// order, so small files first find an unpublished or private
    /// repository before the weights move.
    pub(crate) files: Cow<'static, [ArtifactFile]>,
    pub(crate) licence: LicenceTerms,
}

impl ArtifactManifest {
    /// Every pinned file's bytes, summed.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.files.iter().map(|file| file.bytes).sum()
    }

    /// SHA-256 of the manifest's compact JSON: the identity of exactly these
    /// pins, carried by the installed record.
    pub(crate) fn digest(&self) -> Result<String, ArtifactError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| self.invalid(format!("it does not serialize: {error}")))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Checks the manifest's shape before anything touches disk or network:
    /// a plain id and `org/name` repository, a full commit, at least one
    /// file, each a plain relative path with a SHA-256 and listed once, no
    /// executable code, and a licence whose file is one of the pinned files.
    /// The licence's class is [`super::licence::admit_download`]'s to judge.
    pub(crate) fn validate(&self) -> Result<(), ArtifactError> {
        if !plain_segment(&self.id) {
            return Err(self.invalid(format!(
                "id {:?} must be one plain name: letters, digits, '.', '_' and '-'",
                self.id
            )));
        }
        if !self
            .repo
            .split_once('/')
            .is_some_and(|(org, name)| plain_segment(org) && plain_segment(name))
        {
            return Err(self.invalid(format!("repo {:?} must be a plain org/name", self.repo)));
        }
        if !is_lower_hex(&self.revision, 40) {
            return Err(self.invalid(format!(
                "revision {:?} must be a full 40-hex commit, never a branch or tag",
                self.revision
            )));
        }
        if self.files.is_empty() {
            return Err(self.invalid("it pins no file".to_owned()));
        }
        for (index, file) in self.files.iter().enumerate() {
            self.check_file(file)?;
            let repeated = self.files[..index]
                .iter()
                .any(|earlier| earlier.path.eq_ignore_ascii_case(&file.path));
            if repeated {
                return Err(self.invalid(format!("{} is listed twice", file.path)));
            }
        }
        if self.licence.id.trim().is_empty() {
            return Err(self.invalid("it declares no licence id".to_owned()));
        }
        if !self.files.iter().any(|file| file.path == self.licence.file) {
            return Err(self.invalid(format!(
                "licence file {} is not one of the pinned files",
                self.licence.file
            )));
        }
        Ok(())
    }

    /// One file's path, digest and kind.
    fn check_file(&self, file: &ArtifactFile) -> Result<(), ArtifactError> {
        let path: &str = &file.path;
        if !path.split('/').all(plain_segment) {
            return Err(self.invalid(format!(
                "file {path:?} must be a relative path of plain names: letters, digits, '.', '_' \
                 and '-'"
            )));
        }
        if path == RECORD_FILE || path.ends_with(PARTIAL_SUFFIX) {
            return Err(self.invalid(format!("file {path} takes a name the installer keeps")));
        }
        if is_executable(path) {
            return Err(ArtifactError::ExecutableCode {
                model: self.id.to_string(),
                file: path.to_owned(),
            });
        }
        if !is_lower_hex(&file.sha256, 64) {
            return Err(self.invalid(format!("file {path} has no lowercase hex SHA-256")));
        }
        Ok(())
    }

    fn invalid(&self, reason: String) -> ArtifactError {
        ArtifactError::Invalid {
            model: self.id.to_string(),
            reason,
        }
    }
}

/// Whether a file's extension is in [`EXECUTABLE_EXTENSIONS`].
fn is_executable(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.').is_some_and(|(_, extension)| {
        EXECUTABLE_EXTENSIONS
            .iter()
            .any(|executable| extension.eq_ignore_ascii_case(executable))
    })
}

/// One path or URL segment that stays where it is put: ASCII letters,
/// digits, `.`, `_` and `-`, not empty and not only dots, the embedder's
/// cache-identity rule.
fn plain_segment(segment: &str) -> bool {
    segment.bytes().any(|byte| byte != b'.')
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Exactly `len` lowercase hex digits.
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
