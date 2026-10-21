//! The Oneironer bundle as every runtime reads it (FIX 6755): one manifest
//! schema, one identity and one archive reader, shared by Candle and the
//! runtimes that follow it.
//!
//! A bundle directory holds `oneironer.json`, format 2: hashed `trunk`,
//! `config` and `tokenizer` artifacts, `ner_labels` in classifier order, the
//! optional `mentions`, `coref`, `vad` and `characters` heads, and the
//! `platforms` runtime rows ([`Platform`]). Every artifact row is `file`,
//! full `sha256` and exact `bytes`; the size is identity, never a cap. The
//! SHA-256 prefix of the manifest's exact bytes is the served stack: it
//! binds every row, both platform rows included, on every OS. Every object
//! is closed. A manifest of any other format is the typed [`BundleFormat`]
//! refusal, read before the strict parse; there is no format-1 reader.
//!
//! A platform row's file is one ustar archive, extracted beside it when it
//! is fetched ([`archive`]). A loader uses the rows it runs, and an absent
//! one is not installed, never an error for another runtime.

use std::path::{Component, Path, PathBuf};

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub(crate) mod archive;
mod manifest;
mod platform;

pub(crate) use manifest::{CharacterConfig, Manifest, character_vocab};
pub(crate) use platform::{COREML_ROW, CoreMlPlatform, MLX_ROW, MlxPlatform, Platform, TensorSpec};

/// The manifest's file in a bundle; its SHA-256 prefix is the stack.
pub(crate) const MANIFEST_FILE: &str = "oneironer.json";

/// The one manifest format this build reads.
const FORMAT_VERSION: u32 = 2;

/// A bundle whose manifest states another format than 2. Typed, so the slot
/// serves on without its tagger rather than stop the server, and the
/// refusal names the release that replaces it and how to fetch it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "oneironer bundle is format {found}; this build loads format 2 only: fetch stack {wanted} with `oneiron oneironer fetch --stack {wanted}`, then set oneironer.model_dir and stack_sha16 to the bundle it places"
)]
pub(crate) struct BundleFormat {
    /// The `format_version` the manifest states.
    pub(crate) found: u32,
    /// The stack this build's catalogue ships.
    pub(crate) wanted: &'static str,
}

/// The manifest's version alone, read before the strict parse, so a
/// manifest of another format is named as one and not as a missing field.
#[derive(Deserialize)]
struct FormatProbe {
    format_version: u32,
}

/// A bundle's manifest, parsed and checked, and the stack its exact bytes
/// hash to.
pub(crate) struct ReadManifest {
    pub(crate) manifest: Manifest,
    pub(crate) stack_sha16: String,
}

/// Reads `<dir>/oneironer.json` and nothing else: the one reader behind the
/// local tagger's load, the bundle's identity, `oneironer qualify` and the
/// fetch's check of what it staged or found placed.
pub(crate) fn read_manifest(dir: &Path) -> anyhow::Result<ReadManifest> {
    let bytes = manifest_bytes(dir)?;
    Ok(ReadManifest {
        manifest: parse_manifest(&bytes)?,
        stack_sha16: stack_sha16(&bytes),
    })
}

/// The stack `<dir>/oneironer.json` hashes to, its bytes unparsed: what a
/// managed vault's shared bundle is admitted by, whatever its format, so a
/// bundle of another format reaches the slot and its typed refusal.
pub(crate) fn manifest_stack(dir: &Path) -> anyhow::Result<String> {
    Ok(stack_sha16(&manifest_bytes(dir)?))
}

fn manifest_bytes(dir: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(dir.join(MANIFEST_FILE)).map_err(|error| {
        anyhow::anyhow!(
            "oneironer model_dir {} holds no readable {MANIFEST_FILE}: {error}",
            dir.display()
        )
    })
}

/// Parses manifest bytes: the format first, then the closed parse, then
/// every check that needs no setting ([`Manifest::validate`]).
fn parse_manifest(bytes: &[u8]) -> anyhow::Result<Manifest> {
    let probe: FormatProbe = serde_json::from_slice(bytes).map_err(|error| {
        anyhow::anyhow!("oneironer {MANIFEST_FILE} is not a bundle manifest: {error}")
    })?;
    if probe.format_version != FORMAT_VERSION {
        return Err(BundleFormat {
            found: probe.format_version,
            wanted: super::release::DEFAULT_STACK,
        }
        .into());
    }
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|error| {
        anyhow::anyhow!("oneironer {MANIFEST_FILE} is not a format-2 bundle manifest: {error}")
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// The first 16 hex digits of the SHA-256 of `bytes`: a manifest's stack.
fn stack_sha16(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_owned()
}

/// One file of the bundle: its path under the bundle, its full SHA-256 and
/// its exact size.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) file: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}

impl Artifact {
    /// The row's own shape: a relative path of plain names, and 64
    /// lowercase hex digits.
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            relative(&self.file),
            "oneironer artifact file must be relative to its model directory"
        );
        anyhow::ensure!(
            is_sha256(&self.sha256),
            "oneironer artifact {} sha256 is not 64 lowercase hex digits",
            self.file
        );
        Ok(())
    }

    /// Reads the file whole: its length must be `bytes` before it is
    /// hashed, then its SHA-256 must be `sha256`.
    pub(crate) fn read(&self, dir: &Path) -> anyhow::Result<Vec<u8>> {
        let path = self.path(dir)?;
        let held = std::fs::metadata(&path)?.len();
        anyhow::ensure!(
            held == self.bytes,
            "oneironer artifact {} is {held} bytes; the manifest pins {}",
            self.file,
            self.bytes
        );
        let bytes = std::fs::read(&path)?;
        anyhow::ensure!(
            u64::try_from(bytes.len()).is_ok_and(|read| read == self.bytes)
                && format!("{:x}", Sha256::digest(&bytes)) == self.sha256,
            "oneironer artifact {} SHA-256 mismatch",
            self.file
        );
        Ok(bytes)
    }

    /// The trunk's or a head's tensors, through Candle's safetensors
    /// decoder, which checks the header's ranges fill the file exactly.
    pub(crate) fn weights(
        &self,
        dir: &Path,
        device: &Device,
    ) -> anyhow::Result<VarBuilder<'static>> {
        Ok(VarBuilder::from_buffered_safetensors(
            self.read(dir)?,
            DType::F32,
            device,
        )?)
    }

    fn path(&self, dir: &Path) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            relative(&self.file),
            "oneironer artifact file must be relative to its model directory"
        );
        Ok(dir.join(&self.file))
    }
}

/// Whether `file` is a nonempty relative path of plain names.
fn relative(file: &str) -> bool {
    !file.is_empty()
        && Path::new(file)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Whether `digest` is a full SHA-256: 64 lowercase hex digits.
fn is_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
