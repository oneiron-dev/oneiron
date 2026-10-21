//! The Oneironer bundle as every runtime reads it: one manifest schema and
//! one identity (FIX 6755).

use std::path::{Component, Path};

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

mod manifest;

pub(crate) use manifest::{CharacterConfig, Manifest, character_vocab, validate_labels};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) file: String,
    pub(crate) sha256: String,
}

impl Artifact {
    pub(crate) fn read(&self, dir: &Path) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            !self.file.is_empty()
                && Path::new(&self.file)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "oneironer artifact file must be relative to its model directory"
        );
        let bytes = std::fs::read(dir.join(&self.file))?;
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == self.sha256,
            "oneironer artifact SHA-256 mismatch"
        );
        Ok(bytes)
    }

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
}
