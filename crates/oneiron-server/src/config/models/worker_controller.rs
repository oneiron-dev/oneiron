use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

use super::{ModelsConfig, ModelsFile};

/// Only this command's section is resolved; unrelated vault settings are not resolved.
pub(crate) fn worker_controller_config(path: &Path) -> anyhow::Result<ModelsConfig> {
    #[derive(Deserialize)]
    struct File {
        models: ModelsFile,
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading model worker config {}", path.display()))?;
    let file: File = toml::from_str(&text)
        .with_context(|| format!("parsing model worker config {}", path.display()))?;
    file.models.resolve(path.parent())
}
