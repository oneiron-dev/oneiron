use std::path::Path;

use serde::Deserialize;

use super::{ModelsConfig, ModelsFile};

/// Only this command's section is resolved; unrelated vault settings are not resolved.
/// The file is the vault's config, so it is admitted as serve admits it
/// (`file_admission`), and a file that does not parse names only itself and
/// the place it failed: the parser's own message quotes the line, which can
/// hold the issuer key (FIX 9477).
pub(crate) fn worker_controller_config(path: &Path) -> anyhow::Result<ModelsConfig> {
    #[derive(Deserialize)]
    struct File {
        models: ModelsFile,
    }

    let text = crate::config::file_admission::read_config_file(path)?;
    let file: File = crate::config::parse_toml(path, &text)?;
    file.models.resolve(path.parent())
}
