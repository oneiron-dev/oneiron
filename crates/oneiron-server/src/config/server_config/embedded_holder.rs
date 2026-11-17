//! [`EmbeddedHolderOverrides`]: the explicit vault inputs an embedded
//! binding resolved over its config file, and the serve arguments they
//! replay.

use std::path::PathBuf;

use super::super::ServeArgs;

/// The explicit vault inputs an embedded binding resolved over its config file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedHolderOverrides {
    pub vault_path: PathBuf,
    pub dimensions: Option<usize>,
}

impl EmbeddedHolderOverrides {
    pub(crate) fn serve_args(&self, config: Option<PathBuf>) -> ServeArgs {
        ServeArgs {
            config,
            vault_path: Some(self.vault_path.clone()),
            dimensions: self.dimensions,
            ..Default::default()
        }
    }
}
