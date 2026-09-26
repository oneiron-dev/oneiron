//! Full-vault memory export through the existing five-format pack writers.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::context_pack::PackFormat;

/// Format for the full-vault export; absence uses the model-injection default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportOptions {
    #[serde(default)]
    pub format: Option<String>,
}

/// Rendered full-vault document in the chosen OF-096 format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExport {
    pub format: String,
    pub rendered: String,
}

impl Memory<'_> {
    /// Exports the live vault through the same format writers as context packs.
    /// The underlying snapshot excludes deleted rows and custody bytes and
    /// nulls credentials. Short refs in the document resolve in this vault.
    pub fn export(&self, opts: &ExportOptions) -> MemoryResult<MemoryExport> {
        self.verified_actor_class()?;
        let name = opts.format.as_deref().unwrap_or("toon");
        let format = match name {
            "toon" => PackFormat::Toon,
            "md" => PackFormat::Markdown,
            "json" => PackFormat::Json,
            "yaml" => PackFormat::Yaml,
            "txt" => PackFormat::Plaintext,
            _ => {
                return Err(MemoryError::bad_request_with(
                    format!("unknown export format {name:?}"),
                    &["Use one of: toon, md, json, yaml, txt."],
                ));
            }
        };
        let document = self.vault.export_whole_vault(format)?;
        let rendered = String::from_utf8(document.bytes().to_vec())
            .map_err(|_| MemoryError::bad_request("export serializer emitted non-UTF-8 text"))?;
        Ok(MemoryExport {
            format: name.to_owned(),
            rendered,
        })
    }
}
