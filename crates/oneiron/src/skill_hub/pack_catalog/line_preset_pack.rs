//! Line presets as pack data (design pass 34, sections 3.2 and 3.3; row L1): a pack of kind
//! `capability` may carry line policy documents, one per preset, in
//! [`LINE_PRESET_DIR`]`<name>.json`. `vault.gpu.lines.set { preset }` reads one from the pack's
//! Active install, and checks the digest the owner names against the document's bytes. A preset
//! rides the same sources as a table of setting defaults ([`super::setting_defaults_pack`]).
use heed::RoTxn;
use oneiron_contracts::fingerprint::ContentHash;
use serde_json::{Map, Value};

use super::{LOCAL_PACK_NAME, PackKind, PackManifest, invalid};
use crate::Vault;
use crate::error::Result;
use crate::skill_hub::HubFile;

/// Where a pack keeps its line presets: one `<name>.json` each.
pub const LINE_PRESET_DIR: &str = "knowledge/line-presets/";

/// The longest preset name.
const MAX_PRESET_NAME: usize = 64;

/// One line preset as its pack's source carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackLinePreset {
    /// The file's stem.
    pub name: String,
    /// The content hash (hex) of the document's bytes: what `vault.gpu.lines.set` names.
    pub digest: String,
    pub document: Map<String, Value>,
}

/// Whether `name` names a preset: lowercase letters, digits and dashes, a letter first.
fn preset_name(name: &str) -> bool {
    name.len() <= MAX_PRESET_NAME
        && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The source's line presets, in name order. A preset in the `local` pack or in a pack of
/// another kind than `capability`, one under another path or name, and a document that is not a
/// line policy document, refuse the source.
pub(super) fn read_source_line_presets(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Vec<PackLinePreset>> {
    let mut presets = Vec::new();
    for file in files
        .iter()
        .filter(|file| file.path.starts_with(LINE_PRESET_DIR))
    {
        if manifest.name == LOCAL_PACK_NAME {
            return Err(invalid(
                "the local pack carries no line preset: a resident agent writes it",
            ));
        }
        if manifest.kind != PackKind::Capability {
            return Err(invalid("a line preset rides a capability pack"));
        }
        let name = file
            .path
            .strip_prefix(LINE_PRESET_DIR)
            .and_then(|rest| rest.strip_suffix(".json"))
            .filter(|name| preset_name(name))
            .ok_or_else(|| {
                invalid("a line preset is knowledge/line-presets/<name>.json, its name lowercase")
            })?;
        let document: Map<String, Value> = serde_json::from_slice(&file.content)
            .map_err(|_| invalid("a line preset is one JSON object"))?;
        crate::gpu_line::check_document(&document)
            .map_err(|_| invalid("a line preset is a line policy document"))?;
        presets.push(PackLinePreset {
            name: name.to_owned(),
            digest: ContentHash::of(&file.content).to_hex(),
            document,
        });
    }
    presets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(presets)
}

impl Vault {
    /// The line preset `name` of `pack`'s Active install, where that install may carry presets,
    /// read in `txn` from the source its receipt names
    /// ([`Vault::preset_source_in_txn`]). `None` otherwise.
    pub(crate) fn installed_line_preset_in_txn(
        &self,
        txn: &RoTxn<'_>,
        pack: &str,
        name: &str,
    ) -> Result<Option<PackLinePreset>> {
        Ok(self.preset_source_in_txn(txn, pack)?.and_then(|source| {
            source
                .line_presets()
                .iter()
                .find(|preset| preset.name == name)
                .cloned()
        }))
    }
}
