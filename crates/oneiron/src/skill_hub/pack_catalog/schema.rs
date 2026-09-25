//! Runtime kind descriptors are exact source files, never caller-supplied hashes.
use super::{PackSource, invalid};
use crate::{error::Result, registry::pack_byte_map::PackKindIdentity};
impl PackSource {
    pub(super) fn kind_identities(&self) -> Result<Vec<PackKindIdentity>> {
        self.manifest
            .kinds
            .iter()
            .map(|name| {
                let path = format!("knowledge/kinds/{name}.json");
                let file = self.files.iter().find(|f| f.path == path).ok_or_else(|| {
                    invalid("kind requires an exact knowledge/kinds/name.json descriptor")
                })?;
                let value: serde_json::Value = serde_json::from_slice(&file.content)
                    .map_err(|_| invalid("kind descriptor is not JSON"))?;
                if !value.is_object() {
                    return Err(invalid("kind descriptor must be an object"));
                }
                let identity = PackKindIdentity {
                    name: name.clone(),
                    pack: self.manifest.name.clone(),
                    source_hash: *self.hash.as_bytes(),
                    schema_hash: *blake3::hash(&file.content).as_bytes(),
                };
                identity.validate()?;
                Ok(identity)
            })
            .collect()
    }
}
