//! Pinned `REACTION` MessagePack body, including mirrored provenance.
use crate::EntityId;
use crate::error::{Error, RecordError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

fn invalid(reason: &'static str) -> Error {
    RecordError::InvalidReactionBody(reason).into()
}

/// A connector's stable, provider-authored event identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionExternalId {
    pub connector: String,
    pub id: String,
}

/// One immutable put. `recordedAt` belongs to the entity envelope; revocation
/// belongs to the tombstone, never to this body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionBody {
    pub v: u8,
    pub msg: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<ReactionExternalId>,
}

impl ReactionBody {
    pub fn validate(&self) -> Result<()> {
        if self.v != 1 {
            return Err(invalid("unsupported version"));
        }
        if self.glyph.is_empty() || self.glyph.chars().count() > 64 {
            return Err(invalid("glyph must have 1..=64 Unicode scalars"));
        }
        if self.ext.as_ref().is_some_and(|ext| {
            ext.connector.trim().is_empty()
                || ext.id.trim().is_empty()
                || ext.connector.len() > 256
                || ext.id.len() > 1024
        }) {
            return Err(invalid("invalid external id"));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        rmp_serde::to_vec_named(self).map_err(|_| invalid("encode failed"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("decode failed"))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid("trailing bytes"));
        }
        let rmpv::Value::Map(entries) = value else {
            return Err(invalid("body must be a map"));
        };
        let mut keys = BTreeSet::new();
        for (key, _) in entries {
            let Some(key) = key.as_str() else {
                return Err(invalid("non-string key"));
            };
            if !keys.insert(key.to_owned()) {
                return Err(invalid("duplicate key"));
            }
        }
        let body: Self = rmp_serde::from_slice(bytes).map_err(|_| invalid("invalid fields"))?;
        body.validate()?;
        Ok(body)
    }
}
