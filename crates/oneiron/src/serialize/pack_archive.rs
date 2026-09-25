//! Typed runtime-pack archive bodies: identity is data, payloads always pass nulling.
use super::ExportBody;
use crate::error::{Error, Result};
use crate::registry::pack_byte_map::{PackInstanceEnvelope, PackInstanceOrigin, PackKindIdentity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPackInstance {
    pub version: u8,
    pub kind: PackKindIdentity,
    pub generation: u64,
    pub origin: PackInstanceOrigin,
    pub payload: ExportBody,
}
impl ExportPackInstance {
    pub(super) fn from_envelope(value: PackInstanceEnvelope) -> Self {
        Self {
            version: value.version,
            kind: value.kind,
            generation: value.generation,
            origin: value.origin,
            payload: ExportBody::from_bytes(&value.payload, 0),
        }
    }
    pub(crate) fn envelope(&self) -> Result<PackInstanceEnvelope> {
        let envelope = PackInstanceEnvelope {
            version: self.version,
            kind: self.kind.clone(),
            generation: self.generation,
            origin: self.origin.clone(),
            payload: self.payload.to_bytes()?,
        };
        envelope.to_bytes()?;
        Ok(envelope)
    }
    pub(super) fn validate(&self) -> Result<()> {
        if matches!(self.payload, ExportBody::Pack(_)) {
            return Err(Error::InvalidConfig("nested pack archive envelope".into()));
        }
        // Even when payload was redacted, validate all non-secret envelope fields.
        let mut safe = self.clone();
        safe.payload = ExportBody::Utf8(String::new());
        safe.envelope()?;
        self.payload.validate(0)
    }
}
