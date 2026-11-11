//! Typed runtime-pack archive bodies: identity is data, payloads pass the
//! archive's policy (kept only in the Owner's whole-vault archive with secrets
//! included, nulled in every other export).
use super::{ExportBody, ExportSecrets};
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
    /// [`Self::from_envelope_with`] under [`ExportSecrets::Nulled`].
    pub(super) fn from_envelope(value: PackInstanceEnvelope) -> Self {
        Self::from_envelope_with(value, ExportSecrets::Nulled)
    }

    /// A pack envelope as its archive body under `secrets`: the payload via
    /// [`ExportBody::from_bytes_with`].
    pub(super) fn from_envelope_with(value: PackInstanceEnvelope, secrets: ExportSecrets) -> Self {
        Self {
            version: value.version,
            kind: value.kind,
            generation: value.generation,
            origin: value.origin,
            payload: ExportBody::from_bytes_with(&value.payload, 0, secrets),
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
    /// [`Self::validate_with`] under [`ExportSecrets::Nulled`].
    pub(super) fn validate(&self) -> Result<()> {
        self.validate_with(ExportSecrets::Nulled)
    }

    /// The envelope's checks under `secrets`: the payload validates with
    /// [`ExportBody::validate_with`].
    pub(super) fn validate_with(&self, secrets: ExportSecrets) -> Result<()> {
        if matches!(self.payload, ExportBody::Pack(_)) {
            return Err(Error::InvalidConfig("nested pack archive envelope".into()));
        }
        // Even when payload was redacted, validate all non-secret envelope fields.
        let mut safe = self.clone();
        safe.payload = ExportBody::Utf8(String::new());
        safe.envelope()?;
        self.payload.validate_with(0, secrets)
    }
}
