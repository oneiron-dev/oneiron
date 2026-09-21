//! Name-bearing portable kinds, local registrations, and instance envelopes.

use crate::error::{Error, RegistryError, Result};
use crate::registry::{TypeByteZone, zone_of};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact pack source and kind schema bound to an author-scoped global name.
/// Hashes are content identities, not signatures, verdicts, grants, or trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackKindIdentity {
    /// Canonical dotted name, prefixed by `pack` plus a dot.
    pub name: String,
    /// Canonical dotted author-scoped package name (at least two segments).
    pub pack: String,
    /// Hash of the exact installed source tree, supplied by the pack catalog.
    #[serde(with = "super::hex_bytes")]
    pub source_hash: [u8; 32],
    /// Hash of the exact kind schema, supplied by the pack catalog.
    #[serde(with = "super::hex_bytes")]
    pub schema_hash: [u8; 32],
}

/// One local binding. Retired names remain bound to their original identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackKindRegistration {
    pub identity: PackKindIdentity,
    /// `None` only after inactive, unreferenced handle collection.
    pub handle: Option<u8>,
    /// Monotonic local allocation generation, never reset by garbage collection.
    pub generation: u64,
    pub active: bool,
}

/// Sync/export carrier. This is DATA, never permission to execute a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackByteMapSnapshot {
    pub version: u8,
    /// Random local map lineage id, NOT an authority-chain vault id.
    #[serde(with = "super::hex_bytes")]
    pub map_id: [u8; 16],
    pub revision: u64,
    pub registrations: BTreeMap<String, PackKindRegistration>,
    pub slot_generations: BTreeMap<u8, u64>,
}

/// Original data lineage, retained verbatim when remapped. Never authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstanceOrigin {
    #[serde(with = "super::hex_bytes")]
    pub map_id: [u8; 16],
    pub handle: u8,
    pub generation: u64,
}

/// All runtime-pack rows retain identity in the body as well as the local byte.
/// No execution grant, verdict, source trust or auto-admission flag exists here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstanceEnvelope {
    pub version: u8,
    pub kind: PackKindIdentity,
    pub generation: u64,
    pub origin: PackInstanceOrigin,
    pub payload: Vec<u8>,
}

pub(super) fn invalid(reason: &'static str) -> Error {
    Error::Registry(RegistryError::InvalidPackByteMap(reason))
}

impl PackKindIdentity {
    pub fn validate(&self) -> Result<()> {
        // Same canonical grammar and engine-reserved namespaces as predicates;
        // this is shape vetting only and does not author a CLAIM.
        if crate::claim::validate_predicate(&self.pack, false).is_err()
            || crate::claim::validate_predicate(&self.name, false).is_err()
            || !self
                .name
                .strip_prefix(&self.pack)
                .is_some_and(|suffix| suffix.starts_with('.') && suffix.len() > 1)
        {
            return Err(invalid(
                "kind name must be canonical author.pack.kind identity",
            ));
        }
        Ok(())
    }

    /// Stable presentation namespace; never derives identity from a local byte.
    pub(super) fn short_id_prefix(&self) -> String {
        let hash = blake3::hash(self.name.as_bytes());
        let mut prefix = String::from("pk");
        for byte in hash.as_bytes() {
            prefix.push(char::from(b'a' + (byte >> 4)));
            prefix.push(char::from(b'a' + (byte & 15)));
        }
        prefix
    }
}

impl PackInstanceEnvelope {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| invalid("pack instance encoding failed"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid pack instance envelope"))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Stable transport form across receiver-local rematerialization.
    /// The wire byte is a lineage hint, NEVER identity or local admission.
    /// Reverse CRDT/export adapters must use this rather than echoing a local
    /// remapped header/generation into the shared document.
    pub fn canonical_wire_form(&self) -> Result<(u8, Vec<u8>)> {
        let mut wire = self.clone();
        wire.generation = self.origin.generation;
        Ok((self.origin.handle, wire.to_bytes()?))
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.kind.validate()?;
        if self.version != 1
            || self.generation == 0
            || self.origin.generation == 0
            || zone_of(self.origin.handle) != TypeByteZone::PackHandle
            || crate::entity_id::EntityId::from_bytes(self.origin.map_id).is_err()
        {
            return Err(invalid(
                "invalid pack instance version or allocation lineage",
            ));
        }
        Ok(())
    }
}
