//! Core half of `secret_record::types`: its store-layer items live in
//! `oneiron_store::secret_record::types` and are re-exported here. The custody
//! record stays in the engine: Rust privacy stops at the crate, so only here
//! does `pub(crate)` keep the record's value and manifest reference away from
//! every other crate.

use std::fmt;

pub use oneiron_store::secret_record::types::*;

/// Entity body for `ENTITY_TYPE_SECRET_CUSTODY`: the secret value's home.
///
/// In memory, `value_bytes` is the opened value, which NEVER leaves this
/// record into claims / CRDT / export / receipts / logs. `Debug` redacts it.
/// At rest (stored schema 4, KS-6) the value is sealed under its
/// generation's erasable custody key (`storage_seal`); this record is the
/// opened form, stamped as its plaintext DTO is.
/// `policy_floor_snapshot` records the floor at register time for audit;
/// `manifest_ref` + `declared_paths` are copied from the manifest entry so
/// downstream consumers (SECRET-03, snapshot exclusion) have a vault-side
/// data source.
/// No `Serialize`/`Deserialize`: a derived serializer would emit `value_bytes`
/// into whatever format a caller reached for (JSON log line, receipt, wire
/// payload) with no door in the way — the same leak `Debug` is hand-rolled to
/// prevent. The body codec below is the ONE serialization of this type, and it
/// exists to write the vault-resident body, nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretCustodyRecord {
    /// Body schema version (`SECRET_CUSTODY_SCHEMA_VERSION` at encode).
    pub schema_version: u16,
    /// Unique-per-vault secret name; see [`SECRET_NAME_INDEX_PREFIX`].
    pub name: String,
    /// The custody class — the value-exposure posture.
    pub class: CustodyClass,
    /// The OF-422 portable dial. Stored as data from day one so ONE-1865
    /// needs no migration; enforcement (replication locality) is ONE-1865's.
    /// On a `cross-vault` record this is stored-but-inert.
    pub device_only: bool,
    /// Whether a model may receive plaintext through the reveal doors.
    /// Private copies keep this false independently of their class and bindings.
    pub model_reveal_allowed: bool,
    /// The secret value bytes (plaintext under the DEK plane; redacted in
    /// `Debug`; never serialized into logs/receipts/claims/CRDT).
    ///
    /// `pub(crate)`, not `pub`: a value read must go through the bound door
    /// [`Vault::get_secret_value_in_txn`] (which enforces the effector binding)
    /// rather than reaching the field directly on a decoded record. Within the
    /// crate the codec and doors move the bytes; out-of-crate there is no raw
    /// accessor at all — the value never crosses the crate boundary unbound.
    pub(crate) value_bytes: Vec<u8>,
    /// Lifecycle status.
    pub status: SecretCustodyStatus,
    /// Unix seconds at registration.
    pub registered_at: u64,
    /// Unix seconds of the last rotation (SECRET-04 stamps it).
    pub rotated_at: Option<u64>,
    /// Rotation generation counter.
    pub rotation_generation: u32,
    /// Effector bindings on this record.
    pub bindings: Vec<SecretBinding>,
    /// The manifest path this entry was registered from (empty when
    /// registered outside a manifest flow). Read via [`Self::manifest_ref`];
    /// `pub(crate)` keeps the struct's serde/codec construction inside the
    /// crate while exposing only a read-only reference outward.
    pub(crate) manifest_ref: String,
    /// Declared secret paths copied from the manifest entry (SECRET-03).
    pub declared_paths: Vec<String>,
    /// The resolved vault floor at register time (audit).
    pub policy_floor_snapshot: SecretCustodyFloor,
}

// Deliberately hand-rolled: never print `value_bytes` (S1). The grep-guard
// test asserts `value_bytes` does not appear in the Debug output.
impl fmt::Debug for SecretCustodyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCustodyRecord")
            .field("schema_version", &self.schema_version)
            .field("name", &self.name)
            .field("class", &self.class)
            .field("device_only", &self.device_only)
            .field("model_reveal_allowed", &self.model_reveal_allowed)
            .field(
                "value_bytes",
                &format_args!("<redacted {} bytes>", self.value_bytes.len()),
            )
            .field("status", &self.status)
            .field("registered_at", &self.registered_at)
            .field("rotated_at", &self.rotated_at)
            .field("rotation_generation", &self.rotation_generation)
            .field("bindings", &self.bindings)
            .field("manifest_ref", &self.manifest_ref)
            .field("declared_paths", &self.declared_paths)
            .field("policy_floor_snapshot", &self.policy_floor_snapshot)
            .finish()
    }
}

impl SecretCustodyRecord {
    /// Projects to the value-less metadata read.
    #[must_use]
    pub fn metadata(&self) -> SecretCustodyMetadata {
        SecretCustodyMetadata {
            name: self.name.clone(),
            class: self.class,
            status: self.status,
            registered_at: self.registered_at,
            rotated_at: self.rotated_at,
            rotation_generation: self.rotation_generation,
            bindings: self.bindings.clone(),
        }
    }

    /// Looks up the binding covering `effector`. Drives tier admission.
    #[must_use]
    pub fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }

    /// The manifest path this entry was registered from — the read-only,
    /// binding-door-safe view of `manifest_ref` for out-of-crate consumers
    /// (SECRET-03 snapshot exclusion reads it from the record's body decode).
    /// Empty when the record was registered outside a manifest flow.
    #[must_use]
    pub fn manifest_ref(&self) -> &str {
        &self.manifest_ref
    }
}
