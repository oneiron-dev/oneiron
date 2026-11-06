//! SECRET-01 (ONE-1919) repo-side secret manifest — declaration + narrow-only
//! validation (ARCH-0069 S2).
//!
//! A repo carries a `SecretManifest` that **declares** which secrets exist,
//! their custody classes, the effector bindings (which effector may use which
//! ref, at what tier ceiling), and the declared secret *paths* (consumed by
//! SECRET-03 for snapshot exclusion). The manifest may only **NARROW**
//! relative to the vault floors: every declared entry must fit inside the
//! [`SecretCustodyFloor`] band for its class, and every binding's tier
//! ceiling must be ≤ the floor's max. A manifest that asks for more exposure
//! than the floor allows fails with
//! [`SecretError::ManifestWidensFloor`]; a narrower manifest is stored with its
//! narrow binding.
//!
//! The merge rule is `manifest ∧ vault_floor` — most-restrictive wins. At
//! register time the manifest entry is copied onto the record
//! (`manifest_ref`, `declared_paths`, and the floor snapshot) so downstream
//! consumers have a vault-side data source; see
//! [`crate::Vault::register_secret_as_owner`], which reads the manifest from a
//! served repository through [`crate::Vault::origin_secret_manifest`].

pub use oneiron_store::secret_manifest::*;

#[cfg(test)]
mod tests;
