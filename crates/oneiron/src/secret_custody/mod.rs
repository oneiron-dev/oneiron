//! ARCH-0069 secret custody — SECRET-01 (ONE-1919): custody classes, the
//! custody record that is the secret value's home, repo-side manifest
//! declaration, and vault-resident custody floors.
//!
//! # Custody classes (S1/S2)
//!
//! * `custody-portable` — the value may replicate beyond this device (the
//!   default reach; the ONE-1865 per-credential dial narrows it).
//! * `custody-device-bound` — the value is pinned to this device.
//! * `cross-vault` — door-only: the value never replicates at all.
//!
//! The classes grade **exposure of the secret VALUE** (ARCH-0069 S1
//! carve-out (a)): they are custody postures over where the value may live,
//! never a device tier and never a claim on the credential. Under the
//! host-root authority model (OF-452 D1/D7/D10) there is no hardware-anchored
//! custody principal and no device-lease key plane; the authority principal
//! for any cross-boundary use is the **host-minted capability slip**
//! (verbs+facets+lifetime, minted from the vault's authority log). Enrolment
//! is pairing (D7). In-process callers name their `effector` string honestly
//! or not at all; the receipt trail exists so misuse is never silent. This
//! module does not pretend the in-process effector string is a cryptographic
//! binding — it is the declared scope the slip's cross-boundary authority is
//! narrowed against, and the typed deny (`SecretBindingDenied`) is the
//! fail-closed door when no binding covers `(secret_ref, effector)`.
//!
//! # The value never leaves the body (S1 plane discipline)
//!
//! `SecretCustodyRecord.value_bytes` is **plaintext bytes at rest under the
//! vault DEK plane** — the same at-rest protection every entity body gets.
//! The custody discipline is about planes, not a second encryption layer:
//! the value NEVER leaves this body into claims (secrets are never claims),
//! never into the CRDT plane (the interim ONE-1865 guard seals the type byte
//! from the sync selector), never into export, receipts, or logs. `Debug`
//! for the record redacts the value; `SecretCustodyMetadata` has no value
//! field by construction.
//!
//! # Module map
//!
//! * wire/keystone types: [`CustodyClass`], [`CustodyTier`], [`TierBand`],
//!   [`SecretCustodyFloor`], [`SecretBinding`], [`SecretCustodyStatus`],
//!   [`SecretCustodyRecord`], [`SecretCustodyMetadata`];
//! * body codec: [`SECRET_CUSTODY_BODY_KEYS`], [`encode_secret_custody_body`],
//!   [`decode_secret_custody_body`];
//! * the ONE strict walk over the vault's indexed POLICY_MANIFEST bodies,
//!   shared by every security consumer of that plane:
//!   `policy_manifest_bodies_strict`;
//! * floor resolution over those bodies: [`SecretCustodyFloor::resolve`];
//! * the `Vault` doors: [`Vault::register_secret`],
//!   [`Vault::resolve_secret_ref`], [`Vault::get_secret_metadata`], and the
//!   SECRET-02 value-read door `Vault::get_secret_value_in_txn`.
//!
//! Companion [`crate::secret_manifest`] owns the repo-side TOML declaration
//! and the narrow-only validator (manifest ∧ vault floor, most-restrictive
//! wins).

mod codec;
mod doors;
mod floor;
mod types;

/// MessagePack keys the custody floor reads out of POLICY_MANIFEST bodies.
mod floor_keys {
    pub(super) const PORTABLE_MIN: &str = "secret.custody.floor.portable.min";
    pub(super) const PORTABLE_MAX: &str = "secret.custody.floor.portable.max";
    pub(super) const DEVICE_BOUND_MIN: &str = "secret.custody.floor.device_bound.min";
    pub(super) const DEVICE_BOUND_MAX: &str = "secret.custody.floor.device_bound.max";
    pub(super) const CROSS_VAULT_MIN: &str = "secret.custody.floor.cross_vault.min";
    pub(super) const CROSS_VAULT_MAX: &str = "secret.custody.floor.cross_vault.max";
    pub(super) const ROTATION_MAX_AGE_SECS: &str = "secret.custody.rotation_max_age_secs";
    pub(super) const ENV_BINDINGS: &str = "secret.custody.env_bindings";
}

pub(crate) use self::codec::reject_secret_custody_byte;
pub use self::codec::{decode_secret_custody_body, encode_secret_custody_body};
pub(crate) use self::doors::{
    SecretCustodyAdmission, put_secret_custody_in_txn, read_secret_custody_admission_in_txn,
    read_secret_custody_in_txn, refuse_bindings_wider_than_live_floor, resolve_secret_ref_in_txn,
};
// `decode_secret_custody_admission_body` is only consumed by in-crate tests
// (`secret_lease/tests.rs`); a plain `pub(crate)` re-export would warn as
// unused in non-test builds, so the seam provides it under `cfg(test)`.
#[cfg(test)]
pub(crate) use self::doors::decode_secret_custody_admission_body;
pub(crate) use self::floor::{
    PolicyManifestWalkError, policy_manifest_bodies_strict, policy_manifest_body_map,
};
pub use self::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SECRET_NAME_INDEX_PREFIX, SECRET_SCOPE_READ, SecretBinding, SecretCustodyFloor,
    SecretCustodyMetadata, SecretCustodyRecord, SecretCustodyStatus, TierBand,
};

#[cfg(test)]
mod tests;

// The flat `secret_custody.rs` module used to provide its crate/std import
// header to the sibling test module through `use super::*`. After the
// directory split the seam re-imports those names so `tests.rs` resolves
// exactly as it did before. Secret-custody-internal items all arrive via
// the `pub` / `pub(crate)` re-exports above (`merge` is `pub(super)` for
// the floor-merge test), so no child glob is needed here.
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SECRET_CUSTODY};
#[cfg(test)]
use crate::store::Store;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeMap;
