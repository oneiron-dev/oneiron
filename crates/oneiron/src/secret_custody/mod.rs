//! ARCH-0069 secret custody — SECRET-01 (ONE-1919): custody classes, the
//! custody record that is the secret value's home, repo-side manifest
//! declaration, and vault-resident custody floors.
//!
//! # Custody classes (S1/S2)
//!
//! * `custody-portable` — the value may leave this device (the default
//!   reach; the ONE-1865 per-credential dial narrows it). No sync door
//!   carries it yet: see the seal below.
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
//! same-vault sync, cross-vault export, receipts, or logs. A peer cannot prove
//! the owner wrote a custody body, so every replicated door refuses the type
//! byte and every sync egress drops it (`reject_secret_custody_byte`). `Debug`
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
//! * the `Vault` doors: [`Vault::register_secret`](crate::Vault::register_secret),
//!   [`Vault::resolve_secret_ref`](crate::Vault::resolve_secret_ref), [`Vault::get_secret_metadata`](crate::Vault::get_secret_metadata), and the
//!   SECRET-02 value-read door `Vault::get_secret_value_in_txn`;
//! * the owner's registration door,
//!   [`Vault::register_secret_as_owner`](crate::Vault::register_secret_as_owner);
//! * reveal by handle (OF-560): an agent's `reveal`, `wait` and `describe`,
//!   the owner's answer to a reveal's ask, and the owner's own read,
//!   [`Vault::reveal_secret_as_owner`](crate::Vault::reveal_secret_as_owner).
//! * use by handle (OF-560): an agent hands a secret to one trusted
//!   operation and gets its result back, never the value, under the custody
//!   binding alone; the owner adds that binding with
//!   [`Vault::bind_secret_as_owner`](crate::Vault::bind_secret_as_owner).
//!
//! Companion [`crate::secret_manifest`] owns the repo-side TOML declaration
//! and the narrow-only validator (manifest ∧ vault floor, most-restrictive
//! wins).

mod codec;
mod doors;
mod floor;
mod found_keys;
mod masked_files;
mod owner_door;
mod reveal;
mod transition;
mod types;
mod use_handle;

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

pub(crate) use self::codec::{CUSTODY_SEAL_REASON, reject_secret_custody_byte};
pub use self::codec::{decode_secret_custody_body, encode_secret_custody_body};
pub(crate) use self::doors::{
    CustodyWrite, SecretCustodyAdmission, put_secret_custody_in_txn,
    read_secret_custody_admission_in_txn, read_secret_custody_in_txn,
    refuse_bindings_wider_than_live_floor, register_custody_in_txn, resolve_secret_ref_in_txn,
    restore_secret_custody_in_txn,
};
pub(crate) use self::floor::{PolicyManifestWalkError, policy_manifest_bodies_strict};
pub use self::found_keys::{
    FOUND_KEY_REASON_NOT_A_SECRET, FoundKeyAction, FoundKeyCard, FoundKeyNotice, FoundKeySettled,
    NOTIFICATION_PRODUCER_FOUND_KEY,
};
pub(crate) use self::found_keys::{
    FoundNote, KeptValues, note_found_keys_in_txn, raise_found_key_notices_in_txn,
    settle_found_key_in_txn,
};
pub use self::masked_files::SecretSight;
pub(crate) use self::masked_files::{
    KeyPlaces, KeySpan, MASKED_FILE_BAND, MaskedFile, MemberKeys, MemberStep, filled,
    holds_masked_keys_in_txn, masked_file_in_txn, put_masked_file_in_txn, sighted_bytes_in_txn,
};
pub use self::owner_door::{
    ManifestSource, OwnerSecretRegistration, RequestedBinding, SecretRegistered,
};
pub use self::reveal::{
    HandleReveal, NO_PROJECT_SELECTOR, OwnerSecretReveal, REVEAL_ASK_TTL_SECS,
    REVEAL_LEASE_TTL_SECS, REVEAL_TEXT_MAX_BYTES, RevealTarget, SECRET_REVEAL_REASON_ASKED,
    SECRET_REVEAL_REASON_OWNER, SecretHandleCard, SecretProvenance, SecretRevealAnswer,
    SecretRevealAnswered, SecretRevealAsk, SecretRevealDecision, SecretRevealReceipt,
    SecretRevealState,
};
pub(crate) use self::reveal::{
    RevealAsker, RevealAuthority, parse_secret_handle, reveal_value_in_txn,
};
pub(crate) use self::transition::{
    CustodyApplied, CustodyTransition, apply_custody_transition_in_txn, custody_transitions,
    remember_custody_transition_in_txn, reseal_custody_transitions_in_txn,
    write_custody_transition_in_txn,
};
pub use self::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SECRET_NAME_INDEX_PREFIX, SECRET_NAME_MAX_BYTES, SECRET_SCOPE_READ, SecretBinding,
    SecretCustodyFloor, SecretCustodyMetadata, SecretCustodyRecord, SecretCustodyStatus, TierBand,
};
pub(crate) use self::use_handle::SecretUser;
pub use self::use_handle::{
    SECRET_BIND_DOOR, SECRET_BIND_REASON, SECRET_USE_OPERATIONS, SECRET_USE_REASON,
    SecretBindRequest, SecretBound, SecretUseDecision, SecretUseOperation, SecretUseOutcome,
    SecretUseReceipt, SecretUseSend,
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
