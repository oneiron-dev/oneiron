//! The credential custody client (KS-6, FIX-LIST 5687 part 1): one erasable
//! key per credential generation and per retained carrier instance, on the
//! one typed custody every other client shares (KS-1).
//!
//! A credential's value is sealed at rest under its `CredentialValue` key,
//! item = the custody record's id, generation = the record's rotation
//! generation (CALLS `KS-6 leaf ids`). The key is minted in the writer that
//! stores the sealed value, which pins the custody binding in the same
//! transaction: the entry is published, synced and its Mint journaled before
//! any row sealed under it commits. A transition instance and a request's
//! whole protected input each take a key of their own (`CustodyTransition`,
//! `CustodyRequestInput`): item = the credential's id then a random
//! instance id minted before any byte it seals, slot 0, so every key a
//! credential ever had is found by its id alone, from the custody
//! directory names (the prefix catalog), abandoned and unenacted ones
//! included. Custody owns storage and lifecycle; who may open a key, and
//! which head may carry it, is `secret_custody`'s policy.
//!
//! A connector call's resume state (FIX 9157) seals the same way under its
//! `ConnectorResume` key: item = the call ref, generation = the caller's
//! round generation, retired with its PENDING_CALLS row.

pub mod erase;

use heed::RwTxn;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::key_custody::files::EntryState;
use crate::key_custody::fork::Requirement;
use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySecret;
use crate::key_custody::identity::CustodySubject;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::StoreError;
use oneiron_contracts::entity_id::EntityId;

pub use crate::credential_custody::erase::FenceLookup;
pub use crate::credential_custody::erase::credential_erases_staged;

/// The width of every KS-6 key: an AES-256-GCM key (CALLS `KS-6 leaf ids`,
/// CUSTODY_LEAF_KEY_BYTES).
pub const CUSTODY_LEAF_KEY_BYTES: usize = 32;

/// One KS-6 key, copied out of its custody entry.
pub type CredentialLeaf = Zeroizing<[u8; CUSTODY_LEAF_KEY_BYTES]>;

/// Whether `kind` is one of the per-record sealed-value kinds: KS-6's (a
/// credential's value, or one of its carriers' keys) or a connector call's
/// resume (FIX 9157).
pub const fn credential_kind(kind: CustodyKind) -> bool {
    matches!(
        kind,
        CustodyKind::CredentialValue
            | CustodyKind::CustodyTransition
            | CustodyKind::CustodyRequestInput
            | CustodyKind::ConnectorResume
    )
}

/// `credential`'s value subject in `binding`'s custody.
pub fn value_subject(binding: &CustodyBinding, credential: &EntityId) -> Result<CustodySubject> {
    binding.subject(CustodyKind::CredentialValue, credential.as_bytes())
}

/// `call_ref`'s resume subject in `binding`'s custody (FIX 9157).
pub fn resume_subject(binding: &CustodyBinding, call_ref: &EntityId) -> Result<CustodySubject> {
    binding.subject(CustodyKind::ConnectorResume, call_ref.as_bytes())
}

/// One carrier instance's subject: the credential's id, then the instance's.
pub fn carrier_subject(
    binding: &CustodyBinding,
    kind: CustodyKind,
    credential: &EntityId,
    instance: &[u8; 16],
) -> Result<CustodySubject> {
    if !matches!(
        kind,
        CustodyKind::CustodyTransition | CustodyKind::CustodyRequestInput
    ) {
        return Err(kind.corrupt());
    }
    let mut item = Vec::with_capacity(32);
    item.extend_from_slice(credential.as_bytes());
    item.extend_from_slice(instance);
    binding.subject(kind, &item)
}

/// A key's bytes: exactly [`CUSTODY_LEAF_KEY_BYTES`].
pub fn copy_leaf(kind: CustodyKind, secret: &[u8]) -> Result<CredentialLeaf> {
    let mut leaf = Zeroizing::new([0; CUSTODY_LEAF_KEY_BYTES]);
    if secret.len() != leaf.len() {
        return Err(kind.corrupt());
    }
    leaf.copy_from_slice(secret);
    Ok(leaf)
}

/// What a restore's or an activation's plan finds for one credential value
/// its rows commit to (KS-6 part 2, CALLS `KS-6 required restore set`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedCredential {
    /// The custody the plan takes holds its key live: a fork copies it.
    Live,
    /// Destroyed there, or committed to be: the erase stands.
    Retired,
    /// No custody the plan takes holds it, affirmatively: no entry there,
    /// or no custody at all.
    Missing,
}
