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

use heed::RwTxn;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySecret, CustodySubject, Requirement,
};

/// The width of every KS-6 key: an AES-256-GCM key (CALLS `KS-6 leaf ids`,
/// CUSTODY_LEAF_KEY_BYTES).
pub(crate) const CUSTODY_LEAF_KEY_BYTES: usize = 32;

/// One KS-6 key, copied out of its custody entry.
pub(crate) type CredentialLeaf = Zeroizing<[u8; CUSTODY_LEAF_KEY_BYTES]>;

/// Whether `kind` is one of KS-6's: a credential's value, or one of its
/// carriers' keys.
pub(crate) const fn credential_kind(kind: CustodyKind) -> bool {
    matches!(
        kind,
        CustodyKind::CredentialValue
            | CustodyKind::CustodyTransition
            | CustodyKind::CustodyRequestInput
    )
}

/// `credential`'s value subject in `binding`'s custody.
fn value_subject(binding: &CustodyBinding, credential: &EntityId) -> Result<CustodySubject> {
    binding.subject(CustodyKind::CredentialValue, credential.as_bytes())
}

/// One carrier instance's subject: the credential's id, then the instance's.
fn carrier_subject(
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
fn copy_leaf(kind: CustodyKind, secret: &[u8]) -> Result<CredentialLeaf> {
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
pub(crate) enum PlannedCredential {
    /// The custody the plan takes holds its key live: a fork copies it.
    Live,
    /// Destroyed there, or committed to be: the erase stands.
    Retired,
    /// No custody the plan takes holds it, affirmatively: no entry there,
    /// or no custody at all.
    Missing,
}

/// Plans credential `credential`'s value at `generation` through `plan`,
/// the restore's or activation's one plan, by its exact id: a fork copies
/// that generation alone (CALLS `KS-6 required restore set`,
/// ExactPermittedCommittedRefs). A missing key is never refused here: what
/// the row needs decides.
///
/// # Errors
/// Custody faults, never absence.
pub(crate) fn plan_credential_value(
    plan: &mut CustodyPlan,
    credential: &EntityId,
    generation: u32,
) -> Result<PlannedCredential> {
    let id = match plan.source() {
        Some(source) => value_subject(source, credential)?.at(u64::from(generation)),
        None => return Ok(PlannedCredential::Missing),
    };
    Ok(match plan.require_exact_present(&id)? {
        Some(Requirement::Live) => PlannedCredential::Live,
        Some(Requirement::Retired) => PlannedCredential::Retired,
        None => PlannedCredential::Missing,
    })
}

/// Whether the key credential `credential`'s value at `generation` reads,
/// strictly, from the custody `binding` names: a restore's or a fork's
/// read-back of a value it landed sealed. A fault reads as `false`.
pub(crate) fn credential_value_reads_in(
    binding: &CustodyBinding,
    credential: &EntityId,
    generation: u32,
) -> bool {
    value_subject(binding, credential)
        .map(|subject| subject.at(u64::from(generation)))
        .and_then(|id| crate::store::key_custody::LocalCustody::at(binding).read(&id))
        .and_then(|secret| copy_leaf(CustodyKind::CredentialValue, secret.expose()))
        .is_ok()
}

impl Store {
    /// The key credential `credential`'s value at `generation` is sealed
    /// under, minted in `wtxn` when custody holds none there yet, the
    /// binding pinned in the same transaction: published, synced and its
    /// Mint journaled before the row sealed under it commits. The writer
    /// keeps the finisher from every entry, so no custody guard is taken. A
    /// retry of an uncommitted writer finds the entry it published and keeps
    /// its key, its Mint journaled again before this row commits, so no
    /// sealed row ever stands on an unjournaled key; a retired id is never
    /// minted again.
    ///
    /// # Errors
    /// An archived vault, whose custody is its replacement's; a retired
    /// key, which is never minted again; custody faults.
    pub(crate) fn credential_value_leaf_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        credential: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = value_subject(custody.binding(), credential)?.at(u64::from(generation));
        copy_leaf(
            CustodyKind::CredentialValue,
            custody.get_or_create_journaled(&id)?.expose(),
        )
    }

    /// The key credential `credential`'s value at `generation` is sealed
    /// under, read strictly: a retired, damaged or missing entry, or no
    /// custody at all, is an error, never a new key. The caller holds a
    /// writer, or took the custody read guard before its snapshot.
    ///
    /// # Errors
    /// The key is not there to read.
    pub(crate) fn read_credential_value_leaf(
        &self,
        credential: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        let custody = self
            .core
            .key_custody
            .local()
            .ok_or_else(|| CustodyKind::CredentialValue.corrupt())?;
        let id = value_subject(custody.binding(), credential)?.at(u64::from(generation));
        copy_leaf(CustodyKind::CredentialValue, custody.read(&id)?.expose())
    }

    /// Mints the key of one new carrier instance of credential `credential`
    /// (`kind`: a transition or a request's whole input) in `wtxn`: a fresh
    /// random instance id, then the key, published, synced and its Mint
    /// journaled before any byte it seals exists, so an aborted carrier's
    /// key is still found by the credential's id and erased with it (CALLS
    /// `KS-6 leaf deposit`).
    ///
    /// # Errors
    /// An archived vault; a kind that is no carrier's; custody faults.
    #[allow(
        dead_code,
        reason = "KS-6 carrier wire ships off until live leaf delivery lands (FIX-LIST)"
    )]
    pub(crate) fn mint_carrier_leaf_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        kind: CustodyKind,
        credential: &EntityId,
    ) -> Result<([u8; 16], CredentialLeaf)> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let mut instance = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut instance);
        let id = carrier_subject(custody.binding(), kind, credential, &instance)?.at(0);
        let secret = CustodySecret::random(CUSTODY_LEAF_KEY_BYTES);
        custody.publish_minted(&id, &secret)?;
        Ok((instance, copy_leaf(kind, secret.expose())?))
    }

    /// The key of carrier instance `instance` of credential `credential`,
    /// read strictly, as [`Self::read_credential_value_leaf`] reads.
    ///
    /// # Errors
    /// The key is not there to read; a kind that is no carrier's.
    #[allow(
        dead_code,
        reason = "KS-6 carrier wire ships off until live leaf delivery lands (FIX-LIST)"
    )]
    pub(crate) fn read_carrier_leaf(
        &self,
        kind: CustodyKind,
        credential: &EntityId,
        instance: &[u8; 16],
    ) -> Result<CredentialLeaf> {
        let custody = self
            .core
            .key_custody
            .local()
            .ok_or_else(|| kind.corrupt())?;
        let id = carrier_subject(custody.binding(), kind, credential, instance)?.at(0);
        copy_leaf(kind, custody.read(&id)?.expose())
    }

    /// Every custody subject credential `credential` holds here: its value's
    /// and each carrier instance's, read from the directory names alone
    /// (the prefix catalog, CALLS `KS-6 leaf ids`), in id order. No
    /// custody holds none.
    ///
    /// # Errors
    /// Custody faults.
    #[allow(
        dead_code,
        reason = "KS-6 part 2's erase stages every subject this lists (FIX-LIST)"
    )]
    pub(crate) fn credential_custody_subjects(
        &self,
        credential: &EntityId,
    ) -> Result<Vec<CustodySubject>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        let mut subjects = Vec::new();
        for kind in [
            CustodyKind::CredentialValue,
            CustodyKind::CustodyTransition,
            CustodyKind::CustodyRequestInput,
        ] {
            subjects.extend(custody.subjects_with_prefix(kind, credential.as_bytes())?);
        }
        Ok(subjects)
    }
}
