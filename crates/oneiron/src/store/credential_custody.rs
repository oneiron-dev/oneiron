//! Core half of `store::credential_custody`: its store-layer items live in `oneiron_store::credential_custody` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::credential_custody::*;

pub(crate) use self::erase::{FenceLookup, credential_erases_staged};
pub(crate) use self::fences::CredentialFences;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySecret, CustodySubject, EntryState,
    Requirement, RetireCause, RetirementIntent, stage_retirement_in_txn,
};
use heed::RwTxn;
use rand::RngCore;
use zeroize::Zeroizing;

mod erase;
mod fences;

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

/// The key credential `credential`'s value at `generation` is sealed
/// under, read strictly from the custody `binding` names: an activation's
/// read-back from the custody it forked, before that binding commits.
///
/// # Errors
/// The key is not there to read.
pub(crate) fn credential_value_leaf_in(
    binding: &CustodyBinding,
    credential: &EntityId,
    generation: u32,
) -> Result<CredentialLeaf> {
    let id = value_subject(binding, credential)?.at(u64::from(generation));
    let secret = crate::store::key_custody::LocalCustody::at(binding).read(&id)?;
    copy_leaf(CustodyKind::CredentialValue, secret.expose())
}

impl Store {
    /// Plans exactly the resume generation a retained carrier commits to.
    pub(crate) fn plan_connector_resume(
        plan: &mut CustodyPlan,
        call_ref: &EntityId,
        generation: u32,
    ) -> Result<Option<Requirement>> {
        let Some(source) = plan.source() else {
            return Ok(None);
        };
        let id = resume_subject(source, call_ref)?.at(u64::from(generation));
        plan.require_exact_present(&id)
    }

    /// Reads a resume leaf from an activation's fork, never the old binding.
    pub(crate) fn connector_resume_leaf_in(
        binding: &CustodyBinding,
        call_ref: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        let id = resume_subject(binding, call_ref)?.at(u64::from(generation));
        let secret = crate::store::key_custody::LocalCustody::at(binding).read(&id)?;
        copy_leaf(CustodyKind::ConnectorResume, secret.expose())
    }

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
    /// key, which is never minted again, nor any of an erased credential's
    /// (KS-6 part 2); custody faults.
    pub(crate) fn credential_value_leaf_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        credential: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.refuse_erased_credential_in_txn(wtxn, credential)?;
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = value_subject(custody.binding(), credential)?.at(u64::from(generation));
        copy_leaf(
            CustodyKind::CredentialValue,
            custody.get_or_create(&id)?.expose(),
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

    /// Whether a credential value's key is missing or retired, without
    /// reading key bytes or opening its value. The caller holds a writer,
    /// or took the custody read guard before its snapshot. This takes no
    /// second guard; false is not proof of value readability.
    ///
    /// # Errors
    /// Custody faults, never absence.
    pub(crate) fn credential_value_key_unavailable(
        &self,
        credential: &EntityId,
        generation: u32,
    ) -> Result<bool> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(true);
        };
        let id = value_subject(custody.binding(), credential)?.at(u64::from(generation));
        Ok(matches!(
            custody.state(&id)?,
            EntryState::Missing | EntryState::Retired
        ))
    }

    /// The key connector call `call_ref`'s resume state at `generation` is
    /// sealed under (FIX 9157), minted in `wtxn` when custody holds none
    /// there yet, the binding pinned in the same transaction: published,
    /// synced and its Mint journaled before the row sealed under it commits.
    /// The writer keeps the finisher from every entry, so no custody guard
    /// is taken. A retry of an uncommitted writer finds the entry it
    /// published and keeps its key, its Mint journaled again before this row
    /// commits, so no sealed row ever stands on an unjournaled key; a
    /// retired id is never minted again.
    ///
    /// # Errors
    /// An archived vault, whose custody is its replacement's; a retired
    /// key, which is never minted again; custody faults.
    pub(crate) fn connector_resume_leaf_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        call_ref: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let id = resume_subject(custody.binding(), call_ref)?.at(u64::from(generation));
        copy_leaf(
            CustodyKind::ConnectorResume,
            custody.get_or_create(&id)?.expose(),
        )
    }

    /// The key connector call `call_ref`'s resume state at `generation` is
    /// sealed under (FIX 9157), read strictly: a retired, damaged or missing
    /// entry, or no custody at all, is an error, never a new key. The caller
    /// holds a writer, or took the custody read guard before its snapshot.
    ///
    /// # Errors
    /// The key is not there to read.
    pub(crate) fn read_connector_resume_leaf(
        &self,
        call_ref: &EntityId,
        generation: u32,
    ) -> Result<CredentialLeaf> {
        let custody = self
            .core
            .key_custody
            .local()
            .ok_or_else(|| CustodyKind::ConnectorResume.corrupt())?;
        let id = resume_subject(custody.binding(), call_ref)?.at(u64::from(generation));
        copy_leaf(CustodyKind::ConnectorResume, custody.read(&id)?.expose())
    }

    /// Mints the key of one new carrier instance of credential `credential`
    /// (`kind`: a transition or a request's whole input) in `wtxn`: a fresh
    /// random instance id, then the key, published, synced and its Mint
    /// journaled before any byte it seals exists, so an aborted carrier's
    /// key is still found by the credential's id and erased with it (CALLS
    /// `KS-6 leaf deposit`).
    ///
    /// # Errors
    /// An archived vault; an erased credential (KS-6 part 2); a kind that
    /// is no carrier's; custody faults.
    pub(crate) fn mint_carrier_leaf_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        kind: CustodyKind,
        credential: &EntityId,
    ) -> Result<([u8; 16], CredentialLeaf)> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.refuse_erased_credential_in_txn(wtxn, credential)?;
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

    /// Stages retirement of carrier instance `instance` of credential
    /// `credential` (`kind`) in `wtxn` once what it carried is answered
    /// (FIX 7402): a Retention intent, which the finisher carries out and
    /// which is never an erase's evidence, so it fences nothing. Custody
    /// that holds no such key here, none at all, or an archived vault's,
    /// stages none. Returns whether it staged one.
    ///
    /// # Errors
    /// A kind that is no carrier's; custody and storage faults.
    pub(crate) fn stage_carrier_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        kind: CustodyKind,
        credential: &EntityId,
        instance: &[u8; 16],
    ) -> Result<bool> {
        if self.core.gate_custody_archived() {
            return Ok(false);
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(false);
        };
        let subject = carrier_subject(custody.binding(), kind, credential, instance)?;
        let Some(through) = custody.newest_generation(&subject)? else {
            return Ok(false);
        };
        if custody.first_unretired(&subject)? > through {
            return Ok(false);
        }
        stage_retirement_in_txn(
            self,
            wtxn,
            &RetirementIntent {
                subject,
                through,
                cause: RetireCause::Retention,
            },
        )?;
        Ok(true)
    }

    /// Every custody subject credential `credential` holds here: its value's
    /// and each carrier instance's, read from the directory names alone
    /// (the prefix catalog, CALLS `KS-6 leaf ids`), in id order. No
    /// custody holds none.
    ///
    /// # Errors
    /// Custody faults.
    pub(crate) fn credential_custody_subjects(
        &self,
        credential: &EntityId,
    ) -> Result<Vec<CustodySubject>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        let mut subjects = Vec::new();
        for kind in erase::CREDENTIAL_PARENT_KINDS {
            subjects.extend(custody.subjects_with_prefix(kind, credential.as_bytes())?);
        }
        Ok(subjects)
    }

    /// Stages retirement of every ConnectorResume generation of connector
    /// call `call_ref` (FIX 9157) in `wtxn`, the writer that deletes its
    /// PENDING_CALLS row: one erase intent through the newest generation
    /// custody holds, so a restored pre-erase image cannot open them. The
    /// custody finisher carries it out after commit. No custody, or an
    /// archived vault whose custody is its replacement's, stages none.
    ///
    /// # Errors
    /// Custody and storage faults.
    pub(crate) fn stage_connector_resume_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        call_ref: &EntityId,
    ) -> Result<()> {
        if self.core.gate_custody_archived() {
            return Ok(());
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let subject = resume_subject(custody.binding(), call_ref)?;
        let Some(through) = custody.newest_generation(&subject)? else {
            return Ok(());
        };
        stage_retirement_in_txn(
            self,
            wtxn,
            &RetirementIntent {
                subject,
                through,
                cause: RetireCause::Erase,
            },
        )
    }

    /// Carries out every staged connector resume key retirement (FIX 9157),
    /// an interrupted process's included, in the custody finisher's order.
    /// Only an erase's intent runs: a resume key retires with its call's
    /// row and for nothing else.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, an intent of another
    /// cause, and custody faults.
    pub(crate) fn finish_connector_resume_retirements(&self) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::ConnectorResume, |_, intent| {
            if intent.cause == RetireCause::Erase {
                Ok(true)
            } else {
                Err(Error::CorruptedIndex(
                    "connector resume keys retire for an erase only",
                ))
            }
        })
    }
}
