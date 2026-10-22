//! An erased credential stays erased (KS-6 part 2, FIX-LIST 7403, 5687): one
//! terminal fence per credential id an authorized erase reached, the
//! discovery that stages every key the id names to retire, and the finisher
//! that carries them out.
//!
//! An owner's erase of a custody record, and a run-bound seat's end (FIX
//! 8028), write the fence first, in the erase's own transaction: value-free
//! and permanent. Then the prefix catalog lists every custody subject the id
//! names (its value's, and every transition's and request input's instance,
//! abandoned ones included) and an erase intent is staged for each through
//! the newest generation custody holds of it. A catalog or generation read
//! that faults leaves the fence's discovery owed, warned: the finisher, a
//! reopen and upkeep retry it, and the erase's receipt never reads complete
//! meanwhile (CALLS `KS-6 erase discovery fault`). No erase is refused for
//! it.
//!
//! The fence closes the id, every generation and instance of it: no key is
//! minted under it again, no body is put under it again, and no image, fork,
//! restore, activation, archive or transition brings it back (CALLS `KS-6
//! erase fence form`). Re-entering a credential takes a new id. A fence that
//! does not read where a path would install or re-admit a handle from an
//! image or a fork withholds that handle alone, PendingCustody, warned;
//! anywhere else today's path goes on, warned.
//!
//! Only an erase retires a credential's keys: nothing stages one for a
//! rotate or a revoke, and the finisher runs an erase's intent for a fenced
//! id alone. So a retired credential key in custody a restore admitted is
//! erase-only evidence: a restore derives its parent's fence from it, never
//! from a peer's tombstone.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodySubject, LocalCustody, RetireCause, RetirementIntent,
    retirement_in_txn, stage_retirement_in_txn,
};

/// The kinds a credential's id names in custody, by its id as their items'
/// first 16 bytes: its value, its transitions' and its request inputs'
/// instances. A connector call's resume key is no credential's.
pub(crate) const CREDENTIAL_PARENT_KINDS: [CustodyKind; 3] = [
    CustodyKind::CredentialValue,
    CustodyKind::CustodyTransition,
    CustodyKind::CustodyRequestInput,
];

/// How an erase keeps a credential erased (CALLS `KS-6 erase fence form`,
/// Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyEraseFenceForm {
    /// One value-free LIVE fence per erased id, permanent, its discovery
    /// owed until every key the id names is staged to retire. A fence that
    /// does not read where a path would install or re-admit a handle from
    /// an image or a fork withholds that one handle, PendingCustody with a
    /// warned retry, and everything else proceeds; anywhere else today's
    /// path goes on, warned. Nothing is refused, nothing comes back.
    TerminalParentIdWithPendingDiscovery,
}

const CUSTODY_ERASE_FENCE_FORM: CustodyEraseFenceForm =
    CustodyEraseFenceForm::TerminalParentIdWithPendingDiscovery;

/// What a discovery fault leaves (CALLS `KS-6 erase discovery fault`,
/// Engine 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyEraseDiscoveryFault {
    /// The fence stands, its discovery owed: the finisher, a reopen and
    /// upkeep retry it, and the erase's receipt reads pending until a full
    /// discovery completes. Never a refused erase, an empty success, a
    /// timeout or an expiry.
    FenceAndRetryBeforeComplete,
}

const CUSTODY_ERASE_DISCOVERY_FAULT: CustodyEraseDiscoveryFault =
    CustodyEraseDiscoveryFault::FenceAndRetryBeforeComplete;

/// Where one fence's discovery stands: one byte, `0` owed, `1` complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Discovery {
    Owed,
    Complete,
}

impl RawValue for Discovery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Owed => 0,
            Self::Complete => 1,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Owed),
            [1] => Ok(Self::Complete),
            _ => Err(Error::CorruptedIndex("credential erase fence").into()),
        }
    }
}

/// Each erased credential's fence, by its record id.
const FENCES: SideTable<EntityId, Discovery, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_ERASE);

/// The `vault_meta` prefix of the fences, for readers of raw rows.
pub(crate) fn credential_fence_prefix() -> &'static [u8] {
    FENCES.decl().prefix
}

/// The credential a custody subject of one of [`CREDENTIAL_PARENT_KINDS`]
/// belongs to: its item's first 16 bytes.
fn parent_of(subject: &CustodySubject) -> Option<EntityId> {
    if !CREDENTIAL_PARENT_KINDS.contains(&subject.kind()) {
        return None;
    }
    let id = <[u8; 16]>::try_from(subject.item().get(..16)?).ok()?;
    EntityId::from_bytes(id).ok()
}

/// What a fence says of one credential id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FenceLookup {
    /// An authorized erase reached it: it never comes back.
    Fenced,
    /// Its fence, or the evidence it is derived from, did not read.
    Faulted,
    /// No erase reached it.
    Clear,
}

/// The erase an id's write would bring back (CALLS `KS-6 erase fence
/// form`): the backstop every common write seam refuses with.
fn erased_id() -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(
        "an erased credential's id is never written again; re-enter it under a new id",
    ))
}

/// What a restore, a fork or an activation knows of erased credentials:
/// the ids a live source's fences, the live rows a restore carries, or
/// retired credential keys in the custody it takes fence, and those whose
/// evidence did not read.
#[derive(Clone, Debug, Default)]
pub(crate) struct CredentialFences {
    fenced: BTreeSet<EntityId>,
    faulted: BTreeSet<EntityId>,
    /// A fence row or a custody listing that names no one id did not read:
    /// every credential the path would re-admit is withheld, pending.
    unreadable: bool,
}

impl CredentialFences {
    /// The fences among raw `vault_meta` rows: a live vault's, or the live
    /// rows a restore carries. A fence row whose key does not read fences
    /// no one id: every credential reads faulted then.
    pub(crate) fn in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Self {
        let mut fences = Self::default();
        for (key, _) in rows {
            let Some(rest) = key.strip_prefix(credential_fence_prefix()) else {
                continue;
            };
            match <EntityId as SideKey>::decode_key(rest) {
                Some(id) => {
                    fences.fenced.insert(id);
                }
                None => fences.unreadable = true,
            }
        }
        fences
    }

    /// Adds every fence of `other`.
    pub(crate) fn merge(&mut self, other: &Self) {
        self.fenced.extend(other.fenced.iter().copied());
        self.faulted.extend(other.faulted.iter().copied());
        self.unreadable |= other.unreadable;
    }

    /// Adds the fences the custody `binding` names proves: the credential of
    /// each of its subjects whose first generation is retired, which only an
    /// erase does to a credential's keys. A listing or a marker read that
    /// faults is warned, and leaves those credentials faulted.
    pub(crate) fn derive_from(&mut self, binding: &CustodyBinding) {
        let custody = LocalCustody::at(binding);
        for kind in CREDENTIAL_PARENT_KINDS {
            let subjects = match custody.subjects_with_prefix(kind, &[]) {
                Ok(subjects) => subjects,
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "credential custody did not list; each credential it would re-admit is \
                         withheld, pending"
                    );
                    self.unreadable = true;
                    continue;
                }
            };
            for subject in subjects {
                let Some(parent) = parent_of(&subject) else {
                    continue;
                };
                if self.fenced.contains(&parent) {
                    continue;
                }
                match custody.retired(&subject.at(0)) {
                    Ok(true) => {
                        self.fenced.insert(parent);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(
                            credential = %parent.to_hex(),
                            kind = ?error.kind(),
                            "a credential's custody retirement did not read; it is withheld, pending"
                        );
                        self.faulted.insert(parent);
                    }
                }
            }
        }
    }

    /// What these fences say of `id`.
    pub(crate) fn lookup(&self, id: &EntityId) -> FenceLookup {
        if self.fenced.contains(id) {
            FenceLookup::Fenced
        } else if self.unreadable || self.faulted.contains(id) {
            FenceLookup::Faulted
        } else {
            FenceLookup::Clear
        }
    }

    /// The fence rows a restored or activated vault takes, each with its
    /// discovery owed, so its own finisher finds every key the id names in
    /// the custody it holds now.
    pub(crate) fn rows(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let owed = FENCES.encode_value(&Discovery::Owed)?;
        Ok(self
            .fenced
            .iter()
            .map(|id| (FENCES.key_bytes(id), owed.clone()))
            .collect())
    }

    /// Puts every fence in `wtxn`, its discovery owed: an activation's.
    pub(crate) fn put_in_txn(&self, store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
        for id in &self.fenced {
            FENCES.put(store, wtxn, id, &Discovery::Owed)?;
        }
        Ok(())
    }
}

/// The custody finisher's predicate for a credential's keys: an erase's
/// intent for a fenced id runs; any other waits, warned (nothing else
/// retires a credential's keys).
fn credential_retirement_ready(
    store: &Store,
    txn: &RoTxn<'_>,
    intent: &RetirementIntent,
) -> Result<bool> {
    let parent = parent_of(&intent.subject).ok_or_else(|| intent.subject.kind().corrupt())?;
    let fenced = FENCES.contains(store, txn, &parent)?;
    if intent.cause != RetireCause::Erase || !fenced {
        tracing::warn!(
            credential = %parent.to_hex(),
            "a credential key retirement no erase fenced waits; only an erase retires one"
        );
        return Ok(false);
    }
    Ok(true)
}

impl Store {
    /// What the fence of credential `credential` says in `txn`; a fence
    /// that does not read is `Faulted`, warned, for the caller's path to
    /// rule on.
    pub(crate) fn credential_fence_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> FenceLookup {
        match FENCES.contains(self, txn, credential) {
            Ok(true) => FenceLookup::Fenced,
            Ok(false) => FenceLookup::Clear,
            Err(error) => {
                tracing::warn!(
                    credential = %credential.to_hex(),
                    kind = ?error.kind(),
                    "a credential's erase fence did not read"
                );
                FenceLookup::Faulted
            }
        }
    }

    /// Whether a path that re-admits credential `credential` from an image,
    /// a fork or an owner's archive may bring it back under its id: never an
    /// erased one, and not one whose fence does not read, which is withheld,
    /// pending, warned (CALLS `KS-6 erase fence form`).
    pub(crate) fn credential_readmits_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> bool {
        match self.credential_fence_in_txn(txn, credential) {
            FenceLookup::Clear => true,
            FenceLookup::Fenced => false,
            FenceLookup::Faulted => {
                tracing::warn!(
                    credential = %credential.to_hex(),
                    "a credential whose erase fence did not read is withheld, pending: retry"
                );
                false
            }
        }
    }

    /// Refuses a write that would bring erased credential `credential` back
    /// under its id: a key minted, or a body put (CALLS `KS-6 erase fence
    /// form`). A fence that does not read is warned and keeps today's
    /// path: no such writer installs from an image or a fork.
    pub(crate) fn refuse_erased_credential_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> Result<()> {
        match CUSTODY_ERASE_FENCE_FORM {
            CustodyEraseFenceForm::TerminalParentIdWithPendingDiscovery => {}
        }
        match self.credential_fence_in_txn(txn, credential) {
            FenceLookup::Fenced => Err(erased_id()),
            FenceLookup::Faulted | FenceLookup::Clear => Ok(()),
        }
    }

    /// Fences credential `credential` in `wtxn`, the transaction of an
    /// authorized erase of its record (an owner's erase, or its run-bound
    /// seat's end), then stages an erase intent for every custody subject
    /// its id names through the newest generation custody holds. The fence
    /// is written first: a discovery that faults leaves it owed, warned,
    /// and never refuses the erase.
    ///
    /// # Errors
    /// Storage faults writing the fence, as any row of the erase.
    pub(crate) fn stage_credential_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        credential: &EntityId,
    ) -> Result<()> {
        FENCES.put(self, wtxn, credential, &Discovery::Owed)?;
        if self.discover_credential_in_txn(wtxn, credential) {
            FENCES.put(self, wtxn, credential, &Discovery::Complete)?;
        }
        Ok(())
    }

    /// [`Self::stage_credential_erase_in_txn`] for record `id` an erase
    /// purges or scrubs in `wtxn`, read before it goes: only a custody
    /// record is fenced, and none at all when no row is here. A peer's
    /// tombstone never reaches a custody record (its replay refuses one),
    /// so only this vault's own authorized erase fences.
    ///
    /// # Errors
    /// Storage faults, as any row of the erase.
    pub(crate) fn stage_erased_credential_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        let kind = crate::ports::EntityStoreRead::port_entity_raw_wiped(self, wtxn, id)?
            .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
            .map(|header| header.entity_type);
        if kind == Some(crate::registry::ENTITY_TYPE_SECRET_CUSTODY) {
            self.stage_credential_erase_in_txn(wtxn, id)?;
        }
        Ok(())
    }

    /// Stages an erase intent for every custody subject `credential` names
    /// that still holds a generation not retired, through its newest:
    /// whether discovery completed. A fault is warned and leaves it owed.
    fn discover_credential_in_txn(&self, wtxn: &mut RwTxn<'_>, credential: &EntityId) -> bool {
        match CUSTODY_ERASE_DISCOVERY_FAULT {
            CustodyEraseDiscoveryFault::FenceAndRetryBeforeComplete => {}
        }
        // An archived vault's custody is its replacement's: its discovery
        // waits for its activation.
        if self.core.gate_custody_archived() {
            return false;
        }
        let staged = (|| -> Result<()> {
            let Some(custody) = self.core.key_custody.local() else {
                return Ok(());
            };
            for subject in self.credential_custody_subjects(credential)? {
                let Some(through) = custody.newest_generation(&subject)? else {
                    continue;
                };
                if custody.first_unretired(&subject)? > through {
                    continue;
                }
                let intent = RetirementIntent {
                    subject,
                    through,
                    cause: RetireCause::Erase,
                };
                stage_retirement_in_txn(self, wtxn, &intent)?;
            }
            Ok(())
        })();
        match staged {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    credential = %credential.to_hex(),
                    kind = ?error.kind(),
                    "an erased credential's custody discovery did not finish; it stays owed and \
                     retries"
                );
                false
            }
        }
    }

    /// Completes the discovery of every fence that owes one, each in a
    /// writer of its own; a fence row that does not read is warned and
    /// left.
    fn rediscover_credential_erases(&self) -> Result<()> {
        let owed: Vec<EntityId> = {
            let txn = self.env.read_txn()?;
            if self.archived_in_txn(&txn)? {
                return Ok(());
            }
            let mut owed = Vec::new();
            for row in FENCES.iter_raw_from(self, &txn, &[])? {
                let (key, value) = row?;
                match (
                    <EntityId as SideKey>::decode_key(&key),
                    FENCES.decode_value(&value),
                ) {
                    (Some(id), Ok(Discovery::Owed)) => owed.push(id),
                    (Some(_), Ok(Discovery::Complete)) => {}
                    _ => tracing::warn!("a credential erase fence row did not read; left"),
                }
            }
            owed
        };
        for credential in owed {
            let mut wtxn = self.env.write_txn()?;
            if FENCES.get(self, &wtxn, &credential)? != Some(Discovery::Owed) {
                continue;
            }
            if self.discover_credential_in_txn(&mut wtxn, &credential) {
                FENCES.put(self, &mut wtxn, &credential, &Discovery::Complete)?;
                wtxn.commit()?;
            }
        }
        Ok(())
    }

    /// Carries out every erased credential's custody (KS-6 part 2): each
    /// owed discovery first, then every staged intent of the three kinds,
    /// an interrupted process's included, in the custody finisher's order.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, and storage and
    /// custody faults: the next pass retries.
    pub(crate) fn finish_credential_retirements(&self) -> Result<()> {
        self.rediscover_credential_erases()?;
        for kind in CREDENTIAL_PARENT_KINDS {
            self.finish_custody_retirements(kind, |txn, intent| {
                credential_retirement_ready(self, txn, intent)
            })?;
        }
        Ok(())
    }

    /// Whether the erase of credential `credential` has finished here, for
    /// its receipt's final row: its fence's discovery is complete, no intent
    /// stands for any subject its id names, every generation of each is
    /// retired, and each one's journal obligations are all complete. No
    /// fence, or no custody to read: its proof is missing, pending.
    ///
    /// # Errors
    /// Storage and custody faults: the caller reads them pending.
    pub(crate) fn credential_erase_finished_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> Result<bool> {
        if FENCES.get(self, txn, credential)? != Some(Discovery::Complete) {
            return Ok(false);
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(false);
        };
        for subject in self.credential_custody_subjects(credential)? {
            if retirement_in_txn(self, txn, &subject)?.is_some() {
                return Ok(false);
            }
            let Some(newest) = custody.newest_generation(&subject)? else {
                continue;
            };
            if custody.first_unretired(&subject)? <= newest {
                return Ok(false);
            }
            let obligations = self.custody_obligations_of(&subject)?;
            if obligations.is_empty() || obligations.iter().any(|(_, done)| !done) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// What erased credential `credential` still owes, for its erase's
    /// status read: `None` when no erase fenced it here; else whether its
    /// discovery is owed, and every custody subject its id names.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub(crate) fn credential_erase_debt_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> Result<Option<(bool, Vec<CustodySubject>)>> {
        let Some(discovery) = FENCES.get(self, txn, credential)? else {
            return Ok(None);
        };
        Ok(Some((
            discovery == Discovery::Owed,
            self.credential_custody_subjects(credential)?,
        )))
    }

    /// The credentials among `erased` an erase fenced in `txn`.
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn fenced_credentials_in_txn(
        &self,
        txn: &RoTxn<'_>,
        erased: &[EntityId],
    ) -> Result<Vec<EntityId>> {
        let mut fenced = Vec::new();
        for id in erased {
            if FENCES.contains(self, txn, id)? {
                fenced.push(*id);
            }
        }
        Ok(fenced)
    }
}

impl crate::Vault {
    /// Post-commit door for an erase that fenced a credential (KS-6 part
    /// 2): its discovery and key retirements, carried out now. They are
    /// durable, so a failure here is retried by the next housekeeping pass
    /// or reopen and never reported as a failure of the erase that already
    /// committed.
    pub(crate) fn finish_credential_retirements_after_commit(&self) {
        if let Err(error) = self.store.finish_credential_retirements() {
            tracing::warn!(
                kind = ?error.kind(),
                "credential key retirement deferred to the next housekeeping pass"
            );
        }
    }
}
