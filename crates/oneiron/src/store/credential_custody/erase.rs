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
//! meanwhile (CALLS `KS-6 erase discovery fault`). A fence that does not
//! write is warned and the erase lands all the same: its receipt still
//! binds the credential's whole erase, pending, and the finisher installs
//! the fence again from the erase intents the erase committed. No erase is
//! refused for either.
//!
//! The fence closes the id, every generation and instance of it: no key is
//! minted under it again, no body is put under it again, and no image, fork,
//! restore, activation, archive or transition brings it back, nor is a
//! carrier of it kept or relayed (CALLS `KS-6 erase fence form`).
//! Re-entering a credential takes a new id. A fence that does not read
//! where a path would install or re-admit a handle from an image or a fork
//! withholds that handle alone, PendingCustody, warned; anywhere else
//! today's path goes on, warned.
//!
//! Only an erase retires a credential's keys: nothing stages one for a
//! rotate or a revoke, an image's own erase rows never land (`fences`), and
//! the finisher runs an erase's intent alone. So a retired credential key in
//! custody a restore takes, and a credential key's erase intent, are
//! erase-only evidence: a fence is derived from them, never from a peer's
//! tombstone.

use std::cell::RefCell;
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;
use crate::store::key_custody::{
    CredentialFenceFact, CustodyKind, CustodySubject, FenceFact, RetireCause, RetirementIntent,
    retirements_in_txn, stage_retirement_in_txn,
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

/// Where one fence's discovery stands: one byte, `0` owed, `1` complete
/// with no key found, `2` complete with keys found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Discovery {
    Owed,
    Complete { keys: bool },
}

impl RawValue for Discovery {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Owed => 0,
            Self::Complete { keys: false } => 1,
            Self::Complete { keys: true } => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Owed),
            [1] => Ok(Self::Complete { keys: false }),
            [2] => Ok(Self::Complete { keys: true }),
            _ => Err(Error::CorruptedIndex("credential erase fence").into()),
        }
    }
}

/// Each erased credential's fence, by its record id.
pub(super) const FENCES: SideTable<EntityId, Discovery, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_ERASE);

/// The credential a custody subject of one of [`CREDENTIAL_PARENT_KINDS`]
/// belongs to: its item's first 16 bytes.
pub(super) fn parent_of(subject: &CustodySubject) -> Option<EntityId> {
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
    /// Its own fence, or the evidence it is derived from, did not read.
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

/// What this thread's writers staged: how many credential erases, for the
/// post-commit detection of the writer it runs in, and each id whose fence
/// did not write, which its erase's receipt binds all the same.
struct Staged {
    count: u64,
    unfenced: BTreeSet<EntityId>,
}

thread_local! {
    static STAGED: RefCell<Staged> = const {
        RefCell::new(Staged {
            count: 0,
            unfenced: BTreeSet::new(),
        })
    };
}

/// How many credential erases this thread has staged: a writer that sees
/// it move staged one, and finishes it after its commit.
pub(crate) fn credential_erases_staged() -> u64 {
    STAGED.with(|staged| staged.borrow().count)
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

/// Every credential key's erase intent standing in `txn`, its credential
/// with it.
fn credential_intents_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EntityId, RetirementIntent)>> {
    let mut intents = Vec::new();
    for kind in CREDENTIAL_PARENT_KINDS {
        for intent in retirements_in_txn(store, txn, kind)? {
            if let Some(parent) = parent_of(&intent.subject) {
                intents.push((parent, intent));
            }
        }
    }
    Ok(intents)
}

/// Every fence whose discovery is owed in `txn`; a fence row that does not
/// read is warned and left.
fn owed_fences_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut owed = Vec::new();
    for row in FENCES.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        match (
            <EntityId as SideKey>::decode_key(&key),
            FENCES.decode_value(&value),
        ) {
            (Some(id), Ok(Discovery::Owed)) => owed.push(id),
            (Some(_), Ok(Discovery::Complete { .. })) => {}
            _ => tracing::warn!("a credential erase fence row did not read; left"),
        }
    }
    Ok(owed)
}

impl Store {
    /// Each erased credential's value-free fact for the custody head (FIX
    /// 10584 item 3, KCEraseEvidence): owed while its fence's discovery is,
    /// or while an erase intent of one of its keys stands whose fence did
    /// not write; once discovered, no-subject or keyed; complete once its
    /// erase finished here. Only an authorized erase makes one. A fence row
    /// that does not read is warned and left; a finish that does not read
    /// reads not complete yet.
    ///
    /// # Errors
    /// Storage faults reading the fences or the intents.
    pub(crate) fn credential_fence_facts_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<CredentialFenceFact>> {
        let mut facts = std::collections::BTreeMap::new();
        for (parent, intent) in credential_intents_in_txn(self, txn)? {
            if intent.cause == RetireCause::Erase {
                facts.insert(parent, FenceFact::Owed);
            }
        }
        for row in FENCES.iter_raw_from(self, txn, &[])? {
            let (key, value) = row?;
            let (Some(id), Ok(discovery)) = (
                <EntityId as SideKey>::decode_key(&key),
                FENCES.decode_value(&value),
            ) else {
                tracing::warn!("a credential erase fence row did not read; left");
                continue;
            };
            let fact = match discovery {
                Discovery::Owed => FenceFact::Owed,
                Discovery::Complete { .. }
                    if self
                        .credential_erase_finished_in_txn(txn, &id)
                        .unwrap_or(false) =>
                {
                    FenceFact::Complete
                }
                Discovery::Complete { keys: false } => FenceFact::NoSubject,
                Discovery::Complete { keys: true } => FenceFact::Keyed,
            };
            let slot = facts.entry(id).or_insert(fact);
            *slot = (*slot).max(fact);
        }
        Ok(facts
            .into_iter()
            .map(|(credential, fact)| CredentialFenceFact { credential, fact })
            .collect())
    }
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

    /// Whether an erase fenced credential `credential` in `txn`: a carrier
    /// of it is never kept, applied or relayed again. A fence that does not
    /// read keeps today's path, warned.
    pub(crate) fn credential_fenced_in_txn(&self, txn: &RoTxn<'_>, credential: &EntityId) -> bool {
        self.credential_fence_in_txn(txn, credential) == FenceLookup::Fenced
    }

    /// Every credential an erase fenced in `txn`, for a relay that drops
    /// their carriers from its windows. A row that does not read is warned
    /// and left: today's path.
    #[cfg(feature = "sync")]
    pub(crate) fn erased_credentials_in_txn(&self, txn: &RoTxn<'_>) -> BTreeSet<EntityId> {
        let mut erased = BTreeSet::new();
        let rows = match FENCES.iter_raw_from(self, txn, &[]) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "credential erase fences did not read");
                return erased;
            }
        };
        for row in rows {
            match row.map(|(key, _)| <EntityId as SideKey>::decode_key(&key)) {
                Ok(Some(id)) => {
                    erased.insert(id);
                }
                Ok(None) => tracing::warn!("a credential erase fence row did not read; left"),
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "credential erase fences did not read");
                    break;
                }
            }
        }
        erased
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
    /// is written first. Nothing here refuses the erase: a fence that does
    /// not write is warned, the erase's receipt still binds it, pending,
    /// and the finisher installs it from the intents staged here; a
    /// discovery that faults leaves it owed, warned.
    pub(crate) fn stage_credential_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        credential: &EntityId,
    ) {
        STAGED.with(|staged| staged.borrow_mut().count += 1);
        if let Err(error) = FENCES.put(self, wtxn, credential, &Discovery::Owed) {
            tracing::warn!(
                credential = %credential.to_hex(),
                kind = ?error.kind(),
                "an erased credential's fence did not write; its erase lands, pending, and the \
                 finisher installs the fence"
            );
            STAGED.with(|staged| {
                staged.borrow_mut().unfenced.insert(*credential);
            });
        }
        if let Some(keys) = self.discover_credential_in_txn(wtxn, credential)
            && let Err(error) = FENCES.put(self, wtxn, credential, &Discovery::Complete { keys })
        {
            tracing::warn!(
                credential = %credential.to_hex(),
                kind = ?error.kind(),
                "an erased credential's discovery did not record; it stays owed and retries"
            );
        }
    }

    /// Whether record `id`, read in `txn` before an erase purges or scrubs
    /// it, is a custody record: none at all when no row is here.
    ///
    /// # Errors
    /// Storage faults reading the row, as the purge reading it would meet.
    fn custody_record_in_txn(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let kind = crate::ports::EntityStoreRead::port_entity_raw_wiped(self, txn, id)?
            .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
            .map(|header| header.entity_type);
        Ok(kind == Some(crate::registry::ENTITY_TYPE_SECRET_CUSTODY))
    }

    /// Stages an erase intent for every custody subject `credential` names
    /// that still holds a generation not retired, through its newest:
    /// whether any key was found, once discovery completed. A fault is
    /// warned and leaves it owed (`None`).
    fn discover_credential_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        credential: &EntityId,
    ) -> Option<bool> {
        match CUSTODY_ERASE_DISCOVERY_FAULT {
            CustodyEraseDiscoveryFault::FenceAndRetryBeforeComplete => {}
        }
        // An archived vault's custody is its replacement's: its discovery
        // waits for its activation.
        if self.core.gate_custody_archived() {
            return None;
        }
        let staged = (|| -> Result<bool> {
            let Some(custody) = self.core.key_custody.local() else {
                return Ok(false);
            };
            let subjects = self.credential_custody_subjects(credential)?;
            for subject in &subjects {
                let Some(through) = custody.newest_generation(subject)? else {
                    continue;
                };
                if custody.first_unretired(subject)? > through {
                    continue;
                }
                let intent = RetirementIntent {
                    subject: subject.clone(),
                    through,
                    cause: RetireCause::Erase,
                };
                stage_retirement_in_txn(self, wtxn, &intent)?;
            }
            Ok(!subjects.is_empty())
        })();
        match staged {
            Ok(keys) => Some(keys),
            Err(error) => {
                tracing::warn!(
                    credential = %credential.to_hex(),
                    kind = ?error.kind(),
                    "an erased credential's custody discovery did not finish; it stays owed and \
                     retries"
                );
                None
            }
        }
    }

    /// Installs the fence again, discovery owed, of every credential an
    /// erase intent of one of its keys names and no fence does: an erase
    /// whose fence did not write. Then completes the discovery of every
    /// fence that owes one, each in a writer of its own; a fence row that
    /// does not read is warned and left.
    fn rediscover_credential_erases(&self) -> Result<()> {
        let (unfenced, owed) = {
            let txn = self.env.read_txn()?;
            if self.archived_in_txn(&txn)? {
                return Ok(());
            }
            let mut unfenced = BTreeSet::new();
            for (parent, intent) in credential_intents_in_txn(self, &txn)? {
                if intent.cause == RetireCause::Erase && !FENCES.contains(self, &txn, &parent)? {
                    unfenced.insert(parent);
                }
            }
            (unfenced, owed_fences_in_txn(self, &txn)?)
        };
        if !unfenced.is_empty() {
            let mut wtxn = self.env.write_txn()?;
            for credential in &unfenced {
                FENCES.put(self, &mut wtxn, credential, &Discovery::Owed)?;
            }
            wtxn.commit()?;
        }
        for credential in unfenced.into_iter().chain(owed) {
            let mut wtxn = self.env.write_txn()?;
            if FENCES.get(self, &wtxn, &credential)? != Some(Discovery::Owed) {
                continue;
            }
            if let Some(keys) = self.discover_credential_in_txn(&mut wtxn, &credential) {
                FENCES.put(self, &mut wtxn, &credential, &Discovery::Complete { keys })?;
                wtxn.commit()?;
            }
        }
        Ok(())
    }

    /// Carries out every erased credential's custody (KS-6 part 2): each
    /// fence an erase intent owes installed, each owed discovery, then every
    /// staged intent of the three kinds, an interrupted process's included,
    /// in the custody finisher's order. Whether any of it was owed.
    ///
    /// # Errors
    /// An archived vault with a retirement standing, and storage and
    /// custody faults: the next pass retries.
    pub(crate) fn finish_credential_retirements(&self) -> Result<bool> {
        // KCEraseEvidence (FIX 10584 item 3): every fence's value-free fact
        // rides the custody head; a fault is warned and retried.
        self.publish_credential_erase_evidence();
        let owed = {
            let txn = self.env.read_txn()?;
            !credential_intents_in_txn(self, &txn)?.is_empty()
                || !owed_fences_in_txn(self, &txn)?.is_empty()
        };
        if !owed {
            return Ok(false);
        }
        self.rediscover_credential_erases()?;
        for kind in CREDENTIAL_PARENT_KINDS {
            self.finish_custody_retirements(kind, |txn, intent| {
                credential_retirement_ready(self, txn, intent)
            })?;
        }
        Ok(true)
    }

    /// Whether the erase of credential `credential` has finished here, for
    /// its receipt's final row: its fence installed and its discovery
    /// complete; no intent standing for any key its id names, listed or
    /// not; a key listed now for each its discovery found (none listed then
    /// is missing proof); every generation of each retired, and each one's
    /// journal obligations complete. Anything short of that, no custody to
    /// read included, is pending.
    ///
    /// # Errors
    /// Storage and custody faults: the caller reads them pending.
    pub(crate) fn credential_erase_finished_in_txn(
        &self,
        txn: &RoTxn<'_>,
        credential: &EntityId,
    ) -> Result<bool> {
        let Some(Discovery::Complete { keys }) = FENCES.get(self, txn, credential)? else {
            return Ok(false);
        };
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(false);
        };
        if credential_intents_in_txn(self, txn)?
            .iter()
            .any(|(parent, _)| parent == credential)
        {
            return Ok(false);
        }
        let subjects = self.credential_custody_subjects(credential)?;
        if keys && subjects.is_empty() {
            return Ok(false);
        }
        for subject in subjects {
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

    /// The credentials among `erased` an erase fenced in `txn`, or staged
    /// in this thread with a fence that did not write: each one's receipt
    /// binds its whole erase.
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn fenced_credentials_in_txn(
        &self,
        txn: &RoTxn<'_>,
        erased: &[EntityId],
    ) -> Result<Vec<EntityId>> {
        let unfenced = STAGED.with(|staged| staged.borrow().unfenced.clone());
        let mut fenced = Vec::new();
        for id in erased {
            if unfenced.contains(id) || FENCES.contains(self, txn, id)? {
                fenced.push(*id);
            }
        }
        Ok(fenced)
    }
}

impl crate::Vault {
    /// [`Store::stage_credential_erase_in_txn`] for credential `credential`
    /// an authorized erase takes in `wtxn`, and the carriers this install
    /// keeps of it go too: its sealed transition, and every input and
    /// witness part kept for a request on it, so none is relayed again
    /// (7402, a machine key's ciphertext already released, stays out). A
    /// fault dropping them is warned: the erase lands.
    pub(crate) fn fence_credential_in_txn(&self, wtxn: &mut RwTxn<'_>, credential: &EntityId) {
        self.store.stage_credential_erase_in_txn(wtxn, credential);
        if let Err(error) =
            crate::secret_custody::drop_revoked_copies_in_txn(self, wtxn, credential)
        {
            tracing::warn!(
                credential = %credential.to_hex(),
                kind = ?error.kind(),
                "an erased credential's kept carriers did not drop; its settle retries"
            );
        }
    }

    /// [`Self::fence_credential_in_txn`] for record `id` an erase purges or
    /// scrubs in `wtxn`, read before it goes: only a custody record is
    /// fenced. A peer's tombstone never reaches a custody record (its
    /// replay refuses one), so only this vault's own authorized erase
    /// fences.
    ///
    /// # Errors
    /// Storage faults reading the row, as the purge reading it would meet.
    pub(crate) fn fence_erased_credential_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if self.store.custody_record_in_txn(wtxn, id)? {
            self.fence_credential_in_txn(wtxn, id);
        }
        Ok(())
    }

    /// Post-commit door for an erase that fenced a credential (KS-6 part
    /// 2): its fence, discovery and key retirements, carried out now, then
    /// the overall final row of every erase they completed, outside the
    /// custody locks. They are durable, so a failure here is retried by the
    /// next housekeeping pass or reopen and never reported as a failure of
    /// the erase that already committed.
    pub(crate) fn finish_credential_retirements_after_commit(&self) {
        match self.store.finish_credential_retirements() {
            Ok(true) => self.finish_redaction_erases_logged(),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "credential key retirement deferred to the next housekeeping pass"
            ),
        }
    }
}
