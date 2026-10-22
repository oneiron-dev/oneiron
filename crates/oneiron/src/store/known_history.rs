//! The known-value index's custody client (KS-3, FIX 5684 = FIX 5503 card
//! A; owner KEY STORE = A): the index's master key and every history entry
//! a custody record's values left live in typed custody, never in LMDB, a
//! cache or an image.
//!
//! - The master is one subject per vault: kind `KnownValueIndex`, an empty
//!   item, generation 0, 32 random bytes. It is minted with the first value
//!   the index keys, in that writer, and never minted again: once its
//!   reference is committed, a master custody lacks is custody lost, never a
//!   fresh start. Nothing retires it.
//! - Each history entry is kind `KnownValueEntry`: item = the holding
//!   custody record's id, never a name derived from a value; generation =
//!   the holder's entry slot; secret = [`KnownEntry`]'s 44 bytes. A slot is
//!   taken past every slot the holder's references or its custody hold, an
//!   aborted writer's included, and an entry of the same bytes is never
//!   written twice for one holder. Two holders of the same bytes keep two
//!   entries: erasing one never unmasks the other.
//! - LMDB keeps references only: `secret_known:index:v1` (the master's
//!   generation) and `secret_known:history:v1:<holder>` (each committed slot
//!   with the record generation it was written at). Both are canonical and
//!   live-classed, so an image carries them and a restore requires each one
//!   in current custody ([`require_known_history`]): one missing refuses by
//!   name, one an erase retired goes from the restored rows, and nothing is
//!   indexed again under a new key.
//! - An entry is published and synced, and its Mint journaled, in the writer
//!   that commits its reference, as the training link key's is: every
//!   custody write is nested in its caller's writer, and a reference never
//!   commits before the entry it names.
//! - Only an erase retires history: a hard-deleted holder's purge removes
//!   its references and stages one Erase intent through its newest slot; the
//!   finisher destroys them once the holder's permanent hard-delete marker
//!   stands and no reference is left. A rotation, a revocation, an archive, a
//!   carrier's deletion or a lost handle retires nothing.
//! - A pass reads the history in the writer it runs in (no custody guard,
//!   none after the writer), or, for a stream, through [`KnownHistoryIds`]:
//!   the ids the stream began with, each pass under the custody read guard.

use std::sync::{Arc, Weak};

use heed::{RoTxn, RwTxn};
use zeroize::{Zeroize, Zeroizing};

use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result, StoreError};
use crate::overlay_db::OverlayDb;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::key_custody::{
    CustodyBinding, CustodyId, CustodyKind, CustodyPlan, CustodySecret, CustodySubject, EntryState,
    LocalCustody, Requirement, RetireCause, RetirementIntent, custody_present, retirement_in_txn,
    stage_retirement_in_txn,
};
use crate::store::{Store, StoreCore};

/// How many bytes of a value's first window an entry's tag keeps.
pub(crate) const KNOWN_TAG_BYTES: usize = 8;

/// The width of one history entry's secret.
const ENTRY_BYTES: usize = CustodyKind::KnownValueEntry.secret_len();

/// One reference's width: `generation (u32be) | slot (u64be)`.
const REF_BYTES: usize = 4 + 8;

const INDEX_MISSING: &str = "known_value_index_missing";
const HISTORY_MISSING: &str = "known_value_history_missing";
const HISTORY_CORRUPT: &str = "known_value_history_corrupt";

/// The master key's reference: its custody generation. Key: ().
const INDEX: SideTable<(), u64, Raw> = SideTable::new(&side_table::SECRET_KNOWN_INDEX);

/// Each holder's committed history. Key: the holding custody record's id.
const HISTORY: SideTable<EntityId, HistoryRefs, Raw> =
    SideTable::new(&side_table::SECRET_KNOWN_HISTORY);

/// One committed entry: the record generation it was written at, and its
/// custody slot.
#[derive(Clone, Copy)]
struct HistoryRef {
    generation: u32,
    slot: u64,
}

/// A holder's committed entries, in the order they were written:
/// `(generation u32be | slot u64be)*`, never empty.
#[derive(Default)]
struct HistoryRefs(Vec<HistoryRef>);

impl HistoryRefs {
    fn slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().map(|held| held.slot)
    }
}

impl RawValue for HistoryRefs {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(self.0.len().saturating_mul(REF_BYTES));
        for held in &self.0 {
            out.extend_from_slice(&held.generation.to_be_bytes());
            out.extend_from_slice(&held.slot.to_be_bytes());
        }
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(REF_BYTES) {
            return Err(CustodyKind::KnownValueEntry.corrupt().into());
        }
        bytes
            .chunks_exact(REF_BYTES)
            .map(|chunk| {
                let (generation, slot) = chunk.split_at(4);
                Some(HistoryRef {
                    generation: u32::from_be_bytes(generation.try_into().ok()?),
                    slot: u64::from_be_bytes(slot.try_into().ok()?),
                })
            })
            .collect::<Option<Vec<_>>>()
            .map(Self)
            .ok_or_else(|| CustodyKind::KnownValueEntry.corrupt().into())
    }
}

/// One history entry as the index keeps it: a value's byte length, the
/// keyed tag of its first window and the keyed fingerprint of all of it,
/// never the value. `len (u32be) | tag (8) | fingerprint (32)` in custody;
/// wiped when dropped, and never printed.
pub(crate) struct KnownEntry {
    pub(crate) len: u32,
    pub(crate) tag: [u8; KNOWN_TAG_BYTES],
    pub(crate) fingerprint: [u8; 32],
}

impl KnownEntry {
    fn to_secret(&self) -> CustodySecret {
        let mut bytes = Zeroizing::new(Vec::with_capacity(ENTRY_BYTES));
        bytes.extend_from_slice(&self.len.to_be_bytes());
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&self.fingerprint);
        CustodySecret::from_bytes(bytes)
    }

    /// Strictly: exactly the width, of a value that is not empty.
    fn from_secret(secret: &CustodySecret) -> Option<Self> {
        let bytes = secret.expose();
        if bytes.len() != ENTRY_BYTES {
            return None;
        }
        let (len, rest) = bytes.split_at(4);
        let (tag, fingerprint) = rest.split_at(KNOWN_TAG_BYTES);
        let len = u32::from_be_bytes(len.try_into().ok()?);
        if len == 0 {
            return None;
        }
        Some(Self {
            len,
            tag: tag.try_into().ok()?,
            fingerprint: fingerprint.try_into().ok()?,
        })
    }
}

impl Drop for KnownEntry {
    fn drop(&mut self) {
        self.tag.zeroize();
        self.fingerprint.zeroize();
    }
}

/// The index's master key and each holder's live history, as one pass
/// reads them: held for that pass alone, every byte wiped when it drops.
pub(crate) struct KnownHistory {
    pub(crate) master: Zeroizing<[u8; 32]>,
    /// Each holder with live entries, in id order.
    pub(crate) holders: Vec<(EntityId, Vec<KnownEntry>)>,
}

fn index_subject(binding: &CustodyBinding) -> Result<CustodySubject> {
    binding.subject(CustodyKind::KnownValueIndex, &[])
}

fn holder_subject(binding: &CustodyBinding, holder: &EntityId) -> Result<CustodySubject> {
    binding.subject(CustodyKind::KnownValueEntry, holder.as_bytes())
}

/// The master's bytes, copied out of a custody secret: exactly 32.
fn copy_master(secret: &CustodySecret) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    if secret.expose().len() != key.len() {
        return Err(CustodyKind::KnownValueIndex.corrupt());
    }
    key.copy_from_slice(secret.expose());
    Ok(key)
}

/// `holder`'s live entries at `slots` in `custody`. One retired is skipped
/// (erased, or being); one missing or damaged is custody lost and fails.
/// The caller holds the LMDB writer or the custody read guard.
fn read_entries(
    custody: LocalCustody<'_>,
    holder: &EntityId,
    slots: impl Iterator<Item = u64>,
) -> Result<Vec<KnownEntry>> {
    let subject = holder_subject(custody.binding(), holder)?;
    let mut entries = Vec::new();
    for slot in slots {
        let id = subject.at(slot);
        match custody.state(&id)? {
            EntryState::Retired => continue,
            EntryState::Missing => return Err(CustodyKind::KnownValueEntry.corrupt()),
            EntryState::Live => {}
        }
        let secret = custody.read(&id)?;
        entries.push(
            KnownEntry::from_secret(&secret)
                .ok_or_else(|| CustodyKind::KnownValueEntry.corrupt())?,
        );
    }
    Ok(entries)
}

impl Store {
    /// Records one value of the custody record `holder`, at record
    /// generation `generation`, in `wtxn`, the custody write's own
    /// transaction (KS-3). `entry` computes its entry under the master key,
    /// which is minted here with the first value the index keys. An entry of
    /// the same bytes the holder already holds is not written again; any
    /// other is published and synced, and its Mint journaled, at a slot past
    /// every slot the holder has, and its reference commits with `wtxn`. The
    /// binding is pinned in the same transaction. Returns whether an entry
    /// was published: `false` for one the holder already held (FIX 2781).
    ///
    /// # Errors
    ///
    /// An archived vault, whose custody is its replacement's; a committed
    /// master custody lacks (never minted again); custody and storage faults.
    pub(crate) fn remember_known_entry_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        holder: &EntityId,
        generation: u32,
        entry: impl FnOnce(&[u8; 32]) -> KnownEntry,
    ) -> Result<bool> {
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let master = index_subject(custody.binding())?;
        let master = match INDEX.get(self, wtxn, &())? {
            Some(at) => custody.read(&master.at(at))?,
            None => {
                let secret = custody.get_or_create(&master.at(0))?;
                INDEX.put(self, wtxn, &(), &0)?;
                secret
            }
        };
        let key = copy_master(&master)?;
        drop(master);
        let secret = entry(&*key).to_secret();
        drop(key);
        let subject = holder_subject(custody.binding(), holder)?;
        let mut refs = HISTORY.get(self, wtxn, holder)?.unwrap_or_default();
        for slot in refs.slots() {
            let id = subject.at(slot);
            if custody.state(&id)? == EntryState::Live
                && custody.read(&id)?.expose() == secret.expose()
            {
                return Ok(false);
            }
        }
        let slot = match refs.slots().max().max(custody.newest_generation(&subject)?) {
            None => 0,
            Some(newest) => newest
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("known-value history slot"))?,
        };
        custody.publish_minted(&subject.at(slot), &secret)?;
        refs.0.push(HistoryRef { generation, slot });
        HISTORY.put(self, wtxn, holder, &refs)?;
        Ok(true)
    }

    /// The index's master and every holder's live history, read in the
    /// writer `wtxn` (KS-3): the LMDB writer it holds keeps the finisher
    /// from every file, so no custody guard is taken, and none may be taken
    /// after it. `None` while the index keys no value.
    ///
    /// # Errors
    ///
    /// Custody lost or damaged under a committed reference, and storage
    /// faults.
    pub(crate) fn known_history_in_writer(&self, wtxn: &RwTxn<'_>) -> Result<Option<KnownHistory>> {
        let Some(at) = INDEX.get(self, wtxn, &())? else {
            return Ok(None);
        };
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let master = copy_master(&custody.read(&index_subject(custody.binding())?.at(at))?)?;
        let mut holders = Vec::new();
        for (holder, refs) in HISTORY.scan(self, wtxn)? {
            let entries = read_entries(custody, &holder, refs.slots())?;
            if !entries.is_empty() {
                holders.push((holder, entries));
            }
        }
        Ok(Some(KnownHistory { master, holders }))
    }

    /// The keyed fingerprint of a run-tree steer intent (FIX 10066): `input`
    /// hashed under a subkey derived from the index's master, read in the
    /// writer `wtxn` as [`Self::known_history_in_writer`] reads it. `None`
    /// while the index keys no value: no master exists, and plain input
    /// equality stands. Neither the master nor the subkey leaves this
    /// function.
    ///
    /// # Errors
    ///
    /// Custody lost or damaged under a committed reference, and storage
    /// faults.
    pub(crate) fn intent_fingerprint_in_writer(
        &self,
        wtxn: &RwTxn<'_>,
        input: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        const CONTEXT: &str = "oneiron run_tree steer intent fingerprint v1";
        let Some(at) = INDEX.get(self, wtxn, &())? else {
            return Ok(None);
        };
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let master = copy_master(&custody.read(&index_subject(custody.binding())?.at(at))?)?;
        let subkey = crate::world_keys::derive_guarded(CONTEXT, &[&master[..]]);
        Ok(Some(*blake3::keyed_hash(&subkey, input).as_bytes()))
    }

    /// The ids of the history `txn` commits to, for a stream's sweep
    /// (KS-3); `txn` is a snapshot taken under the custody read guard
    /// ([`Store::custody_snapshot`]). `None` while the index keys no value.
    ///
    /// # Errors
    ///
    /// Storage faults, and a committed binding of another vault.
    pub(crate) fn known_history_ids_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Option<KnownHistoryIds>> {
        let Some(index) = INDEX.get(self, txn, &())? else {
            return Ok(None);
        };
        let custody = self.core.key_custody.bind_in_txn(self, txn)?;
        let holders = HISTORY
            .scan(self, txn)?
            .into_iter()
            .map(|(holder, refs)| (holder, refs.slots().collect()))
            .collect();
        Ok(Some(KnownHistoryIds {
            core: Arc::downgrade(&self.core),
            binding: custody.binding().clone(),
            index,
            holders,
        }))
    }

    /// The erase of the custody record `holder`, in `wtxn`, its purge's own
    /// transaction (KS-3): its committed known-value history goes, and one
    /// [`RetireCause::Erase`] intent is staged through the newest slot its
    /// custody holds, an aborted writer's included, for the finisher to
    /// destroy once this commits. Another holder's entries and the index's
    /// master stay. Called for an erase alone.
    ///
    /// # Errors
    ///
    /// Storage and custody faults.
    pub(crate) fn stage_known_history_erase_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        holder: &EntityId,
    ) -> Result<()> {
        let refs = HISTORY.get(self, wtxn, holder)?;
        if refs.is_some() {
            HISTORY.delete(self, wtxn, holder)?;
        }
        // Unbound: no entry was ever published here.
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let subject = holder_subject(custody.binding(), holder)?;
        let newest = refs
            .iter()
            .flat_map(HistoryRefs::slots)
            .max()
            .max(custody.newest_generation(&subject)?);
        let Some(through) = newest else {
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

    /// Whether `holder` has committed known-value history an erase must
    /// take (KS-3): part of its delete scope.
    ///
    /// # Errors
    ///
    /// Storage faults.
    pub(crate) fn known_history_scope_exists_in_txn(
        &self,
        txn: &RoTxn<'_>,
        holder: &EntityId,
    ) -> Result<bool> {
        HISTORY.contains(self, txn, holder)
    }

    /// Carries out every staged known-value history retirement (KS-3), an
    /// interrupted process's included: the custody finisher's order (marker,
    /// unlink, directory sync), then the handoff to the custody journal,
    /// whose obligations carry completion. Only an erase's intent runs, for
    /// a holder whose permanent hard-delete marker stands and whose history
    /// no reference names; anything else is refused by name.
    ///
    /// # Errors
    ///
    /// An archived vault with a retirement standing, the rule's refusals,
    /// and custody faults.
    pub(crate) fn finish_known_history_retirements(&self) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::KnownValueEntry, |txn, intent| {
            known_retirement_ready(self, txn, intent)
        })
    }
}

/// The history client's rule for the custody finisher: see
/// [`Store::finish_known_history_retirements`].
fn known_retirement_ready(
    store: &Store,
    txn: &RoTxn<'_>,
    intent: &RetirementIntent,
) -> Result<bool> {
    let holder = <[u8; 16]>::try_from(intent.subject.item())
        .ok()
        .and_then(|raw| EntityId::from_bytes(raw).ok())
        .ok_or_else(|| CustodyKind::KnownValueEntry.corrupt())?;
    if intent.cause != RetireCause::Erase {
        return Err(Error::CorruptedIndex(
            "known-value history retires for an erase only",
        ));
    }
    if !store.port_deletion_marked(txn, DeletionMarker::HardDelete, &holder)? {
        return Err(Error::CorruptedIndex(
            "retiring known-value history has no erase marker",
        ));
    }
    if HISTORY.contains(store, txn, &holder)? {
        return Err(Error::CorruptedIndex(
            "retiring known-value history still has references",
        ));
    }
    Ok(true)
}

/// The ids a stream's sweep reads known values through (KS-3): the history
/// the index held when the stream began, never a payload, and a store it
/// does not keep open.
#[derive(Clone)]
pub(crate) struct KnownHistoryIds {
    core: Weak<StoreCore>,
    binding: CustodyBinding,
    index: u64,
    holders: Vec<(EntityId, Vec<u64>)>,
}

impl KnownHistoryIds {
    /// Each holder these ids name, in id order.
    pub(crate) fn holders(&self) -> impl Iterator<Item = &EntityId> {
        self.holders.iter().map(|(holder, _)| holder)
    }

    /// Runs `pass` over the history these ids name, read now: the custody
    /// read guard first, held until `pass` returns, then a snapshot. An
    /// entry retired since is skipped, and so is a holder whose erase is
    /// staged; `None` when no entry is left. What was read is wiped before
    /// this returns.
    ///
    /// # Errors
    ///
    /// The vault closed, custody lost or damaged under an id, storage
    /// faults, and `pass`'s errors.
    pub(crate) fn with_history<T>(
        &self,
        pass: impl FnOnce(Option<&KnownHistory>) -> Result<T>,
    ) -> Result<T> {
        let core = self.core.upgrade().ok_or(Error::InvariantViolation(
            "a known-value sweep outlived its vault",
        ))?;
        let _guard = core.key_custody.read_guard()?;
        let history = {
            let txn = core.env.read_txn()?;
            let vault_meta = OverlayDb::canonical(core.raw.vault_meta);
            let custody = LocalCustody::at(&self.binding);
            let master =
                copy_master(&custody.read(&index_subject(&self.binding)?.at(self.index))?)?;
            let mut holders = Vec::new();
            for (holder, slots) in &self.holders {
                let subject = holder_subject(&self.binding, holder)?;
                if retirement_in_txn(&vault_meta, &txn, &subject)?.is_some() {
                    continue;
                }
                let entries = read_entries(custody, holder, slots.iter().copied())?;
                if !entries.is_empty() {
                    holders.push((*holder, entries));
                }
            }
            KnownHistory { master, holders }
        };
        pass((!history.holders.is_empty()).then_some(&history))
    }
}

/// The `vault_meta` prefixes of the known-value history references.
pub(crate) fn known_history_prefixes() -> [&'static [u8]; 2] {
    [HISTORY.decl().prefix, INDEX.decl().prefix]
}

/// `known_value_*`: a restore's typed refusal, naming no value.
fn unavailable(reason: &'static str) -> Error {
    ArtifactError::KnownValueHistoryUnavailable { reason }.into()
}

/// What a restore needs of one id its rows commit to.
enum Need {
    Live,
    Retired,
    Missing,
}

fn need(plan: &mut CustodyPlan, source: &CustodyBinding, id: &CustodyId) -> Result<Need> {
    let error = match plan.require_exact(id) {
        Ok(Requirement::Live) => return Ok(Need::Live),
        Ok(Requirement::Retired) => return Ok(Need::Retired),
        Err(error) => error,
    };
    // A binding another platform wrote, or one whose custody stayed on
    // another host, holds nothing here.
    if !custody_present(source.root())?
        || LocalCustody::at(source).state(id)? == EntryState::Missing
    {
        return Ok(Need::Missing);
    }
    Err(error)
}

/// The known-value history references among raw `vault_meta` rows: the
/// master's generation, and each holder's row key and references.
type RowsHistory = (Option<u64>, Vec<(Vec<u8>, EntityId, HistoryRefs)>);

fn history_in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<RowsHistory> {
    let mut index = None;
    let mut history = Vec::new();
    for (key, value) in rows {
        if key.as_slice() == INDEX.decl().prefix {
            let at = INDEX
                .decode_value(value)
                .map_err(|_| unavailable(HISTORY_CORRUPT))?;
            index = Some(at);
        } else if let Some(holder) = key.strip_prefix(HISTORY.decl().prefix) {
            let holder = <EntityId as SideKey>::decode_key(holder)
                .ok_or_else(|| unavailable(HISTORY_CORRUPT))?;
            let refs = HISTORY
                .decode_value(value)
                .map_err(|_| unavailable(HISTORY_CORRUPT))?;
            history.push((key.clone(), holder, refs));
        }
    }
    Ok((index, history))
}

/// Requires the master at generation `index` of `source` through `plan`,
/// strictly read.
fn require_master(plan: &mut CustodyPlan, source: &CustodyBinding, index: u64) -> Result<()> {
    let master = index_subject(source)?.at(index);
    match need(plan, source, &master)? {
        Need::Live => {
            LocalCustody::at(source)
                .read(&master)
                .and_then(|secret| copy_master(&secret))
                .map_err(|_| unavailable(HISTORY_CORRUPT))?;
            Ok(())
        }
        Need::Retired => Err(Error::InvariantViolation(
            "the known-value index's master key is retired",
        )),
        Need::Missing => Err(unavailable(INDEX_MISSING)),
    }
}

/// Requires each of `holder`'s committed entries `refs` of `source`
/// through `plan`, strictly read. Returns the ones kept, a retired one
/// dropped, and whether any is missing.
fn require_holder(
    plan: &mut CustodyPlan,
    source: &CustodyBinding,
    holder: &EntityId,
    refs: HistoryRefs,
) -> Result<(HistoryRefs, bool)> {
    let subject = holder_subject(source, holder)?;
    let mut kept = Vec::with_capacity(refs.0.len());
    let mut missing = false;
    for held in refs.0 {
        let id = subject.at(held.slot);
        match need(plan, source, &id)? {
            Need::Live => {
                LocalCustody::at(source)
                    .read(&id)
                    .ok()
                    .and_then(|secret| KnownEntry::from_secret(&secret))
                    .ok_or_else(|| unavailable(HISTORY_CORRUPT))?;
                kept.push(held);
            }
            Need::Retired => {}
            Need::Missing => missing = true,
        }
    }
    Ok((HistoryRefs(kept), missing))
}

/// Requires the known-value history the raw `vault_meta` `rows` commit to
/// through `plan`, the one plan a restore's or an activation's claim keys
/// and bodies share, before anything is made (KS-3): the index's master
/// live, and every committed entry live and strictly read, each recorded by
/// exact id so the fork copies every retained rotation and nothing else. An
/// entry a carried-out retirement covers, or a marker retired, leaves
/// `rows` with its reference. No key is minted and no value indexed again in
/// place of one custody lacks.
///
/// # Errors
///
/// `known_value_index_missing` for a master custody lacks,
/// `known_value_history_missing` for an entry it lacks,
/// `known_value_history_corrupt` for one that does not read; a retired
/// master is an invariant failure; custody errors.
pub(crate) fn require_known_history(
    rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    plan: &mut CustodyPlan,
) -> Result<()> {
    let (index, history) = history_in_rows(rows)?;
    if index.is_none() && history.is_empty() {
        return Ok(());
    }
    let (Some(index), Some(source)) = (index, plan.source().cloned()) else {
        return Err(unavailable(INDEX_MISSING));
    };
    require_master(plan, &source, index)?;
    let mut missing = false;
    let mut kept_rows = Vec::with_capacity(history.len());
    for (key, holder, refs) in history {
        let (kept, lacks) = require_holder(plan, &source, &holder, refs)?;
        missing |= lacks;
        kept_rows.push((key, kept));
    }
    if missing {
        return Err(unavailable(HISTORY_MISSING));
    }
    for (key, kept) in kept_rows {
        let Some(at) = rows.iter().position(|(row, _)| *row == key) else {
            continue;
        };
        if kept.0.is_empty() {
            rows.remove(at);
        } else {
            rows[at].1 = HISTORY.encode_value(&kept)?;
        }
    }
    Ok(())
}

/// Reads back, under `binding` (an activation's forked custody), the master
/// and every entry the known-value history `rows` commit to, strictly
/// (KS-3): the fork holds each one before the archive lifts.
///
/// # Errors
///
/// An entry or master the fork lacks or that does not read, and custody
/// errors.
pub(crate) fn read_back_known_history(
    rows: &[(Vec<u8>, Vec<u8>)],
    binding: &CustodyBinding,
) -> Result<()> {
    let custody = LocalCustody::at(binding);
    for (key, value) in rows {
        if key.as_slice() == INDEX.decl().prefix {
            let master = index_subject(binding)?.at(INDEX.decode_value(value)?);
            copy_master(&custody.read(&master)?)?;
        } else if let Some(holder) = key
            .strip_prefix(HISTORY.decl().prefix)
            .and_then(<EntityId as SideKey>::decode_key)
        {
            let refs = HISTORY.decode_value(value)?;
            read_entries(custody, &holder, refs.slots())?;
        }
    }
    Ok(())
}
