//! Durable sealed-bundle execution. Source stages are detached at acceptance;
//! only the final writer makes a prepared generation readable.

mod memory;
mod storage;
pub use self::memory::{sealed_bundle_work_memory_bytes, sealed_bundle_work_memory_room};
pub use self::storage::cleanup_sealed_bundle_work;
pub(super) use self::storage::stages_in;

use serde::{Deserialize, Serialize};

use super::super::bundle_turn::{hold_turn_in, published_in};
use super::{
    Asked, GENERATIONS, PARTS, STAGE_PARTS, STAGES, STORED_PART, SealedBundleEntry,
    SealedBundleKitRoot, SealedBundleObject, SealedBundleStage, decode_stage, denied, entries_in,
    entry_in, owner_machine, owner_machine_in, part_key, retained_stage_whole, retire_in,
    sealed_digest_hex, sealed_generation_hex, stage_identity, stage_key, stage_parts_prefix,
};
use crate::authority::{AuthorityEntryHash, PeerMachine};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{
    RecoveryRootId, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle, sealed_bundle_slot,
};
use crate::{EntityId, Vault};

// Request receipts keep their exact request:machine keys and codec. These
// prefixes are not request hashes, so request-result cleanup skips them.
const WORK: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT);
const WORK_PREFIX: &str = "work:";
const RESERVATION_PREFIX: &str = "generation:";
pub const SEALED_BUNDLE_WORK_PART_BYTES: u64 = STORED_PART as u64;
const WORK_ID_CONTEXT: &str = "oneiron sealed bundle commit work v1";

/// The immutable publication a caller asks the home to finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleCommitInput {
    pub generation: SealedBundleGeneration,
    pub parent: Option<SealedBundleGeneration>,
    pub root: Option<RecoveryRootId>,
    pub request: Option<AuthorityEntryHash>,
}

/// Execution outcome, distinct from an owner-request publication receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedBundleWorkOutcome {
    Pending,
    Committed(SealedBundleEntry),
    NeedsRebase,
    Refused,
}

/// An authenticated read of an immutable attempt. Its id is not authority.
#[derive(Clone, Debug)]
pub struct SealedBundleWorkStatus {
    pub work_id: [u8; 32],
    pub home: Option<EntityId>,
    pub executor: EntityId,
    pub input: SealedBundleCommitInput,
    pub bundle_digest: [u8; 32],
    pub pads_digest: [u8; 32],
    pub prepared: u64,
    pub total: u64,
    pub phase: &'static str,
    pub outcome: SealedBundleWorkOutcome,
}

#[derive(Clone, Serialize, Deserialize)]
struct Source {
    header: Vec<u8>,
    cleaned: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    ValidateBundle,
    ValidatePads,
    CopyBundle,
    CopyPads,
    Publish,
    Committed,
    NeedsRebase,
    Refused,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    executor: EntityId,
    key: [u8; 32],
    home: Option<EntityId>,
    generation: [u8; 24],
    parent: Option<[u8; 24]>,
    root: Option<[u8; 32]>,
    request: Option<AuthorityEntryHash>,
    sources: [Source; 2],
    prepared: [u64; 2],
    source_offsets: [u64; 2],
    phase: Phase,
    entry: Option<Vec<u8>>,
    cleanup_done: bool,
}

impl Record {
    fn input(&self) -> Result<SealedBundleCommitInput> {
        Ok(SealedBundleCommitInput {
            generation: SealedBundleGeneration::from_bytes(&self.generation)?,
            parent: self
                .parent
                .as_ref()
                .map(|raw| SealedBundleGeneration::from_bytes(raw))
                .transpose()?,
            root: self.root.map(RecoveryRootId),
            request: self.request,
        })
    }

    fn stage(&self, index: usize) -> Result<SealedBundleStage> {
        Ok(decode_stage(&self.sources[index].header, object(index))?.1)
    }

    fn terminal(&self) -> bool {
        matches!(
            self.phase,
            Phase::Committed | Phase::NeedsRebase | Phase::Refused
        )
    }

    fn status(&self, id: [u8; 32]) -> Result<SealedBundleWorkStatus> {
        let input = self.input()?;
        let bundle = self.stage(0)?;
        let pads = self.stage(1)?;
        let outcome = match self.phase {
            Phase::Committed => SealedBundleWorkOutcome::Committed(SealedBundleEntry::decode(
                input.generation,
                self.entry.as_deref().ok_or(Error::InvalidKey)?,
            )?),
            Phase::NeedsRebase => SealedBundleWorkOutcome::NeedsRebase,
            Phase::Refused => SealedBundleWorkOutcome::Refused,
            _ => SealedBundleWorkOutcome::Pending,
        };
        Ok(SealedBundleWorkStatus {
            work_id: id,
            home: self.home,
            executor: self.executor,
            input,
            bundle_digest: bundle.digest,
            pads_digest: pads.digest,
            prepared: self.prepared.iter().copied().sum(),
            total: bundle.total.saturating_add(pads.total),
            phase: match self.phase {
                Phase::ValidateBundle => "validateBundle",
                Phase::ValidatePads => "validatePads",
                Phase::CopyBundle => "copyBundle",
                Phase::CopyPads => "copyPads",
                Phase::Publish => "publish",
                Phase::Committed => "committed",
                Phase::NeedsRebase => "needsRebase",
                Phase::Refused => "refused",
            },
            outcome,
        })
    }
}

fn object(index: usize) -> SealedBundleObject {
    if index == 0 {
        SealedBundleObject::Bundle
    } else {
        SealedBundleObject::Pads
    }
}

fn work_key(id: &[u8; 32]) -> String {
    format!("{WORK_PREFIX}{}", sealed_digest_hex(id))
}

fn reservation_key(generation: &SealedBundleGeneration) -> String {
    format!("{RESERVATION_PREFIX}{}", sealed_generation_hex(generation))
}

fn load_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &[u8; 32]) -> Result<Option<Record>> {
    WORK.get_bytes(&vault.store, txn, &work_key(id))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| Error::InvalidKey))
        .transpose()
}

fn save_in(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: &[u8; 32], record: &Record) -> Result<()> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::InvalidKey)?;
    WORK.put(&vault.store, txn, &work_key(id), &bytes)
}

fn bound_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: PeerMachine,
    record: &Record,
) -> Result<()> {
    let machine = owner_machine_in(vault, txn, peer, true, Asked::Any)?;
    if peer
        != (PeerMachine::Proven {
            machine: record.executor,
            key: record.key,
        })
        || machine != record.executor
        || (record.home.is_some()
            && crate::identity::read_machine_id_in_txn(vault, txn)? != record.home)
    {
        return Err(denied());
    }
    Ok(())
}

/// A caller-known address before the first commit send, including a direct
/// publication with no owner request. Lengths and digests bind both objects.
#[must_use]
pub fn sealed_bundle_work_id(
    home: Option<EntityId>,
    executor: EntityId,
    input: SealedBundleCommitInput,
    objects: [(u64, [u8; 32]); 2],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key(WORK_ID_CONTEXT);
    hash.update(&[u8::from(home.is_some())]);
    if let Some(home) = home {
        hash.update(home.as_bytes());
    }
    hash.update(executor.as_bytes());
    hash.update(&input.generation.to_bytes());
    hash.update(&[u8::from(input.parent.is_some())]);
    if let Some(parent) = input.parent {
        hash.update(&parent.to_bytes());
    }
    for value in [input.root.map(|root| root.0), input.request] {
        hash.update(&[u8::from(value.is_some())]);
        if let Some(value) = value {
            hash.update(&value);
        }
    }
    for (len, digest) in objects {
        hash.update(&len.to_be_bytes());
        hash.update(&digest);
    }
    *hash.finalize().as_bytes()
}

/// Atomically accepts an immutable attempt and detaches its stage handles.
/// An id already accepted returns that same state even after source cleanup.
pub fn begin_sealed_bundle_work(
    vault: &Vault,
    peer: PeerMachine,
    input: SealedBundleCommitInput,
    known_id: Option<[u8; 32]>,
) -> Result<SealedBundleWorkStatus> {
    begin_sealed_bundle_work_authorized(vault, peer, input, known_id, &|_| true)
}

/// The serving host rechecks its caller in the acceptance writer as well.
pub fn begin_sealed_bundle_work_authorized(
    vault: &Vault,
    peer: PeerMachine,
    input: SealedBundleCommitInput,
    known_id: Option<[u8; 32]>,
    admitted: &dyn Fn(&heed::RwTxn<'_>) -> bool,
) -> Result<SealedBundleWorkStatus> {
    let machine = owner_machine(vault, peer, true, Asked::Any)?;
    let PeerMachine::Proven { key, .. } = peer else {
        return Err(denied());
    };
    vault.with_write_txn_grouped(|txn| {
        if !admitted(txn) {
            return Err(denied());
        }
        if let Some(id) = known_id
            && let Some(record) = load_in(vault, txn, &id)?
        {
            bound_in(vault, txn, peer, &record)?;
            if record.input()? != input {
                return Err(denied());
            }
            return record.status(id);
        }
        owner_machine_in(vault, txn, peer, true, Asked::Any)?;
        let home = crate::identity::read_machine_id_in_txn(vault, txn)?;
        let mut headers = Vec::with_capacity(2);
        let mut objects = [(0, [0; 32]); 2];
        for index in 0..2 {
            let header = STAGES
                .get_bytes(&vault.store, txn, &stage_key(machine, object(index)))?
                .ok_or_else(denied)?;
            let (_, stage, staged) = decode_stage(&header, object(index))?;
            if stage.generation != input.generation || staged != stage.total {
                return Err(denied());
            }
            objects[index] = (stage.total, stage.digest);
            headers.push(Source { header, cleaned: 0 });
        }
        let addressed = sealed_bundle_work_id(home, machine, input, objects);
        // A caller whose home proof has not synced yet can still publish.
        // Its explicit unknown-home address binds the same immutable attempt;
        // the record is still scoped to this vault and the actually proved peer.
        let unproven_home = sealed_bundle_work_id(None, machine, input, objects);
        let id = match known_id {
            Some(id) if id == addressed || id == unproven_home => id,
            Some(_) => return Err(denied()),
            None => addressed,
        };
        if let Some(record) = load_in(vault, txn, &id)? {
            bound_in(vault, txn, peer, &record)?;
            return record.status(id);
        }
        let record = Record {
            executor: machine,
            key,
            home,
            generation: input.generation.to_bytes(),
            parent: input.parent.map(|value| value.to_bytes()),
            root: input.root.map(|value| value.0),
            request: input.request,
            sources: headers.try_into().map_err(|_| Error::InvalidKey)?,
            prepared: [0; 2],
            source_offsets: [0; 2],
            phase: Phase::ValidateBundle,
            entry: None,
            cleanup_done: false,
        };
        save_in(vault, txn, &id, &record)?;
        // Only the two active handles go. Their immutable parts now belong
        // to this record, not to a subsequent offset-zero upload.
        for index in 0..2 {
            STAGES.delete(&vault.store, txn, &stage_key(machine, object(index)))?;
        }
        record.status(id)
    })
}

/// Reads only. Resuming execution is a separate, write-authorized step.
pub fn sealed_bundle_work_status(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
) -> Result<Option<SealedBundleWorkStatus>> {
    owner_machine(vault, peer, true, Asked::Any)?;
    let txn = vault.store.env.read_txn()?;
    let Some(record) = load_in(vault, &txn, &id)? else {
        return Ok(None);
    };
    bound_in(vault, &txn, peer, &record)?;
    Ok(Some(record.status(id)?))
}

/// Maximum source-object bytes the next strict validation reads. The host
/// reserves parser allocations as well, before it invokes the step.
pub fn sealed_bundle_work_validation_bytes(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    let record = load_in(vault, &txn, &id)?.ok_or_else(denied)?;
    bound_in(vault, &txn, peer, &record)?;
    Ok(match record.phase {
        Phase::ValidateBundle | Phase::ValidatePads => {
            record.stage(0)?.total.max(record.stage(1)?.total)
        }
        _ => 0,
    })
}

/// Read-only owner-request reconciliation must report an accepted pending
/// execution, not pretend the absent publication receipt frees a new upload.
pub fn sealed_bundle_work_for_request(
    vault: &Vault,
    peer: PeerMachine,
    request: AuthorityEntryHash,
) -> Result<Option<SealedBundleWorkStatus>> {
    let machine = owner_machine(vault, peer, false, Asked::named(Some(request)))?;
    let txn = vault.store.env.read_txn()?;
    for row in WORK.iter_raw_from(&vault.store, &txn, WORK_PREFIX.as_bytes())? {
        let (key, raw) = row?;
        let record: Record = serde_json::from_slice(&raw).map_err(|_| Error::InvalidKey)?;
        if record.executor != machine || record.request != Some(request) || record.terminal() {
            continue;
        }
        bound_in(vault, &txn, peer, &record)?;
        let key = std::str::from_utf8(&key).map_err(|_| Error::InvalidKey)?;
        let id =
            super::sealed_digest_from_hex(key.strip_prefix(WORK_PREFIX).ok_or(Error::InvalidKey)?)
                .ok_or(Error::InvalidKey)?;
        return Ok(Some(record.status(id)?));
    }
    Ok(None)
}

fn reserve_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    record: &Record,
) -> Result<bool> {
    let key = reservation_key(&record.input()?.generation);
    if let Some(owner) = WORK.get_bytes(&vault.store, txn, &key)? {
        return Ok(owner.as_slice() == id);
    }
    WORK.put(&vault.store, txn, &key, &id.to_vec())?;
    Ok(true)
}

fn owns_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &[u8; 32], record: &Record) -> Result<bool> {
    Ok(WORK
        .get_bytes(
            &vault.store,
            txn,
            &reservation_key(&record.input()?.generation),
        )?
        .is_some_and(|owner| owner.as_slice() == id))
}

/// One validation or stored-part page, with publication once all pages exist.
/// Whole strict parsing and the existing retention transaction are indivisible;
/// callers run this on a tracked blocking phase, never on the socket loop.
pub fn step_sealed_bundle_work(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
) -> Result<SealedBundleWorkStatus> {
    step_sealed_bundle_work_authorized(vault, peer, id, &|_| true)
}

/// The host supplies its live caller consult. It runs after the fair wait,
/// before validation and again inside the publication/page writer. A lapsed
/// caller detaches; it does not cancel already accepted durable work.
pub fn step_sealed_bundle_work_authorized(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    admitted: &dyn Fn(Option<&heed::RwTxn<'_>>) -> bool,
) -> Result<SealedBundleWorkStatus> {
    let machine = owner_machine(vault, peer, true, Asked::Any)?;
    let turn = vault.admit_task_work_blocking(machine);
    step_sealed_bundle_work_in_turn(vault, peer, id, &turn, admitted)
}

/// Async hosts admit a fair turn before starting their blocking phase, so a
/// queued turn can detach on socket/host stop without leaving a queued thread.
pub fn step_sealed_bundle_work_in_turn(
    vault: &Vault,
    peer: PeerMachine,
    id: [u8; 32],
    _turn: &crate::work_line::TaskWorkTurn,
    admitted: &dyn Fn(Option<&heed::RwTxn<'_>>) -> bool,
) -> Result<SealedBundleWorkStatus> {
    if !admitted(None) {
        return Err(denied());
    }
    let record = {
        let txn = vault.store.env.read_txn()?;
        let record = load_in(vault, &txn, &id)?.ok_or_else(denied)?;
        bound_in(vault, &txn, peer, &record)?;
        record
    };
    if record.terminal() {
        return record.status(id);
    }
    let valid = match record.phase {
        Phase::ValidateBundle | Phase::ValidatePads => {
            let index = usize::from(record.phase == Phase::ValidatePads);
            let txn = vault.store.env.read_txn()?;
            let whole =
                retained_stage_whole(vault, &txn, &record.sources[index].header, object(index))?;
            drop(txn);
            match whole {
                None => false,
                Some((stage, bytes)) => {
                    let generation = if index == 0 {
                        SealedVaultBundle::from_bytes(&bytes).map(|value| value.generation())
                    } else {
                        SealedKeyPads::from_bytes(&bytes).map(|value| value.generation())
                    };
                    generation.is_ok_and(|generation| generation == stage.generation)
                }
            }
        }
        _ => true,
    };
    vault.with_write_txn_grouped(|txn| {
        if !admitted(Some(txn)) {
            return Err(denied());
        }
        let mut current = load_in(vault, txn, &id)?.ok_or_else(denied)?;
        bound_in(vault, txn, peer, &current)?;
        // Two attachments may prepare the same next phase, but only one can
        // advance its durable cursor. No transaction or permit crosses a wait.
        if current.phase != record.phase || current.prepared != record.prepared {
            return current.status(id);
        }
        if !valid {
            current.phase = Phase::Refused;
        } else {
            match current.phase {
                Phase::ValidateBundle => current.phase = Phase::ValidatePads,
                Phase::ValidatePads => current.phase = Phase::CopyBundle,
                Phase::CopyBundle | Phase::CopyPads => {
                    let generation = current.input()?.generation;
                    if entry_in(vault, txn, &generation)?.is_some() {
                        current.phase = Phase::Refused;
                    } else if reserve_in(vault, txn, &id, &current)? {
                        let index = usize::from(current.phase == Phase::CopyPads);
                        let stage = current.stage(index)?;
                        let offset = current.prepared[index];
                        let len = usize::try_from(
                            stage.total.saturating_sub(offset).min(STORED_PART as u64),
                        )
                        .map_err(|_| Error::InvalidKey)?;
                        if len > 0 {
                            let (part, source_offset) = copy_page_in(
                                vault,
                                txn,
                                &current.sources[index].header,
                                current.source_offsets[index],
                                offset,
                                len,
                            )?;
                            PARTS.put(
                                &vault.store,
                                txn,
                                &part_key(&generation, object(index), offset),
                                &part,
                            )?;
                            current.source_offsets[index] = source_offset;
                            current.prepared[index] += len as u64;
                        }
                        if current.prepared[index] == stage.total {
                            current.phase = if index == 0 {
                                Phase::CopyPads
                            } else {
                                Phase::Publish
                            };
                        }
                    }
                }
                Phase::Publish => publish_in(vault, txn, peer, &id, &mut current)?,
                _ => {}
            }
        }
        save_in(vault, txn, &id, &current)?;
        current.status(id)
    })
}

// The cursor names the original upload part containing `offset`. Exact key
// lookups avoid re-reading every earlier part for each stored-part page.
fn copy_page_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    header: &[u8],
    mut source_offset: u64,
    offset: u64,
    len: usize,
) -> Result<(Vec<u8>, u64)> {
    let prefix = stage_parts_prefix(&stage_identity(header)?);
    let mut out = Vec::with_capacity(len);
    let mut at = offset;
    while out.len() < len {
        let key = format!("{prefix}{source_offset:016x}");
        let part = STAGE_PARTS
            .get_borrowed(&vault.store, txn, &key)?
            .ok_or(Error::InvalidKey)?;
        let from = usize::try_from(at.checked_sub(source_offset).ok_or(Error::InvalidKey)?)
            .map_err(|_| Error::InvalidKey)?;
        let remaining = part
            .get(from..)
            .filter(|slice| !slice.is_empty())
            .ok_or(Error::InvalidKey)?;
        let count = remaining.len().min(len - out.len());
        out.extend_from_slice(&remaining[..count]);
        at = at.checked_add(count as u64).ok_or(Error::InvalidKey)?;
        if count == remaining.len() {
            source_offset = at;
        }
    }
    Ok((out, source_offset))
}

fn publish_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    peer: PeerMachine,
    id: &[u8; 32],
    record: &mut Record,
) -> Result<()> {
    bound_in(vault, txn, peer, record)?;
    let input = record.input()?;
    let kept = entries_in(vault, txn)?;
    let latest = kept.last().map(|entry| entry.generation);
    if latest != input.parent {
        record.phase = Phase::NeedsRebase;
        return Ok(());
    }
    let now = vault.instant_in_txn(txn)?.secs();
    let now_slot = sealed_bundle_slot(now);
    if latest.is_some_and(|latest| input.generation.slot < latest.slot)
        || input.generation.slot > now_slot
        || entry_in(vault, txn, &input.generation)?.is_some()
        || !owns_in(vault, txn, id, record)?
        || !hold_turn_in(vault, txn, record.executor, now)?
    {
        record.phase = Phase::Refused;
        return Ok(());
    }
    let kit = match input.root {
        None => None,
        Some(root) => {
            let fold = vault.authority_fold_readonly_in_txn(txn)?;
            let Some((_, value)) =
                crate::authority::owner_root_record_in_txn(&vault.store, txn, &fold, root)?
            else {
                record.phase = Phase::Refused;
                return Ok(());
            };
            Some(SealedBundleKitRoot {
                root,
                anchor_key: value.anchor_key,
            })
        }
    };
    let bundle = record.stage(0)?;
    let pads = record.stage(1)?;
    if record.prepared != [bundle.total, pads.total] {
        return Err(Error::InvalidKey);
    }
    let entry = SealedBundleEntry {
        generation: input.generation,
        commit_order: super::order::next_commit_order(&kept),
        bundle_len: bundle.total,
        bundle_digest: bundle.digest,
        pads_len: pads.total,
        pads_digest: pads.digest,
        kit,
    };
    GENERATIONS.put(
        &vault.store,
        txn,
        &sealed_generation_hex(&input.generation),
        &entry.encode(),
    )?;
    if let Some(request) = input.request {
        super::commit_receipt::record_in(vault, txn, record.executor, request, &entry)?;
    }
    published_in(vault, txn, record.executor, now)?;
    retire_in(vault, txn, now_slot)?;
    record.phase = Phase::Committed;
    record.entry = Some(entry.encode());
    WORK.delete(&vault.store, txn, &reservation_key(&input.generation))?;
    Ok(())
}

/// The synchronous engine interface drains the SAME durable implementation.
pub(super) fn commit(
    vault: &Vault,
    peer: PeerMachine,
    input: SealedBundleCommitInput,
) -> Result<SealedBundleEntry> {
    let mut status = begin_sealed_bundle_work(vault, peer, input, None)?;
    loop {
        match status.outcome {
            SealedBundleWorkOutcome::Committed(entry) => {
                // Publication has already succeeded. A cleanup fault leaves
                // its durable obligation; it cannot turn that fact into an error.
                while matches!(storage::cleanup_one(vault, Some(status.work_id)), Ok(true)) {}
                return Ok(entry);
            }
            SealedBundleWorkOutcome::NeedsRebase | SealedBundleWorkOutcome::Refused => {
                return Err(denied());
            }
            SealedBundleWorkOutcome::Pending => {
                let next = step_sealed_bundle_work(vault, peer, status.work_id)?;
                if next.phase == status.phase && next.prepared == status.prepared {
                    return Err(Error::sync_protocol(
                        crate::error::SyncProtocolValidation::DocumentPendingUpdate,
                    ));
                }
                status = next;
            }
        }
    }
}
