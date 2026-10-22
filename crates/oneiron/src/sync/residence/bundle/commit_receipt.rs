//! The home's commit of a staged generation, and its record of each commit an
//! asked executor made for the owner's bundle publication request (FIX 4787).
//!
//! A commit may name the request it publishes for. When that request counts
//! here, names this home and names the committing machine as its executor,
//! the home records the commit (the machine, the generation and the bundle's
//! ciphertext digest) in the commit's own transaction, so the commit and its
//! record land together or not at all. When this home's fold has not seen
//! the request yet (an owner machine may commit before the home folds the
//! ask), the home keeps the commit's claim the same way (FIX 5554, CALLS
//! BUNDLE_COMMIT_CLAIM), to be checked once the request folds. Each record
//! is keyed by the request and the committing machine, so another machine's
//! commit never takes the executor's slot; the first one per pair stands. A
//! record outlives its generation's retirement, with no expiry and no count
//! bound, and goes once the request has its result here. A commit whose
//! request folded here and does not check is taken exactly as one naming
//! none: nothing is refused that was taken before.
//!
//! The executor reads the record back before it assembles another upload for
//! the request (`sync::client`'s bundle publication), so an acknowledgement
//! lost on the way does not make it publish twice. A claim whose request this
//! home has not folded yet answers that it cannot tell, never that there is
//! none: the executor holds its upload as uncertain and asks again later.

use super::super::bundle_turn::{hold_turn_in, published_in};
use super::{
    Asked, GENERATIONS, SealedBundleEntry, SealedBundleKitRoot, SealedBundleObject, denied,
    drop_stage_in, entries_in, entry_in, order, owner_machine, put_object_in, retire_in,
    sealed_digest_hex, sealed_generation_hex, stage_key, staged_whole,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, OwnerWorkBody, PeerMachine};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{
    RecoveryRootId, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle, sealed_bundle_slot,
};

/// Each asked commit the home recorded, by its request and its committer.
const RECEIPTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT);

/// Whether a record's request checked when its commit landed (1), or this
/// home's fold had not seen it yet, a claim (0) ‖ the machine (16) ‖ the
/// generation (24) ‖ the bundle's digest (32).
const RECEIPT_LEN: usize = 1 + 16 + 24 + 32;

/// What a record is for an early commit (CALLS BUNDLE_COMMIT_CLAIM, FIX
/// 5554).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EarlyCommit {
    /// A commit naming a request this home's fold has not seen keeps its
    /// claim, keyed by the request and the committer. Read back, it is the
    /// receipt once the request folds counted naming this home and that
    /// committer; nothing once the request folded otherwise; and, until the
    /// request folds here, an answer that the home cannot tell yet, so the
    /// executor holds its upload. No expiry, no count bound.
    ClaimCheckedOnRead,
}

const BUNDLE_COMMIT_CLAIM: EarlyCommit = EarlyCommit::ClaimCheckedOnRead;

/// A record's kind byte.
const CHECKED: u8 = 1;
const CLAIM: u8 = 0;

/// The record key: the request's entry hash, then the committing machine.
fn receipt_key(request: &AuthorityEntryHash, machine: EntityId) -> String {
    format!("{}:{}", sealed_digest_hex(request), machine.to_hex())
}

/// The request a record key names.
fn receipt_request(key: &[u8]) -> Option<AuthorityEntryHash> {
    let key = std::str::from_utf8(key).ok()?;
    let (request, _) = key.split_once(':')?;
    super::sealed_digest_from_hex(request)
}

/// Whether `fold` has seen the request signed as entry `request`, with
/// effect or without.
fn folded_here(fold: &AuthorityFold, request: &AuthorityEntryHash) -> bool {
    fold.owner_work_request(request).is_some()
        || fold.refused_owner_work().contains(request)
        || fold.valid_entries.contains(request)
}

/// A claim whose request this home has not folded yet: the home cannot tell
/// whether the commit is the request's (FIX 5554). The status read answers
/// it as a refused call, which the executor holds on as uncertain.
fn claim_unsettled() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentPendingUpdate)
}

/// The commit the home recorded for one bundle publication request: the
/// executor that made it, the generation and the sealed bundle's digest.
/// Ids and a ciphertext digest only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleCommitReceipt {
    pub executor: EntityId,
    pub generation: SealedBundleGeneration,
    /// BLAKE3 of the sealed bundle's bytes.
    pub bundle_digest: [u8; 32],
}

impl SealedBundleCommitReceipt {
    fn encode(&self, kind: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_LEN);
        out.push(kind);
        out.extend_from_slice(self.executor.as_bytes());
        out.extend_from_slice(&self.generation.to_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out
    }

    /// The record's kind byte and its receipt.
    fn decode(raw: &[u8]) -> Result<(u8, Self)> {
        let Some((&kind, raw)) = raw.split_first() else {
            return Err(Error::InvalidKey);
        };
        if raw.len() != RECEIPT_LEN - 1 || (kind != CHECKED && kind != CLAIM) {
            return Err(Error::InvalidKey);
        }
        let executor: [u8; 16] = raw[..16].try_into().map_err(|_| Error::InvalidKey)?;
        Ok((
            kind,
            Self {
                executor: EntityId::from_bytes(executor).map_err(|_| Error::InvalidKey)?,
                generation: SealedBundleGeneration::from_bytes(&raw[16..40])?,
                bundle_digest: raw[40..].try_into().map_err(|_| Error::InvalidKey)?,
            },
        ))
    }
}

/// Whether the counted request signed as entry `request` asks `machine` to
/// publish to `home`, this install.
fn asks_here(
    fold: &AuthorityFold,
    request: &AuthorityEntryHash,
    machine: EntityId,
    home: Option<EntityId>,
) -> bool {
    fold.counted_owner_work_request(request)
        .is_some_and(|asked| match asked.work {
            OwnerWorkBody::PublishBundle { home: to } => {
                asked.executor == machine && home == Some(to)
            }
            OwnerWorkBody::WorldKey { .. }
            | OwnerWorkBody::Root { .. }
            | OwnerWorkBody::Custody { .. } => false,
        })
}

/// Records `machine`'s commit of `entry` for `request` in the commit's own
/// transaction, when the request checks (FIX 4787) or this home's fold has
/// not seen it yet, its claim (FIX 5554), unless a commit of `machine` is
/// recorded for it already; then forgets every record whose request has its
/// result here.
fn record_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    machine: EntityId,
    request: AuthorityEntryHash,
    entry: &SealedBundleEntry,
) -> Result<()> {
    let fold = vault.authority_fold_readonly_in_txn(wtxn)?;
    let home = crate::identity::read_machine_id_in_txn(vault, wtxn)?;
    let key = receipt_key(&request, machine);
    let kind = if asks_here(&fold, &request, machine, home) {
        Some(CHECKED)
    } else {
        match BUNDLE_COMMIT_CLAIM {
            EarlyCommit::ClaimCheckedOnRead => (!folded_here(&fold, &request)).then_some(CLAIM),
        }
    };
    if let Some(kind) = kind
        && RECEIPTS.get_bytes(&vault.store, wtxn, &key)?.is_none()
    {
        let receipt = SealedBundleCommitReceipt {
            executor: machine,
            generation: entry.generation,
            bundle_digest: entry.bundle_digest,
        };
        RECEIPTS.put(&vault.store, wtxn, &key, &receipt.encode(kind))?;
    }
    let mut resolved = Vec::new();
    for row in RECEIPTS.iter_raw_from(&vault.store, wtxn, &[])? {
        let (row_key, _) = row?;
        let answered =
            receipt_request(&row_key).is_some_and(|asked| fold.owner_work_result(&asked).is_some());
        if answered {
            resolved.push(String::from_utf8(row_key).map_err(|_| Error::InvalidKey)?);
        }
    }
    for row_key in &resolved {
        RECEIPTS.delete(&vault.store, wtxn, row_key)?;
    }
    Ok(())
}

/// [`super::commit_sealed_bundle`]'s body: the commit, and with `request`
/// its record, in one transaction.
pub(super) fn commit(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
    parent: Option<SealedBundleGeneration>,
    root: Option<RecoveryRootId>,
    request: Option<AuthorityEntryHash>,
) -> Result<SealedBundleEntry> {
    let machine = owner_machine(vault, peer, true, Asked::Any)?;
    let kit = match root {
        None => None,
        Some(root) => {
            let (_, record) = vault
                .owner_root_records()?
                .remove(&root)
                .ok_or_else(denied)?;
            Some(SealedBundleKitRoot {
                root,
                anchor_key: record.anchor_key,
            })
        }
    };
    let (bundle, pads) = {
        let txn = vault.store.env.read_txn()?;
        (
            staged_whole(vault, &txn, machine, SealedBundleObject::Bundle)?,
            staged_whole(vault, &txn, machine, SealedBundleObject::Pads)?,
        )
    };
    let (Some((bundle_stage, bundle_bytes)), Some((pads_stage, pads_bytes))) = (bundle, pads)
    else {
        return Err(denied());
    };
    let bundle = SealedVaultBundle::from_bytes(&bundle_bytes).map_err(|_| denied())?;
    drop(bundle_bytes);
    let pads = SealedKeyPads::from_bytes(&pads_bytes).map_err(|_| denied())?;
    drop(pads_bytes);
    if [
        bundle_stage.generation,
        pads_stage.generation,
        bundle.generation(),
        pads.generation(),
    ]
    .iter()
    .any(|staged| *staged != generation)
    {
        return Err(denied());
    }
    let mut entry = SealedBundleEntry {
        generation,
        commit_order: 0,
        bundle_len: bundle_stage.total,
        bundle_digest: bundle_stage.digest,
        pads_len: pads_stage.total,
        pads_digest: pads_stage.digest,
        kit,
    };
    vault.with_write_txn_grouped(|wtxn| {
        let kept = entries_in(vault, wtxn)?;
        let latest = kept.last().map(|entry| entry.generation);
        let now = vault.instant_in_txn(wtxn)?.secs();
        let now_slot = sealed_bundle_slot(now);
        // A fresh generation of the newest's own slot is taken (FIX 8885):
        // the parent, the slot order and the clock are what refuse, never a
        // count. A generation kept already is never written over.
        if latest != parent
            || latest.is_some_and(|latest| generation.slot < latest.slot)
            || generation.slot > now_slot
            || entry_in(vault, wtxn, &generation)?.is_some()
            || !hold_turn_in(vault, wtxn, machine, now)?
        {
            return Err(denied());
        }
        entry.commit_order = order::next_commit_order(&kept);
        put_object_in(
            vault,
            wtxn,
            &generation,
            SealedBundleObject::Bundle,
            bundle.as_bytes(),
        )?;
        put_object_in(
            vault,
            wtxn,
            &generation,
            SealedBundleObject::Pads,
            pads.as_bytes(),
        )?;
        GENERATIONS.put(
            &vault.store,
            wtxn,
            &sealed_generation_hex(&generation),
            &entry.encode(),
        )?;
        for object in [SealedBundleObject::Bundle, SealedBundleObject::Pads] {
            drop_stage_in(vault, wtxn, &stage_key(machine, object))?;
        }
        if let Some(request) = request {
            record_in(vault, wtxn, machine, request, &entry)?;
        }
        published_in(vault, wtxn, machine, now)?;
        retire_in(vault, wtxn, now_slot)?;
        Ok(entry)
    })
}

/// The commit the home recorded for the owner's bundle publication
/// `request` (FIX 4787), for the machine `peer` proved when it made that
/// commit: a machine of the owner's whose proof stands here, or the one the
/// request asked to publish here. A record made while the request checked
/// is the receipt. A claim (FIX 5554) is checked now: the receipt once the
/// request counts here naming this home and that machine, `None` once it
/// folded here otherwise. `None` when the home recorded none for that
/// machine. Reads only.
///
/// # Errors
///
/// A refused peer; a claim whose request this home has not folded yet,
/// which the home cannot tell about (CALLS BUNDLE_COMMIT_CLAIM); storage
/// errors.
pub fn sealed_bundle_commit_receipt(
    vault: &Vault,
    peer: PeerMachine,
    request: AuthorityEntryHash,
) -> Result<Option<SealedBundleCommitReceipt>> {
    let machine = owner_machine(vault, peer, false, Asked::named(Some(request)))?;
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = RECEIPTS.get_bytes(&vault.store, &txn, &receipt_key(&request, machine))? else {
        return Ok(None);
    };
    let (kind, receipt) = SealedBundleCommitReceipt::decode(&raw)?;
    if receipt.executor != machine {
        return Ok(None);
    }
    if kind == CHECKED {
        return Ok(Some(receipt));
    }
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    let home = crate::identity::read_machine_id_in_txn(vault, &txn)?;
    if asks_here(&fold, &request, machine, home) {
        Ok(Some(receipt))
    } else if folded_here(&fold, &request) {
        Ok(None)
    } else {
        Err(claim_unsettled())
    }
}
