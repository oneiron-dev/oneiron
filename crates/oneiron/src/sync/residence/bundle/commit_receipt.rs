//! The home's commit of a staged generation, and its record of each commit an
//! asked executor made for the owner's bundle publication request (FIX 4787).
//!
//! A commit may name the request it publishes for. When that request counts
//! here, names this home and names the committing machine as its executor,
//! the home records the commit (the machine, the generation and the bundle's
//! ciphertext digest) in the commit's own transaction, so the commit and its
//! record land together or not at all. The first commit recorded for a
//! request stands. A record outlives its generation's retirement, with no
//! expiry and no count bound, and goes once the request has its result here.
//! A commit whose request does not check is taken exactly as one naming
//! none: nothing is refused that was taken before.
//!
//! The executor reads the record back before it assembles another upload for
//! the request (`sync::client`'s bundle publication), so an acknowledgement
//! lost on the way does not make it publish twice.

use super::super::bundle_turn::{hold_turn_in, published_in};
use super::{
    Asked, GENERATIONS, SealedBundleEntry, SealedBundleKitRoot, SealedBundleObject, denied,
    drop_stage_in, entries_in, owner_machine, put_object_in, retire_in, sealed_digest_hex,
    sealed_generation_hex, stage_key, staged_whole,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, OwnerWorkBody, PeerMachine};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{
    RecoveryRootId, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle, sealed_bundle_slot,
};

/// Each asked commit the home recorded, by its request.
const RECEIPTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT);

/// The machine (16) ‖ the generation (24) ‖ the bundle's digest (32).
const RECEIPT_LEN: usize = 16 + 24 + 32;

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
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_LEN);
        out.extend_from_slice(self.executor.as_bytes());
        out.extend_from_slice(&self.generation.to_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != RECEIPT_LEN {
            return Err(Error::InvalidKey);
        }
        let executor: [u8; 16] = raw[..16].try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            executor: EntityId::from_bytes(executor).map_err(|_| Error::InvalidKey)?,
            generation: SealedBundleGeneration::from_bytes(&raw[16..40])?,
            bundle_digest: raw[40..].try_into().map_err(|_| Error::InvalidKey)?,
        })
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
/// transaction, when the request checks (FIX 4787), unless a commit is
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
    let key = sealed_digest_hex(&request);
    if asks_here(&fold, &request, machine, home)
        && RECEIPTS.get_bytes(&vault.store, wtxn, &key)?.is_none()
    {
        let receipt = SealedBundleCommitReceipt {
            executor: machine,
            generation: entry.generation,
            bundle_digest: entry.bundle_digest,
        };
        RECEIPTS.put(&vault.store, wtxn, &key, &receipt.encode())?;
    }
    let mut resolved = Vec::new();
    for row in RECEIPTS.iter_raw_from(&vault.store, wtxn, &[])? {
        let (row_key, _) = row?;
        let answered = std::str::from_utf8(&row_key)
            .ok()
            .and_then(super::sealed_digest_from_hex)
            .is_some_and(|asked| fold.owner_work_result(&asked).is_some());
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
    let entry = SealedBundleEntry {
        generation,
        bundle_len: bundle_stage.total,
        bundle_digest: bundle_stage.digest,
        pads_len: pads_stage.total,
        pads_digest: pads_stage.digest,
        kit,
    };
    vault.with_write_txn_grouped(|wtxn| {
        let latest = entries_in(vault, wtxn)?
            .last()
            .map(|entry| entry.generation);
        let now = vault.instant_in_txn(wtxn)?.secs();
        let now_slot = sealed_bundle_slot(now);
        if latest != parent
            || latest.is_some_and(|latest| generation.slot <= latest.slot)
            || generation.slot > now_slot
            || !hold_turn_in(vault, wtxn, machine, now)?
        {
            return Err(denied());
        }
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
/// request asked to publish here. `None` when the home recorded none for
/// that machine. Reads only.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn sealed_bundle_commit_receipt(
    vault: &Vault,
    peer: PeerMachine,
    request: AuthorityEntryHash,
) -> Result<Option<SealedBundleCommitReceipt>> {
    let machine = owner_machine(vault, peer, false, Asked::named(Some(request)))?;
    let txn = vault.store.env.read_txn()?;
    Ok(RECEIPTS
        .get_bytes(&vault.store, &txn, &sealed_digest_hex(&request))?
        .map(|raw| SealedBundleCommitReceipt::decode(&raw))
        .transpose()?
        .filter(|receipt| receipt.executor == machine))
}
