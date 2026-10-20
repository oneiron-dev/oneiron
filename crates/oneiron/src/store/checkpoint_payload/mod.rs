//! Checkpoint payload custody (KS-7, FIX 5688): the ordinary payload a
//! checkpoint copies is sealed one owner at a time, each owner's compartment
//! under its own typed custody leaf (kind `CheckpointPayload`), so an erase
//! that retires the leaf reaches every old checkpoint holding that owner's
//! bytes. Shared bytes keep their holders and refcounts; a checkpoint is
//! never a reference that keeps an erase from running.
//!
//! This module holds the item codec, the instance table ([`instance`]) and
//! the custody glue a capture and a restore call: the binding pinned with
//! the leaves it protects, the mint under the custody guard, guarded reads,
//! and the restore plan for a list of compartments. Nothing calls them yet:
//! projection (KS7-2), the mixed sync carriers (KS7-3), erase, hold and
//! retention staging (KS7-4) and capture and restore (KS7-5) do. Until KS7-6
//! flips [`CHECKPOINT_PAYLOADS_ENABLED`], every write here refuses and every
//! read answers empty.
#![allow(
    dead_code,
    reason = "KS7-2 to KS7-5 call these; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

pub(crate) mod instance;
pub(crate) mod loro;
pub(crate) mod rows;

use heed::RwTxn;
use oneiron_crypto::Purpose;
use zeroize::Zeroizing;

use crate::error::{Error, Result, StoreError};
use crate::side_table::SideKey;
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodyPlan, CustodySubject, LocalCustody, Requirement,
    retirement_in_txn,
};

use self::instance::{Lifecycle, PayloadInstance};

/// CALLS CHECKPOINT_PAYLOADS_ENABLED (Engine 10-20 07:1x): the one switch
/// for all of KS-7, false until KS7-6. While it is false nothing mints a
/// leaf, writes the instance table, changes a checkpoint manifest or refuses
/// anything that runs today.
///
/// Sealing is copy-only (call a): live rows and every reader of them stay as
/// they are; only the copy a checkpoint takes of an owner's rows is sealed,
/// under that owner's leaf. Owners are entity trees and random attachment
/// occurrences, never a digest (call b, [`Subtype`]). A history purge rolls
/// the purged owner's generation, so its older checkpoints lose that owner's
/// pre-purge history (call d, [`instance::roll_generation_in_txn`]).
pub(crate) const CHECKPOINT_PAYLOADS_ENABLED: bool = false;

/// The width of an owner's canonical id in an item.
pub(crate) const OWNER_LEN: usize = 32;

/// The width of an incarnation: fresh random bytes, never taken from a digest
/// (call b).
pub(crate) const INCARNATION_LEN: usize = 16;

/// CALLS: the item width, 49: subtype (1) | canonical owner (32) |
/// incarnation (16).
pub(crate) const ITEM_LEN: usize = CustodyKind::CheckpointPayload.item_len();

const _: () = assert!(ITEM_LEN == 1 + OWNER_LEN + INCARNATION_LEN);

/// CALLS: the envelope purpose a compartment is sealed under (24).
pub(crate) const PAYLOAD_PURPOSE: Purpose = Purpose::CheckpointPayload;

fn corrupt() -> Error {
    CustodyKind::CheckpointPayload.corrupt()
}

/// Refuses while [`CHECKPOINT_PAYLOADS_ENABLED`] is false: no caller reaches a
/// write or a custody read here before KS7-6.
fn ensure_enabled() -> Result<()> {
    if CHECKPOINT_PAYLOADS_ENABLED {
        Ok(())
    } else {
        Err(Error::InvariantViolation(
            "checkpoint payload custody is off (CHECKPOINT_PAYLOADS_ENABLED)",
        ))
    }
}

/// What a compartment's owner is, which fixes how its canonical id fills the
/// item's 32 owner bytes. The set is closed: a row whose owner none of these
/// names is not compartmented, and is never sealed under a guessed owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Subtype {
    /// One 16-byte-id tree: an ordinary entity with its revisions, entity
    /// documents and NOTE heads, typed and office bodies and their forks,
    /// index-source text copies and blob heads and versions; a code
    /// artifact's codebase snapshots; a code session's revisions. Owner: the
    /// id (16), zero-padded.
    EntityTree,
    /// One occurrence of attached bytes: inline ASSET bytes and the body
    /// descriptor that holds them. Owner: the holding record's id (16), then
    /// the occurrence id (16); never the bytes' digest, so a later copy of
    /// the same bytes is another owner.
    AttachmentOccurrence,
    /// One code document's heads, tested frontiers and ingress edits. Owner:
    /// the document id (32).
    CodeDocument,
    /// One outbound call's frozen input. Owner: the attempt id (16), then the
    /// call sequence (u64be), zero-padded; never the intent or payload hash.
    OutboundCall,
}

impl Subtype {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::EntityTree => 1,
            Self::AttachmentOccurrence => 2,
            Self::CodeDocument => 3,
            Self::OutboundCall => 4,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::EntityTree),
            2 => Some(Self::AttachmentOccurrence),
            3 => Some(Self::CodeDocument),
            4 => Some(Self::OutboundCall),
            _ => None,
        }
    }

    /// The width of this subtype's canonical owner id; the owner bytes after
    /// it are zero.
    pub(crate) const fn owner_len(self) -> usize {
        match self {
            Self::EntityTree => 16,
            Self::AttachmentOccurrence | Self::CodeDocument => 32,
            Self::OutboundCall => 24,
        }
    }

    /// The canonical 32 owner bytes of `id`; refused when `id` is not this
    /// subtype's owner width.
    pub(crate) fn owner(self, id: &[u8]) -> Result<[u8; OWNER_LEN]> {
        if id.len() != self.owner_len() {
            return Err(corrupt());
        }
        let mut owner = [0; OWNER_LEN];
        owner[..id.len()].copy_from_slice(id);
        Ok(owner)
    }
}

/// One compartment's custody item: subtype (1) | canonical owner (32) |
/// incarnation (16). Strict both ways, so one compartment has one name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PayloadItem {
    subtype: Subtype,
    owner: [u8; OWNER_LEN],
    incarnation: [u8; INCARNATION_LEN],
}

impl PayloadItem {
    /// Refuses an owner whose bytes past its subtype's width are not zero.
    pub(crate) fn new(
        subtype: Subtype,
        owner: [u8; OWNER_LEN],
        incarnation: [u8; INCARNATION_LEN],
    ) -> Result<Self> {
        if owner[subtype.owner_len()..].iter().any(|byte| *byte != 0) {
            return Err(corrupt());
        }
        Ok(Self {
            subtype,
            owner,
            incarnation,
        })
    }

    pub(crate) fn subtype(&self) -> Subtype {
        self.subtype
    }

    pub(crate) fn owner(&self) -> &[u8; OWNER_LEN] {
        &self.owner
    }

    pub(crate) fn incarnation(&self) -> &[u8; INCARNATION_LEN] {
        &self.incarnation
    }

    pub(crate) fn encode(&self) -> [u8; ITEM_LEN] {
        let mut out = [0; ITEM_LEN];
        out[0] = self.subtype.tag();
        out[1..=OWNER_LEN].copy_from_slice(&self.owner);
        out[1 + OWNER_LEN..].copy_from_slice(&self.incarnation);
        out
    }

    /// The item `bytes` spell: exactly [`ITEM_LEN`] bytes, a known subtype and
    /// a zero-padded owner; `None` otherwise.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ITEM_LEN {
            return None;
        }
        let subtype = Subtype::from_tag(bytes[0])?;
        let owner = bytes[1..=OWNER_LEN].try_into().ok()?;
        let incarnation = bytes[1 + OWNER_LEN..].try_into().ok()?;
        Self::new(subtype, owner, incarnation).ok()
    }

    /// This compartment's custody subject in `binding`'s vault.
    pub(crate) fn subject(&self, binding: &CustodyBinding) -> Result<CustodySubject> {
        binding.subject(CustodyKind::CheckpointPayload, &self.encode())
    }
}

/// The 49 item bytes, after the instance table's prefix.
impl SideKey for PayloadItem {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encode());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Self::decode(bytes)
    }
}

/// A leaf's 32 key bytes, out of custody's secret.
fn leaf_key(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let key: [u8; 32] = secret.try_into().map_err(|_| corrupt())?;
    Ok(Zeroizing::new(key))
}

fn retiring() -> Error {
    Error::InvalidConfig("a checkpoint payload compartment is retiring".into())
}

impl Store {
    /// The leaf keys a capture seals `instances` under, in order, each minted
    /// while unpublished: the binding is pinned in `wtxn` with them, and a
    /// leaf is synced and its mint journaled (KS-4) before `wtxn` may commit
    /// anything sealed under it. The caller holds the custody read guard
    /// ([`crate::store::Store::custody_snapshot`]'s) from before `wtxn`
    /// opened until its last seal. Refused for an archived vault, whose
    /// custody is its replacement's, for an incarnation that is not active,
    /// and for a generation whose retirement is staged: nothing new is sealed
    /// under a leaf being destroyed, and a retired leaf is never minted again.
    pub(crate) fn checkpoint_payload_keys_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        instances: &[PayloadInstance],
    ) -> Result<Vec<Zeroizing<[u8; 32]>>> {
        ensure_enabled()?;
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        self.core.key_custody.pin_in_txn(self, wtxn)?;
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let mut keys = Vec::with_capacity(instances.len());
        for instance in instances {
            if instance.lifecycle != Lifecycle::Active {
                return Err(retiring());
            }
            let subject = instance.item.subject(custody.binding())?;
            if retirement_in_txn(self, &*wtxn, &subject)?
                .is_some_and(|intent| intent.through >= instance.generation)
            {
                return Err(retiring());
            }
            let secret = custody.get_or_create(&subject.at(instance.generation))?;
            keys.push(leaf_key(secret.expose())?);
        }
        Ok(keys)
    }

    /// The leaf key of a live compartment in this vault's own custody, read
    /// strictly: a retired, damaged or missing leaf refuses, and so does a
    /// vault that never published one. The caller holds the custody read
    /// guard, or a [`crate::store::Store::custody_snapshot`], from before its
    /// LMDB snapshot until its last open, so no finisher destroys the leaf in
    /// between.
    pub(crate) fn checkpoint_payload_key(
        &self,
        item: &PayloadItem,
        generation: u64,
    ) -> Result<Zeroizing<[u8; 32]>> {
        ensure_enabled()?;
        let custody = self.core.key_custody.local().ok_or_else(corrupt)?;
        read_key(custody, item, generation)
    }
}

/// The leaf key of a live compartment in `custody` (a restore's source),
/// read strictly, under the guard its caller holds.
pub(crate) fn read_key(
    custody: LocalCustody<'_>,
    item: &PayloadItem,
    generation: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    ensure_enabled()?;
    let subject = item.subject(custody.binding())?;
    leaf_key(custody.read(&subject.at(generation))?.expose())
}

/// What a restore needs of each compartment `required` names (its item and
/// generation, from the image's manifest), recorded in the one plan the
/// restore's claim keys use, so its fork copies these leaves as well. Each
/// answer stands alone, in order: a live leaf opens; a retired one's rows are
/// dropped and recorded as erased; an error (a missing leaf, or no source
/// binding) is the caller's to weigh under KS-4's restore rules, and never
/// stops the census of the others.
pub(crate) fn require_all(
    plan: &mut CustodyPlan,
    required: &[(PayloadItem, u64)],
) -> Result<Vec<Result<Requirement>>> {
    ensure_enabled()?;
    Ok(required
        .iter()
        .map(|(item, generation)| {
            let source = plan.source().ok_or_else(corrupt)?;
            let subject = item.subject(source)?;
            plan.require(&subject.at(*generation))
        })
        .collect())
}
