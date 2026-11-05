//! Checkpoint payload custody (KS-7, FIX 5688): the ordinary payload a
//! checkpoint copies is sealed one owner at a time, each owner's compartment
//! under its own typed custody leaf (kind `CheckpointPayload`), so an erase
//! that retires the leaf reaches every old checkpoint holding that owner's
//! bytes. Shared bytes keep their holders and refcounts; a checkpoint is
//! never a reference that keeps an erase from running.
//!
//! This module holds the item codec, the instance table ([`instance`]) and
//! the custody glue a capture and a restore call: the binding pinned with
//! the leaves it protects, the mint under the custody guard ([`capture`]),
//! guarded reads, the restore plan for a list of compartments
//! ([`compartment_access`]) and what the kept copies still need of them
//! ([`kept`]). Projection (KS7-2), the mixed sync carriers (KS7-3), erase,
//! hold and retention staging (KS7-4) and capture and restore (KS7-5) call
//! them, now that KS7-6 turned [`CHECKPOINT_PAYLOADS_ENABLED`] on.
#![allow(dead_code, reason = "the strict live-key read waits on callers")]

pub mod kept;

use heed::RwTxn;
use oneiron_crypto::Purpose;
use zeroize::Zeroizing;

use crate::key_custody::identity::CustodyBinding;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;
use crate::restore_admission::Rejected;
use crate::restore_admission::RestoreAdmissionReason;
use crate::side_table::key::SideKey;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::StoreError;

/// CALLS CHECKPOINT_PAYLOADS_ENABLED (Engine 10-20 07:1x): the one switch
/// for all of KS-7, on since KS7-6 (Engine 10-30 11:12). A capture seals
/// each owner's rows under its compartment, an erase retires its leaves,
/// and a restore opens what its custody still holds. Off, nothing mints a
/// leaf, writes the instance table or changes a checkpoint manifest.
///
/// Sealing is copy-only (call a): live rows and every reader of them stay as
/// they are; only the copy a checkpoint takes of an owner's rows is sealed,
/// under that owner's leaf. Owners are entity trees and random attachment
/// occurrences, never a digest (call b, [`Subtype`]). A history purge rolls
/// the purged owner's generation, so its older checkpoints lose that owner's
/// pre-purge history (call d, [`instance::roll_generation_in_txn`]).
pub const CHECKPOINT_PAYLOADS_ENABLED: bool = true;

/// The width of an owner's canonical id in an item.
pub const OWNER_LEN: usize = 32;

/// The width of an incarnation: fresh random bytes, never taken from a digest
/// (call b).
pub const INCARNATION_LEN: usize = 16;

/// CALLS: the item width, 49: subtype (1) | canonical owner (32) |
/// incarnation (16).
pub const ITEM_LEN: usize = CustodyKind::CheckpointPayload.item_len();

const _: () = assert!(ITEM_LEN == 1 + OWNER_LEN + INCARNATION_LEN);

/// CALLS: the envelope purpose a compartment is sealed under (24).
pub const PAYLOAD_PURPOSE: Purpose = Purpose::CheckpointPayload;

pub fn corrupt() -> Error {
    CustodyKind::CheckpointPayload.corrupt()
}

/// Refuses while [`CHECKPOINT_PAYLOADS_ENABLED`] is false: no caller reaches a
/// write or a custody read here before KS7-6.
pub fn ensure_enabled() -> Result<()> {
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
pub enum Subtype {
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
    pub const fn tag(self) -> u8 {
        match self {
            Self::EntityTree => 1,
            Self::AttachmentOccurrence => 2,
            Self::CodeDocument => 3,
            Self::OutboundCall => 4,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
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
    pub const fn owner_len(self) -> usize {
        match self {
            Self::EntityTree => 16,
            Self::AttachmentOccurrence | Self::CodeDocument => 32,
            Self::OutboundCall => 24,
        }
    }

    /// The canonical 32 owner bytes of `id`; refused when `id` is not this
    /// subtype's owner width.
    pub fn owner(self, id: &[u8]) -> Result<[u8; OWNER_LEN]> {
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
pub struct PayloadItem {
    pub subtype: Subtype,
    pub owner: [u8; OWNER_LEN],
    pub incarnation: [u8; INCARNATION_LEN],
}

impl PayloadItem {
    /// Refuses an owner whose bytes past its subtype's width are not zero.
    pub fn new(
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

    pub fn subtype(&self) -> Subtype {
        self.subtype
    }

    pub fn owner(&self) -> &[u8; OWNER_LEN] {
        &self.owner
    }

    pub fn incarnation(&self) -> &[u8; INCARNATION_LEN] {
        &self.incarnation
    }

    pub fn encode(&self) -> [u8; ITEM_LEN] {
        let mut out = [0; ITEM_LEN];
        out[0] = self.subtype.tag();
        out[1..=OWNER_LEN].copy_from_slice(&self.owner);
        out[1 + OWNER_LEN..].copy_from_slice(&self.incarnation);
        out
    }

    /// The item `bytes` spell: exactly [`ITEM_LEN`] bytes, a known subtype and
    /// a zero-padded owner; `None` otherwise.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ITEM_LEN {
            return None;
        }
        let subtype = Subtype::from_tag(bytes[0])?;
        let owner = bytes[1..=OWNER_LEN].try_into().ok()?;
        let incarnation = bytes[1 + OWNER_LEN..].try_into().ok()?;
        Self::new(subtype, owner, incarnation).ok()
    }

    /// This compartment's custody subject in `binding`'s vault.
    pub fn subject(&self, binding: &CustodyBinding) -> Result<CustodySubject> {
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
pub fn leaf_key(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let key: [u8; 32] = secret.try_into().map_err(|_| corrupt())?;
    Ok(Zeroizing::new(key))
}

pub fn retiring() -> Error {
    Error::InvalidConfig("a checkpoint payload compartment is retiring".into())
}

/// A restore whose custody holds no compartment it needs: KS-4's lost
/// custody, by name.
pub fn custody_missing() -> Rejected {
    Rejected::new(RestoreAdmissionReason::CustodyKeyMissing, corrupt())
}

/// How a restore opens one compartment its image names (KS7-5).
pub enum CompartmentAccess {
    /// Its leaf is live in the restore's source custody: the compartment
    /// opens with this key.
    Open(Zeroizing<[u8; 32]>),
    /// Its leaf is retired, or committed to be: its owner's rows are
    /// dropped as its erase took them.
    Retired,
}

pub mod loro;
