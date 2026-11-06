//! Core half of `store::key_custody::protocol`: its store-layer items live in `oneiron_store::key_custody::protocol` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::key_custody::protocol::*;

pub use super::identity::{CustodyNamespace, CustodyVaultId};
use crate::EntityId;
use crate::error::{Error, Result};
pub use oneiron_store::key_custody::log::{CustodyEpoch, CustodyPosition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
// Where a restore asks its residence home to start the log (FIX 12045).
pub use self::drain::{
    DRAIN_VERSION, DrainAck, DrainTicket, DrainToken, drain_operation_id, drain_origin,
    drain_placement,
};
pub use self::fetched::{CustodyHomeCursor, CustodyHomePage, FetchedCustodySource};
pub(crate) use super::anchor::anchored_position;
use super::files::read_whole;
use super::identity::hex_decode;
use super::log::{frame_hash, frame_name};

mod drain;
mod fetched;

/// One lineage a target holds: a vault's custody in one namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lineage {
    pub vault: CustodyVaultId,
    pub namespace: CustodyNamespace,
}

impl Lineage {
    pub(super) fn of(position: &CustodyPosition) -> Self {
        Self {
            vault: position.vault,
            namespace: position.namespace,
        }
    }

    /// The lineage a wire names: vault (64 hex) and namespace (32 hex).
    pub fn from_hex(vault: &str, namespace: &str) -> Option<Self> {
        Some(Self {
            vault: CustodyVaultId::from_bytes(hex_decode(vault)?.try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(hex_decode(namespace)?.try_into().ok()?),
        })
    }

    /// Its vault and namespace in hex, as a wire names them.
    pub fn to_hex(&self) -> (String, String) {
        (hex(self.vault.as_bytes()), hex(self.namespace.as_bytes()))
    }
}

/// Where a restore reads a lineage's custody from: an archive target or
/// the kit's fetch, through the same validator.
pub trait CustodySource {
    /// The lineage's latest head there, if any.
    fn head(&self, lineage: Lineage) -> Result<Option<Vec<u8>>>;
    /// The lineage's log frame at `seq` there, if any.
    fn frame(&self, lineage: Lineage, seq: u64) -> Result<Option<Vec<u8>>>;
}

/// A holder a publication pass drives. An async holder (the residence home)
/// runs the same batch and ack contract over its own channel.
pub trait CustodyTarget: CustodySource {
    /// The target's member entry in the required set.
    fn spec(&self) -> TargetSpec;

    /// Ships the frames of `batch` the target lacks, makes its head the
    /// latest in one compare-and-swap step (refused over a newer position),
    /// deletes every superseded head, stage and alias, shows by inventory
    /// that none is left, persists the acknowledgement and returns it. A
    /// step that cannot finish answers [`TargetPublication::Pending`]; a
    /// target whose held head a newer pass published answers
    /// [`TargetPublication::Covered`] ([`CustodyBatch::covered_by`]).
    fn publish(&self, batch: &CustodyBatch) -> Result<TargetPublication>;
}

/// One pass's frozen publication: the head sealed at the local position,
/// the set revision it was sealed for, and the local frames up to it.
pub struct CustodyBatch {
    pub(super) position: CustodyPosition,
    pub(super) head: Zeroizing<Vec<u8>>,
    pub(super) set_revision: u64,
    pub(super) journal: PathBuf,
    /// Whether the head is wrapped to the vault data key as well as the
    /// recovery root.
    pub(super) data_key: bool,
}

impl CustodyBatch {
    pub fn lineage(&self) -> Lineage {
        Lineage::of(&self.position)
    }

    pub fn position(&self) -> CustodyPosition {
        self.position
    }

    /// The sealed head: key-bearing bytes for the target's latest-head slot
    /// only, never a log line, an error, a receipt or a digest elsewhere.
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The BLAKE3 of the sealed head bytes: the object an ack names.
    pub fn head_object_id(&self) -> [u8; 32] {
        *blake3::hash(&self.head).as_bytes()
    }

    pub fn set_revision(&self) -> u64 {
        self.set_revision
    }

    /// `derive_key("oneiron/custody-operation/v1", position (96) | head
    /// object id (32))`: the publish-and-delete-superseded operation this
    /// batch asks of every target.
    pub fn operation_id(&self) -> [u8; 32] {
        operation_id(&self.position, &self.head_object_id())
    }

    /// The local log frame at `seq`, if this install holds it (a lineage a
    /// disaster recovery took over starts its local log after the admitted
    /// position).
    pub fn frame(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        read_whole(&self.journal.join(frame_name(seq)))
    }

    /// Whether a target's head at `held` already covers this batch: a later
    /// position of this install's own log (the same lineage and writer
    /// epoch, past this position, and the local frame there hashes to its
    /// tip). A newer pass published it and acks it; this batch has nothing
    /// to write there (FIX 6394). A frame that does not read is no proof.
    pub fn covered_by(&self, held: &CustodyPosition) -> bool {
        held.same_lineage(&self.position)
            && held.epoch == self.position.epoch
            && held.seq > self.position.seq
            && self
                .frame(held.seq)
                .ok()
                .flatten()
                .is_some_and(|frame| frame_hash(&frame) == held.tip)
    }

    /// Every local frame after `after` through the batch's position.
    pub fn frames_after(&self, after: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut frames = Vec::new();
        for seq in after.saturating_add(1)..=self.position.seq {
            if let Some(frame) = self.frame(seq)? {
                frames.push((seq, frame));
            }
        }
        Ok(frames)
    }

    /// The ack a target that did all of [`CustodyTarget::publish`] returns
    /// for this batch.
    pub fn ack(&self, target: &TargetId, evidence: DeletionEvidence, attester: &str) -> AckRecord {
        self.facts().ack(target, evidence, attester)
    }

    /// What an ack of this batch is checked against, without its head.
    pub(super) fn facts(&self) -> BatchFacts {
        BatchFacts {
            position: self.position,
            head_object_id: self.head_object_id(),
            set_revision: self.set_revision,
            data_key: self.data_key,
        }
    }
}

/// A batch's keyless facts: what its ack must name, kept once its
/// key-bearing bytes are gone (a Hypnos outbox's retained batch, FIX 5899).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BatchFacts {
    pub(super) position: CustodyPosition,
    pub(super) head_object_id: [u8; 32],
    pub(super) set_revision: u64,
    pub(super) data_key: bool,
}

impl BatchFacts {
    pub(super) fn operation_id(&self) -> [u8; 32] {
        operation_id(&self.position, &self.head_object_id)
    }

    /// The ack of this batch by `target`.
    pub(super) fn ack(
        &self,
        target: &TargetId,
        evidence: DeletionEvidence,
        attester: &str,
    ) -> AckRecord {
        AckRecord {
            version: ACK_VERSION,
            target_id: target.as_str().to_owned(),
            set_revision: self.set_revision,
            position: AckPosition::of(&self.position),
            head_object_id: hex(&self.head_object_id),
            operation: AckOperation::PublishAndDeleteSuperseded,
            operation_id: hex(&self.operation_id()),
            evidence,
            attester: attester.to_owned(),
            acked_at: crate::unix_seconds_now(),
        }
    }
}

/// The publish-and-delete-superseded operation of the head `head_object_id`
/// at `position`.
pub(super) fn operation_id(position: &CustodyPosition, head_object_id: &[u8; 32]) -> [u8; 32] {
    let mut material = position.to_bytes().to_vec();
    material.extend_from_slice(head_object_id);
    blake3::derive_key(OPERATION_CONTEXT, &material)
}

/// A target's durable acknowledgement of one batch: named MessagePack
/// (`rmp_serde::to_vec_named`) at rest, JSON on a wire. Ids, positions and
/// digests only; never a key, a wrap, head bytes or a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRecord {
    pub version: u8,
    pub target_id: String,
    pub set_revision: u64,
    pub position: AckPosition,
    /// The BLAKE3 (64 hex) of the head the target now holds as its latest.
    pub head_object_id: String,
    pub operation: AckOperation,
    /// [`CustodyBatch::operation_id`], 64 hex.
    pub operation_id: String,
    pub evidence: DeletionEvidence,
    /// Who attests: `this-install` for a local folder, the residence home's
    /// machine id (hex) as its socket proved it, a hosted adapter's own id.
    pub attester: String,
    /// Unix seconds the target persisted the ack.
    pub acked_at: u64,
}

/// A machine's commit of the head it staged at its residence home: the
/// batch's set revision, position, head object id and operation id. The
/// home checks the staged bytes against all of them before it switches its
/// head, and acks as the target `residence:<its machine hex>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidenceCommit {
    pub set_revision: u64,
    pub position: CustodyPosition,
    pub head_object_id: [u8; 32],
    pub operation_id: [u8; 32],
}

/// A custody position in an ack: vault (64 hex), namespace (32 hex), writer
/// epoch, log sequence number and tip (64 hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckPosition {
    pub vault: String,
    pub namespace: String,
    pub epoch: u64,
    pub seq: u64,
    pub tip: String,
}

impl AckPosition {
    pub fn of(position: &CustodyPosition) -> Self {
        Self {
            vault: hex(position.vault.as_bytes()),
            namespace: hex(position.namespace.as_bytes()),
            epoch: position.epoch.get(),
            seq: position.seq,
            tip: hex(&position.tip),
        }
    }

    /// The position this names; `None` when a field does not parse.
    pub fn position(&self) -> Option<CustodyPosition> {
        Some(CustodyPosition {
            vault: CustodyVaultId::from_bytes(hex_decode(&self.vault)?.try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(hex_decode(&self.namespace)?.try_into().ok()?),
            epoch: CustodyEpoch(self.epoch),
            seq: self.seq,
            tip: hex_decode(&self.tip)?.try_into().ok()?,
        })
    }
}

/// What a target did with a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetPublication {
    Acked(AckRecord),
    Pending(TargetPending),
    /// It holds a newer head of the batch's own log, which covers it: the
    /// pass that published that head acks it, and nothing was written here
    /// (FIX 6394). Neither an ack of the older position nor a pending note.
    Covered,
}
