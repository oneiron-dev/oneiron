//! The KS-4 custody protocol (FIX 5685), public so the holders of a vault's
//! custody outside this crate keep one contract: the self-host HTTP anchor,
//! and the cloud lane's hosted targets and anchors (KS-C4).
//!
//! A publication pass seals one [`CustodyBatch`]: the latest head at the
//! local log position, with the frames up to it, bound to the required
//! target set's revision. Each target ships the frames it lacks, makes the
//! head its latest in one compare-and-swap step (never over a newer
//! position), deletes every superseded head, stage and alias it holds for
//! the lineage, proves by inventory that none is left, persists its
//! [`AckRecord`] and only then replies. The engine accepts an ack only when
//! it names this batch exactly (target, set revision, position, head object
//! id, operation id) and stores it durably in the lineage's journal. A
//! target that cannot do all of that answers [`TargetPublication::Pending`]
//! with a [`PendingCode`]: it stays pending by name and the next pass
//! retries. No quorum, no expiry and no silent removal: a retirement is
//! complete once every member of the required set acked a position at or
//! past its log frame and the anchor stands there too.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::EntityId;
use crate::error::{Error, Result};

pub use super::identity::{CustodyNamespace, CustodyVaultId};
pub use super::log::{CustodyEpoch, CustodyPosition};

use super::files::read_whole;
use super::identity::hex_decode;
use super::log::{frame_hash, frame_name};

mod drain;

pub use self::drain::{
    DRAIN_VERSION, DrainAck, DrainTicket, DrainToken, drain_operation_id, drain_origin,
    drain_placement,
};

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

/// What a compare-and-swap advance did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorAdvance {
    /// The record is the store's current one.
    Advanced,
    /// The current record is not the one the caller expected: another writer
    /// moved it. Nothing changed.
    Moved,
}

/// An external anchor: keyless read and compare-and-swap advance of each
/// lineage's current record (`OCAN | 1 | position (96) | tag (32)`). The
/// store compares the BLAKE3 of the whole current record with `expected`,
/// writes nothing when it moved, and refuses a record that does not extend
/// the current one; the reader checks the tag under the head's control
/// secret.
pub trait AnchorStore {
    /// The lineage's current record, if it has one.
    fn read(&self, vault: CustodyVaultId, namespace: CustodyNamespace) -> Result<Option<Vec<u8>>>;

    /// Makes `record` the current one of its lineage when the current one is
    /// still the one whose BLAKE3 is `expected` (`None`: none yet). A record
    /// that does not extend the current one (another lineage, an older
    /// writer epoch, an older sequence, or another tip at the same position)
    /// is refused.
    fn advance(&self, expected: Option<[u8; 32]>, record: &[u8]) -> Result<AnchorAdvance>;
}

/// A member's stable, opaque id in the required set: `<kind>:<name>`, a
/// kind of lowercase letters and digits, then lowercase letters, digits,
/// `.`, `_` or `-`, at most 128 bytes in all. Never reused for another
/// holder.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetId(String);

const TARGET_ID_MAX: usize = 128;

impl TargetId {
    pub fn new(id: &str) -> Result<Self> {
        let valid = id.len() <= TARGET_ID_MAX
            && id.split_once(':').is_some_and(|(kind, name)| {
                !kind.is_empty()
                    && kind
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && !name.is_empty()
                    && name.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(Error::InvalidConfig(
                "a custody target id is `<kind>:<name>`, lowercase, at most 128 bytes".into(),
            ));
        }
        Ok(Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `folder:<16 hex>`: the BLAKE3 of the folder's absolute path.
    fn of_folder(folder: &Path) -> Self {
        let absolute = std::path::absolute(folder).unwrap_or_else(|_| folder.to_path_buf());
        let hash = blake3::hash(absolute.as_os_str().as_encoded_bytes()).to_hex();
        Self(format!("folder:{}", &hash[..16]))
    }
}

impl std::fmt::Display for TargetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A hosted holder kind. A Hypnos outbox member ships through the outbox
/// its managed host names (FIX 5899); every other kind, and an outbox member
/// with no outbox named, stays pending as [`PendingCode::NoAdapter`] until
/// its adapter lands (KS-C4), never acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedKind {
    Wasabi,
    S3,
    R2,
    SshShelf,
    HypnosOutbox,
}

/// What kind of holder a member is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// A directory beside the backups (or any folder the owner named).
    Folder,
    /// The vault's residence home.
    Residence,
    /// A hosted holder.
    Hosted(HostedKind),
}

impl TargetKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Residence => "residence",
            Self::Hosted(HostedKind::Wasabi) => "wasabi",
            Self::Hosted(HostedKind::S3) => "s3",
            Self::Hosted(HostedKind::R2) => "r2",
            Self::Hosted(HostedKind::SshShelf) => "ssh_shelf",
            Self::Hosted(HostedKind::HypnosOutbox) => "hypnos_outbox",
        }
    }
}

/// What a member holds: heads and the log, or the keyless log alone (its
/// ack then names no head, [`EvidenceKind::NoHeadInScope`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    HeadAndLog,
    LogOnly,
}

/// One member of the required set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    id: TargetId,
    kind: TargetKind,
    scope: TargetScope,
    /// A folder member's folder, so every pass retries it there.
    folder: Option<PathBuf>,
}

impl TargetSpec {
    /// A hosted holder's member, registered before its first exposure.
    pub fn hosted(id: TargetId, kind: HostedKind, scope: TargetScope) -> Self {
        Self {
            id,
            kind: TargetKind::Hosted(kind),
            scope,
            folder: None,
        }
    }

    /// A hosted holder declared by its id alone, its kind read from the
    /// prefix: `wasabi:`, `s3:`, `r2:`, `shelf:` (an SSH shelf) or `outbox:`
    /// (a Hypnos outbox). It holds heads and the log.
    pub fn declared(id: &str) -> Result<Self> {
        let id = TargetId::new(id)?;
        let kind = match id.as_str().split_once(':').map(|(kind, _)| kind) {
            Some("wasabi") => HostedKind::Wasabi,
            Some("s3") => HostedKind::S3,
            Some("r2") => HostedKind::R2,
            Some("shelf") => HostedKind::SshShelf,
            Some("outbox") => HostedKind::HypnosOutbox,
            _ => {
                return Err(Error::InvalidConfig(
                    "a declared custody target is `wasabi:`, `s3:`, `r2:`, `shelf:` or `outbox:` \
                     and a name"
                        .into(),
                ));
            }
        };
        Ok(Self::hosted(id, kind, TargetScope::HeadAndLog))
    }

    /// The folder member at `folder`, for the owner's re-enrolment of one he
    /// drained (FIX 11274): `folder:<16 hex>` of its absolute path.
    pub(crate) fn of_folder(folder: PathBuf) -> Self {
        Self::folder(folder)
    }

    pub(super) fn folder(folder: PathBuf) -> Self {
        Self {
            id: TargetId::of_folder(&folder),
            kind: TargetKind::Folder,
            scope: TargetScope::HeadAndLog,
            folder: Some(folder),
        }
    }

    /// The residence home `home` proved itself as: `residence:<machine hex>`.
    pub(crate) fn residence(home: EntityId) -> Self {
        Self {
            id: TargetId(format!("residence:{}", home.to_hex())),
            kind: TargetKind::Residence,
            scope: TargetScope::HeadAndLog,
            folder: None,
        }
    }

    pub(super) fn member(
        id: TargetId,
        kind: TargetKind,
        scope: TargetScope,
        folder: Option<PathBuf>,
    ) -> Self {
        Self {
            id,
            kind,
            scope,
            folder,
        }
    }

    pub fn id(&self) -> &TargetId {
        &self.id
    }

    pub fn kind(&self) -> TargetKind {
        self.kind
    }

    pub fn scope(&self) -> TargetScope {
        self.scope
    }

    pub(super) fn folder_path(&self) -> Option<&Path> {
        self.folder.as_deref()
    }
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

const OPERATION_CONTEXT: &str = "oneiron/custody-operation/v1";

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

pub(super) fn hex(bytes: &[u8]) -> String {
    crate::entity_id::bytes_to_hex_lower(bytes)
}

/// The ack grammar's version.
pub const ACK_VERSION: u8 = 1;

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

/// The operation an ack covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckOperation {
    PublishAndDeleteSuperseded,
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

/// How a target showed the superseded heads are gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A folder, node, outbox or staging directory: atomic latest, every
    /// superseded head, temporary and owned alias unlinked, directories
    /// synced, the lineage directory listed again.
    FilesystemSweep,
    /// The residence home: latest-head CAS, old head parts and every stale
    /// stage removed, synced, listed again, the ack persisted before reply.
    ResidenceSweep,
    /// An SSH shelf: an authenticated inventory and delete command separate
    /// from the put-only upload; the inventory shows only the latest.
    SshVersionSweep,
    /// An object store: every page of versions and multipart uploads listed,
    /// each superseded version id deleted and its absence verified.
    ObjectVersionSweep,
    /// A log-only member: it holds no head, so none is superseded.
    NoHeadInScope,
    /// An unversioned object store (e.g. the CP's Convex storage): every
    /// superseded head object and upload stage deleted, a fresh listing
    /// shows none.
    UnversionedObjectSweep,
}

/// The inventory a target took after its deletions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionEvidence {
    pub kind: EvidenceKind,
    /// Superseded heads, stages and temporaries this operation removed.
    pub superseded_removed: u64,
    /// Key-bearing heads left for the lineage: exactly one (the latest), or
    /// zero for a log-only member.
    pub remaining_heads: u64,
    /// BLAKE3 (64 hex) over the post-deletion inventory, in the target's
    /// own canonical order, then the head object id.
    pub inventory_digest: String,
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

/// Why a target is still pending, in words naming no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPending {
    pub code: PendingCode,
    pub detail: String,
}

/// A pending target's sanitized reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCode {
    /// Unreachable: an unmounted folder, a home offline, a network fault.
    Offline,
    /// Reachable, but its storage is locked or read-only.
    Locked,
    /// It refused the operation (authentication, permission).
    Denied,
    /// No adapter for its kind in this build (hosted until KS-C4).
    NoAdapter,
    /// It holds a newer position: another writer moved it.
    Moved,
    /// Anything else, or an ack that did not match its batch.
    Failed,
}

impl PendingCode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Locked => "locked",
            Self::Denied => "denied",
            Self::NoAdapter => "no_adapter",
            Self::Moved => "moved",
            Self::Failed => "failed",
        }
    }
}
