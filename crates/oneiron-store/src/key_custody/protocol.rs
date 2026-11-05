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

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub use crate::key_custody::identity::CustodyNamespace;
pub use crate::key_custody::identity::CustodyVaultId;

use crate::key_custody::identity::hex_decode;

pub mod drain;

pub use crate::key_custody::protocol::drain::DRAIN_VERSION;
pub use crate::key_custody::protocol::drain::DrainToken;
pub use crate::key_custody::protocol::drain::drain_placement;

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
pub struct TargetId(pub String);

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
    pub fn of_folder(folder: &Path) -> Self {
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
    pub id: TargetId,
    pub kind: TargetKind,
    pub scope: TargetScope,
    /// A folder member's folder, so every pass retries it there.
    pub folder: Option<PathBuf>,
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
    pub fn of_folder(folder: PathBuf) -> Self {
        Self::folder(folder)
    }

    pub fn folder(folder: PathBuf) -> Self {
        Self {
            id: TargetId::of_folder(&folder),
            kind: TargetKind::Folder,
            scope: TargetScope::HeadAndLog,
            folder: Some(folder),
        }
    }

    /// The residence home `home` proved itself as: `residence:<machine hex>`.
    pub fn residence(home: EntityId) -> Self {
        Self {
            id: TargetId(format!("residence:{}", home.to_hex())),
            kind: TargetKind::Residence,
            scope: TargetScope::HeadAndLog,
            folder: None,
        }
    }

    pub fn member(
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

    pub fn folder_path(&self) -> Option<&Path> {
        self.folder.as_deref()
    }
}

pub const OPERATION_CONTEXT: &str = "oneiron/custody-operation/v1";

pub fn hex(bytes: &[u8]) -> String {
    oneiron_contracts::entity_id::bytes_to_hex_lower(bytes)
}

/// The ack grammar's version.
pub const ACK_VERSION: u8 = 1;

/// The operation an ack covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckOperation {
    PublishAndDeleteSuperseded,
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
