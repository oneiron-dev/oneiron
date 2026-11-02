//! A vault VM's outbox carrier (FIX 5235, FIX 5467): one persistent,
//! bidirectional stream on vsock port [`VM_OUTBOX_PORT`] that carries every
//! outbox kind between the guest's vault disk and the host's outbox trees.
//!
//! The guest's root companion (`oneiron-vm-outbox`) dials the host's port,
//! names its vault ([`VmOutboxFrame::Hello`]) and is welcomed by the host's
//! attachment, which is bound to that one VM before it starts: no guest field
//! selects a host vault or path. The two sides then take turns. The guest
//! opens each of its turns with its engine's registered backup label, once
//! there is one ([`VmOutboxFrame::BackupRegistered`], FIX 7046), sends each
//! set it has, then [`VmOutboxFrame::Pull`]; the host sends each set it has,
//! then [`VmOutboxFrame::Done`]. A set is one or more
//! [`VmOutboxFrame::Transfer`]s, the last marked `commit_set`; the receiver
//! publishes the whole set, or none of it, and answers each transfer with a
//! [`VmOutboxAck`] once the set is durable or why it is not.
//!
//! A transfer names a member, a kind's protocol name relative to that kind's
//! root and never a host path ([`vm_outbox_member`]). A `put` is followed by
//! its `length` bytes in data chunks: each a big-endian `u32` length (1 to
//! [`VM_OUTBOX_CHUNK_BYTES`]) then those bytes. A long file takes more
//! chunks; nothing caps a file, a set, a turn or an outbox. A `remove` has no
//! data and names the exact version it retires. Each member has one origin
//! side, the only side that puts it; the other side's removal of it reaches
//! the origin as a retirement, the way a shipper or a consumer removes the one
//! shared copy on a node, except for a backup artifact and its `.cpfact`
//! checkpoint fact, which only the engine's prune retires. Revisions order a
//! member's changes, and a transfer's id, a per-direction ordinal the sender
//! keeps across restarts, is its identity: a replay of one already taken is
//! answered durable without writing again, and the same id with other
//! content is refused.
//!
//! An ack is transport only: it retires the sender's retransmission state and
//! nothing else. It is never a registry, intake, custody, e-sign or backup
//! receipt; those stay with each kind's business owner, whose codecs ride
//! here unchanged. Nothing here carries a key, a credential or an unsealed
//! backup. Port 1030 and the 64 KiB chunk are LC's co-signed terms, as was
//! wire revision 1; revision 2 adds the backup-label registration and the
//! `diverged_unagreed` answer to a retirement (FIX 11074); revision 3 adds
//! the guest's [`VmOutboxFrame::DivergenceCleared`] notice of the owner's
//! answer to a diverged copy (FIX 11736, FIX 11737); revision 4 adds the
//! notice's [`VmOutboxNoticeAction`] and the host's
//! [`VmOutboxFrame::AsideRemoved`] answer to a removal of its kept-aside copy
//! (FIX 11985) and [`VmOutboxFrame::AsideKept`] answer to a keep of one
//! (FIX 12010). This
//! extension rides contract version 3 with a build floor, and a vault reports
//! it on `Ping` (`vm_outbox_revision`).

mod members;

pub use self::members::{VmOutboxMember, vm_outbox_member};
pub use crate::vm::VM_OUTBOX_PORT;

use serde::{Deserialize, Serialize};

/// The carrier's wire revision, which every frame names and a vault VM
/// reports on `Ping` (`vm_outbox_revision`) once its carrier is complete.
pub const VM_OUTBOX_WIRE_REVISION: u32 = 4;
/// The most bytes one data chunk carries: a buffering choice, not a bound on
/// any file.
pub const VM_OUTBOX_CHUNK_BYTES: usize = 64 * 1024;
/// One frame line, newline included: the bound of this metadata codec only.
pub const MAX_VM_OUTBOX_LINE: usize = 4096;
/// The guest's outbox root on its vault disk, outside the encrypted storage
/// as a node keeps its outboxes, root-owned so the engine's UID can replace
/// none of the protected sets in it.
pub const VM_GUEST_OUTBOX_DIR: &str = "/vault/outbox";
/// The most characters a refusal or deferral detail keeps.
const MAX_DETAIL_CHARS: usize = 160;

/// The outbox kinds the carrier carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxKind {
    /// The vault's data-key escrow reports (`--escrow-outbox-dir`).
    Escrow,
    /// Hosted custody batches, `custody/` under the escrow outbox.
    Custody,
    /// The e-sign delivery outbox (`--esign-delivery-outbox-dir`).
    Esign,
    /// The publisher training outbox (`--publisher-training-outbox-dir`).
    Training,
    /// The escrow recipients' public keys the engine seals its data key to.
    Recipients,
    /// Sealed backup artifacts in the vault's actual backup directory.
    Backup,
    /// The supervisor's root-stage acks, under that directory's
    /// `.backup-handoff/` (`crate::backup_handoff`).
    BackupStageAck,
}

impl VmOutboxKind {
    /// Every kind, in the order a turn sends them.
    pub const ALL: [Self; 7] = [
        Self::Recipients,
        Self::Escrow,
        Self::Custody,
        Self::Esign,
        Self::Training,
        Self::Backup,
        Self::BackupStageAck,
    ];

    /// The kind's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Escrow => "escrow",
            Self::Custody => "custody",
            Self::Esign => "esign",
            Self::Training => "training",
            Self::Recipients => "recipients",
            Self::Backup => "backup",
            Self::BackupStageAck => "backup_stage_ack",
        }
    }
}

impl std::fmt::Display for VmOutboxKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One end of the carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxSide {
    Guest,
    Host,
}

impl VmOutboxSide {
    /// The other end.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Guest => Self::Host,
            Self::Host => Self::Guest,
        }
    }
}

/// What a transfer does to its member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxOperation {
    /// The member's bytes, `length` of them in data chunks after the line.
    Put,
    /// Retires the member's version `expected_digest` names; no data follows.
    Remove,
}

/// One transfer's line.
///
/// `blake3` and `length` are a put's content; a remove carries `length` 0
/// and the retired version's digest as both `blake3` and `expected_digest`.
/// A put's `expected_digest` names the version it replaces, none when the
/// sender knows of none. `set_id` is the member's set
/// ([`VmOutboxMember::set`]), and `commit_set` marks a set's last transfer.
/// Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmOutboxDescriptor {
    pub wire_revision: u32,
    /// The sender's ordinal for this direction, from 1, kept across
    /// restarts: a replay carries the same one.
    pub transfer_id: u64,
    pub kind: VmOutboxKind,
    pub member: String,
    /// The member's revision this transfer makes, from 1.
    pub revision: u64,
    pub length: u64,
    /// 64 lowercase hex.
    pub blake3: String,
    pub operation: VmOutboxOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    pub set_id: String,
    pub commit_set: bool,
}

impl VmOutboxDescriptor {
    /// The member's class, once this line is well formed and `from` may send
    /// it: only the origin puts a member, and the other side removes one only
    /// where a removal there retires it.
    pub fn validate(&self, from: VmOutboxSide) -> Result<VmOutboxMember, VmOutboxOutcome> {
        let refused = VmOutboxOutcome::refused;
        if self.wire_revision != VM_OUTBOX_WIRE_REVISION {
            return Err(refused(
                VmOutboxRefusal::UnsupportedRevision,
                &format!("the carrier speaks wire revision {VM_OUTBOX_WIRE_REVISION}"),
            ));
        }
        let well_formed = self.transfer_id > 0
            && self.revision > 0
            && is_digest(&self.blake3)
            && self.expected_digest.as_deref().is_none_or(is_digest);
        if !well_formed {
            return Err(refused(
                VmOutboxRefusal::MalformedDescriptor,
                "an id, revision or digest is malformed",
            ));
        }
        let Some(member) = vm_outbox_member(self.kind, &self.member) else {
            return Err(refused(
                VmOutboxRefusal::MemberNotAllowed,
                "no member of this kind has that name",
            ));
        };
        if self.set_id != member.set {
            return Err(refused(
                VmOutboxRefusal::MalformedDescriptor,
                "the set is not the member's",
            ));
        }
        let allowed = match self.operation {
            VmOutboxOperation::Put => member.origin == from,
            VmOutboxOperation::Remove => {
                if self.length != 0 || self.expected_digest.as_deref() != Some(self.blake3.as_str())
                {
                    return Err(refused(
                        VmOutboxRefusal::MalformedDescriptor,
                        "a remove carries no data and names the version it retires",
                    ));
                }
                member.origin == from || member.peer_retires
            }
        };
        if !allowed {
            return Err(refused(
                VmOutboxRefusal::DirectionNotAllowed,
                "this side may not make that change to the member",
            ));
        }
        Ok(member)
    }
}

/// The answer to one transfer: its identity, echoed, and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmOutboxAck {
    pub wire_revision: u32,
    pub transfer_id: u64,
    pub kind: VmOutboxKind,
    pub member: String,
    pub revision: u64,
    pub blake3: String,
    pub outcome: VmOutboxOutcome,
}

impl VmOutboxAck {
    /// `outcome` for `transfer`, its identity echoed.
    #[must_use]
    pub fn answering(transfer: &VmOutboxDescriptor, outcome: VmOutboxOutcome) -> Self {
        Self {
            wire_revision: VM_OUTBOX_WIRE_REVISION,
            transfer_id: transfer.transfer_id,
            kind: transfer.kind,
            member: transfer.member.clone(),
            revision: transfer.revision,
            blake3: transfer.blake3.clone(),
            outcome,
        }
    }

    /// Whether this ack echoes exactly `transfer`'s identity.
    #[must_use]
    pub fn answers(&self, transfer: &VmOutboxDescriptor) -> bool {
        self.wire_revision == VM_OUTBOX_WIRE_REVISION
            && self.transfer_id == transfer.transfer_id
            && self.kind == transfer.kind
            && self.member == transfer.member
            && self.revision == transfer.revision
            && self.blake3 == transfer.blake3
    }
}

/// What became of a transfer. Durable means the receiver published it, or
/// already had it, and synced its record; a deferral keeps the work on both
/// sides and names the bound it waits on; a refusal names why this transfer
/// is never taken as it is. A diverged one is the origin's retirement taken
/// for the version the carrier agreed on, while the receiver keeps its own
/// copy of the member, one the carrier never agreed on, hashing to `held`:
/// it is never removed but by its owner's answer (FIX 11074).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VmOutboxOutcome {
    Durable,
    DivergedUnagreed {
        held: String,
        length: u64,
    },
    Deferred {
        code: VmOutboxDeferral,
        bound: String,
        detail: String,
    },
    Refused {
        code: VmOutboxRefusal,
        detail: String,
    },
}

impl VmOutboxOutcome {
    /// A deferral on `bound`, its detail kept short and free of control
    /// characters.
    #[must_use]
    pub fn deferred(code: VmOutboxDeferral, bound: &str, detail: &str) -> Self {
        Self::Deferred {
            code,
            bound: clip(bound),
            detail: clip(detail),
        }
    }

    /// A refusal, its detail kept as a deferral's is.
    #[must_use]
    pub fn refused(code: VmOutboxRefusal, detail: &str) -> Self {
        Self::Refused {
            code,
            detail: clip(detail),
        }
    }
}

/// Why a transfer waits. Each keeps the sender's work for a later turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxDeferral {
    /// The receiving filesystem is full (ENOSPC); the bound names it.
    Capacity,
    /// The receiver has no root for the kind yet: none configured, not
    /// laid out, or a backup plan not registered.
    TargetUnavailable,
    /// The receiver denies new transfers while it stops or is destroyed.
    Draining,
    /// Another transfer of the same set could not be taken, so none was.
    SetIncomplete,
    /// Another I/O failure on the receiving side.
    Io,
}

/// Why a transfer is refused as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxRefusal {
    UnsupportedRevision,
    MalformedDescriptor,
    MemberNotAllowed,
    DirectionNotAllowed,
    LengthMismatch,
    DigestMismatch,
    /// The transfer's id was taken before with other content.
    IdentityConflict,
    /// The receiver holds a version of the member the transfer does not name.
    ExpectedDigestMismatch,
    /// The guest named another vault than the one the attachment is bound to.
    WrongVault,
}

/// One line on the carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum VmOutboxFrame {
    /// Guest to host, first on each connection.
    Hello { wire_revision: u32, vault: String },
    /// Host to guest: the session is open.
    Welcome { wire_revision: u32 },
    /// Host to guest: the session is refused, and the connection ends.
    Refused {
        wire_revision: u32,
        code: VmOutboxRefusal,
        detail: String,
    },
    /// Guest to host, at the start of each guest turn once the guest's
    /// engine registered its backup plan: that plan's label, which the host
    /// keeps for the vault its attachment is bound to (FIX 7046).
    BackupRegistered { label: String },
    /// Guest to host, at the start of a guest turn after the owner answered
    /// a diverged copy of `kind`'s `member` hashing to `held`, which
    /// `held_by` keeps (FIX 11736, FIX 11737). A guest copy was removed or
    /// moved aside, so a refusal the host gave its own version for that
    /// copy no longer holds and its next scan offers it again. A host copy
    /// the owner kept moves aside on the host under its own name, so the
    /// guest's next version lands, and the host answers [`Self::AsideKept`]
    /// with its move's result (FIX 12010). With `remove_aside`, the owner had the
    /// host's kept-aside copy removed: the host deletes its side copy and
    /// answers [`Self::AsideRemoved`] (FIX 11985). The host acts only on a
    /// copy its own record keeps with that digest.
    DivergenceCleared {
        kind: VmOutboxKind,
        member: String,
        held: String,
        held_by: VmOutboxSide,
        action: VmOutboxNoticeAction,
    },
    /// Host to guest, first in the host's turn: its kept-aside copy of
    /// `kind`'s `member` hashing to `held`, which a `remove_aside` notice
    /// named, is deleted, or `failed` says why it is not (FIX 11985).
    AsideRemoved {
        kind: VmOutboxKind,
        member: String,
        held: String,
        failed: Option<String>,
    },
    /// Host to guest, first in the host's turn: its copy of `kind`'s
    /// `member` hashing to `held`, which a keep notice named, moved aside
    /// under its own name, or `failed` says why it did not, while the copy
    /// stays at the member's name (FIX 12010).
    AsideKept {
        kind: VmOutboxKind,
        member: String,
        held: String,
        failed: Option<String>,
    },
    /// One transfer; a put's data chunks follow its line.
    Transfer(VmOutboxDescriptor),
    /// The answer to one transfer, after its set.
    Ack(VmOutboxAck),
    /// Guest to host: the guest's sets are sent; the host's turn.
    Pull,
    /// Host to guest: the host's sets are sent; the guest's turn.
    Done,
}

/// What a [`VmOutboxFrame::DivergenceCleared`] notice tells the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOutboxNoticeAction {
    /// The owner answered a diverged copy, remove or keep (FIX 11737).
    Answered,
    /// The owner had the host's kept-aside copy removed (FIX 11985).
    RemoveAside,
}

/// `detail` as an aside answer's failure carries it: short and free of
/// control characters, as a refusal's detail.
#[must_use]
pub fn vm_outbox_detail(detail: &str) -> String {
    clip(detail)
}

/// One frame as the line the carrier carries.
pub fn encode_vm_outbox_frame(frame: &VmOutboxFrame) -> anyhow::Result<String> {
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    anyhow::ensure!(
        line.len() <= MAX_VM_OUTBOX_LINE,
        "outbox frame over its line bound"
    );
    Ok(line)
}

/// Parses one carrier line. A line over the bound is refused whole.
pub fn decode_vm_outbox_frame(line: &str) -> anyhow::Result<VmOutboxFrame> {
    anyhow::ensure!(
        line.len() <= MAX_VM_OUTBOX_LINE,
        "outbox frame over its line bound"
    );
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// A data chunk's header for `len` bytes, or `None` for an empty or
/// oversized chunk.
#[must_use]
pub fn vm_outbox_chunk_header(len: usize) -> Option<[u8; 4]> {
    if !(1..=VM_OUTBOX_CHUNK_BYTES).contains(&len) {
        return None;
    }
    u32::try_from(len).ok().map(u32::to_be_bytes)
}

/// The length a data chunk's header announces, or `None` for one no sender
/// writes.
#[must_use]
pub fn vm_outbox_chunk_len(header: [u8; 4]) -> Option<usize> {
    let len = usize::try_from(u32::from_be_bytes(header)).ok()?;
    (1..=VM_OUTBOX_CHUNK_BYTES).contains(&len).then_some(len)
}

/// Whether `text` is 64 lowercase hex, a BLAKE3 digest.
#[must_use]
pub fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn clip(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL_CHARS)
        .collect()
}
