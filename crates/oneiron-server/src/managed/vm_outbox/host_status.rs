//! The host's read-only snapshot of its own outbox carrier member records.
//!
//! `read_vm_outbox_member_statuses` projects the same `store` records
//! `Store::open` loads into `VmOutboxHostMemberStatus`, for a trusted host
//! caller that already holds `VmOutboxHostRoots`. It starts no VM, asks no
//! guest, opens no carrier, and creates, writes, chmods, repairs, prunes,
//! retires, or schedules nothing: a diagnostic read only. An eligible record
//! that does not read or parse is an error, never a healthy empty.
//!
//! What it returns is observed retained metadata only (member names, digests,
//! lengths, aside names): not a live, current, drain, or physical-erase
//! proof, and not whole-directory health. The caller owns root selection; no
//! vault name is guessed from a path and no backup registration is required,
//! so the read works before any label. There is no new authenticated door
//! here.

use super::host::VmOutboxHostRoots;
use super::local::open_dir_path;
use super::store::SourceStatus;
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};
use serde::{Deserialize, Serialize};

/// One member's retained status the host's own carrier records keep, beside
/// its revision: the same three facts the guest board publishes, projected
/// from the same canonical member record without its raw body. Answer and
/// removal-failure presence are booleans only; no raw failure text, path
/// body, account, or key leaves here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VmOutboxHostMemberStatus {
    /// This end's own file, read again: it hashes to `read`, no longer to
    /// `recorded`, so none of it is sent until it changes. Only a recorded
    /// `SourceDigestMismatch`; a `Recheck` is not a failure.
    SourceDigestMismatch {
        kind: VmOutboxKind,
        member: String,
        recorded: String,
        read: String,
    },
    /// A copy the carrier never agreed on, kept by `held_by`, whose digest
    /// is `held` and whose retired agreed digest is `retired` when the
    /// retirement named one. `answer_recorded` is whether this record keeps
    /// an answer.
    DivergedUnagreed {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        held: String,
        length: u64,
        retired: Option<String>,
        answer_recorded: bool,
    },
    /// A diverged copy the owner kept, which `held_by` moved aside to its
    /// side name `aside` at `kept_at_ms`. `removal_failure_recorded` is
    /// whether the entry keeps a removal failure.
    KeptAside {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        held: String,
        length: u64,
        aside: String,
        kept_at_ms: u64,
        removing: bool,
        removal_failure_recorded: bool,
    },
}

/// The statuses the VM's host carrier records retain, read from `roots`'
/// carrier records alone: no VM is started or asked. `None` only when the
/// store root or its `members/` directory is missing; `Some` with an empty
/// list only when a readable `members/` holds no such status; an error for
/// any other directory, read, or parse failure.
pub fn read_vm_outbox_member_statuses(
    roots: &VmOutboxHostRoots,
) -> anyhow::Result<Option<Vec<VmOutboxHostMemberStatus>>> {
    let dir = match open_dir_path(&roots.store) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(records) = super::store::read_member_records(&dir)? else {
        return Ok(None);
    };
    let mut statuses = Vec::new();
    for ((kind, member), record) in records.iter() {
        if let Some(diverged) = &record.diverged {
            statuses.push(VmOutboxHostMemberStatus::DivergedUnagreed {
                kind: *kind,
                member: member.clone(),
                held_by: diverged.held_by,
                held: diverged.held.blake3.clone(),
                length: diverged.held.length,
                retired: diverged.retired.clone(),
                answer_recorded: diverged.answer.is_some(),
            });
        }
        if let Some(SourceStatus::SourceDigestMismatch { recorded, read, .. }) = &record.source {
            statuses.push(VmOutboxHostMemberStatus::SourceDigestMismatch {
                kind: *kind,
                member: member.clone(),
                recorded: recorded.clone(),
                read: read.clone(),
            });
        }
        for entry in &record.aside {
            statuses.push(VmOutboxHostMemberStatus::KeptAside {
                kind: *kind,
                member: member.clone(),
                held_by: entry.held_by,
                held: entry.held.blake3.clone(),
                length: entry.held.length,
                aside: entry.aside.clone(),
                kept_at_ms: entry.kept_at_ms,
                removing: entry.removing,
                removal_failure_recorded: entry.failed.is_some(),
            });
        }
    }
    Ok(Some(statuses))
}
