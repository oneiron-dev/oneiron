//! One end's durable carrier state: a record per member and its next
//! transfer id, in a directory only that end's root (or host process) reads.
//!
//! A member's record is `members/<64 hex>.json`, the BLAKE3 of its kind and
//! name, written whole: a temporary sibling, synced, renamed, the directory
//! synced. It holds no member bytes: the agreed version's digest, the last
//! transfer taken from the other end, the transfer sent and not yet acked,
//! the highest revision this end ever sent, and a digest cache keyed by the
//! local file's stamp. A record outlives its member as a tombstone, so a
//! late replay never brings a retired file back; none is aged out or
//! evicted. The next transfer id is `next-transfer`.
//! Every record is read into memory when the end starts.
//!
//! The host also keeps `backup-label.json` (FIX 7046): the backup label the
//! guest last named as its engine's registered one, with the vault the
//! attachment is bound to, written whole the same way. Only that frame writes
//! it, a changed label replaces it, and it outlives the VM's exit and the
//! host's restart: the last registration the host was told of, not proof the
//! VM runs.

use super::local::FileStamp;
use oneiron_vault_contract::vm_outbox::{VmOutboxDescriptor, VmOutboxKind};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

const MEMBERS: &str = "members";
const NEXT_TRANSFER: &str = "next-transfer";
const BACKUP_LABEL: &str = "backup-label.json";
/// The longest record or counter read back: a few short fields and one
/// transfer line.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// A member's version: its content's digest and length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Version {
    pub(super) blake3: String,
    pub(super) length: u64,
}

/// The digest of the local file as it stood at `stamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Cached {
    pub(super) stamp: FileStamp,
    pub(super) version: Version,
}

/// The last transfer this end took from the other: the replay check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Received {
    pub(super) transfer_id: u64,
    pub(super) revision: u64,
    pub(super) blake3: String,
}

/// What this end knows of one member.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MemberRecord {
    /// The member's latest revision either end made, as this end knows it.
    pub(super) revision: u64,
    /// The version both ends hold at `revision`; `None` once it is removed.
    pub(super) agreed: Option<Version>,
    /// The highest revision this end recorded on a transfer it sent, kept
    /// once that transfer is acked, refused or passed: a new change goes
    /// past it, so no revision is given twice. Written with the pending
    /// transfer that raises it.
    pub(super) floor: u64,
    #[serde(default)]
    pub(super) cached: Option<Cached>,
    #[serde(default)]
    pub(super) received: Option<Received>,
    /// The transfer this end sent and the other has not acked: its
    /// retransmission state, replayed with the same identity.
    #[serde(default)]
    pub(super) pending: Option<VmOutboxDescriptor>,
    /// The change the other end refused (`put:<digest>` or
    /// `remove:<digest>`), not sent again until the member changes.
    #[serde(default)]
    pub(super) refused: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    kind: VmOutboxKind,
    member: String,
    record: MemberRecord,
}

/// The backup label the guest last named, kept with the vault the host's
/// attachment is bound to, which no guest field chooses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackupLabelBinding {
    pub(super) vault: String,
    pub(super) label: String,
}

pub(super) struct Store {
    dir: File,
    members: File,
    records: BTreeMap<(VmOutboxKind, String), MemberRecord>,
    next_transfer: u64,
    /// `backup-label.json` as last read or written; `None` when there is
    /// none, or one that did not read, which the next registration replaces.
    backup_label: Option<BackupLabelBinding>,
}

impl Store {
    /// The store in `dir`, held, its records read in. A record that does not
    /// read is said and left on disk; its member starts over from revision 0.
    pub(super) fn open(dir: File) -> anyhow::Result<Self> {
        match rustix::fs::mkdirat(&dir, MEMBERS, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        let members = super::local::open_dir_at(&dir, MEMBERS)?;
        let mut records = BTreeMap::new();
        for entry in rustix::fs::Dir::read_from(&members)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            match read_small(&members, &name).map(|bytes| serde_json::from_slice::<Stored>(&bytes))
            {
                Ok(Ok(stored)) => {
                    records.insert((stored.kind, stored.member), stored.record);
                }
                _ => tracing::warn!(
                    reason = "vm_outbox_record_unreadable",
                    record = %name,
                    "an outbox carrier record does not read; its member starts over"
                ),
            }
        }
        let next_transfer = match read_small(&dir, NEXT_TRANSFER) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).trim().parse()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 1,
            Err(error) => return Err(error.into()),
        };
        let backup_label = read_backup_label(&dir).ok().flatten();
        Ok(Self {
            dir,
            members,
            records,
            next_transfer,
            backup_label,
        })
    }

    /// `member`'s record; a fresh one when this end knows nothing of it.
    pub(super) fn get(&self, kind: VmOutboxKind, member: &str) -> MemberRecord {
        self.records
            .get(&(kind, member.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    /// Every member of `kind` this end has a record of.
    pub(super) fn members(&self, kind: VmOutboxKind) -> Vec<(String, MemberRecord)> {
        self.records
            .iter()
            .filter(|((of, _), _)| *of == kind)
            .map(|((_, member), record)| (member.clone(), record.clone()))
            .collect()
    }

    /// Writes `member`'s record durably, then keeps it in memory.
    pub(super) fn put(
        &mut self,
        kind: VmOutboxKind,
        member: &str,
        record: MemberRecord,
    ) -> std::io::Result<()> {
        let key = (kind, member.to_owned());
        if self.records.get(&key) == Some(&record) {
            return Ok(());
        }
        let stored = Stored {
            kind,
            member: member.to_owned(),
            record,
        };
        let bytes = serde_json::to_vec(&stored).map_err(std::io::Error::other)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(kind.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(member.as_bytes());
        let name = format!("{}.json", hasher.finalize().to_hex());
        write_whole(&self.members, &name, &bytes)?;
        self.records.insert(key, stored.record);
        Ok(())
    }

    /// `count` fresh transfer ids, the first returned, the counter synced
    /// past them before any is used.
    pub(super) fn allocate(&mut self, count: u64) -> std::io::Result<u64> {
        let first = self.next_transfer;
        let next = first.saturating_add(count);
        write_whole(&self.dir, NEXT_TRANSFER, next.to_string().as_bytes())?;
        self.next_transfer = next;
        Ok(first)
    }

    /// Writes `binding` durably as `backup-label.json`, then keeps it in
    /// memory; the same binding again writes nothing.
    pub(super) fn bind_backup_label(&mut self, binding: BackupLabelBinding) -> std::io::Result<()> {
        if self.backup_label.as_ref() == Some(&binding) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&binding).map_err(std::io::Error::other)?;
        write_whole(&self.dir, BACKUP_LABEL, &bytes)?;
        self.backup_label = Some(binding);
        Ok(())
    }
}

/// `backup-label.json` in the store `dir`, or `None` when there is none. It
/// reads only as this store's own file: not followed through a link, a
/// regular file with one name, mode 0600, owned by the directory's owner.
pub(super) fn read_backup_label(dir: &File) -> anyhow::Result<Option<BackupLabelBinding>> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::openat(dir, BACKUP_LABEL, flags, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    let (metadata, owner) = (file.metadata()?, dir.metadata()?.uid());
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == owner,
        "the backup label record is not the carrier store's own private file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES).read_to_end(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// A small file in `dir`, read without following a link.
fn read_small(dir: &File, name: &str) -> std::io::Result<Vec<u8>> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = File::from(rustix::fs::openat(dir, name, flags, Mode::empty())?);
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Writes `bytes` as `dir/name`: a temporary sibling made new at 0600,
/// written and synced, renamed over `name`, then `dir` synced.
fn write_whole(dir: &File, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = format!(".{name}.tmp");
    match rustix::fs::unlinkat(dir, temporary.as_str(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(rustix::fs::openat(
        dir,
        temporary.as_str(),
        flags,
        Mode::from_raw_mode(0o600),
    )?);
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::renameat(dir, temporary.as_str(), dir, name)?;
    dir.sync_all()
}
