//! What one end has to send, found by comparing its tree with its records.
//!
//! A member this end originates is put when its bytes differ from the agreed
//! version, and removed when it is gone; a member the other end originates is
//! removed (retired at its origin) when it is gone here and the kind lets
//! this end retire it. A transfer sent and not acked is sent again with its
//! identity while the tree still matches it; once the tree moved on, the next
//! change takes a revision past it. A digest is computed only when a file's
//! stamp changed. A training outbox is read under its lock, so a manifest and
//! its chunks are one snapshot.

use super::Carrier;
use super::local::{self, FileStamp};
use super::store::{Cached, MemberRecord, Version};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxDescriptor, VmOutboxKind, VmOutboxOperation, vm_outbox_member,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::time::Instant;

/// One change to send.
pub(super) struct OutOp {
    pub(super) member: String,
    pub(super) operation: VmOutboxOperation,
    pub(super) revision: u64,
    /// A put's content, or the version a remove retires.
    pub(super) version: Version,
    pub(super) expected: Option<String>,
    /// A put's file stamp when it was digested: the file sent must still
    /// have it.
    pub(super) stamp: Option<FileStamp>,
    pub(super) rank: u8,
    /// The id of the unacked transfer this sends again.
    pub(super) replay: Option<u64>,
}

/// The changes to one set, in the order they go.
pub(super) struct OutSet {
    pub(super) kind: VmOutboxKind,
    pub(super) set: String,
    pub(super) ops: Vec<OutOp>,
}

impl Carrier {
    /// Every set this end has to send now, kind by kind. A set the other end
    /// deferred waits out its pacing first. A backup kind waiting on a
    /// backup label the session did not keep is not scanned, so its records
    /// stay as they are until it goes.
    pub(super) fn outgoing(&mut self) -> anyhow::Result<Vec<OutSet>> {
        let mut sets = Vec::new();
        let now = Instant::now();
        for kind in VmOutboxKind::ALL {
            if self.backup_waits(kind).is_some() {
                continue;
            }
            let root = match self.roots.open(kind) {
                Ok(Some(root)) => root,
                Ok(None) => continue,
                Err(error) => {
                    self.say(kind, "", &format!("its root does not open: {error}"));
                    continue;
                }
            };
            let lock = match kind {
                VmOutboxKind::Training => local::lock_training(&root),
                _ => Ok(None),
            };
            if let Err(error) = &lock {
                self.say(kind, "", &format!("its lock is not taken: {error}"));
                continue;
            }
            let ops = self.scan_kind(kind, &root)?;
            drop(lock);
            let mut grouped: BTreeMap<String, Vec<OutOp>> = BTreeMap::new();
            for (set, op) in ops {
                grouped.entry(set).or_default().push(op);
            }
            for (set, mut ops) in grouped {
                if self
                    .paced
                    .get(&(kind, set.clone()))
                    .is_some_and(|(at, _)| *at > now)
                {
                    continue;
                }
                ops.sort_by(|a, b| (a.rank, &a.member).cmp(&(b.rank, &b.member)));
                sets.push(OutSet { kind, set, ops });
            }
        }
        Ok(sets)
    }

    /// `kind`'s changes under `root`, each with its set.
    fn scan_kind(
        &mut self,
        kind: VmOutboxKind,
        root: &File,
    ) -> anyhow::Result<Vec<(String, OutOp)>> {
        let roots = &self.roots;
        let listed = local::list(root, kind, self.owner, &|member: &str| {
            roots.takes(kind, member)
        });
        let found = match listed {
            Ok(found) => found,
            Err(error) => {
                self.say(kind, "", &format!("its root does not list: {error}"));
                return Ok(Vec::new());
            }
        };
        let mut ops = Vec::new();
        for (member, stamp) in &found {
            let Some(class) = vm_outbox_member(kind, member) else {
                continue;
            };
            let mut record = self.store.get(kind, member);
            if class.origin != self.side {
                // The other end's member is here again: a retirement this
                // end had pending for it no longer holds.
                if record.pending.take().is_some() {
                    self.store.put(kind, member, record)?;
                }
                continue;
            }
            let version = match &record.cached {
                Some(cached) if cached.stamp == *stamp => cached.version.clone(),
                _ => {
                    let read =
                        local::open_member(root, member, Some(self.owner)).and_then(|opened| {
                            opened
                                .map(|(file, now)| {
                                    local::digest(&file).map(|version| (now, version))
                                })
                                .transpose()
                        });
                    let (now, version) = match read {
                        Ok(Some(read)) => read,
                        Ok(None) => continue,
                        Err(error) => {
                            self.say(kind, member, &format!("it does not read: {error}"));
                            continue;
                        }
                    };
                    record.cached = Some(Cached {
                        stamp: now,
                        version: version.clone(),
                    });
                    version
                }
            };
            let stamp = record.cached.as_ref().map(|cached| cached.stamp);
            let op = put_op(&mut record, member, version, stamp, class.put_rank);
            self.store.put(kind, member, record)?;
            ops.extend(op.map(|op| (class.set, op)));
        }
        for (member, mut record) in self.store.members(kind) {
            if found.contains_key(&member) || !self.roots.takes(kind, &member) {
                continue;
            }
            let Some(class) = vm_outbox_member(kind, &member) else {
                continue;
            };
            let retires = class.origin == self.side || class.peer_retires;
            let op = remove_op(&mut record, &member, retires, class.remove_rank);
            record.cached = None;
            self.store.put(kind, &member, record)?;
            ops.extend(op.map(|op| (class.set, op)));
        }
        Ok(ops)
    }
}

/// The put `member`'s file at `version` needs, if any.
fn put_op(
    record: &mut MemberRecord,
    member: &str,
    version: Version,
    stamp: Option<FileStamp>,
    rank: u8,
) -> Option<OutOp> {
    let mut past = record.revision;
    if let Some(pending) = record.pending.take() {
        if pending.operation == VmOutboxOperation::Put
            && pending.blake3 == version.blake3
            && pending.revision > record.revision
        {
            let op = replay(&pending, version, stamp, rank);
            record.pending = Some(pending);
            return Some(op);
        }
        // The tree moved past an unacked transfer the other end may hold:
        // the next change goes past its revision, whatever it is.
        past = past.max(pending.revision);
    } else if record
        .agreed
        .as_ref()
        .is_some_and(|agreed| agreed.blake3 == version.blake3)
        || record.refused.as_deref() == Some(format!("put:{}", version.blake3).as_str())
    {
        return None;
    }
    Some(OutOp {
        member: member.to_owned(),
        operation: VmOutboxOperation::Put,
        revision: past + 1,
        expected: record.agreed.as_ref().map(|agreed| agreed.blake3.clone()),
        version,
        stamp,
        rank,
        replay: None,
    })
}

/// The remove a gone `member` needs, if any: `retires` says whether this
/// end's loss of it retires it at the other end.
fn remove_op(record: &mut MemberRecord, member: &str, retires: bool, rank: u8) -> Option<OutOp> {
    let mut past = record.revision;
    let mut held = record.agreed.clone();
    if let Some(pending) = record.pending.take() {
        if pending.operation == VmOutboxOperation::Remove && pending.revision > record.revision {
            let version = Version {
                blake3: pending.blake3.clone(),
                length: 0,
            };
            let op = replay(&pending, version, None, rank);
            record.pending = Some(pending);
            return Some(op);
        }
        // An unacked put the other end may hold is the version to retire.
        past = past.max(pending.revision);
        held = Some(Version {
            blake3: pending.blake3,
            length: pending.length,
        });
    }
    let held = held.filter(|_| retires)?;
    if record.refused.as_deref() == Some(format!("remove:{}", held.blake3).as_str()) {
        return None;
    }
    Some(OutOp {
        member: member.to_owned(),
        operation: VmOutboxOperation::Remove,
        revision: past + 1,
        expected: Some(held.blake3.clone()),
        version: Version {
            blake3: held.blake3,
            length: 0,
        },
        stamp: None,
        rank,
        replay: None,
    })
}

fn replay(
    pending: &VmOutboxDescriptor,
    version: Version,
    stamp: Option<FileStamp>,
    rank: u8,
) -> OutOp {
    OutOp {
        member: pending.member.clone(),
        operation: pending.operation,
        revision: pending.revision,
        version,
        expected: pending.expected_digest.clone(),
        stamp,
        rank,
        replay: Some(pending.transfer_id),
    }
}
