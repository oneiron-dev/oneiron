//! A receiving end's whole-set publication (FIX 7543).
//!
//! A set the other end sent is published whole, or this end keeps working
//! until it is; nothing of it is rolled back and nothing is dropped. Before
//! the set's first change, this end journals the set durably in its carrier
//! store ([`SetJournal`]): each change in the set's order, and the record
//! each member gets once its change is made. The staged bodies the journal
//! names are synced first. A set with more than one change on disk also
//! marks its kind's root ([`VM_OUTBOX_SET_MARK`]) before the first change,
//! and a reader of more than one member waits while the mark stands. Then
//! each change is made, each record written, the mark removed and the
//! journal deleted, in that order. Only then is the set durable, and only
//! then are its transfers answered so.
//!
//! When a step does not go through, the set is unfinished: each of its
//! transfers is deferred on what failed, the journal, the mark and the
//! staged temporaries the journal names stay, and the kind waits on its
//! carrier records, so none of its sets is sent, scanned or taken. The
//! kind's next turn finishes the set from its journal before anything else
//! of the kind runs: a staged temporary still there is published, one
//! published before is found in place, a removal is made again, and every
//! record is written. A set a crash left unfinished is finished the same way
//! once the end starts again. When the other end sends the set again, each
//! of its transfers is a replay of one now taken and is answered durable.

use super::local::{self, Staged};
use super::store::{Cached, Diverged, MemberRecord, Received, Version};
use super::{Carrier, Mode, PACE_CEILING, RESCAN_EVERY, RecordWait};
use oneiron_vault_contract::vm_outbox::{
    VM_OUTBOX_SET_MARK, VmOutboxDeferral, VmOutboxDescriptor, VmOutboxKind, VmOutboxOperation,
    VmOutboxOutcome,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::sync::Arc;
use std::time::Instant;

/// What an unfinished set is said under, per kind: no member's name, as no
/// part of one starts with a dot.
const SET_SAID: &str = ".set";

/// A set this end is publishing, as journaled before its first change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SetJournal {
    kind: VmOutboxKind,
    set_id: String,
    /// Whether the set marks its kind's root while it stands.
    marked: bool,
    entries: Vec<Entry>,
}

/// One change of a journaled set and the member's record once it is made.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    member: String,
    change: Change,
    /// The record that proves the change received; its digest cache is
    /// filled from the published file.
    record: MemberRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
enum Change {
    /// The staged temporary of `transfer_id`, renamed over the member.
    Put {
        transfer_id: u64,
        length: u64,
        blake3: String,
        protected: bool,
    },
    /// The member removed.
    Remove,
    /// This end's own copy kept as the member's origin retired the agreed
    /// version (FIX 11074): nothing changes on disk.
    Keep,
}

impl Change {
    fn on_disk(&self) -> bool {
        !matches!(self, Self::Keep)
    }
}

/// One change of a taken set, as its commit hands it over in the set's
/// order.
pub(super) struct SetChange {
    pub(super) descriptor: VmOutboxDescriptor,
    pub(super) protected: bool,
    pub(super) making: Making,
}

/// What a set's change makes.
pub(super) enum Making {
    Put(Box<Staged>),
    Remove,
    /// The copy this end keeps, as recorded for its owner's answer.
    Keep(Diverged),
}

/// The step an unfinished set stopped at.
enum Stop {
    /// A change under the kind's root, or its mark.
    Root(std::io::Error),
    /// A record or the journal in this end's carrier store.
    Records(std::io::Error),
}

impl Stop {
    fn error(&self) -> &std::io::Error {
        match self {
            Self::Root(error) | Self::Records(error) => error,
        }
    }
}

impl Carrier {
    /// Publishes `changes`, one taken set's changes in its order, whole
    /// under `kind`'s `root`, as the module says, and returns one answer
    /// per change. The caller holds the gate and, for training, the
    /// outbox's lock.
    pub(super) fn publish_set(
        &mut self,
        kind: VmOutboxKind,
        root: &File,
        changes: Vec<SetChange>,
    ) -> Vec<VmOutboxOutcome> {
        let set_id = changes
            .first()
            .map(|change| change.descriptor.set_id.clone())
            .unwrap_or_default();
        let mut descriptors = Vec::with_capacity(changes.len());
        let mut staged = Vec::with_capacity(changes.len());
        let mut entries = Vec::with_capacity(changes.len());
        for SetChange {
            descriptor,
            protected,
            making,
        } in changes
        {
            let (change, file, kept) = match making {
                Making::Put(file) => (
                    Change::Put {
                        transfer_id: descriptor.transfer_id,
                        length: descriptor.length,
                        blake3: descriptor.blake3.clone(),
                        protected,
                    },
                    Some(file),
                    None,
                ),
                Making::Remove => (Change::Remove, None, None),
                Making::Keep(kept) => (Change::Keep, None, Some(kept)),
            };
            entries.push(Entry {
                member: descriptor.member.clone(),
                change,
                record: self.received_record(&descriptor, kept),
            });
            staged.push(file);
            descriptors.push(descriptor);
        }
        let marked = entries
            .iter()
            .filter(|entry| entry.change.on_disk())
            .count()
            > 1;
        let mut journal = SetJournal {
            kind,
            set_id,
            marked,
            entries,
        };
        if let Err(stop) = self.begin_set(root, &journal, &staged) {
            // Nothing changed: the mark and the journal go again, and the
            // set is deferred. One of them that does not go stays with the
            // set's temporaries, and the kind finishes the set.
            let undone = (!journal.marked || local::unmark_set(root).is_ok())
                && self.store.remove_set_journal(kind).is_ok();
            if undone {
                drop(staged);
                return vec![self.stop_outcome(kind, &stop); descriptors.len()];
            }
            staged
                .iter_mut()
                .flatten()
                .for_each(|file| file.keep_for_journal());
            return self.set_unfinished(journal, &stop, descriptors.len());
        }
        // The journal names each temporary from here on.
        staged
            .iter_mut()
            .flatten()
            .for_each(|file| file.keep_for_journal());
        let done = self
            .make_changes(root, &mut journal, staged)
            .and_then(|()| self.finish_set(root, &journal));
        match done {
            Ok(()) => {
                self.settled(kind, SET_SAID);
                descriptors
                    .iter()
                    .zip(&journal.entries)
                    .map(|(descriptor, entry)| {
                        self.received_written(kind, &entry.member);
                        self.taken_answer(descriptor, &entry.record)
                    })
                    .collect()
            }
            Err(stop) => self.set_unfinished(journal, &stop, descriptors.len()),
        }
    }

    /// Finishes `kind`'s unfinished set, if it has one, from its journal,
    /// under the gate as a local commit and, for training, the outbox's
    /// lock: `true` once none is left. One that does not finish stays, and
    /// the kind waits one more step; a draining end finishes none.
    pub(super) fn finish_unfinished_set(&mut self, kind: VmOutboxKind) -> bool {
        let Some(mut journal) = self.unfinished.remove(&kind) else {
            return true;
        };
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        if *held == Mode::Draining {
            self.unfinished.insert(kind, journal);
            return false;
        }
        let root = match self.roots.open(kind) {
            Ok(Some(root)) => root,
            Ok(None) => {
                let outcome = VmOutboxOutcome::deferred(
                    VmOutboxDeferral::TargetUnavailable,
                    &format!("this end's {kind} root"),
                    "this end has no root for the kind yet",
                );
                self.wait_on_set(kind, outcome);
                self.unfinished.insert(kind, journal);
                return false;
            }
            Err(error) => {
                let outcome = self.io_outcome(kind, &error);
                self.wait_on_set(kind, outcome);
                self.unfinished.insert(kind, journal);
                return false;
            }
        };
        let lock = match kind {
            VmOutboxKind::Training => local::lock_training(&root),
            _ => Ok(None),
        };
        let done = match lock {
            Ok(lock) => {
                let done = self
                    .redo_changes(&root, &mut journal)
                    .and_then(|()| self.finish_set(&root, &journal));
                drop(lock);
                done
            }
            Err(error) => Err(Stop::Root(error)),
        };
        drop(held);
        match done {
            Ok(()) => {
                for entry in &journal.entries {
                    self.received_written(kind, &entry.member);
                }
                self.settled(kind, SET_SAID);
                tracing::info!(
                    side = ?self.side,
                    %kind,
                    set = %journal.set_id,
                    "an outbox carrier set left unfinished is now published whole"
                );
                true
            }
            Err(stop) => {
                self.set_unfinished(journal, &stop, 0);
                false
            }
        }
    }

    /// Takes in each set a stop left unfinished, from the journals in this
    /// end's store, when the end starts: each kind with one waits on it,
    /// and its first turn finishes it. A journal that does not read is said
    /// and left on disk, and its kind's set mark goes, so no reader waits
    /// on a set this end cannot finish; the other end's transfers of it,
    /// never answered durable, come again as a set of their own.
    pub(super) fn load_unfinished_sets(&mut self) {
        for (kind, read) in self.store.read_set_journals() {
            let journal = read.and_then(|bytes| {
                serde_json::from_slice::<SetJournal>(&bytes).map_err(std::io::Error::other)
            });
            match journal {
                Ok(journal) if journal.kind == kind => {
                    let outcome = VmOutboxOutcome::deferred(
                        VmOutboxDeferral::Io,
                        &format!("this end's unfinished {kind} set"),
                        "a set this end took is not published whole yet; the work is kept",
                    );
                    self.record_wait.insert(
                        kind,
                        RecordWait {
                            outcome,
                            at: Instant::now(),
                            step: RESCAN_EVERY,
                            retry: Default::default(),
                        },
                    );
                    self.unfinished.insert(kind, journal);
                }
                read => {
                    let error = read.err().map_or_else(
                        || "it names another kind".to_owned(),
                        |error| error.to_string(),
                    );
                    tracing::warn!(
                        reason = "vm_outbox_set_journal_unreadable",
                        side = ?self.side,
                        %kind,
                        %error,
                        "an outbox carrier set journal does not read; its set mark goes"
                    );
                    if let Ok(Some(root)) = self.roots.open(kind) {
                        let _ = local::unmark_set(&root);
                    }
                }
            }
        }
    }

    /// `transfer`'s member's record once its change is made, `kept` the
    /// copy a retirement leaves this end; its digest cache is filled from
    /// the published file.
    fn received_record(
        &self,
        transfer: &VmOutboxDescriptor,
        kept: Option<Diverged>,
    ) -> MemberRecord {
        let mut record = self.store.get(transfer.kind, &transfer.member);
        record.revision = record.revision.max(transfer.revision);
        record.agreed = (transfer.operation == VmOutboxOperation::Put).then(|| Version {
            blake3: transfer.blake3.clone(),
            length: transfer.length,
        });
        record.cached = None;
        record.received = Some(Received {
            transfer_id: transfer.transfer_id,
            revision: transfer.revision,
            blake3: transfer.blake3.clone(),
        });
        if record
            .pending
            .as_ref()
            .is_some_and(|pending| pending.revision <= transfer.revision)
        {
            record.pending = None;
        }
        record.refused = None;
        record.diverged = kept;
        record
    }

    /// Syncs each staged body, journals the set and marks the root when the
    /// set marks it: nothing is changed yet.
    fn begin_set(
        &self,
        root: &File,
        journal: &SetJournal,
        staged: &[Option<Box<Staged>>],
    ) -> Result<(), Stop> {
        for file in staged.iter().flatten() {
            file.sync().map_err(Stop::Root)?;
        }
        let bytes = serde_json::to_vec(journal)
            .map_err(|error| Stop::Records(std::io::Error::other(error)))?;
        self.store
            .write_set_journal(journal.kind, &bytes)
            .map_err(Stop::Records)?;
        if journal.marked {
            local::mark_set(root, self.owner, &journal.set_id).map_err(Stop::Root)?;
        }
        Ok(())
    }

    /// Makes each change in order with the staged bodies at hand, filling
    /// each put's digest cache; stops at the first that does not go through.
    fn make_changes(
        &self,
        root: &File,
        journal: &mut SetJournal,
        staged: Vec<Option<Box<Staged>>>,
    ) -> Result<(), Stop> {
        let kind = journal.kind;
        for (entry, file) in journal.entries.iter_mut().zip(staged) {
            let stamp = match (&entry.change, file) {
                (Change::Put { protected, .. }, Some(file)) => Some(
                    (*file)
                        .publish(self.owner, *protected)
                        .map_err(Stop::Root)?,
                ),
                (Change::Remove, _) => {
                    local::remove(root, kind, &entry.member).map_err(Stop::Root)?;
                    None
                }
                _ => None,
            };
            fill_cache(&mut entry.record, stamp);
        }
        Ok(())
    }

    /// Makes each journaled change again, in order, from what is on disk.
    /// A put whose staged bytes are gone, and whose member does not hold
    /// them, cannot be made: it is said and its record is not written, so
    /// the other end's transfer of it is taken as new when its set comes
    /// again.
    fn redo_changes(&self, root: &File, journal: &mut SetJournal) -> Result<(), Stop> {
        let kind = journal.kind;
        let mut lost = Vec::new();
        for (index, entry) in journal.entries.iter_mut().enumerate() {
            let stamp = match &entry.change {
                Change::Put {
                    transfer_id,
                    length,
                    blake3,
                    protected,
                } => {
                    let published = local::publish_staged(
                        root,
                        &entry.member,
                        *transfer_id,
                        *length,
                        blake3,
                        self.owner,
                        *protected,
                    )
                    .map_err(Stop::Root)?;
                    if published.is_none() {
                        lost.push(index);
                        continue;
                    }
                    published
                }
                Change::Remove => {
                    local::remove(root, kind, &entry.member).map_err(Stop::Root)?;
                    None
                }
                Change::Keep => None,
            };
            fill_cache(&mut entry.record, stamp);
        }
        for index in lost.into_iter().rev() {
            let entry = journal.entries.remove(index);
            tracing::warn!(
                reason = "vm_outbox_set_put_lost",
                side = ?self.side,
                %kind,
                member = %entry.member,
                set = %journal.set_id,
                "a put of an unfinished outbox carrier set has no staged bytes left; it is taken again when its set comes again"
            );
        }
        Ok(())
    }

    /// Writes each record of a set whose changes are made, removes its
    /// mark, then deletes its journal.
    fn finish_set(&mut self, root: &File, journal: &SetJournal) -> Result<(), Stop> {
        for entry in &journal.entries {
            self.store
                .put(journal.kind, &entry.member, entry.record.clone())
                .map_err(Stop::Records)?;
        }
        if journal.marked {
            local::unmark_set(root).map_err(Stop::Root)?;
        }
        self.store
            .remove_set_journal(journal.kind)
            .map_err(Stop::Records)
    }

    /// Keeps `journal`'s set unfinished after `stop`: said once, the kind
    /// waiting on it, and each of its `count` transfers answered with the
    /// stop's deferral.
    fn set_unfinished(
        &mut self,
        journal: SetJournal,
        stop: &Stop,
        count: usize,
    ) -> Vec<VmOutboxOutcome> {
        let kind = journal.kind;
        let outcome = self.stop_outcome(kind, stop);
        self.say(
            kind,
            SET_SAID,
            &format!(
                "its set {} is not published whole yet ({}): {}; it is kept, and finished first at the kind's next turn",
                journal.set_id,
                VM_OUTBOX_SET_MARK,
                stop.error()
            ),
        );
        self.wait_on_set(kind, outcome.clone());
        self.unfinished.insert(kind, journal);
        vec![outcome; count]
    }

    /// The deferral a set's transfers get after `stop`.
    fn stop_outcome(&self, kind: VmOutboxKind, stop: &Stop) -> VmOutboxOutcome {
        match stop {
            Stop::Root(error) => self.io_outcome(kind, error),
            Stop::Records(error) => self.records_outcome(error),
        }
    }

    /// Makes `kind` wait on its unfinished set, answered with `outcome`,
    /// until a later turn finishes it: after one step, each twice the last,
    /// up to [`PACE_CEILING`]. Records kept to write again stay kept.
    fn wait_on_set(&mut self, kind: VmOutboxKind, outcome: VmOutboxOutcome) {
        let previous = self.record_wait.remove(&kind);
        let step = previous
            .as_ref()
            .map_or(RESCAN_EVERY, |wait| (wait.step * 2).min(PACE_CEILING));
        self.record_wait.insert(
            kind,
            RecordWait {
                outcome,
                at: Instant::now() + step,
                step,
                retry: previous.map(|wait| wait.retry).unwrap_or_default(),
            },
        );
    }
}

/// Fills `record`'s digest cache from the stamp its member was published
/// at, for a put; a removal or a kept copy has none.
fn fill_cache(record: &mut MemberRecord, stamp: Option<local::FileStamp>) {
    record.cached = stamp
        .zip(record.agreed.clone())
        .map(|(stamp, version)| Cached { stamp, version });
}
