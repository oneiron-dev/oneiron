//! The diverged copies the owner kept, moved aside under their side names
//! ([`local::aside_name`]), and his removal of one (FIX 11985, FIX 11986).
//!
//! Each kept copy is an entry on its member's record ([`KeptAside`]): on the
//! end that holds it, and on the guest as the host holds it, which the
//! guest's status read lists. His `remove` of one deletes the side copy: the
//! guest's own at its next turn; the host's once a `remove_aside` notice
//! tells it, which the guest sends at each turn until the host answers
//! ([`VmOutboxFrame::AsideRemoved`]). The entry goes once its side copy is
//! deleted; a delete that fails is said and keeps the entry, with why. A
//! host copy whose move aside failed when he kept it keeps that keep on the
//! host's record and moves aside once it blocks the guest's next put; the
//! host answers the keep with its move's result
//! ([`VmOutboxFrame::AsideKept`]), so the guest's entry says when the copy
//! stays at the member's name (FIX 12010).

use super::link::Link;
use super::local;
use super::store::{DivergedAnswer, KeptAside, MemberRecord, Version};
use super::{Carrier, Mode};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxDescriptor, VmOutboxFrame, VmOutboxKind, VmOutboxNoticeAction, VmOutboxOutcome,
    VmOutboxSide, vm_outbox_detail,
};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Records `held`, which `held_by` keeps, as moved aside to `aside` now,
/// once per copy.
pub(super) fn record_kept_aside(
    record: &mut MemberRecord,
    held_by: VmOutboxSide,
    held: &Version,
    aside: String,
) {
    if record
        .aside
        .iter()
        .any(|entry| entry.held_by == held_by && entry.held.blake3 == held.blake3)
    {
        return;
    }
    let kept_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX));
    record.aside.push(KeptAside {
        held_by,
        held: held.clone(),
        aside,
        kept_at_ms,
        removing: false,
        failed: None,
    });
}

impl Carrier {
    /// On the guest, under the gate the caller holds: carries out the
    /// owner's removal of the kept-aside copy of `kind`'s `member` hashing
    /// to `held`. Its own side copy is deleted and the entry goes, or stays
    /// with why not; a host copy's entry is marked, and the host is told at
    /// each turn until it answers.
    pub(super) fn remove_kept_aside(&mut self, kind: VmOutboxKind, member: &str, held: &str) {
        let mut record = self.store.get(kind, member);
        let Some(entry) = record
            .aside
            .iter_mut()
            .find(|entry| entry.held.blake3 == held)
        else {
            return;
        };
        if entry.held_by != self.side {
            entry.removing = true;
            entry.failed = None;
        } else if let Err(error) = self.remove_side_copy(kind, member, held) {
            let what = format!("its kept-aside copy was not removed: {error}");
            entry.failed = Some(what.clone());
            self.say(kind, member, &what);
        } else {
            record.aside.retain(|entry| entry.held.blake3 != held);
            self.settled(kind, member);
        }
        self.write_record(kind, member, record);
    }

    /// On the guest: tells the host of each of its kept-aside copies the
    /// owner had removed, at each turn until the host answers.
    pub(super) fn send_aside_removals<S: Read + Write>(
        &self,
        link: &mut Link<S>,
    ) -> anyhow::Result<()> {
        for (kind, member, record) in self.store.records() {
            for entry in record.aside.iter().filter(|entry| entry.removing) {
                link.send(&VmOutboxFrame::DivergenceCleared {
                    kind,
                    member: member.to_owned(),
                    held: entry.held.blake3.clone(),
                    held_by: entry.held_by,
                    action: VmOutboxNoticeAction::RemoveAside,
                })?;
            }
        }
        Ok(())
    }

    /// On the guest: takes the host's answer to a removal of its kept-aside
    /// copy, under this end's gate. The entry goes, or stays with why not,
    /// no longer marked, for the owner to answer again.
    pub(super) fn aside_removed(&mut self, frame: VmOutboxFrame) {
        let VmOutboxFrame::AsideRemoved {
            kind,
            member,
            held,
            failed,
        } = frame
        else {
            return;
        };
        let gate = Arc::clone(&self.gate);
        let mode = gate.hold();
        if *mode == Mode::Draining {
            return;
        }
        let host = self.side.peer();
        let mut record = self.store.get(kind, &member);
        let answered =
            |entry: &KeptAside| entry.removing && entry.held_by == host && entry.held.blake3 == held;
        match failed {
            None => record.aside.retain(|entry| !answered(entry)),
            Some(why) => {
                for entry in &mut record.aside {
                    if answered(&*entry) {
                        entry.removing = false;
                        entry.failed = Some(why.clone());
                    }
                }
            }
        }
        self.write_record(kind, &member, record);
        drop(mode);
    }

    /// On the guest: takes the host's answer to a keep of its copy, under
    /// this end's gate (FIX 12010). A move that failed marks the entry with
    /// why, while the copy stays at the member's name until the next put
    /// moves it; a move that went through, at the keep or at that later put,
    /// clears the mark (FIX 12028).
    pub(super) fn aside_kept(&mut self, frame: VmOutboxFrame) {
        let VmOutboxFrame::AsideKept {
            kind,
            member,
            held,
            failed,
        } = frame
        else {
            return;
        };
        let gate = Arc::clone(&self.gate);
        let mode = gate.hold();
        if *mode == Mode::Draining {
            return;
        }
        let host = self.side.peer();
        let mut record = self.store.get(kind, &member);
        let what = failed
            .map(|why| format!("{why}; it stays at the member's name until the next put moves it"));
        let mut changed = false;
        for entry in &mut record.aside {
            if entry.held_by == host && entry.held.blake3 == held && entry.failed != what {
                entry.failed = what.clone();
                changed = true;
            }
        }
        if changed {
            self.write_record(kind, &member, record);
        }
        drop(mode);
    }

    /// On the host, under the gate the caller holds: deletes its kept-aside
    /// copy of `kind`'s `member` hashing to `held`, which a `remove_aside`
    /// notice named, and queues its answer for the guest's next pull. A
    /// keep whose move aside failed is removed at the member's name while
    /// the copy still hashes to `held`. A copy this end's record does not
    /// keep is answered removed: none is kept here.
    pub(super) fn remove_aside_for_guest(&mut self, kind: VmOutboxKind, member: &str, held: &str) {
        let mut record = self.store.get(kind, member);
        let side = self.side;
        let pending = record.diverged.as_ref().is_some_and(|diverged| {
            diverged.held_by == side
                && diverged.held.blake3 == held
                && diverged.answer == Some(DivergedAnswer::Keep)
        });
        let kept = record
            .aside
            .iter()
            .any(|entry| entry.held_by == side && entry.held.blake3 == held);
        let removed = if pending {
            self.remove_own_copy(kind, member, held)
                .map(|()| record.diverged = None)
        } else if kept {
            self.remove_side_copy(kind, member, held)
                .map(|()| record.aside.retain(|entry| entry.held.blake3 != held))
        } else {
            Ok(())
        };
        let failed = removed
            .err()
            .map(|error| vm_outbox_detail(&format!("the host's kept copy was not removed: {error}")));
        match &failed {
            Some(what) => self.say(kind, member, what),
            None => self.settled(kind, member),
        }
        self.write_record(kind, member, record);
        self.aside_answers.push(VmOutboxFrame::AsideRemoved {
            kind,
            member: member.to_owned(),
            held: held.to_owned(),
            failed,
        });
    }

    /// On the host: queues the answer to the guest's keep notice for
    /// `kind`'s `member` hashing to `held`: whether this end's move aside
    /// went through, for the guest's next pull (FIX 12010).
    pub(super) fn queue_aside_kept(
        &mut self,
        kind: VmOutboxKind,
        member: &str,
        held: &str,
        failed: Option<String>,
    ) {
        self.aside_answers.push(VmOutboxFrame::AsideKept {
            kind,
            member: member.to_owned(),
            held: held.to_owned(),
            failed,
        });
    }

    /// On the host: sends the guest each answer to a keep or a removal of
    /// a kept-aside copy, first in its turn. One lost with the connection
    /// is answered again, as the guest tells the host again.
    pub(super) fn send_aside_answers<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
    ) -> anyhow::Result<()> {
        for frame in std::mem::take(&mut self.aside_answers) {
            link.send(&frame)?;
        }
        Ok(())
    }

    /// On the end that holds it, under the commit's gate: moves aside its
    /// copy `held` of `transfer`'s member, a keep that did not move aside
    /// when the owner answered, once it blocks `transfer`, a put from the
    /// member's origin (FIX 11986). `None` when no keep stands for that
    /// copy, or its move fails again, which is said once while the copy
    /// stays; `Some(None)` once it moved, so the put lands; a record that
    /// does not write defers the put and is kept to write again.
    pub(super) fn move_kept_copy(
        &mut self,
        root: &File,
        transfer: &VmOutboxDescriptor,
        record: &MemberRecord,
        held: &Version,
    ) -> Option<Option<VmOutboxOutcome>> {
        let diverged = record.diverged.as_ref().filter(|diverged| {
            diverged.held_by == self.side
                && diverged.held.blake3 == held.blake3
                && diverged.answer == Some(DivergedAnswer::Keep)
        })?;
        let (kind, member) = (transfer.kind, transfer.member.as_str());
        let aside = match local::move_aside(root, member, &held.blake3) {
            Ok(aside) => aside,
            Err(error) => {
                let what = format!("its kept copy did not move aside: {error}");
                self.say(kind, member, &what);
                return None;
            }
        };
        let mut moved = record.clone();
        moved.diverged = None;
        if let Some(aside) = aside {
            record_kept_aside(&mut moved, self.side, &diverged.held, aside);
        }
        self.settled(kind, member);
        // The guest's entry for this copy drops the failed move's mark
        // (FIX 12028).
        self.queue_aside_kept(kind, member, &held.blake3, None);
        match self.store.put(kind, member, moved.clone()) {
            Ok(()) => Some(None),
            Err(error) => {
                let outcome = self.records_outcome(&error);
                self.received_failed(kind, member, moved, &error);
                Some(Some(outcome))
            }
        }
    }

    /// Deletes this end's side copy of `kind`'s `member` hashing to `held`.
    fn remove_side_copy(
        &self,
        kind: VmOutboxKind,
        member: &str,
        held: &str,
    ) -> std::io::Result<()> {
        match self.roots.open(kind)? {
            Some(root) => local::remove_aside(&root, kind, member, held),
            None => Err(std::io::Error::other("this end has no root for the kind now")),
        }
    }

    /// Writes `member`'s record, or keeps it to write again, as
    /// [`Self::received_failed`] keeps one.
    fn write_record(&mut self, kind: VmOutboxKind, member: &str, record: MemberRecord) {
        if let Err(error) = self.store.put(kind, member, record.clone()) {
            self.received_failed(kind, member, record, &error);
        }
    }
}
