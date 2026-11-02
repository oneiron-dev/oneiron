//! The guest carrier's member status read and the owner's answers to its
//! diverged copies (FIX 11074, FIX 11242).
//!
//! A copy of a member the carrier never agreed on, kept as the member's
//! origin retired the agreed version, is `diverged_unagreed`: on the end
//! that holds it, and on the guest as the host answered when the host holds
//! it. A file whose put the other end refused as `digest_mismatch` and that
//! no longer hashes to its own recorded digest is `source_digest_mismatch`
//! (FIX 11075). The guest's lifecycle endpoint reads both from the board the
//! carrier publishes at each turn, and takes the owner's answers to a
//! diverged copy, which the carrier carries out at its next turn: `keep`
//! moves the copy aside under its own name, a hidden sibling of the member
//! ([`local::move_aside`]), where it is listed as kept aside until he has it
//! removed ([`super::aside`], FIX 11985), so the origin's next version lands
//! (FIX 11736);
//! `remove` removes the guest's own copy while it still hashes to the digest
//! he answered, or, for the host's copy, takes that copy as the agreed
//! version, so the guest's next scan retires it as an ordinary removal
//! naming its digest (or replaces it with the guest's own newer version).
//! The guest tells the host of every other answer at its next turn
//! (FIX 11737): the host moves its own kept copy aside, or offers its own
//! version again once the guest's copy is out of its way. Nothing here
//! removes a copy without his answer.

use super::aside::record_kept_aside;
use super::link::Link;
use super::local;
use super::store::{Diverged, DivergedAnswer, SourceStatus};
use super::{Carrier, Mode};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxFrame, VmOutboxKind, VmOutboxNoticeAction, VmOutboxSide, vm_outbox_detail,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

/// A diverged copy's answer the guest sent the host, by kind and member.
pub(super) type Notice = (VmOutboxKind, String, Diverged);

/// The owner route that takes his answer to a diverged copy.
pub(crate) const DIVERGED_ANSWER_ROUTE: &str = "POST /v1/owner/outbox/diverged";

/// One member's status the guest carrier reports beside its revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum VmOutboxMemberStatus {
    /// A copy the carrier never agreed on, kept by `held_by` as the
    /// member's origin retired the agreed version, whose digest is
    /// `retired` when the retirement named one. `answer` is the owner's,
    /// once given: a removal stands here until it is carried.
    DivergedUnagreed {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        held: String,
        length: u64,
        retired: Option<String>,
        answer: Option<DivergedAnswer>,
    },
    /// The guest's own file, whose put the host refused as
    /// `digest_mismatch`, read again: it hashes to `read`, no longer to
    /// `recorded`, so none of it is sent until it changes (FIX 11075).
    SourceDigestMismatch {
        kind: VmOutboxKind,
        member: String,
        recorded: String,
        read: String,
    },
    /// A diverged copy the owner kept, which `held_by` moved aside to its
    /// side name `aside` at `kept_at_ms` (FIX 11985). `removing` once he had
    /// it removed, until the host answers; `failed` why the last removal did
    /// not go through.
    KeptAside {
        kind: VmOutboxKind,
        member: String,
        held_by: VmOutboxSide,
        held: String,
        length: u64,
        aside: String,
        kept_at_ms: u64,
        removing: bool,
        failed: Option<String>,
    },
}

/// The owner's answer to one diverged copy, as the engine passes it on:
/// the copy by kind, member and the digest he answered for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DivergedOwnerAnswer {
    pub(crate) kind: VmOutboxKind,
    pub(crate) member: String,
    pub(crate) held: String,
    pub(crate) answer: DivergedAnswer,
}

/// What the guest carrier shares with its lifecycle endpoint: its members'
/// statuses as the carrier last published them, and the owner's answers
/// waiting for its next turn.
#[derive(Debug, Default)]
pub(super) struct MemberBoard {
    statuses: Vec<VmOutboxMemberStatus>,
    answers: Vec<DivergedOwnerAnswer>,
}

pub(super) type Board = Arc<Mutex<MemberBoard>>;

impl MemberBoard {
    /// Every status the carrier last published.
    pub(super) fn statuses(&self) -> Vec<VmOutboxMemberStatus> {
        self.statuses.clone()
    }

    /// Queues `answer` for the carrier's next turn when it names a diverged
    /// copy the board shows by its digest, or is a removal of a kept-aside
    /// copy it shows; else why not.
    pub(super) fn answer(&mut self, answer: DivergedOwnerAnswer) -> Result<(), String> {
        let removal = answer.answer == DivergedAnswer::Remove;
        let names = |kind: &VmOutboxKind, member: &String, held: &String| {
            *kind == answer.kind && *member == answer.member && *held == answer.held
        };
        let shown = self.statuses.iter().any(|status| match status {
            VmOutboxMemberStatus::DivergedUnagreed {
                kind, member, held, ..
            } => names(kind, member, held),
            VmOutboxMemberStatus::KeptAside {
                kind, member, held, ..
            } => removal && names(kind, member, held),
            VmOutboxMemberStatus::SourceDigestMismatch { .. } => false,
        });
        if !shown {
            return Err(
                "the carrier keeps no copy of that member with that digest for that answer".into(),
            );
        }
        self.answers.push(answer);
        Ok(())
    }
}

impl Carrier {
    /// On the guest: carries out the owner's answers waiting on the board,
    /// then publishes its members' statuses there. Nothing on the host.
    pub(super) fn member_turn(&mut self) {
        let Some(board) = self.board.clone() else {
            return;
        };
        let answers =
            std::mem::take(&mut board.lock().unwrap_or_else(PoisonError::into_inner).answers);
        for answer in answers {
            self.take_owner_answer(answer);
        }
        let statuses = self.member_statuses();
        board
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .statuses = statuses;
    }

    /// Every member's status worth an owner's look.
    fn member_statuses(&self) -> Vec<VmOutboxMemberStatus> {
        let mut statuses = Vec::new();
        for (kind, member, record) in self.store.records() {
            if let Some(diverged) = &record.diverged {
                statuses.push(VmOutboxMemberStatus::DivergedUnagreed {
                    kind,
                    member: member.to_owned(),
                    held_by: diverged.held_by,
                    held: diverged.held.blake3.clone(),
                    length: diverged.held.length,
                    retired: diverged.retired.clone(),
                    answer: diverged.answer,
                });
            }
            if let Some(SourceStatus::SourceDigestMismatch { recorded, read, .. }) = &record.source
            {
                statuses.push(VmOutboxMemberStatus::SourceDigestMismatch {
                    kind,
                    member: member.to_owned(),
                    recorded: recorded.clone(),
                    read: read.clone(),
                });
            }
            for entry in &record.aside {
                statuses.push(VmOutboxMemberStatus::KeptAside {
                    kind,
                    member: member.to_owned(),
                    held_by: entry.held_by,
                    held: entry.held.blake3.clone(),
                    length: entry.held.length,
                    aside: entry.aside.clone(),
                    kept_at_ms: entry.kept_at_ms,
                    removing: entry.removing,
                    failed: entry.failed.clone(),
                });
            }
        }
        statuses
    }

    /// Carries out one owner answer, under this end's gate; an answer for a
    /// copy no longer kept with that digest is dropped, as the copy changed
    /// or went since, but a removal of a copy kept aside with that digest
    /// removes it (FIX 11985). While this end stops, the answer waits for its
    /// next turn.
    fn take_owner_answer(&mut self, answer: DivergedOwnerAnswer) {
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        if *held == Mode::Draining {
            if let Some(board) = &self.board {
                board
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .answers
                    .push(answer);
            }
            return;
        }
        let (kind, member) = (answer.kind, answer.member.as_str());
        let mut record = self.store.get(kind, member);
        let Some(diverged) = record
            .diverged
            .clone()
            .filter(|diverged| diverged.held.blake3 == answer.held)
        else {
            if answer.answer == DivergedAnswer::Remove {
                self.remove_kept_aside(kind, member, &answer.held);
            }
            return;
        };
        let answered = Diverged {
            answer: Some(answer.answer),
            ..diverged.clone()
        };
        let own = diverged.held_by == self.side;
        record.diverged = match answer.answer {
            // The kept copy moves aside under its own name, out of the way
            // of the origin's next version (FIX 11736).
            DivergedAnswer::Keep if own => {
                match self.move_own_copy_aside(kind, member, &diverged.held.blake3) {
                    Ok(aside) => {
                        said_moved_aside(self.side, kind, member, aside.as_deref());
                        if let Some(aside) = aside {
                            record_kept_aside(&mut record, self.side, &diverged.held, aside);
                        }
                        record.notice = Some(answered);
                        None
                    }
                    Err(error) => {
                        let what = format!("its kept copy did not move aside: {error}");
                        self.say(kind, member, &what);
                        return;
                    }
                }
            }
            // The host moves its copy aside once told, and this end's
            // version it refused for that copy goes again.
            DivergedAnswer::Keep => {
                let aside = local::aside_name(member, &diverged.held.blake3);
                record_kept_aside(&mut record, diverged.held_by, &diverged.held, aside);
                record.refused = None;
                record.notice = Some(answered);
                None
            }
            DivergedAnswer::Remove if own => {
                match self.remove_own_copy(kind, member, &diverged.held.blake3) {
                    Ok(()) => {
                        record.notice = Some(answered);
                        None
                    }
                    Err(error) => {
                        self.say(
                            kind,
                            member,
                            &format!("its kept copy was not removed: {error}"),
                        );
                        return;
                    }
                }
            }
            DivergedAnswer::Remove => {
                // The other end's copy is retired as an ordinary change
                // naming its digest: it is the agreed version now.
                record.agreed = Some(diverged.held.clone());
                record.refused = None;
                Some(answered)
            }
        };
        tracing::info!(
            reason = "vm_outbox_diverged_answered",
            side = ?self.side,
            %kind,
            member,
            held = %answer.held,
            answer = ?answer.answer,
            "the owner answered a diverged outbox copy"
        );
        if let Err(error) = self.store.put(kind, member, record.clone()) {
            self.received_failed(kind, member, record, &error);
        }
        drop(held);
    }

    /// Removes this end's own copy of `kind`'s `member` while it still
    /// hashes to `blake3`; a copy that changed or went is left as it is.
    pub(super) fn remove_own_copy(
        &self,
        kind: VmOutboxKind,
        member: &str,
        blake3: &str,
    ) -> std::io::Result<()> {
        match self.own_copy_root(kind, member, blake3)? {
            Some(root) => local::remove(&root, kind, member),
            None => Ok(()),
        }
    }

    /// Moves this end's own copy of `kind`'s `member` aside under its side
    /// name while it still hashes to `blake3` (FIX 11736): the side name, or
    /// `None` when no copy is there now. A copy that changed is left as it
    /// is.
    fn move_own_copy_aside(
        &self,
        kind: VmOutboxKind,
        member: &str,
        blake3: &str,
    ) -> std::io::Result<Option<String>> {
        match self.own_copy_root(kind, member, blake3)? {
            Some(root) => local::move_aside(&root, member, blake3),
            None => Ok(None),
        }
    }

    /// This end's root for `kind` while its own copy of `member` is there
    /// and still hashes to `blake3`; `None` when no copy is there.
    fn own_copy_root(
        &self,
        kind: VmOutboxKind,
        member: &str,
        blake3: &str,
    ) -> std::io::Result<Option<File>> {
        let Some(root) = self.roots.open(kind)? else {
            return Err(std::io::Error::other(
                "this end has no root for the kind now",
            ));
        };
        let Some((file, _)) = local::open_member(&root, member, None)? else {
            return Ok(None);
        };
        if local::digest(&file)?.blake3 != blake3 {
            return Err(std::io::Error::other(
                "the copy changed since the owner answered",
            ));
        }
        Ok(Some(root))
    }

    /// On the guest: sends the host each owner answer to a diverged copy it
    /// is still to be told of (FIX 11736, FIX 11737), and returns those
    /// sent, for [`Self::divergence_notices_told`] once the turn's frames
    /// are flushed; then each removal of a host's kept-aside copy, until
    /// the host answers it (FIX 11985).
    pub(super) fn send_divergence_notices<S: Read + Write>(
        &self,
        link: &mut Link<S>,
    ) -> anyhow::Result<Vec<Notice>> {
        let notices: Vec<Notice> = self
            .store
            .records()
            .filter_map(|(kind, member, record)| {
                Some((kind, member.to_owned(), record.notice.clone()?))
            })
            .collect();
        for (kind, member, notice) in &notices {
            link.send(&VmOutboxFrame::DivergenceCleared {
                kind: *kind,
                member: member.clone(),
                held: notice.held.blake3.clone(),
                held_by: notice.held_by,
                action: VmOutboxNoticeAction::Answered,
            })?;
        }
        self.send_aside_removals(link)?;
        Ok(notices)
    }

    /// Forgets each notice in `told`, sent and flushed, under this end's
    /// gate; one answered again since stays to send. A record that does not
    /// write is kept to write again, as [`Self::received_failed`] keeps one.
    pub(super) fn divergence_notices_told(&mut self, told: Vec<Notice>) {
        if told.is_empty() {
            return;
        }
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        if *held == Mode::Draining {
            return;
        }
        for (kind, member, notice) in told {
            let mut record = self.store.get(kind, &member);
            if record.notice.as_ref() != Some(&notice) {
                continue;
            }
            record.notice = None;
            if let Err(error) = self.store.put(kind, &member, record.clone()) {
                self.received_failed(kind, &member, record, &error);
            }
        }
        drop(held);
    }

    /// On the host: takes the guest's notice that the owner answered the
    /// diverged copy of `kind`'s `member` hashing to `held`, which `held_by`
    /// keeps (FIX 11736, FIX 11737), under this end's gate, once this end's
    /// record keeps that copy. One this end holds, which the owner kept,
    /// moves aside under its own name, so the guest's next version lands;
    /// when it does not move, the keep stays on this end's record and the
    /// copy moves aside once it blocks the guest's next put (FIX 11986),
    /// and the guest is answered with the move's result (FIX 12010).
    /// The guest's copy is out of the member's way, so a refusal of this
    /// end's version for it no longer holds and the next scan offers that
    /// version again, as [`Self::reoffer`] does. A `remove_aside` notice
    /// deletes this end's kept-aside copy (FIX 11985).
    pub(super) fn take_divergence_cleared(&mut self, frame: VmOutboxFrame) {
        let VmOutboxFrame::DivergenceCleared {
            kind,
            member,
            held,
            held_by,
            action,
        } = frame
        else {
            return;
        };
        let member = member.as_str();
        let gate = Arc::clone(&self.gate);
        let mode = gate.hold();
        if *mode == Mode::Draining {
            return;
        }
        if action == VmOutboxNoticeAction::RemoveAside {
            self.remove_aside_for_guest(kind, member, &held);
            return;
        }
        let mut record = self.store.get(kind, member);
        let Some(diverged) = record
            .diverged
            .clone()
            .filter(|diverged| diverged.held_by == held_by && diverged.held.blake3 == held)
        else {
            return;
        };
        if held_by == self.side {
            match self.move_own_copy_aside(kind, member, &held) {
                Ok(aside) => {
                    said_moved_aside(self.side, kind, member, aside.as_deref());
                    if let Some(aside) = aside {
                        record_kept_aside(&mut record, self.side, &diverged.held, aside);
                    }
                    self.queue_aside_kept(kind, member, &held, None);
                }
                Err(error) => {
                    let what = format!("its kept copy did not move aside: {error}");
                    self.say(kind, member, &what);
                    let failed = vm_outbox_detail(&format!(
                        "the host's kept copy did not move aside: {error}"
                    ));
                    self.queue_aside_kept(kind, member, &held, Some(failed));
                    record.diverged = Some(Diverged {
                        answer: Some(DivergedAnswer::Keep),
                        ..diverged
                    });
                    if let Err(error) = self.store.put(kind, member, record.clone()) {
                        self.received_failed(kind, member, record, &error);
                    }
                    return;
                }
            }
        } else {
            record.refused = None;
        }
        record.diverged = None;
        self.settled(kind, member);
        if let Err(error) = self.store.put(kind, member, record.clone()) {
            self.received_failed(kind, member, record, &error);
        }
        drop(mode);
    }

    /// Says once that `transfer`'s member is kept as a copy the carrier
    /// never agreed on, as `diverged` records, for its owner to answer.
    pub(super) fn say_diverged(
        &self,
        transfer: &oneiron_vault_contract::vm_outbox::VmOutboxDescriptor,
        diverged: &Diverged,
    ) {
        tracing::warn!(
            reason = "vm_outbox_diverged_unagreed",
            side = ?self.side,
            kind = %transfer.kind,
            member = %transfer.member,
            held_by = ?diverged.held_by,
            held = %diverged.held.blake3,
            retired = ?diverged.retired,
            "the origin retired an outbox member's agreed version while a copy the carrier never \
             agreed on is kept; it stays until its owner answers remove or keep"
        );
    }
}

/// Says that `side`'s copy of `kind`'s `member` the owner kept moved aside to
/// `aside`, or was no longer at the member's name.
fn said_moved_aside(side: VmOutboxSide, kind: VmOutboxKind, member: &str, aside: Option<&str>) {
    tracing::info!(
        reason = "vm_outbox_diverged_moved_aside",
        ?side,
        %kind,
        member,
        aside = ?aside,
        "a diverged outbox copy the owner kept moved aside under its own name"
    );
}
