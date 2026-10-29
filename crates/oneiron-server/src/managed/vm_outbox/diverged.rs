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
//! records his answer and the copy stays; `remove` removes the guest's own
//! copy while it still hashes to the digest he answered, or, for the host's
//! copy, takes that copy as the agreed version, so the guest's next scan
//! retires it as an ordinary removal naming its digest (or replaces it with
//! the guest's own newer version). Nothing here removes a copy without his
//! answer.

use super::local;
use super::store::{Diverged, DivergedAnswer, SourceStatus};
use super::{Carrier, Mode};
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, PoisonError};

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
    /// copy the board shows by its digest; else why not.
    pub(super) fn answer(&mut self, answer: DivergedOwnerAnswer) -> Result<(), String> {
        let shown = self.statuses.iter().any(|status| {
            matches!(
                status,
                VmOutboxMemberStatus::DivergedUnagreed { kind, member, held, .. }
                    if *kind == answer.kind && *member == answer.member && *held == answer.held
            )
        });
        if !shown {
            return Err("the carrier keeps no diverged copy of that member with that digest".into());
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
        board.lock().unwrap_or_else(PoisonError::into_inner).statuses = statuses;
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
            if let Some(SourceStatus::SourceDigestMismatch { recorded, read, .. }) = &record.source {
                statuses.push(VmOutboxMemberStatus::SourceDigestMismatch {
                    kind,
                    member: member.to_owned(),
                    recorded: recorded.clone(),
                    read: read.clone(),
                });
            }
        }
        statuses
    }

    /// Carries out one owner answer, under this end's gate; an answer for a
    /// copy no longer kept with that digest is dropped, as the copy changed
    /// or went since. While this end stops, the answer waits for its next
    /// turn.
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
            return;
        };
        record.diverged = match answer.answer {
            DivergedAnswer::Keep => Some(Diverged {
                answer: Some(DivergedAnswer::Keep),
                ..diverged
            }),
            DivergedAnswer::Remove if diverged.held_by == self.side => {
                match self.remove_own_copy(kind, member, &diverged.held.blake3) {
                    Ok(()) => None,
                    Err(error) => {
                        self.say(kind, member, &format!("its kept copy was not removed: {error}"));
                        return;
                    }
                }
            }
            DivergedAnswer::Remove => {
                // The other end's copy is retired as an ordinary change
                // naming its digest: it is the agreed version now.
                record.agreed = Some(diverged.held.clone());
                record.refused = None;
                Some(Diverged {
                    answer: Some(DivergedAnswer::Remove),
                    ..diverged
                })
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
    fn remove_own_copy(
        &self,
        kind: VmOutboxKind,
        member: &str,
        blake3: &str,
    ) -> std::io::Result<()> {
        let Some(root) = self.roots.open(kind)? else {
            return Err(std::io::Error::other("this end has no root for the kind now"));
        };
        let Some((file, _)) = local::open_member(&root, member, None)? else {
            return Ok(());
        };
        if local::digest(&file)?.blake3 != blake3 {
            return Err(std::io::Error::other(
                "the copy changed since the owner answered",
            ));
        }
        drop(file);
        local::remove(&root, kind, member)
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
