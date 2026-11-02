//! A taken set's check against this end's own versions before it is
//! published, and the copy this end keeps, or learns the other end keeps,
//! when a member's origin retires the agreed version while the end that
//! does not originate it holds a copy the carrier never agreed on
//! (FIX 6686, FIX 11074). The kept copy is never removed by the carrier: only
//! its owner's answer removes it ([`super::super::diverged`]). One he kept
//! that did not move aside then moves aside once it blocks its origin's put
//! (FIX 11986).

use super::{Plan, Taken};
use crate::managed::vm_outbox::Carrier;
use crate::managed::vm_outbox::local;
use crate::managed::vm_outbox::store::{Diverged, MemberRecord, Version};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxDescriptor, VmOutboxOperation, VmOutboxOutcome, VmOutboxRefusal,
};
use std::fs::File;

impl Carrier {
    /// Per transfer, a refusal when this end holds a version of its member
    /// the transfer does not name and the carrier never agreed on. A
    /// retirement by the member's origin is no such refusal: its plan turns
    /// to [`Plan::Keep`], so it is taken for the agreed version and this
    /// end's copy is kept, and it holds back none of its set. A copy the
    /// owner kept that did not move aside moves aside before a put it
    /// blocks ([`Carrier::move_kept_copy`]).
    pub(super) fn check_local(
        &mut self,
        root: &File,
        taken: &mut [Taken],
    ) -> Vec<Option<VmOutboxOutcome>> {
        taken
            .iter_mut()
            .map(|item| {
                if matches!(item.plan, Plan::Answer(_)) {
                    return None;
                }
                let transfer = &item.descriptor;
                let record = self.store.get(transfer.kind, &transfer.member);
                let held = match local::open_member(root, &transfer.member, None) {
                    Ok(Some((file, stamp))) => match &record.cached {
                        Some(cached) if cached.stamp == stamp => Some(cached.version.clone()),
                        _ => local::digest(&file).ok(),
                    },
                    _ => return None,
                }?;
                let known = Some(&held.blake3) == transfer.expected_digest.as_ref()
                    || record
                        .agreed
                        .as_ref()
                        .is_some_and(|agreed| agreed.blake3 == held.blake3)
                    || (transfer.operation == VmOutboxOperation::Put
                        && held.blake3 == transfer.blake3);
                if known {
                    return None;
                }
                let retired_at_origin = matches!(item.plan, Plan::Remove)
                    && item
                        .member
                        .as_ref()
                        .is_some_and(|member| member.origin == self.side.peer());
                if retired_at_origin {
                    item.plan = Plan::Keep(held);
                    return None;
                }
                if transfer.operation == VmOutboxOperation::Put
                    && let Some(outcome) = self.move_kept_copy(root, transfer, &record, &held)
                {
                    return outcome;
                }
                Some(VmOutboxOutcome::refused(
                    VmOutboxRefusal::ExpectedDigestMismatch,
                    "this end holds a version of the member the transfer does not name",
                ))
            })
            .collect()
    }

    /// The copy `held` this end keeps as it takes `transfer`, its origin's
    /// retirement of the agreed version, recorded for its owner's answer.
    pub(super) fn kept(&self, transfer: &VmOutboxDescriptor, held: Version) -> Diverged {
        let diverged = Diverged {
            held_by: self.side,
            held,
            retired: transfer.expected_digest.clone(),
            answer: None,
        };
        self.say_diverged(transfer, &diverged);
        diverged
    }

    /// The answer `transfer`, taken and recorded as `record`, gets, the
    /// first time or as a replay: the copy this end kept as it took its
    /// origin's retirement, or durable.
    pub(super) fn taken_answer(
        &self,
        transfer: &VmOutboxDescriptor,
        record: &MemberRecord,
    ) -> VmOutboxOutcome {
        match &record.diverged {
            Some(diverged)
                if diverged.held_by == self.side
                    && transfer.operation == VmOutboxOperation::Remove =>
            {
                VmOutboxOutcome::DivergedUnagreed {
                    held: diverged.held.blake3.clone(),
                    length: diverged.held.length,
                }
            }
            _ => VmOutboxOutcome::Durable,
        }
    }

    /// Takes the other end's answer that it took `transfer`, this end's
    /// retirement of `record`'s member, for the agreed version and keeps
    /// its own copy `held`: the retirement stands here, nothing of it is
    /// sent again, and the copy is recorded for its owner's answer, which
    /// this end's status read shows.
    pub(super) fn peer_kept(
        &mut self,
        record: &mut MemberRecord,
        transfer: &VmOutboxDescriptor,
        held: Version,
    ) {
        record.revision = record.revision.max(transfer.revision);
        record.agreed = None;
        record.pending = None;
        record.refused = None;
        let diverged = Diverged {
            held_by: self.side.peer(),
            held,
            retired: transfer.expected_digest.clone(),
            answer: None,
        };
        self.settled(transfer.kind, &transfer.member);
        self.say_diverged(transfer, &diverged);
        record.diverged = Some(diverged);
    }
}
