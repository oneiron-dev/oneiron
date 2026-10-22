//! Room-work funding proved by join receipts.
//! Entry: `room_funding_in_txn`.
//! This module owns the funding result types; consent vocabulary stays in `join_consent`.

use super::*;

/// What funds an actor's work in a room or thread (FIX 805), as
/// [`room_funding_in_txn`] reads it: who the actor takes part as, and the
/// spend consent on the Ready join that covers the place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomFunding {
    /// The PERSON the actor takes part as: itself, or the PERSON a
    /// person-anchored agent speaks for. `None` for any other agent, or an
    /// actor that takes part in no room.
    pub person: Option<EntityId>,
    pub spend: RoomSpend,
}

/// The spend consent on the Ready join covering a room or thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomSpend {
    /// No Ready join was filed for the actor's subject in the place.
    NotJoined,
    /// A Ready join was filed there, but none covers the place against live
    /// facts now: it no longer holds, or a private thread's audience leaves
    /// the subject off.
    Lapsed,
    /// The covering join launches no paid work.
    NoPaidWork,
    /// The covering join's payer funds the tree `scope` spends under.
    Paid {
        payer: EntityId,
        scope: SpendScopeId,
    },
}

/// The spend consent on `actor`'s Ready join covering `room`, or its thread
/// `branch`, re-proved against live facts now. Its subject is the one
/// [`require_actor_join_in_txn`] resolves, and the receipt that covers the
/// place is the one OF-529's covering rule picks: the thread's own, else the
/// room's, and neither for a subject off a private thread's audience. Each
/// receipt is decided again as [`require_join_for_branch_in_txn`] decides
/// it. An actor that takes part in no room has no join.
pub fn room_funding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
) -> Result<RoomFunding> {
    let now = vault.store.clock.now_recorded_at();
    let subject = match super::rooms::join_subject_for_actor_in_txn(vault, txn, actor, now) {
        Ok(subject) => subject,
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => {
            return Ok(RoomFunding {
                person: None,
                spend: RoomSpend::NotJoined,
            });
        }
        Err(error) => return Err(error),
    };
    let person = match subject {
        JoinSubject::Person(person) => Some(person),
        JoinSubject::Agent(_) => None,
    };
    let spend = covering_spend_in_txn(vault, txn, room, branch, &subject, now)?;
    Ok(RoomFunding { person, spend })
}

/// The spend consent on `subject`'s Ready join covering `room`, or its
/// thread `branch`, by OF-529's covering rule, decided at `now`.
pub(super) fn covering_spend_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    now: u64,
) -> Result<RoomSpend> {
    let filed = |branch| filed_spend_in_txn(vault, txn, room, branch, subject, now);
    // A receipt filed for the place that does not cover it now.
    let mut lapsed = false;
    if let Some(thread) = branch {
        // A root not stored yet stands as the covering rule lets it.
        let hears = match super::thread_audience_allows_in(vault, txn, room, thread, subject.id()) {
            Ok(hears) => hears,
            Err(Error::EntityNotFound) => true,
            Err(error) => return Err(error),
        };
        match filed(branch)? {
            Filed::Holds(spend) if hears => return Ok(spend),
            Filed::Absent => {}
            Filed::Lapsed | Filed::Holds(_) => lapsed = true,
        }
        if !hears {
            lapsed |= !matches!(filed(None)?, Filed::Absent);
            return Ok(if lapsed {
                RoomSpend::Lapsed
            } else {
                RoomSpend::NotJoined
            });
        }
    }
    Ok(match filed(None)? {
        Filed::Holds(spend) => spend,
        Filed::Lapsed => RoomSpend::Lapsed,
        Filed::Absent if lapsed => RoomSpend::Lapsed,
        Filed::Absent => RoomSpend::NotJoined,
    })
}

/// A Ready join filed for one exact place, decided again now.
pub(super) enum Filed {
    /// None was filed there.
    Absent,
    /// One was, and it no longer holds against live facts.
    Lapsed,
    /// One was, and it holds: its spend consent.
    Holds(RoomSpend),
}

/// `subject`'s Ready join filed for exactly `room` and `branch`, decided
/// against live facts at `now` as [`require_join_for_branch_in_txn`]
/// decides it.
pub(super) fn filed_spend_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    now: u64,
) -> Result<Filed> {
    let Some(join) = READY.get(&vault.store, txn, &ready_key(room, subject, branch))? else {
        return Ok(Filed::Absent);
    };
    let receipt = JOINS
        .get(&vault.store, txn, &join)?
        .ok_or(Error::CorruptedIndex("ready join has no receipt"))?;
    if receipt.request.room != room
        || receipt.request.branch != branch
        || receipt.request.subject != *subject
    {
        return Err(Error::CorruptedIndex(
            "ready join names another room or subject",
        ));
    }
    let (decision, consents) = decide_with_in_txn(
        vault,
        txn,
        &receipt.request,
        receipt.principal_id(),
        &receipt.answers,
        now,
    )?;
    if decision != JoinDecision::Ready {
        return Ok(Filed::Lapsed);
    }
    Ok(match consents.spend {
        ConsentState::Granted(SpendConsent::Paid { payer, scope, .. }) => {
            Filed::Holds(RoomSpend::Paid { payer, scope })
        }
        ConsentState::Granted(SpendConsent::NoPaidWork) => Filed::Holds(RoomSpend::NoPaidWork),
        // A Ready join holds its spend consent.
        ConsentState::Missing(_) | ConsentState::Denied(_) => Filed::Lapsed,
    })
}

impl Vault {
    /// [`room_funding_in_txn`] in a read snapshot of its own.
    pub fn room_funding(
        &self,
        room: EntityId,
        branch: Option<EntityId>,
        actor: EntityId,
    ) -> Result<RoomFunding> {
        let txn = self.store.env.read_txn()?;
        room_funding_in_txn(self, &txn, room, branch, actor)
    }
}
