//! Asking to join a private thread (owner ruling 2026-10-20, FIX 6381,
//! 6384): the Owner and Admins may "ASK to join (the thread's members
//! decide)", and agents "never walk in; they may only request to join".
//!
//! # The request
//!
//! A request is a TURN of the thread's audience log
//! ([`super::audience_events`]), never a side table: its person is the
//! caller itself, as its credential binds it, never one it names. The
//! vault's Owner or an Admin, as a person, and any agent may ask, by the
//! thread's exact root; anyone else is refused as an unknown thread is. A
//! repeat while one is pending answers that one, and the answer says
//! nothing of the thread the caller does not already know. Every member
//! now is asked ([`super::audience_notices`]).
//!
//! # The answer
//!
//! Only a member in the thread's audience now lists its pending requests,
//! and any one of them approves or denies one, read again in the write: the
//! first answer committed settles it, and a later one answers how it
//! settled. An approval is an ordinary add from now on of the one who
//! asked, citing the request: it may land one off the room (the Owner, an
//! Admin or an agent), and grants no seat, Ready receipt or spend. A denial
//! is its own TURN and changes no one's place. The one who asked is told
//! either way, no member named.

use super::audience::{ThreadBinding, names_actor_in, root_audience_in, thread_binding};
use super::audience_doors::{put_audience_event_in, unknown_thread, vault_owner_or_admin_in};
use super::audience_events::{
    AudienceEvent, AudienceOp, AudiencePerson, FoldedAudience, JoinRequest, JoinSettlement,
    ThreadAudienceHistory, erased_from_room_in,
};
use super::audience_notices::{ThreadNotice, tell_requester, tell_thread_members};
use super::*;
use crate::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::RosterActor;

/// `vault.rooms.thread_join.request`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

/// `vault.rooms.thread_join.requests`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequestsRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

/// `vault.rooms.thread_join.approve` and `.deny`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinDecisionRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The request's TURN, 32-hex.
    pub request_ref: String,
}

/// How a request to join stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreadJoinRequestState {
    /// No member answered it yet.
    Pending,
    /// The one who asked was added, by an approval or otherwise.
    Approved,
    /// A member denied it.
    Denied,
}

/// One request to join a private thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequestView {
    /// The thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The request's TURN, 32-hex.
    pub request_ref: String,
    /// Who asked, 32-hex.
    pub requester_ref: String,
    /// When they asked, Unix seconds.
    pub at: u64,
    pub state: ThreadJoinRequestState,
    /// The TURN that settled it, 32-hex; absent while it is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
}

/// The refusal for an answer naming no request of the thread, or one whose
/// asker this vault erased.
fn unknown_request() -> MemoryError {
    MemoryError::not_found("no request to join this thread by that ref")
}

/// `request` of the thread rooted at `root` as its view reads it in `txn`;
/// `None` for a request whose asker was erased.
fn view_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    request: &JoinRequest,
) -> Result<Option<ThreadJoinRequestView>> {
    let Some(requester) = request.person.live() else {
        return Ok(None);
    };
    let at = vault
        .entity_header_in_txn(txn, &request.event)?
        .map_or(0, |header| header.occurred_start);
    let (state, decision_ref) = match request.settled {
        None => (ThreadJoinRequestState::Pending, None),
        Some((turn, JoinSettlement::Approved)) => {
            (ThreadJoinRequestState::Approved, Some(turn.to_hex()))
        }
        Some((turn, JoinSettlement::Denied)) => {
            (ThreadJoinRequestState::Denied, Some(turn.to_hex()))
        }
    };
    Ok(Some(ThreadJoinRequestView {
        thread_ref: root.to_hex(),
        request_ref: request.event.to_hex(),
        requester_ref: requester.to_hex(),
        at,
        state,
        decision_ref,
    }))
}

impl Memory<'_> {
    /// Asks to join a private thread (FIX 6381, 6384): one request TURN on
    /// its audience log for the caller itself, every member asked once it
    /// committed. The Owner or an Admin, as a person, or an agent may ask;
    /// a request already pending is answered again, unwritten.
    pub fn rooms_thread_join_request(
        &self,
        input: &ThreadJoinRequest,
    ) -> MemoryResult<ThreadJoinRequestView> {
        let root = EntityId::from_hex(&input.thread_ref)?;
        let actor = self.actor();
        let (view, asked) = self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            let (binding, folded) = self.join_thread_in(txn, root)?;
            if names_actor_in(vault, txn, &folded.current(), actor)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the caller is in this private thread's audience already: there is nothing to ask",
                    &["Read the thread; a request to join is for one outside it."],
                ));
            }
            // The verified class of this write's actor, never a caller's flag.
            let asks = match self.actor_class() {
                EdgeActorClass::Human => vault_owner_or_admin_in(vault, txn, actor)?,
                EdgeActorClass::Agent => true,
                _ => false,
            };
            // One this vault erased from the room is no one the thread could
            // take in.
            if !asks
                || !matches!(
                    live_entity_row_in_txn(&vault.store, txn, &actor)?.live_type(),
                    Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
                )
                || erased_from_room_in(vault, txn, binding.room, actor)?
            {
                return Err(unknown_thread());
            }
            if let Some(pending) = folded
                .pending()
                .find(|request| request.person == AudiencePerson::Live(actor))
            {
                let view = view_in(vault, txn, root, pending)?.ok_or_else(unknown_request)?;
                return Ok((view, None));
            }
            let event = put_audience_event_in(
                vault,
                txn,
                &binding,
                &AudienceEvent {
                    root,
                    person: AudiencePerson::Live(actor),
                    by: RosterActor::Actor(actor),
                    op: AudienceOp::RequestJoin,
                    history: None,
                    request: None,
                },
            )?;
            let at = vault
                .entity_header_in_txn(txn, &event)?
                .map_or(0, |header| header.occurred_start);
            let view = ThreadJoinRequestView {
                thread_ref: root.to_hex(),
                request_ref: event.to_hex(),
                requester_ref: actor.to_hex(),
                at,
                state: ThreadJoinRequestState::Pending,
                decision_ref: None,
            };
            Ok((view, Some(event)))
        })?;
        if let Some(event) = asked {
            tell_thread_members(
                self.vault(),
                root,
                actor,
                ThreadNotice::JoinRequested { event },
            );
        }
        Ok(view)
    }

    /// The requests to join a private thread pending now, in order, for a
    /// member in its audience now alone.
    pub fn rooms_thread_join_requests(
        &self,
        input: &ThreadJoinRequestsRequest,
    ) -> MemoryResult<Vec<ThreadJoinRequestView>> {
        let root = EntityId::from_hex(&input.thread_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let (_, folded) = self.join_thread_in(&txn, root)?;
        self.require_thread_member_in(&txn, &folded)?;
        let mut views = Vec::new();
        for request in folded.pending() {
            views.extend(view_in(vault, &txn, root, request)?);
        }
        Ok(views)
    }

    /// Approves a request to join a private thread: any one member in its
    /// audience now adds the one who asked from now on, citing the request,
    /// and they are told. A settled request answers how it settled.
    pub fn rooms_thread_join_approve(
        &self,
        input: &ThreadJoinDecisionRequest,
    ) -> MemoryResult<ThreadJoinRequestView> {
        self.answer_thread_join(input, JoinSettlement::Approved)
    }

    /// Denies a request to join a private thread: any one member in its
    /// audience now, and the one who asked is told. A settled request
    /// answers how it settled.
    pub fn rooms_thread_join_deny(
        &self,
        input: &ThreadJoinDecisionRequest,
    ) -> MemoryResult<ThreadJoinRequestView> {
        self.answer_thread_join(input, JoinSettlement::Denied)
    }

    /// The private thread rooted at `root` as a join door reads it in
    /// `txn`: a live TURN whose own binding names it, of the room a
    /// room-bound turn is bound to, with its audience folded. A public or
    /// unknown thread is refused as an unknown thread is.
    fn join_thread_in(
        &self,
        txn: &heed::RoTxn<'_>,
        root: EntityId,
    ) -> MemoryResult<(ThreadBinding, FoldedAudience)> {
        let vault = self.vault();
        let binding = match live_entity_row_in_txn(&vault.store, txn, &root)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } => thread_binding(&body)?.filter(|binding| binding.root == root),
            _ => None,
        }
        .ok_or_else(unknown_thread)?;
        if self
            .room_turn()
            .is_some_and(|turn| turn.room != binding.room)
        {
            return Err(unknown_thread());
        }
        match root_audience_in(vault, txn, binding.room, root) {
            Ok(Some(folded)) => Ok((binding, folded)),
            Ok(None) | Err(Error::EntityNotFound) => Err(unknown_thread()),
            Err(error) => Err(error.into()),
        }
    }

    /// Refuses anyone not in the audience of the thread `folded` now, a pen
    /// through its PERSON: the Owner or an Admin, who may know the thread
    /// exists, hear why; anyone else as an unknown thread.
    fn require_thread_member_in(
        &self,
        txn: &heed::RoTxn<'_>,
        folded: &FoldedAudience,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        if names_actor_in(vault, txn, &folded.current(), self.actor())? {
            return Ok(());
        }
        if vault_owner_or_admin_in(vault, txn, self.actor())? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only a member in a private thread's audience reads or answers its requests to join",
                &["Ask to join the thread, or walk in, first."],
            ));
        }
        Err(unknown_thread())
    }

    /// The write approve and deny both make, in one transaction: the
    /// thread, the caller's place in it now, the request, and the answer's
    /// TURN; the one who asked is told once it committed.
    fn answer_thread_join(
        &self,
        input: &ThreadJoinDecisionRequest,
        answer: JoinSettlement,
    ) -> MemoryResult<ThreadJoinRequestView> {
        let root = EntityId::from_hex(&input.thread_ref)?;
        let request = EntityId::from_hex(&input.request_ref)?;
        let actor = self.actor();
        let (view, told) = self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            let (binding, folded) = self.join_thread_in(txn, root)?;
            self.require_thread_member_in(txn, &folded)?;
            let asked = folded.request(request).ok_or_else(unknown_request)?;
            let requester = asked.person.live().ok_or_else(unknown_request)?;
            if asked.settled.is_some() {
                let view = view_in(vault, txn, root, asked)?.ok_or_else(unknown_request)?;
                return Ok((view, None));
            }
            let (op, history, state) = match answer {
                JoinSettlement::Approved => {
                    if !matches!(
                        live_entity_row_in_txn(&vault.store, txn, &requester)?.live_type(),
                        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
                    ) {
                        return Err(MemoryError::new(
                            MEMORY_CODE_INVALID_STATE,
                            "the one who asked to join is no longer a live PERSON or AGENT_DEF: there is no one to add",
                            &["Deny the request instead."],
                        ));
                    }
                    (
                        AudienceOp::Add,
                        Some(ThreadAudienceHistory::FromNow),
                        ThreadJoinRequestState::Approved,
                    )
                }
                JoinSettlement::Denied => {
                    (AudienceOp::DenyJoin, None, ThreadJoinRequestState::Denied)
                }
            };
            let event = put_audience_event_in(
                vault,
                txn,
                &binding,
                &AudienceEvent {
                    root,
                    person: AudiencePerson::Live(requester),
                    by: RosterActor::Actor(actor),
                    op,
                    history,
                    request: Some(request),
                },
            )?;
            let mut view = view_in(vault, txn, root, asked)?.ok_or_else(unknown_request)?;
            view.state = state;
            view.decision_ref = Some(event.to_hex());
            Ok((view, Some((event, requester))))
        })?;
        if let Some((event, requester)) = told {
            let notice = match answer {
                JoinSettlement::Approved => ThreadNotice::JoinApproved { event, request },
                JoinSettlement::Denied => ThreadNotice::JoinDenied { event, request },
            };
            tell_requester(self.vault(), root, actor, requester, notice);
        }
        Ok(view)
    }
}
