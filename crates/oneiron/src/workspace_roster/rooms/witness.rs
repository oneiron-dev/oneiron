//! Claim-before-speaking guard inside the existing witness transaction.
use super::audience::{
    ThreadBinding, names_actor_in, record_thread_admits_in, thread_audience_allows_in,
    thread_audience_now_in, thread_binding, validate_private_audience_in,
};
use super::participation::{
    addressable_agent_in_txn, admit_speech_in, agent_standing_in_txn, participant_in_txn,
    thread_root_in_txn,
};
use super::retry_claim::RETRY_CLAIM_RECEIPT_PREFIX;
use super::*;
use crate::conversation_dag::{ProvenRoomQuote, QuotedReply};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::{WitnessAuthor, WitnessTurn};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::JoinSubject;
use std::collections::BTreeMap;

/// What the room guard proved for one witness.
pub(crate) struct RoomWitness {
    /// The reply topology the witness mints into the TURN's first body and
    /// write when its messages quote (OF-460, FIX 2028): a project room's
    /// thread reply's, or an ordinary room's quoted turn's (FIX 2027), whose
    /// body also keeps its messages' quotes. A project room's trunk turn
    /// keeps its quotes in its room row alone, and its TURN is minted
    /// opaque: `None`, as for a stored TURN.
    pub(crate) quoted: Option<QuotedReply>,
    /// The thread binding a minted TURN is born with (FIX 2951): its root,
    /// room and trunk anchor and, on the root, the audience it names. A stored TURN already holds
    /// the same one. `None` for a trunk turn, or outside a project room.
    pub(crate) thread: Option<ThreadBinding>,
}

/// A Retry's leave to answer a project room's claimed turn again (FIX
/// 3149). It is proven inside the Retry's own transactions from its action
/// and the answering agent, never carried in a message's metadata.
/// RESPONSE keeps the claim's first answer as its slot: a regenerated
/// answer answers the same parent, in the same thread, naming the same
/// agents, and its `regenerates` lineage reaches that slot. It bypasses no
/// audience, participation, speaking role, write ceiling or claim check. On
/// a claim a Retry took, the participation gate takes the requester's press
/// as the agent's address on the parent (HOMERETRY-AUTHORITY = C).
pub(crate) struct RoomRegenerationPermit {
    /// The room row of the turn the Retry answers again.
    pub(crate) source: RoomTurn,
    /// The answer RESPONSE holds for the claimed parent.
    slot: EntityId,
    /// The claim the Retry takes on a parent that holds none
    /// (HOMERETRY-AUTHORITY = C), until its reply's write lands it.
    takes: Option<super::retry_claim::RetryClaim>,
    /// The parent whose claim this permit's write took.
    took: Option<EntityId>,
    /// The parent the requester's press addresses the agent on, when its
    /// claim is one a Retry takes or took (REVIEW-9153 round 2).
    pressed_parent: Option<EntityId>,
}

impl RoomRegenerationPermit {
    /// Proves `action`, a standing Retry, lets `actor` answer its source's
    /// claimed parent again: the source is `actor`'s room turn of the
    /// action's conversation holding its MESSAGE, `actor` and the requester
    /// both still read its thread, `actor` still holds the parent's claim,
    /// and the MESSAGE's `regenerates` lineage, each step `actor`'s live
    /// answer to the same parent in the same thread, reaches the slot. A
    /// parent that holds no claim is claimed by the Retry itself when the
    /// claim door's checks admit it (HOMERETRY-AUTHORITY = C): the source is
    /// then the slot, and [`Self::take_claim_in_txn`] writes the claim. On a
    /// parent whose claim a Retry took, a press admitted as the first one
    /// was addresses the agent there; without one, the agent answers again
    /// only where it is named or holds a task, as on any other claim.
    pub(crate) fn prove_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        action: &crate::conversation::TurnActionAttempt,
        actor: EntityId,
    ) -> Result<Self> {
        let old = turn_in(vault, txn, action.assistant_turn)?;
        if action.action != crate::conversation::TurnAction::Retry
            || !action.requester_live_in(vault, txn)
            || old.room_id != action.conversation.to_hex()
            || old.actor != actor.to_hex()
            || !old.message_ids.contains(&action.message.to_hex())
        {
            return Err(invalid());
        }
        for reader in [actor, action.actor] {
            if !record_thread_admits_in(vault, txn, action.assistant_turn, reader)? {
                return Err(invalid());
            }
        }
        let parent = EntityId::from_hex(old.reply_to.as_deref().ok_or_else(invalid)?)?;
        let parent_row = turn_in(vault, txn, parent)?;
        if parent_row.room_id != old.room_id {
            return Err(invalid());
        }
        let (slot, takes, pressed) = match CLAIMS.get(&vault.store, txn, &parent)? {
            Some(claim) => {
                if claim.room_id != old.room_id || claim.actor != old.actor {
                    return Err(invalid());
                }
                // The press only adds an address: a press that is not
                // admitted (an agent's, say) leaves the participation gate
                // to read a naming or a task, as for any other claim.
                let pressed = claim.receipt_ref.starts_with(RETRY_CLAIM_RECEIPT_PREFIX)
                    && super::retry_claim::admit_press_in(vault, txn, action, actor, &parent_row)
                        .is_ok();
                let slot = RESPONSE
                    .get(&vault.store, txn, &parent)?
                    .ok_or_else(invalid)?;
                (slot, None, pressed)
            }
            None => {
                let claim = super::retry_claim::RetryClaim::admit_in(
                    vault,
                    txn,
                    action,
                    actor,
                    parent,
                    &parent_row,
                )?;
                (claim.slot(), Some(claim), true)
            }
        };
        let edge = |message: &EntityId, kind: EdgeKind| {
            crate::memory::sole_edge_target(&vault.store, txn, message, kind, "message")
                .map_err(|_| invalid())
        };
        // The whole lineage is read, however long (rule 5); a cycle refuses.
        let mut count = crate::scan_check::ScanCount::start(
            &vault.store,
            txn,
            crate::scan_check::EngineScan::RoomRetryLineageRows,
            action.message.as_bytes(),
        )?;
        let mut cursor = action.message;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(cursor) {
                return Err(invalid());
            }
            count.row();
            if !live_entity_row_in_txn(&vault.store, txn, &cursor)?.is_live()
                || edge(&cursor, EdgeKind::AuthoredBy)? != Some(actor)
                || edge(&cursor, EdgeKind::BelongsTo)? != Some(action.conversation)
            {
                return Err(invalid());
            }
            let turn = edge(&cursor, EdgeKind::PartOf)?.ok_or_else(invalid)?;
            let row = turn_in(vault, txn, turn)?;
            if row.actor != old.actor
                || row.room_id != old.room_id
                || row.reply_to != old.reply_to
                || row.thread_of != old.thread_of
            {
                return Err(invalid());
            }
            if turn == slot {
                count.defer(&vault.store);
                return Ok(Self {
                    source: old,
                    slot,
                    takes,
                    took: None,
                    pressed_parent: pressed.then_some(parent),
                });
            }
            cursor = edge(&cursor, EdgeKind::Regenerates)?.ok_or_else(invalid)?;
        }
    }

    /// The parent this permit's Retry claims, while its claim is not yet
    /// written: both the agent and the requester must read it, as a
    /// claimant reads the turn it claims.
    pub(crate) fn claimed_parent(&self) -> Option<EntityId> {
        self.takes
            .as_ref()
            .map(super::retry_claim::RetryClaim::parent)
    }

    /// The parent the requester's press addresses the agent on, when the
    /// parent's claim is one a Retry takes or took: the participation gate
    /// takes it in place of a naming on that parent or a thread task
    /// (HOMERETRY-AUTHORITY = C; REVIEW-9153 round 2).
    pub(crate) const fn pressed_parent(&self) -> Option<EntityId> {
        self.pressed_parent
    }

    /// The parent whose claim this permit's write took, once
    /// [`Self::take_claim_in_txn`] wrote it: its live windows take the claim
    /// after the write commits (FIX 1794).
    pub(crate) const fn took_claim(&self) -> Option<EntityId> {
        self.took
    }

    /// Writes the claim this permit's Retry takes, if any, at `at` in `txn`,
    /// the write that lands its reply, before the room's witness admits the
    /// reply (HOMERETRY-AUTHORITY = C).
    pub(crate) fn take_claim_in_txn(
        &mut self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        at: u64,
    ) -> Result<()> {
        if let Some(claim) = self.takes.take() {
            claim.take_in_txn(vault, txn, at)?;
            self.took = Some(claim.parent());
        }
        Ok(())
    }

    /// Whether `actor`'s answer in `room` to `reply_to`, in `thread_of`,
    /// naming `mentions`, while RESPONSE holds `prior`, is the one this
    /// permit proved.
    fn admits(
        &self,
        room: EntityId,
        actor: EntityId,
        reply_to: Option<EntityId>,
        thread_of: Option<EntityId>,
        mentions: &BTreeSet<String>,
        prior: EntityId,
    ) -> bool {
        self.takes.is_none()
            && self.slot == prior
            && self.source.room_id == room.to_hex()
            && self.source.actor == actor.to_hex()
            && self.source.reply_to == reply_to.map(|id| id.to_hex())
            && self.source.thread_of == thread_of.map(|id| id.to_hex())
            && self.source.addressed_agents == *mentions
    }
}

// An erased actor's name, out of the room claims that record it (FIX 3520;
// HOMERETRY-CLAIM-AUTHOR = B, Engine 16 Nov 23:32): a claim's holder, and
// the person a Retry's claim names as its author, read as the erased
// identity once that actor is erased, in this vault's rows and in a carried
// copy (FIX 4870).

/// The person a Retry's claim receipt names as its author. `None` for any
/// other receipt, and for an author already erased.
pub(super) fn retry_claim_author(receipt_ref: &str) -> Option<EntityId> {
    EntityId::from_hex(receipt_ref.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?).ok()
}

/// Rewrites `claim` so that it names `actor` nowhere: as its holder, or as
/// the author of a Retry's claim, it names the erased identity instead.
/// Whether anything changed.
pub(super) fn erase_claim_actor(claim: &mut RoomClaimReceipt, actor: &EntityId) -> bool {
    let mut changed = false;
    if claim.actor == actor.to_hex() {
        claim.actor = ERASED_CALL_IDENTITY.to_owned();
        changed = true;
    }
    if retry_claim_author(&claim.receipt_ref) == Some(*actor) {
        claim.receipt_ref = format!("{RETRY_CLAIM_RECEIPT_PREFIX}{ERASED_CALL_IDENTITY}");
        changed = true;
    }
    changed
}

/// The receipt reference two copies of one claim carry, merged as a carried
/// holder is (REVIEW-4366 round 4): the same reference, or a Retry's claim
/// whose author one copy names and the other names as the erased identity,
/// which wins. `None` when they are not one receipt.
pub(super) fn merged_receipt_ref(held: &str, carried: &str) -> Option<String> {
    if held == carried {
        return Some(held.to_owned());
    }
    let author = crate::deletion::carrier_actor_merged(
        held.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?,
        carried.strip_prefix(RETRY_CLAIM_RECEIPT_PREFIX)?,
        ERASED_CALL_IDENTITY,
    )?;
    Some(format!("{RETRY_CLAIM_RECEIPT_PREFIX}{author}"))
}

/// The actor scrub `ROOMS_CLAIM` declares: every claim that names `actor`,
/// as its holder or as a Retry's author, names the erased identity instead.
/// A turn an erased holder claimed stays claimed, as a carried one does.
pub(crate) fn erase_claim_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in CLAIMS.iter_from(&vault.store, wtxn, &[])? {
        let (turn, mut claim) = row?;
        if erase_claim_actor(&mut claim, actor) {
            erased.push((turn, claim));
        }
    }
    for (turn, claim) in &erased {
        CLAIMS.put(&vault.store, wtxn, turn, claim)?;
    }
    Ok(())
}

/// Doors for `tests/room_home_retry_claim.rs` (HOMERETRY-CLAIM-AUTHOR = B):
/// a claim row planted and read raw, and a copy another machine of this
/// vault carried, merged as replica sync merges it. Compiled only under the
/// test-support cfg.
#[cfg(oneiron_test_support)]
pub(crate) mod claim_doors {
    use super::super::replica::{RoomSideRow, SideMerge, merge_replicated_side_row_in_txn};
    use super::*;

    /// Writes `claim` as its turn's claim row.
    pub(crate) fn put_claim(vault: &Vault, claim: &RoomClaimReceipt) -> Result<()> {
        let turn = EntityId::from_hex(&claim.turn_id)?;
        vault.with_write_txn_grouped(|txn| CLAIMS.put(&vault.store, txn, &turn, claim))
    }

    /// `turn`'s claim row, raw.
    pub(crate) fn claim(vault: &Vault, turn: EntityId) -> Result<Option<RoomClaimReceipt>> {
        let txn = vault.store.env.read_txn()?;
        CLAIMS.get(&vault.store, &txn, &turn)
    }

    /// Merges `claim` as a carried copy; the merge's outcome by name:
    /// `written`, `held`, `conflict` or `refused`.
    pub(crate) fn merge_carried_claim(
        vault: &Vault,
        claim: &RoomClaimReceipt,
    ) -> Result<&'static str> {
        let row = RoomSideRow::Claim {
            claim: claim.clone(),
        };
        let merged = vault
            .with_write_txn_grouped(|txn| merge_replicated_side_row_in_txn(vault, txn, &row))?;
        Ok(match merged {
            SideMerge::Written => "written",
            SideMerge::Held => "held",
            SideMerge::Conflict => "conflict",
            SideMerge::Refused(_) => "refused",
        })
    }
}

/// The guard every base witness passes in its write transaction: the
/// room's claim, participation and quote rules, and a thread's audience
/// (FIX 2951), checked before any message. `quote_key` is the speaker's
/// read key, taken before the writer opened, that a quote's selection is
/// read under (FIX 2027). `messages` are the input messages' ids, in order;
/// each quote is proven, pinned and kept against its message's id (FIX
/// 2028). `regeneration` is a Retry's proven leave to answer a claimed turn
/// again (FIX 3149); every other witness has none.
#[expect(
    clippy::too_many_arguments,
    reason = "binds the witness transaction to its resolved actor, container and message ids"
)]
pub(crate) fn admit_witness(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    room: EntityId,
    turn_id: EntityId,
    input: &WitnessTurn,
    messages: &[EntityId],
    quote_key: Option<&crate::claim::ScopedReadActorKey>,
    regeneration: Option<&RoomRegenerationPermit>,
) -> Result<RoomWitness> {
    // OF-530 ruling A: a room-wide offer card a new message names, or a
    // reply answers, is engaged in this write: here in an ordinary room, and
    // in a project room once its writer is admitted below.
    let writer = crate::WriteActor::new(actor, class);
    // A stored TURN keeps the thread it was born in (FIX 2951).
    let stored_body = match live_entity_row_in_txn(&vault.store, txn, &turn_id)? {
        LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_TURN,
            body,
        } => Some(body),
        _ => None,
    };
    let stored = stored_body.as_deref().map(thread_binding).transpose()?;
    // One adding to a stored TURN of a private thread, in any room, writes
    // from the audience that reads that turn, the root included (FIX 5653):
    // one added from a later turn on adds nothing to a turn before its add.
    // A turn this write mints writes from the audience now, below.
    if stored_body.is_some() && !record_thread_admits_in(vault, txn, turn_id, actor)? {
        return Err(invalid());
    }
    let quoting = input.messages.iter().any(|m| m.quote.is_some());
    if !super::super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)? {
        // An ordinary room's thread opens on its DAG, so a witness opens
        // none; one adding to a private thread's TURN met that turn's
        // audience above. A room regeneration answers a project room's claim.
        if input.thread_audience.is_some() || regeneration.is_some() {
            return Err(invalid());
        }
        // FIX 2027: a quote rides a turn in any room (ARCH-0006a:229), one
        // per message (FIX 2028). Its speaker takes part here, on a seat or a
        // live Ready join, and each selection is one the speaker's own read
        // admits under the room's ceiling, or the thread's a stored turn sits
        // in. An ordinary room's turn's first body keeps its messages'
        // quotes by citing MESSAGE, its room row none: they are born with
        // the TURN, which stays an opaque one answering its first quoted
        // message in that message's TURN, no thread, no `Parent`. A retried message carries
        // its own kept quote again; a stored TURN takes no new one.
        if quoting {
            let now = vault.store.clock.now_recorded_at();
            let subject = participant_in_txn(vault, txn, actor, now)?.ok_or_else(invalid)?;
            let members = vault.members_in_txn(txn, room)?;
            if !members.contains(&actor) && !members.contains(&subject.id()) {
                super::participation::joined(
                    crate::workspace_roster::require_join_for_branch_in_txn(
                        vault, txn, room, None, &subject, None,
                    ),
                )?
                .ok_or_else(invalid)?;
            }
        }
        let landing = stored
            .as_ref()
            .and_then(|held| held.as_ref())
            .map(|held| held.root);
        let kept = match &stored_body {
            Some(body) => crate::conversation_dag::witness_turn_quotes(body)?,
            None => BTreeMap::new(),
        };
        let mut quotes = BTreeMap::new();
        let mut target = None;
        for (message, id) in input.messages.iter().zip(messages) {
            let Some(quote) = message.quote else {
                if kept.contains_key(id) {
                    return Err(invalid());
                }
                continue;
            };
            quote_read_in_txn(vault, txn, room, landing, actor, quote, quote_key)?;
            let proven =
                ProvenRoomQuote::prove_ordinary_in_txn(vault, txn, room, writer, quote, *id)?;
            match kept.get(id) {
                Some(stored_quote) => proven.require_stored_in_txn(vault, txn, stored_quote)?,
                None if stored_body.is_some() => return Err(invalid()),
                None => {
                    proven.pin_in_txn(vault, txn)?;
                    target.get_or_insert((proven.message(), proven.target_turn()));
                    quotes.insert(*id, proven.metadata());
                }
            }
        }
        let quoted = match target {
            Some(target) => Some(QuotedReply::ordinary_in_txn(
                vault, txn, room, target, quotes,
            )?),
            None => None,
        };
        // THREAD-TASK-EVERY-ROOM: the turn keeps its room row in this write,
        // through the one writer every room's turn takes. A turn this write
        // mints is a trunk turn, as its DAG holds it; its quotes stay in its
        // first body alone. A stored turn's new messages join the row it
        // keeps.
        if stored_body.is_some() {
            for message in messages {
                super::turn_record::record_room_message_in_txn(vault, txn, turn_id, *message)?;
            }
        } else {
            let turn = RoomTurn {
                turn_id: turn_id.to_hex(),
                room_id: room.to_hex(),
                actor: actor.to_hex(),
                addressed_agents: BTreeSet::new(),
                message_ids: messages.iter().map(EntityId::to_hex).collect(),
                reply_to: None,
                thread_of: None,
                at: input.occurred_at,
                task_ids: Vec::new(),
                converted_project: None,
                quotes: BTreeMap::new(),
            };
            super::turn_record::record_room_turn_in_txn(
                vault,
                txn,
                None,
                &turn,
                None,
                true,
                None,
                vault.store.clock.now_recorded_at(),
            )?;
        }
        super::offer_activity::witness_in_txn(vault, txn, writer, room, input, messages)?;
        return Ok(RoomWitness {
            quoted,
            thread: None,
        });
    }
    // OF-529: an agent needs no seat: it stands on a Ready receipt, checked
    // once its thread is known. A person stands on its seat or a live Ready
    // join, or joins by this write, at the participation gate below (OF-417).
    let now = vault.store.clock.now_recorded_at();
    let speaker = participant_in_txn(vault, txn, actor, now)?;
    let current_room = match speaker {
        Some(_) => room_access_in(vault, txn, room)?,
        None => require_member(vault, txn, room, actor)?,
    };
    let mut mentions = BTreeSet::new();
    let mut reply_to = None;
    let mut thread_of = None;
    for message in &input.messages {
        let metadata = message.metadata.as_ref();
        for (field, out) in [
            ("room_reply_to", &mut reply_to),
            ("room_thread_of", &mut thread_of),
        ] {
            if let Some(value) = metadata.and_then(|m| m.get(field)) {
                let id = EntityId::from_hex(value.as_str().ok_or_else(invalid)?)?;
                if out.as_ref().is_some_and(|prior| *prior != id) {
                    return Err(invalid());
                }
                let parent = turn_in(vault, txn, id)?;
                if parent.room_id != room.to_hex() {
                    return Err(invalid());
                }
                *out = Some(id);
            }
        }
        if let Some(value) = metadata.and_then(|m| m.get("room_mentions")) {
            let handles = value.as_array().ok_or_else(invalid)?;
            // Every mention is validated and kept, however many (rule 5).
            let mut count = crate::scan_check::ScanCount::start(
                &vault.store,
                txn,
                crate::scan_check::EngineScan::RoomMentions,
                room.as_bytes(),
            )?;
            count.rows(handles.len());
            count.defer(&vault.store);
            for handle in handles {
                let handle = handle.as_str().ok_or_else(invalid)?;
                // Unknown mentions fail closed rather than opening the turn
                // to every companion in the room.
                let addressed = HANDLES
                    .get(&vault.store, txn, &(room, handle.to_owned()))?
                    .ok_or_else(invalid)?;
                // An agent may be named without a seat: naming enrolls no
                // one and grants nothing (OF-529).
                if !current_room.member_ids.contains(&addressed.to_hex())
                    && !addressable_agent_in_txn(vault, txn, addressed, now)?
                {
                    return Err(invalid());
                }
                mentions.insert(addressed.to_hex());
            }
        }
    }
    // A reply within an existing thread inherits its trunk anchor. This is
    // the same thread_of fact the room index uses to keep HEAD on the trunk;
    // neither an omitted metadata field nor a nested reply may advance HEAD.
    if let Some(parent) = reply_to {
        let mut count = crate::scan_check::ScanCount::start(
            &vault.store,
            txn,
            crate::scan_check::EngineScan::RoomLinkWalkRows,
            room.as_bytes(),
        )?;
        let mut cursor = Some(parent);
        let mut seen = BTreeSet::new();
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(invalid());
            }
            count.row();
            let ancestor = turn_in(vault, txn, id)?;
            if ancestor.room_id != room.to_hex() {
                return Err(invalid());
            }
            if let Some(anchor) = ancestor.thread_of {
                let anchor = EntityId::from_hex(&anchor)?;
                if thread_of.is_some_and(|explicit| explicit != anchor) {
                    return Err(invalid());
                }
                thread_of = Some(anchor);
                break;
            }
            cursor = ancestor
                .reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?;
        }
        count.defer(&vault.store);
    }
    // The participation gate (OF-529): the thread this turn lands in is its
    // root, and a person's turn is its join there.
    let branch = thread_root_in_txn(vault, txn, turn_id, reply_to, thread_of)?;
    // FIX 2951: the binding this turn is born with, or holds. A thread's
    // root names its audience once, at birth: a retry keeps it, and a set it
    // restates must be the same one. Every later turn names that root and
    // writes there only from its audience, which the participation gate
    // checks; the root's own later writes are checked here.
    let thread = match branch {
        None if input.thread_audience.is_some() => return Err(invalid()),
        None => None,
        Some(root) if root == turn_id => Some(match &stored {
            Some(Some(binding)) => {
                if binding.root != turn_id
                    || input
                        .thread_audience
                        .as_ref()
                        .is_some_and(|set| Some(set) != binding.audience.as_ref())
                    || !thread_audience_allows_in(vault, txn, room, turn_id, actor)?
                {
                    return Err(invalid());
                }
                binding.clone()
            }
            // A stored root born without one never takes an audience later.
            Some(None) if input.thread_audience.is_some() => return Err(invalid()),
            Some(None) | None => {
                if let Some(audience) = &input.thread_audience {
                    validate_private_audience_in(vault, txn, room, actor, audience)?;
                }
                ThreadBinding {
                    root: turn_id,
                    room,
                    anchor: thread_of,
                    audience: input.thread_audience.clone(),
                }
            }
        }),
        Some(root) => {
            let binding = ThreadBinding {
                root,
                room,
                anchor: thread_of,
                audience: None,
            };
            if input.thread_audience.is_some()
                || matches!(&stored, Some(Some(held)) if *held != binding)
            {
                return Err(invalid());
            }
            Some(binding)
        }
    };
    let admitted = super::admit_participation_in_txn(
        vault,
        txn,
        room,
        branch,
        writer,
        JoinCause::Wrote { turn: turn_id },
        reply_to,
        regeneration.and_then(RoomRegenerationPermit::pressed_parent),
        None,
        now,
    )?;
    // A private thread names only its audience now (CURRENT), a stored
    // root's edits folded in (FIX 5545): a mention hands the named agent the
    // turn. A pen is named there through its PERSON (FIX 3123).
    let private = match &thread {
        Some(binding) if binding.root == turn_id && stored.is_none() => binding.audience.clone(),
        Some(binding) => thread_audience_now_in(vault, txn, room, binding.root)?,
        None => None,
    };
    if let Some(audience) = &private {
        for named in &mentions {
            let named = EntityId::from_hex(named).map_err(|_| invalid())?;
            if !names_actor_in(vault, txn, audience, named)? {
                return Err(invalid());
            }
        }
    }
    let standing = match speaker {
        Some(JoinSubject::Agent(agent)) => Some(
            agent_standing_in_txn(vault, txn, room, branch, agent, None)?.ok_or_else(invalid)?,
        ),
        _ => None,
    };
    // An agent cannot masquerade as a user to evade a claim. The witness
    // author ceiling remains an additional, independent gate below this one.
    let is_response = class != EdgeActorClass::Human
        || input
            .messages
            .iter()
            .any(|m| m.author == WitnessAuthor::Companion);
    // An accepted offer card lands as the agent's own turn (OF-530): the
    // settlement that made its join Ready bound exactly this turn to the
    // offer and its thread in this write, in place of a claim on an
    // addressed turn. The speaking role and the author ceiling still decide.
    let accepted_offer = is_response
        && super::offers::accepts_offer_in_txn(vault, txn, room, branch, actor, turn_id)?;
    // A regeneration answers a claimed turn, nothing else (FIX 3149).
    if regeneration.is_some() && (!is_response || accepted_offer) {
        return Err(invalid());
    }
    if accepted_offer {
        admit_speech_in(vault, txn, room, actor, standing.as_ref())?;
    } else if is_response {
        // Only a speaker who speaks as a persona answers; the claim door
        // checks the same, and upkeep never holds one.
        admit_speech_in(vault, txn, room, actor, standing.as_ref())?;
        let parent = reply_to.ok_or_else(invalid)?;
        let claim = CLAIMS
            .get(&vault.store, txn, &parent)?
            .ok_or_else(invalid)?;
        if claim.actor != actor.to_hex() || claim.room_id != room.to_hex() {
            return Err(invalid());
        }
        // RESPONSE keeps the claim's first answer as its slot. A Retry's
        // answer leaves it there, linked to it by its `regenerates` lineage
        // (FIX 3149).
        let prior = RESPONSE.get(&vault.store, txn, &parent)?;
        if let Some(permit) = regeneration {
            if !prior.is_some_and(|prior| {
                permit.admits(room, actor, reply_to, thread_of, &mentions, prior)
            }) {
                return Err(invalid());
            }
        } else {
            if prior.is_some_and(|prior| prior != turn_id) {
                return Err(invalid());
            }
            RESPONSE.put(&vault.store, txn, &parent, &turn_id)?;
        }
    }
    // FIX 2027: each selection is one the speaker's own read admits under
    // the destination's ceiling: the thread's the turn lands in, or the
    // room's for a trunk turn and for a thread's root this write births,
    // which has no thread to read from yet. A stored or missing other root
    // keeps the fail-closed gates above.
    let read_branch = if branch == Some(turn_id) && stored.is_none() {
        None
    } else {
        branch
    };
    for quote in input.messages.iter().filter_map(|message| message.quote) {
        quote_read_in_txn(vault, txn, room, read_branch, actor, quote, quote_key)?;
    }
    // OF-460, FIX 2028: each message's quote is proven in this write against
    // the reply's own thread chain, never moved onto the quoted target, so a
    // thread reply may quote a trunk message, and that MESSAGE cites it. A
    // thread's root, which names its anchor and answers no turn, continues
    // the anchor. The claim parent above stays `reply_to`. Every quote is
    // kept in the turn's room row by citing MESSAGE, once: a retried message
    // carries its own again, a message stored without one takes none, and a
    // new message on a stored turn adds its own. A trunk turn's quotes read
    // from the trunk alone and its TURN stays opaque and unchained, so the
    // room's DAG keeps its one trunk root; a thread reply minted with quotes
    // is a DAG thread record answering its first quoted message in that
    // message's TURN (FIX 9771).
    let parent = match thread_of {
        Some(anchor) if quoting => Some(dag_parent_in_txn(
            vault,
            txn,
            anchor,
            reply_to.unwrap_or(anchor),
        )?),
        _ => None,
    };
    let old = TURNS.get(&vault.store, txn, &turn_id)?;
    let mut quotes = old
        .as_ref()
        .map_or_else(BTreeMap::new, |old| old.quotes.clone());
    let mut target = None;
    for (message, id) in input.messages.iter().zip(messages) {
        let kept = quotes.get(&id.to_hex()).copied();
        let Some(quote) = message.quote else {
            if kept.is_some() {
                return Err(invalid());
            }
            continue;
        };
        let proven = ProvenRoomQuote::prove_in_txn(vault, txn, room, parent, writer, quote, *id)?;
        target.get_or_insert((proven.message(), proven.target_turn()));
        match kept {
            Some(stored_quote) => proven.require_stored_in_txn(vault, txn, &stored_quote)?,
            None if vault.get_entity_type_in_txn(txn, id)?.is_some() => return Err(invalid()),
            None => {
                proven.pin_in_txn(vault, txn)?;
                quotes.insert(id.to_hex(), proven.metadata());
            }
        }
    }
    let quoted = match (parent, target) {
        (Some(parent), Some(target)) if stored.is_none() => Some(QuotedReply::thread_in_txn(
            vault, txn, room, parent, target,
        )?),
        _ => None,
    };
    let mut turn = RoomTurn {
        turn_id: turn_id.to_hex(),
        room_id: room.to_hex(),
        actor: actor.to_hex(),
        addressed_agents: mentions,
        message_ids: messages.iter().map(EntityId::to_hex).collect(),
        reply_to: reply_to.map(|id| id.to_hex()),
        thread_of: thread_of.map(|id| id.to_hex()),
        at: input.occurred_at,
        task_ids: Vec::new(),
        converted_project: None,
        quotes,
    };
    // FIX 15647: only the write that mints the turn's row stages its wakes;
    // one adding to a stored turn wakes no one again.
    let minted = old.is_none();
    if let Some(old) = old {
        if old.actor != turn.actor
            || old.room_id != turn.room_id
            || old.addressed_agents != turn.addressed_agents
            || old.reply_to != turn.reply_to
            || old.thread_of != turn.thread_of
        {
            return Err(invalid());
        }
        turn.at = old.at;
        turn.task_ids = old.task_ids;
        turn.converted_project = old.converted_project;
        let mut all = old.message_ids;
        for id in &turn.message_ids {
            if !all.contains(id) {
                all.push(id.clone());
            }
        }
        turn.message_ids = all;
    }
    super::turn_record::record_room_turn_in_txn(
        vault,
        txn,
        branch,
        &turn,
        Some(&admitted),
        minted,
        private.as_ref(),
        now,
    )?;
    super::offer_activity::witness_in_txn(vault, txn, writer, room, input, messages)?;
    Ok(RoomWitness { quoted, thread })
}

/// The read a quote's selection passes in the witness's own write snapshot
/// (FIX 2027): `key`, the speaker's read key taken before the writer opened,
/// read under the ceiling the destination puts on `actor` now, the room's
/// or, for a turn landing in thread `branch`, that thread's. A key a host
/// bound to a room turn reads only inside that room, its ceiling narrowed by
/// the destination's. Joining a room is never a widen: the room Scope, its
/// audience and peers, and the key's own grants all bind. Beside it, FIX
/// 3127: a private thread's MESSAGE is quoted only inside that thread.
fn quote_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
    quote: crate::conversation_dag::QuoteSpan,
    key: Option<&crate::claim::ScopedReadActorKey>,
) -> Result<()> {
    let key = key.ok_or_else(invalid)?;
    if key.room_turn().is_some_and(|held| held.room != room) {
        return Err(invalid());
    }
    let now = match branch {
        Some(thread) => crate::context_board::thread_ceiling_in(vault, txn, room, thread, actor)?,
        None => crate::context_board::room_ceiling_in(vault, txn, room, actor)?,
    }
    .ok_or_else(invalid)?;
    let mut ceiling = key
        .room_turn()
        .map_or_else(|| now.clone(), |held| held.narrowed_by(&now));
    // The quoted words reach the roster: the read is held (FIX 5636).
    ceiling.personal = false;
    let lane = vault
        .scoped_read(key.clone().in_room_turn(ceiling))
        .with_claim_status(crate::claim::ClaimReadStatus::Recorded);
    if !lane
        .entities_readable_in_txn(txn, &[quote.message])?
        .into_iter()
        .all(|readable| readable)
    {
        return Err(invalid());
    }
    crate::conversation_dag::require_quote_landing_in_txn(vault, txn, room, quote.message, branch)
}

/// The record a quoted thread reply's DAG chain continues: the nearest turn
/// up its room reply chain that the DAG holds as a thread record, or the
/// thread's trunk `anchor`. Unquoted replies carry no DAG chain, so the
/// quoted ones chain onto each other, and never onto the quoted target.
fn dag_parent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    anchor: EntityId,
    reply_to: EntityId,
) -> Result<EntityId> {
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::RoomLinkWalkRows,
        anchor.as_bytes(),
    )?;
    let mut cursor = reply_to;
    let mut seen = BTreeSet::new();
    while cursor != anchor
        && !crate::conversation_dag::is_thread_record(&vault.store, txn, &cursor)?
    {
        if !seen.insert(cursor) {
            return Err(invalid());
        }
        count.row();
        match turn_in(vault, txn, cursor)?.reply_to {
            Some(parent) => cursor = EntityId::from_hex(&parent)?,
            None => {
                count.defer(&vault.store);
                return Ok(anchor);
            }
        }
    }
    count.defer(&vault.store);
    Ok(cursor)
}

/// Erasing `actor` from the room turn rows (FIX 6543): each turn row it
/// spoke or edited an audience in keeps its links, time, messages, tasks,
/// quotes and history, and names no one as its actor, in the erased form
/// the roster rows write ([`crate::receipt::ERASED_CALL_IDENTITY`]), as its
/// TURN body's editor already does (FIX 5639). One-way, in the erase's own
/// transaction; every turn row is read, however many (rule 5). An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a turn row that cannot be read.
pub(crate) fn erase_turn_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::workspace_roster::join_receipt::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let named = actor.to_hex();
    let mut erased = Vec::new();
    for row in TURNS.iter_from(&vault.store, wtxn, &[])? {
        let (id, mut turn) = row?;
        if turn.actor == named {
            turn.actor = crate::receipt::ERASED_CALL_IDENTITY.to_owned();
            erased.push((id, turn));
        }
    }
    for (id, turn) in &erased {
        TURNS.put(&vault.store, wtxn, id, turn)?;
    }
    Ok(())
}
