//! A private thread's audience edits (FIX 5545). Owner ruling 2026-10-19:
//! "you can add and remove ppl anytime; when you add, you choose whether to
//! share the full thread or like start from now (they wont see prev
//! messages)".
//!
//! # One TURN per edit
//!
//! Each add or remove is a TURN of the thread. It carries the `room_thread`
//! binding a reply of that thread carries, and the door-owned
//! `room_thread_audience` key: the root, the person, who edited, the op and,
//! on an add, the history it shares. Its carrier is the thread's room, and an
//! `About` edge names the root, so a root's edits are its incoming `About`
//! edges. No side table holds them: an edit syncs as the TURN it is, and one
//! that has not arrived yet is not folded.
//!
//! # The fold
//!
//! The root's seed starts each member it names with the whole thread. The
//! edits then apply in TURN id order, the creation-time order every thread
//! projection sorts by: an add with full history gives the whole thread, an
//! add from now gives the turns from the edit's own on, and a remove ends
//! every read of that person's, old turns included. The latest edit per
//! person wins, and the audience may end empty, read by no one.

use super::audience::{ThreadBinding, thread_binding};
use super::*;
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeMap;

/// The door-owned TURN body key an audience edit rides under.
pub(crate) const ROOM_THREAD_AUDIENCE_KEY: &str = "room_thread_audience";

/// What an add shares with the person it adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreadAudienceHistory {
    /// The whole thread, its earlier turns included.
    Full,
    /// The turns from the add on; the earlier ones stay withheld.
    FromNow,
}

/// Whether an edit adds its person or removes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AudienceOp {
    Add,
    Remove,
}

/// One audience edit as its TURN carries it: the thread's root, the person
/// added or removed, the actor whose door wrote it and, on an add alone, the
/// history it shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AudienceEvent {
    pub(crate) root: EntityId,
    pub(crate) person: EntityId,
    pub(crate) by: EntityId,
    pub(crate) op: AudienceOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) history: Option<ThreadAudienceHistory>,
}

/// The audience edit a TURN's MessagePack `body` carries; `None` for a body
/// that carries none, or is no map. An edit that does not decode, an add
/// naming no history or a remove naming one is refused.
pub(crate) fn audience_event(body: &[u8]) -> Result<Option<AudienceEvent>> {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(None);
    };
    let mut values = fields
        .into_iter()
        .filter(|(key, _)| key.as_str() == Some(ROOM_THREAD_AUDIENCE_KEY));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if !bytes.is_empty() || values.next().is_some() {
        return Err(invalid());
    }
    let event: AudienceEvent = rmpv::ext::from_value(value).map_err(|_| invalid())?;
    if (event.op == AudienceOp::Add) != event.history.is_some() {
        return Err(invalid());
    }
    Ok(Some(event))
}

/// The body of the TURN recording `event` in the thread `binding` names: the
/// edit, and the binding every reply of that thread carries.
pub(super) fn event_body(binding: &ThreadBinding, event: &AudienceEvent) -> Result<Vec<u8>> {
    let fields = vec![(
        rmpv::Value::from(ROOM_THREAD_AUDIENCE_KEY),
        rmpv::ext::to_value(event).map_err(|_| invalid())?,
    )];
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields)).map_err(|_| invalid())?;
    super::audience::stamp_thread(&body, binding)
}

/// Why a put of the TURN `id` with `body`, over the stored `prior` body if
/// any, is refused for its audience edit, or `None` when it is not. An edit
/// rides a reply of the thread it names, never the root; and it is a birth
/// fact of its TURN, as the thread binding is, so a re-put keeps it whole.
pub(crate) fn audience_event_put_refusal(
    id: EntityId,
    prior: Option<&[u8]>,
    body: &[u8],
) -> Result<Option<&'static str>> {
    let event = audience_event(body)?;
    if let Some(event) = &event
        && thread_binding(body)?
            .is_none_or(|binding| binding.root != event.root || binding.root == id)
    {
        return Ok(Some("a thread audience edit rides a reply of its thread"));
    }
    if let Some(prior) = prior.filter(|prior| !prior.is_empty())
        && audience_event(prior)? != event
    {
        return Ok(Some("a TURN's thread audience edit is immutable"));
    }
    Ok(None)
}

/// A private thread's audience now: each member, and the first turn of the
/// thread it reads, `None` for the whole thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoldedAudience {
    root: EntityId,
    members: BTreeMap<EntityId, Option<EntityId>>,
}

impl FoldedAudience {
    /// Everyone in the audience now, whatever turn each reads from.
    pub(crate) fn current(&self) -> BTreeSet<EntityId> {
        self.members.keys().copied().collect()
    }

    /// The members who read `turn` of the thread: each whose first turn is
    /// at or before it. The root reads for every member now, one added from
    /// a later turn on as well.
    pub(crate) fn reading(&self, turn: EntityId) -> BTreeSet<EntityId> {
        self.members
            .iter()
            .filter(|(_, from)| turn == self.root || from.is_none_or(|from| from <= turn))
            .map(|(id, _)| *id)
            .collect()
    }
}

/// The audience of the private thread rooted at `root`, whose root names
/// `seed`: the seed with every edit of the root folded in, read on base
/// whatever view the root was read in (ARCH-0052: authority reads base).
/// Every edit is read, however many (rule 5); one whose TURN is not here
/// has not arrived yet.
pub(crate) fn fold_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    seed: &BTreeSet<EntityId>,
) -> Result<FoldedAudience> {
    let mut events = Vec::new();
    for row in crate::ports::EdgeStoreRead::port_edges(
        &vault.store,
        txn,
        &root,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::About),
        None,
    )? {
        let turn = row?.target;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &turn)?
        else {
            continue;
        };
        if let (Some(event), Some(binding)) = (audience_event(&body)?, thread_binding(&body)?)
            && event.root == root
            && binding.root == root
        {
            events.push((turn, event));
        }
    }
    events.sort_unstable_by_key(|(turn, _)| *turn);
    let mut members: BTreeMap<_, _> = seed.iter().map(|id| (*id, None)).collect();
    for (turn, event) in events {
        match (event.op, event.history) {
            (AudienceOp::Remove, _) => {
                members.remove(&event.person);
            }
            (AudienceOp::Add, Some(ThreadAudienceHistory::FromNow)) => {
                members.insert(event.person, Some(turn));
            }
            (AudienceOp::Add, _) => {
                members.insert(event.person, None);
            }
        }
    }
    Ok(FoldedAudience { root, members })
}
