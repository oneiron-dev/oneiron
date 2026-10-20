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
//! that has not arrived yet is not folded. A privacy erase leaves the TURN
//! in place, its editor no one (FIX 5639, [`super::audience_erase`]), so it
//! folds as it did; no plain delete removes it while its root lives
//! ([`super::audience_edit_guard`]).
//!
//! # Erased people
//!
//! An actor's erase, and a room's erase of one of its people, take that
//! person out of every edit that names them (FIX 5640): as its editor, the
//! edit was made by no one; as the person it adds or removes, it names the
//! root's stand-in for them, an opaque digest of the root and that person,
//! one per root and person. No PERSON or AGENT_DEF stands behind a
//! stand-in, and anyone else an edit names stays named.
//!
//! # The fold
//!
//! The root's seed starts each member it names with the whole thread. The
//! edits then apply in TURN id order, the creation-time order every thread
//! projection sorts by: an add with full history gives the whole thread, an
//! add from now gives the turns from the edit's own on, and a remove ends
//! every read of that person's, old turns included. The latest edit per
//! person wins, and the audience may end empty, read by no one.
//!
//! A person the root's edits name by a stand-in folds under it: the seed's
//! place for them, and any live edit of theirs before the last edit naming
//! the stand-in, a copy from before their erase, so an add and its erased
//! remove still meet. A live edit after it names them anew. A stand-in is no
//! one's place: who is in the thread, who reads a turn, and which turns are
//! cut all skip it.
//!
//! # Walk-ins and opened history
//!
//! Owner ruling 2026-10-20 (FIX 6381, 6383): a self-add is a walk-in. It
//! enters its person from its own turn on, and leaves one already in the
//! audience as they are, so a self re-add never moves a cut either way. The
//! Owner's opened full history puts its person in the audience reading
//! every turn, and keeps them there until a remove: a later add or walk-in
//! does not cut them again. Each walk-in that entered and each opened
//! history stays on the thread as its own edit, the log its members read.

use super::audience::{ThreadBinding, thread_binding};
use super::*;
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::RosterActor;
use std::collections::BTreeMap;

/// The door-owned TURN body key an audience edit rides under.
pub(crate) const ROOM_THREAD_AUDIENCE_KEY: &str = "room_thread_audience";

/// The domain of an erased person's stand-in in a root's audience edits
/// (FIX 5640).
const AUDIENCE_PERSON_ERASED_DOMAIN: &str = "oneiron.rooms.thread-audience.person-erased.v1";

/// What a stand-in reads and writes as, before its digest's hex.
const ERASED_PERSON_PREFIX: &str = "erased:";

/// Whom an audience edit adds or removes (FIX 5640): a live id, or no one,
/// the stand-in the edit's root keeps for a person once they were erased.
/// It reads and writes as the id's hex, or as `erased:` and the digest's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AudiencePerson {
    Live(EntityId),
    Erased([u8; 16]),
}

impl AudiencePerson {
    /// The stand-in the root `root` keeps for `person` once they were
    /// erased: one per root and person, so an add and a remove of them still
    /// meet, and two people never share one.
    pub(crate) fn erased(root: EntityId, person: EntityId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUDIENCE_PERSON_ERASED_DOMAIN.as_bytes());
        hasher.update(&[0]);
        hasher.update(root.as_bytes());
        hasher.update(person.as_bytes());
        let mut digest = [0; 16];
        digest.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self::Erased(digest)
    }

    /// The person, while not erased.
    pub(crate) const fn live(&self) -> Option<EntityId> {
        match self {
            Self::Live(id) => Some(*id),
            Self::Erased(_) => None,
        }
    }

    /// This, or the stand-in the root `root` keeps for it once erased.
    pub(super) fn stand_in(self, root: EntityId) -> Self {
        self.live().map_or(self, |live| Self::erased(root, live))
    }
}

impl Serialize for AudiencePerson {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Live(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased(digest) => serializer.serialize_str(&format!(
                "{ERASED_PERSON_PREFIX}{}",
                crate::entity_id::bytes_to_hex_lower(digest)
            )),
        }
    }
}

impl<'de> Deserialize<'de> for AudiencePerson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let Some(hex) = value.strip_prefix(ERASED_PERSON_PREFIX) else {
            return EntityId::from_hex(&value)
                .map(Self::Live)
                .map_err(serde::de::Error::custom);
        };
        let invalid = || <D::Error as serde::de::Error>::custom("invalid erased person");
        // One spelling: thirty-two lowercase hex digits.
        if hex.len() != 32
            || !hex
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(invalid());
        }
        let mut digest = [0; 16];
        for (at, byte) in digest.iter_mut().enumerate() {
            let pair = hex.get(at * 2..at * 2 + 2).ok_or_else(invalid)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self::Erased(digest))
    }
}

/// What an add shares with the person it adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreadAudienceHistory {
    /// The whole thread, its earlier turns included.
    Full,
    /// The turns from the add on; the earlier ones stay withheld.
    FromNow,
}

/// Whether an edit adds its person, removes them, walks them in or opens
/// the thread's full history to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AudienceOp {
    Add,
    Remove,
    /// A self-add (FIX 6381): its person enters from this edit's turn on,
    /// or stays as they are when already in.
    WalkIn,
    /// The Owner's explicit act (FIX 6383): its person reads every turn of
    /// the thread until a remove.
    OpenFullHistory,
}

/// One audience edit as its TURN carries it: the thread's root, the person
/// added or removed (the root's stand-in for them once erased, FIX 5640),
/// the actor whose door wrote it (no one once a privacy erase took it, FIX
/// 5639) and, on an add alone, the history it shares: a walk-in and an
/// opened history name none, their op is their history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AudienceEvent {
    pub(crate) root: EntityId,
    pub(crate) person: AudiencePerson,
    pub(crate) by: RosterActor,
    pub(crate) op: AudienceOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) history: Option<ThreadAudienceHistory>,
}

impl AudienceEvent {
    /// This edit as a privacy erase of it leaves it: the same root, person,
    /// op and history, made by no one.
    pub(super) fn erased(self) -> Self {
        Self {
            by: RosterActor::Erased,
            ..self
        }
    }

    /// This edit with `actor` erased where it names them (FIX 5640): made by
    /// no one when they made it, and naming the root's stand-in for them
    /// when it adds or removes them. Anyone else it names stays named. `None`
    /// when it names `actor` in neither place.
    pub(super) fn erased_for(self, actor: EntityId) -> Option<Self> {
        let made = self.by.is(actor);
        let named = self.person == AudiencePerson::Live(actor);
        (made || named).then(|| Self {
            by: if made { RosterActor::Erased } else { self.by },
            person: if named {
                AudiencePerson::erased(self.root, actor)
            } else {
                self.person
            },
            ..self
        })
    }

    /// Whether `to` is this edit with none, some or all of whom it names
    /// erased, and nothing else changed. Never the other way: no erased
    /// slot names anyone again.
    fn erases_to(&self, to: &Self) -> bool {
        (self.root, self.op, self.history) == (to.root, to.op, to.history)
            && (self.by == to.by || to.by == RosterActor::Erased)
            && (self.person == to.person || self.person.stand_in(self.root) == to.person)
    }

    /// Whether this edit names someone as no one: its editor, or its person.
    fn names_erased(&self) -> bool {
        self.by == RosterActor::Erased || self.person.live().is_none()
    }
}

/// `event` with each actor it names that this vault erased named as no one
/// (FIX 5640): read by this vault's own hard-delete marker, as every carrier
/// copy is ([`crate::deletion::ACTOR_ERASE_CARRIER_SOURCE`]).
pub(super) fn erased_here_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut event: AudienceEvent,
) -> Result<AudienceEvent> {
    if let Some(by) = event.by.id()
        && vault.carrier_actor_erased_in_txn(txn, &by)?
    {
        event.by = RosterActor::Erased;
    }
    if let Some(person) = event.person.live()
        && vault.carrier_actor_erased_in_txn(txn, &person)?
    {
        event.person = AudiencePerson::erased(event.root, person);
    }
    Ok(event)
}

/// The audience edit the live TURN `id` carries, with its thread binding;
/// `None` for any other row, and for an edit that does not decode, which
/// no put admits.
pub(super) fn live_edit_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(ThreadBinding, AudienceEvent)>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, id)?
    else {
        return Ok(None);
    };
    let Some(event) = audience_event(&body).ok().flatten() else {
        return Ok(None);
    };
    Ok(thread_binding(&body)
        .ok()
        .flatten()
        .map(|binding| (binding, event)))
}

/// The audience edit a TURN's MessagePack `body` carries; `None` for a body
/// that carries none, or is no map. An edit that does not decode, an add
/// naming no history or any other edit naming one is refused.
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

/// Whether `body` is an erased audience edit's TURN body (FIX 5639, 5640):
/// its thread binding and its edit, naming someone as no one, and no other
/// byte.
pub(crate) fn audience_edit_is_erased(body: &[u8]) -> Result<bool> {
    let (Some(event), Some(binding)) = (audience_event(body)?, thread_binding(body)?) else {
        return Ok(false);
    };
    Ok(event.names_erased() && event_body(&binding, &event)? == body)
}

/// Whether `body` is the TURN body `prior` as a privacy erase leaves it
/// (FIX 5639, 5640): the same thread binding and edit, more of whom it names
/// erased or as much, in its erased form ([`audience_edit_is_erased`]).
/// The one change the DAG admits on an edit's pinned TURN.
pub(crate) fn audience_edit_erased_from(prior: &[u8], body: &[u8]) -> Result<bool> {
    let (Some(held), Some(binding)) = (audience_event(prior)?, thread_binding(prior)?) else {
        return Ok(false);
    };
    Ok(
        audience_event(body)?.is_some_and(|event| held.erases_to(&event))
            && thread_binding(body)?.as_ref() == Some(&binding)
            && audience_edit_is_erased(body)?,
    )
}

/// Why a put of the TURN `id` with `body`, over the stored `prior` body if
/// any, is refused for its audience edit, or `None` when it is not. An edit
/// rides a reply of the thread it names, never the root; and it is a birth
/// fact of its TURN, as the thread binding is, so a re-put keeps it whole,
/// but for a privacy erase of whom it names (FIX 5639, 5640).
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
    if let Some(prior) = prior.filter(|prior| !prior.is_empty()) {
        let held = audience_event(prior)?;
        let erased = held
            .zip(event)
            .is_some_and(|(held, event)| held.erases_to(&event));
        if held != event && !erased {
            return Ok(Some("a TURN's thread audience edit is immutable"));
        }
    }
    Ok(None)
}

/// A private thread's audience now: each member, and the first turn of the
/// thread it reads, `None` for the whole thread; a stand-in among them is
/// no one's place (FIX 5640).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoldedAudience {
    members: BTreeMap<AudiencePerson, Option<EntityId>>,
    /// The stand-ins the root's edits name: each person they forgot.
    forgotten: BTreeSet<AudiencePerson>,
    /// Each walk-in that entered its person and each opened history, by
    /// its edit's TURN, in order (FIX 6381, 6383).
    entries: Vec<(EntityId, AudienceOp, AudiencePerson)>,
}

impl FoldedAudience {
    /// Everyone in the audience now, whatever turn each reads from: who is
    /// in the thread (the CURRENT rule, [`super::audience`]).
    pub(crate) fn current(&self) -> BTreeSet<EntityId> {
        self.members
            .keys()
            .filter_map(AudiencePerson::live)
            .collect()
    }

    /// The members who read `turn` of the thread: each whose first turn is
    /// at or before it (the CONTENT rule). The root is a turn like any
    /// other, so one added from a later turn on does not read it (FIX 5545,
    /// Engine ruling 2026-10-19).
    pub(crate) fn reading(&self, turn: EntityId) -> BTreeSet<EntityId> {
        self.members
            .iter()
            .filter(|(_, from)| from.is_none_or(|from| from <= turn))
            .filter_map(|(person, _)| person.live())
            .collect()
    }

    /// Whether `turn` of the thread sits before some member's add, so the
    /// audience now is wider than the one that reads it: a place in the
    /// thread for every member, and a read for none it is withheld from.
    pub(crate) fn cuts(&self, turn: EntityId) -> bool {
        self.members
            .iter()
            .any(|(person, from)| person.live().is_some() && from.is_some_and(|from| from > turn))
    }

    /// What `person` reads of the thread now: the whole of it, or its turns
    /// from their add on; `None` while they are not in the audience.
    pub(crate) fn history_of(&self, person: EntityId) -> Option<ThreadAudienceHistory> {
        self.members
            .get(&AudiencePerson::Live(person))
            .map(|from| match from {
                None => ThreadAudienceHistory::Full,
                Some(_) => ThreadAudienceHistory::FromNow,
            })
    }

    /// Each walk-in that entered its person and each opened history, by its
    /// edit's TURN, in order (FIX 6381, 6383): a re-add that changed nothing
    /// is not among them. A person since erased is named by their stand-in.
    pub(crate) fn entries(&self) -> &[(EntityId, AudienceOp, AudiencePerson)] {
        &self.entries
    }
}

/// Whom a new remove of `person` from the thread rooted at `root`, whose
/// audience is `folded`, names (FIX 5640): the root's stand-in for them once
/// this vault erased them (its own hard-delete marker) or the root's edits
/// name that stand-in, so the remove folds with the edits before it and
/// names no erased person again; else them.
pub(super) fn removed_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    folded: &FoldedAudience,
    root: EntityId,
    person: EntityId,
) -> Result<AudiencePerson> {
    let stand_in = AudiencePerson::erased(root, person);
    Ok(
        if folded.forgotten.contains(&stand_in)
            || vault.carrier_actor_erased_in_txn(txn, &person)?
        {
            stand_in
        } else {
            AudiencePerson::Live(person)
        },
    )
}

/// The audience of the private thread rooted at `root`, whose root names
/// `seed`: the seed with every edit of the root folded in, read on base
/// whatever view the root was read in (ARCH-0052: authority reads base).
/// Every edit is read, however many (rule 5); one whose TURN is not here
/// has not arrived yet. A person the edits forgot folds under the root's
/// stand-in for them (module docs).
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
    // The last edit naming each stand-in, ids in order.
    let mut erased_until = BTreeMap::new();
    for (turn, event) in &events {
        if event.person.live().is_none() {
            erased_until.insert(event.person, *turn);
        }
    }
    // Whom the Owner opened the whole thread to, until a remove, and the
    // walk-ins and opened histories that the thread's log shows.
    let mut opened = BTreeSet::new();
    let mut entries = Vec::new();
    // The seed's place for a forgotten person, and a live edit of theirs
    // before the last one naming their stand-in, fold under the stand-in.
    let key = |person: AudiencePerson, at: Option<EntityId>| {
        if erased_until.is_empty() {
            return person;
        }
        let stand_in = person.stand_in(root);
        match erased_until.get(&stand_in) {
            Some(last) if at.is_none_or(|at| at < *last) => stand_in,
            _ => person,
        }
    };
    let mut members: BTreeMap<_, _> = seed
        .iter()
        .map(|id| (key(AudiencePerson::Live(*id), None), None))
        .collect();
    for (turn, event) in events {
        let person = key(event.person, Some(turn));
        match (event.op, event.history) {
            (AudienceOp::Remove, _) => {
                members.remove(&person);
                opened.remove(&person);
            }
            (AudienceOp::WalkIn, _) => {
                if let std::collections::btree_map::Entry::Vacant(entry) = members.entry(person) {
                    entry.insert(Some(turn));
                    entries.push((turn, AudienceOp::WalkIn, person));
                }
            }
            (AudienceOp::OpenFullHistory, _) => {
                members.insert(person, None);
                opened.insert(person);
                entries.push((turn, AudienceOp::OpenFullHistory, person));
            }
            (AudienceOp::Add, Some(ThreadAudienceHistory::FromNow)) => {
                members.insert(person, (!opened.contains(&person)).then_some(turn));
            }
            (AudienceOp::Add, _) => {
                members.insert(person, None);
            }
        }
    }
    Ok(FoldedAudience {
        members,
        forgotten: erased_until.into_keys().collect(),
        entries,
    })
}
