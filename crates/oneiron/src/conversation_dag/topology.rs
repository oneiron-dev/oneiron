//! Shared DAG shape, session placement, and prospective Parent validation.

use super::graph::{self, invalid};
#[cfg(feature = "sync")]
use super::graph::{HEAD, MIGRATED, key};
use crate::EntityId;
use crate::edge::EdgeKind;
#[cfg(feature = "sync")]
use crate::error::RecordError;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordKind {
    Record,
    Thread,
}

impl RecordKind {
    pub(crate) fn from_thread(thread: bool) -> Self {
        if thread { Self::Thread } else { Self::Record }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Thread => "thread",
        }
    }
}

pub(crate) fn record_kind(body: &[u8]) -> Result<Option<RecordKind>> {
    // The typed DAG marker and its addressing carrier are one admission
    // unit. Every topology reader must see the same refusal as entity put.
    Ok(
        super::admission::addressing(body)?.map(|(kind, _)| match kind {
            "record" => RecordKind::Record,
            "thread" => RecordKind::Thread,
            _ => unreachable!("addressing decoder admits only typed DAG kinds"),
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionPlacement {
    Ordinary { session: EntityId },
    Spawned { session: EntityId, anchor: EntityId },
}
impl SessionPlacement {
    pub(crate) fn session(self) -> EntityId {
        match self {
            Self::Ordinary { session } | Self::Spawned { session, .. } => session,
        }
    }
    pub(crate) fn anchor(self) -> Option<EntityId> {
        match self {
            Self::Ordinary { .. } => None,
            Self::Spawned { anchor, .. } => Some(anchor),
        }
    }
}

/// One fact whose arrival can change a deferred Parent's verdict.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Dependency {
    Entity(EntityId),
    ConversationMembership(EntityId),
    SessionAnchor(EntityId),
    #[cfg(feature = "sync")]
    ParentOf(EntityId),
}

#[cfg(feature = "sync")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NonEmptyDependencies {
    pub(crate) first: Dependency,
    pub(crate) rest: Vec<Dependency>,
}
#[cfg(feature = "sync")]
impl NonEmptyDependencies {
    fn one(first: Dependency) -> Self {
        Self {
            first,
            rest: Vec::new(),
        }
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = Dependency> + '_ {
        std::iter::once(self.first).chain(self.rest.iter().copied())
    }
}

#[derive(Debug)]
pub(crate) struct DagRejection(pub(crate) &'static str);
impl DagRejection {
    pub(crate) fn into_error(self) -> Error {
        invalid(self.0)
    }
}

/// Permission to apply exactly this Parent in the transaction whose facts
/// were checked. Not Clone/Copy; no reusable permission survives the txn.
#[cfg(feature = "sync")]
#[derive(Debug)]
pub(crate) struct ValidatedParent {
    pub(crate) source: EntityId,
    pub(crate) target: EntityId,
}

#[cfg(feature = "sync")]
#[derive(Debug)]
pub(crate) enum ParentAdmission {
    Ready(ValidatedParent),
    Wait(NonEmptyDependencies),
    Reject(DagRejection),
}

pub(crate) enum Fact<T> {
    Known(T),
    Wait(Dependency),
    Reject(DagRejection),
}
fn reject<T>(reason: &'static str) -> Fact<T> {
    Fact::Reject(DagRejection(reason))
}

fn owner(store: &Store, txn: &heed::RoTxn<'_>, turn: EntityId) -> Result<Fact<EntityId>> {
    match live_entity_row_in_txn(store, txn, &turn)? {
        LiveEntityRow::Absent => return Ok(Fact::Wait(Dependency::Entity(turn))),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            ..
        } => {}
        LiveEntityRow::DeletedShell => return Ok(reject("received Parent touches a deleted TURN")),
        _ => return Ok(reject("received Parent needs TURN endpoints")),
    }
    let owners = graph::edge_ids(store, txn, &turn, EdgeKind::ChildOf, false, 2)?;
    let Some(&conversation) = owners.first() else {
        return Ok(Fact::Wait(Dependency::ConversationMembership(turn)));
    };
    if owners.len() != 1 {
        return Ok(reject("received Parent has multiple conversations"));
    }
    match live_entity_row_in_txn(store, txn, &conversation)? {
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            Ok(Fact::Wait(Dependency::Entity(conversation)))
        }
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        } => Ok(Fact::Known(conversation)),
        _ => Ok(reject("received Parent has a non-conversation owner")),
    }
}

/// Strict writer and reader can turn Wait into a typed refusal; receive keeps
/// the exact dependency. A declared anchor without SpawnedBy is never ordinary.
pub(crate) fn classify_session(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: EntityId,
    conversation: EntityId,
) -> Result<Fact<SessionPlacement>> {
    let body = match live_entity_row_in_txn(store, txn, &session)? {
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(Fact::Wait(Dependency::Entity(session)));
        }
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_SESSION,
            body,
        } => body,
        _ => return Ok(reject("received Parent names a non-session")),
    };
    let declaration = match rmpv::decode::read_value(&mut body.as_slice()) {
        Ok(rmpv::Value::Map(fields)) => {
            let mut anchors = fields
                .iter()
                .filter(|(key, _)| key.as_str() == Some("dag_spawning_turn"));
            let anchor = if let Some((_, value)) = anchors.next() {
                let Some(text) = value.as_str() else {
                    return Ok(reject("invalid sub-session anchor"));
                };
                let Ok(id) = EntityId::from_hex(text) else {
                    return Ok(reject("invalid sub-session anchor"));
                };
                if id.to_hex() != text {
                    return Ok(reject("noncanonical sub-session anchor"));
                }
                Some(id)
            } else {
                None
            };
            if anchors.next().is_some() {
                return Ok(reject("duplicate sub-session anchor"));
            }
            anchor
        }
        _ => None,
    };
    // HardErase removes an anchor TURN's incident SpawnedBy edge. Only the
    // content-free pin captured from that previously validated topology may
    // restore its placement; a merely absent edge never invents an anchor.
    let spawned = super::redacted::spawned_by(store, txn, &session)?
        .into_iter()
        .collect::<Vec<_>>();
    match (declaration, spawned.as_slice()) {
        (None, []) => Ok(Fact::Known(SessionPlacement::Ordinary { session })),
        (Some(_), []) => Ok(Fact::Wait(Dependency::SessionAnchor(session))),
        (declared, [anchor]) if declared.is_none_or(|expected| expected == *anchor) => {
            let anchor_owner = match live_entity_row_in_txn(store, txn, anchor)? {
                LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                    match super::redacted::read(store, txn, anchor)? {
                        Some(pin) => Fact::Known(pin.room),
                        None => owner(store, txn, *anchor)?,
                    }
                }
                _ => owner(store, txn, *anchor)?,
            };
            match anchor_owner {
                Fact::Known(actual) if actual == conversation => {
                    Ok(Fact::Known(SessionPlacement::Spawned {
                        session,
                        anchor: *anchor,
                    }))
                }
                Fact::Known(_) => Ok(reject("received session anchor is outside conversation")),
                Fact::Wait(dep) => Ok(Fact::Wait(dep)),
                Fact::Reject(reason) => Ok(Fact::Reject(reason)),
            }
        }
        _ => Ok(reject("received session anchor disagrees with SpawnedBy")),
    }
}

/// Shared local/received rule: ordinary containment is not a spawned scope.
pub(crate) fn parent_boundary(
    source: Option<SessionPlacement>,
    target: Option<SessionPlacement>,
    target_id: EntityId,
) -> std::result::Result<Option<EntityId>, DagRejection> {
    let anchor = source.and_then(SessionPlacement::anchor);
    if let Some(anchor) = anchor
        && target_id != anchor
        && target.map(SessionPlacement::session) != source.map(SessionPlacement::session)
    {
        return Err(DagRejection("received Parent crosses sub-session boundary"));
    }
    if Some(target_id) != anchor
        && let Some(SessionPlacement::Spawned { session, .. }) = target
        && source.map(SessionPlacement::session) != Some(session)
    {
        return Err(DagRejection("received Parent enters another sub-session"));
    }
    Ok(anchor)
}

#[cfg(feature = "sync")]
fn remote_error(error: Error) -> Result<ParentAdmission> {
    match error {
        Error::Record(RecordError::InvalidConversationDag(reason)) => {
            Ok(ParentAdmission::Reject(DagRejection(reason)))
        }
        local => Err(local),
    }
}

/// One shared prospective check of the effective transactional graph. The
/// coordinator consumes Ready immediately or persists Wait's typed fact.
#[cfg(feature = "sync")]
pub(crate) fn prospective_parent(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    target: EntityId,
) -> Result<ParentAdmission> {
    use crate::limits::MAX_ANCESTOR_DEPTH;
    use std::collections::HashSet;
    macro_rules! need {
        ($fact:expr) => {
            match $fact? {
                Fact::Known(value) => value,
                Fact::Wait(dep) => return Ok(ParentAdmission::Wait(NonEmptyDependencies::one(dep))),
                Fact::Reject(reason) => return Ok(ParentAdmission::Reject(reason)),
            }
        };
    }
    if source == target {
        return Ok(ParentAdmission::Reject(DagRejection(
            "received Parent contains a cycle",
        )));
    }
    let conversation = need!(owner(store, txn, source));
    let target_conversation = need!(owner(store, txn, target));
    if conversation != target_conversation {
        return Ok(ParentAdmission::Reject(DagRejection(
            "received Parent crosses conversations",
        )));
    }
    let existing = match graph::parent(store, txn, &source) {
        Ok(parent) => parent,
        Err(error) => return remote_error(error),
    };
    if let Some(existing) = existing
        && existing != target
    {
        return Ok(ParentAdmission::Reject(DagRejection(
            "received record has a different Parent",
        )));
    }
    let source_body = graph::require_type(store, txn, &source, ENTITY_TYPE_TURN)?;
    let target_body = graph::require_type(store, txn, &target, ENTITY_TYPE_TURN)?;
    let source_session = match super::membership::carrier(&source_body) {
        Ok(value) => value,
        Err(Error::Record(RecordError::InvalidConversationDag(reason))) => {
            return Ok(ParentAdmission::Reject(DagRejection(reason)));
        }
        Err(local) => return Err(local),
    };
    let target_session = match super::membership::carrier(&target_body) {
        Ok(value) => value,
        Err(Error::Record(RecordError::InvalidConversationDag(reason))) => {
            return Ok(ParentAdmission::Reject(DagRejection(reason)));
        }
        Err(local) => return Err(local),
    };
    let source_placement = match source_session {
        Some(session) => Some(need!(classify_session(store, txn, session, conversation))),
        None => None,
    };
    let anchor = source_placement.and_then(SessionPlacement::anchor);
    let target_placement = if Some(target) == anchor {
        None
    } else {
        match target_session {
            Some(session) => Some(need!(classify_session(store, txn, session, conversation))),
            None => None,
        }
    };
    let anchor = match parent_boundary(source_placement, target_placement, target) {
        Ok(anchor) => anchor,
        Err(reason) => return Ok(ParentAdmission::Reject(reason)),
    };
    if existing == Some(target) {
        return Ok(ParentAdmission::Ready(ValidatedParent { source, target }));
    }
    let mut seen = HashSet::new();
    let mut cursor = Some(target);
    let mut root = target;
    while let Some(id) = cursor {
        if !seen.insert(id) || id == source {
            return Ok(ParentAdmission::Reject(DagRejection(
                "received Parent contains a cycle",
            )));
        }
        if seen.len() >= MAX_ANCESTOR_DEPTH {
            return Ok(ParentAdmission::Reject(DagRejection(
                "received Parent exceeds ancestor depth",
            )));
        }
        let actual = need!(owner(store, txn, id));
        if actual != conversation {
            return Ok(ParentAdmission::Reject(DagRejection(
                "received Parent crosses conversations",
            )));
        }
        root = id;
        cursor = match graph::parent(store, txn, &id) {
            Ok(parent) => parent,
            Err(error) => return remote_error(error),
        };
    }
    if let Some(anchor) = anchor
        && !seen.contains(&anchor)
    {
        return Ok(ParentAdmission::Wait(NonEmptyDependencies::one(
            Dependency::ParentOf(root),
        )));
    }
    if let Some(marker) = store.vault_meta.get(txn, &key(MIGRATED, &conversation))? {
        if marker.as_ref() != [1] {
            return Err(Error::CorruptedIndex("conversation DAG migration marker"));
        }
        if let Some(head) = graph::read_id(store, txn, HEAD, &conversation)?
            && graph::chain(store, txn, &conversation, head)?.contains(&source)
        {
            return Ok(ParentAdmission::Reject(DagRejection(
                "received Parent changes the adopted main line",
            )));
        }
    }
    Ok(ParentAdmission::Ready(ValidatedParent { source, target }))
}
