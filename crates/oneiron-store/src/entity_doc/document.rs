//! The common actor-stamped Loro document primitive.

use crate::receipt_identity::ERASED_CALL_IDENTITY;
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::ActorStamp;
use crate::write_envelope::provenance::made_by::MadeBy;
use crate::write_envelope::provenance::made_by::MadeByClass;
use loro::{
    CommitOptions, ExportMode, Frontiers, LoroDoc, LoroMap, LoroText, LoroValue, ValueOrContainer,
};
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

pub const BODY: &str = "body";
/// The root map a document keeps its birth and metadata in.
pub const META: &str = "meta";
pub const BIRTH: &str = "entity_doc_birth";
/// The engine stamp every local commit message opens with.
pub const STAMP: &str = "oneiron.entity_doc.v1";

/// The bytes under `key` in `map`; `None` when it holds none, or no bytes.
pub fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// How a document's birth commit is spelled.
pub enum BirthCommit<'a> {
    /// The caller's own message: a proposal artifact's receipted stamp.
    Message(&'a str),
    /// The engine stamp naming the birth actor's token, with the row's own
    /// birth envelope as its receipt when it names this birth (FIX 10929),
    /// else the generic receipt.
    Stamp(Option<&'a MadeBy>),
}

/// Commits what canonical recovery replayed into `doc`: the commit restates
/// the row's birth and names no one (FIX 10929).
pub fn restate_birth(doc: &LoroDoc) {
    doc.commit_with(
        CommitOptions::new().commit_msg(crate::entity_doc::commit_receipts::ROW_BIRTH_RESTATED),
    );
}

/// Persisted operation attribution resolved through the existing peer binding
/// ladder. A commit message alone never authenticates its claimed actor; its
/// stamp token resolves to the actor its claim names (FIX 10930).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChange {
    pub actor: Option<WriteActor>,
    pub peer: u64,
    pub timestamp: u64,
}

/// What one commit message says of its actor (FIX 6072, Engine R2).
pub enum Stamped {
    /// An engine stamp naming its writer's token and class (FIX 10930),
    /// which the token's claim resolves to the actor, or to no one once the
    /// actor is erased.
    Live(ActorStamp),
    /// An engine stamp whose actor was erased: no one.
    Erased,
    /// No engine stamp: the peer binding may name the actor.
    NotStamped,
}

/// The one stamp grammar the reader and the checkpoint split share: what
/// one reads as a stamp is what the other cuts.
pub fn parse_stamp(message: Option<&str>) -> Stamped {
    let Some((_, id, tail)) = message.and_then(cut_stamp) else {
        return Stamped::NotStamped;
    };
    if id == ERASED_CALL_IDENTITY {
        return Stamped::Erased;
    }
    match (EntityId::from_hex(id), stamp_class(tail)) {
        (Ok(token), Some(class)) => Stamped::Live(ActorStamp { token, class }),
        _ => Stamped::NotStamped,
    }
}

/// The actor class a stamp names after its token: `.<class>`, to the next
/// space.
fn stamp_class(tail: &str) -> Option<oneiron_base::edge::EdgeActorClass> {
    let class = tail.strip_prefix('.')?.split(' ').next()?;
    crate::write_envelope::actor_tokens::actor_class_from_token(class)
}

/// `message` cut around its actor token, when it is an engine stamp spelled
/// as [`stamp`] writes it (`oneiron.entity_doc.v1 <verb> actor=<token>.<class>
/// op=...`, single spaced, then its receipt): the message before the token,
/// the token (an actor's, spelled as an id, or [`ERASED_CALL_IDENTITY`]), and
/// the rest from the class on.
pub fn cut_stamp(message: &str) -> Option<(&str, &str, &str)> {
    let rest = message.strip_prefix(STAMP)?.strip_prefix(' ')?;
    let (verb, rest) = rest.split_once(' ')?;
    if verb.is_empty() {
        return None;
    }
    let id_on = rest.strip_prefix("actor=")?;
    let (id, _) = id_on.split_once('.')?;
    let head = message.get(..message.len() - id_on.len())?;
    let tail = id_on.get(id.len()..)?;
    Some((head, id, tail))
}
